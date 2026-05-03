"""Aragorn supervisor — owns the worker subprocess.

The MCP server stays in the supervisor; dbgeng lives in the worker.
This module exposes:

    sup = get_supervisor()
    result = await sup.call("method_name", *args, **kwargs)
    await sup.restart()                     # kill worker, spawn fresh
    sup.is_worker_alive()
    await sup.shutdown()

Why: dbgeng has a "one kdnet attach per process lifetime" limit. When
that limit is hit (very common after wedge recovery), the only fix is a
fresh process. Doing it in a worker subprocess instead of the MCP
server itself means we never have to ask the user to `/mcp` reconnect.

Wire format mirrors `worker.py`. JSON-RPC over stdio, newline-delimited.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import threading
from typing import Any, Optional

log = logging.getLogger("aragorn.supervisor")


class WorkerError(Exception):
    """Error raised when a worker call fails."""

    def __init__(self, error_type: str, message: str,
                 traceback_str: str = "", hr: int | None = None):
        self.error_type = error_type
        self.message = message
        self.traceback = traceback_str
        self.hr = hr
        suffix = f" (HRESULT 0x{hr & 0xFFFFFFFF:08X})" if hr is not None else ""
        super().__init__(f"{error_type}: {message}{suffix}")


class WorkerDeadError(WorkerError):
    """Raised when the worker subprocess died unexpectedly."""

    def __init__(self, exit_code: int | None):
        super().__init__("WorkerDead",
                         f"worker exited with code {exit_code}")
        self.exit_code = exit_code


class Supervisor:
    """Manages a single Aragorn worker subprocess.

    Public API is async; instances are intended to be used as a process-
    wide singleton. Concurrent `call()`s are serialized on a single
    request-id counter and a single stdin write lock.
    """

    def __init__(self):
        self._proc: subprocess.Popen | None = None
        self._proc_started_count = 0
        self._next_id = 1
        self._pending: dict[int, asyncio.Future] = {}
        self._stdin_lock = asyncio.Lock()
        self._reader_task: asyncio.Task | None = None
        self._stderr_task: asyncio.Task | None = None
        self._spawn_lock = asyncio.Lock()

    # ─── Lifecycle ───────────────────────────────────────────────────

    def is_worker_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    async def ensure_worker(self) -> None:
        if self.is_worker_alive():
            return
        async with self._spawn_lock:
            if self.is_worker_alive():
                return
            await self._spawn()

    async def _spawn(self) -> None:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        # Tell debugger.py's _is_supervisor_mode() to return False inside
        # the worker — we want the worker to run dbgeng in-process, not
        # try to forward calls to itself.
        env["ARAGORN_WORKER"] = "1"
        # `python -m Aragorn.worker` keeps it import-system-friendly.
        worker_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cmd = [sys.executable, "-m", "Aragorn.worker"]
        log.info("Spawning worker: %s", " ".join(cmd))
        # bufsize=0 → unbuffered pipes. Python's text-mode wrapper still
        # buffers internally when bufsize>0; on Windows that can stall a
        # readline-driven child waiting for data we already wrote.
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0,
            cwd=worker_root, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self._proc_started_count += 1
        log.info("Worker spawned (pid=%d, attempt=%d)",
                 self._proc.pid, self._proc_started_count)
        # Cancel any lingering reader from a previous worker
        if self._reader_task is not None:
            self._reader_task.cancel()
        if self._stderr_task is not None:
            self._stderr_task.cancel()
        loop = asyncio.get_running_loop()
        self._reader_task = loop.create_task(self._reader_loop(self._proc))
        self._stderr_task = loop.create_task(self._stderr_loop(self._proc))
        # Yield so the reader loop can start before we issue any RPCs.
        await asyncio.sleep(0.05)
        # Ping the new worker to confirm it's responsive. Use the raw
        # request path (bypasses ensure_worker, which would recurse).
        try:
            rid = self._next_id
            self._next_id += 1
            ready_fut: asyncio.Future = loop.create_future()
            self._pending[rid] = ready_fut
            ping = (json.dumps({"id": rid, "method": "_ping",
                                 "args": [], "kwargs": {}}) + "\n").encode("utf-8")
            proc = self._proc
            await loop.run_in_executor(
                None, lambda: (proc.stdin.write(ping), proc.stdin.flush()))
            await asyncio.wait_for(ready_fut, timeout=5.0)
            log.info("Worker ready (pid=%d)", self._proc.pid)
        except Exception as e:
            log.warning("Worker spawn ping failed: %s", e)
            self._pending.pop(rid, None)

    async def _reader_loop(self, proc: subprocess.Popen) -> None:
        """Read JSON-RPC responses from worker stdout and resolve futures."""
        loop = asyncio.get_running_loop()
        try:
            while True:
                raw = await loop.run_in_executor(None, proc.stdout.readline)
                if not raw:
                    break
                if isinstance(raw, bytes):
                    try:
                        line = raw.decode("utf-8", errors="replace")
                    except Exception:
                        continue
                else:
                    line = raw
                try:
                    resp = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("Worker emitted non-JSON stdout: %r", line[:200])
                    continue
                rid = resp.get("id")
                if rid is None:
                    continue
                fut = self._pending.pop(rid, None)
                if fut is None or fut.done():
                    continue
                if resp.get("ok"):
                    fut.set_result(resp.get("result"))
                else:
                    fut.set_exception(WorkerError(
                        resp.get("error_type", "Exception"),
                        resp.get("error_message", "(no message)"),
                        resp.get("traceback", ""),
                        hr=resp.get("hr"),
                    ))
        finally:
            # Worker is done. Fail any in-flight calls.
            exit_code = proc.poll()
            for fut in list(self._pending.values()):
                if not fut.done():
                    fut.set_exception(WorkerDeadError(exit_code))
            self._pending.clear()
            log.info("Reader loop ended (exit_code=%s)", exit_code)

    async def _stderr_loop(self, proc: subprocess.Popen) -> None:
        """Forward worker stderr to our own stderr, prefixed."""
        loop = asyncio.get_running_loop()
        try:
            while True:
                raw = await loop.run_in_executor(None, proc.stderr.readline)
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace") \
                    if isinstance(raw, bytes) else raw
                sys.stderr.write(f"[worker.{proc.pid}] {line}")
                sys.stderr.flush()
        except Exception:
            pass

    async def shutdown(self) -> None:
        """Tell the worker to exit, then reap it."""
        if not self.is_worker_alive():
            return
        try:
            await self.call("_shutdown", _timeout=2.0)
        except Exception:
            pass
        if self._proc is not None and self._proc.poll() is None:
            try:
                self._proc.kill()
            except Exception:
                pass
        self._proc = None

    async def restart(self) -> dict:
        """Kill the current worker and spawn a fresh one.

        Use this whenever the in-process dbgeng state is wedged (direct
        transport one-attach limit, COM in indeterminate state, etc.).
        Pending calls are failed with WorkerDeadError; the next call
        will spawn a new worker on demand.
        """
        old_pid = self._proc.pid if self._proc else None
        if self._proc is not None and self._proc.poll() is None:
            try:
                self._proc.kill()
            except Exception:
                pass
            try:
                self._proc.wait(timeout=3)
            except Exception:
                pass
        self._proc = None
        # Fail anything in-flight
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(WorkerDeadError(None))
        self._pending.clear()
        await self.ensure_worker()
        return {
            "status": "restarted",
            "old_pid": old_pid,
            "new_pid": self._proc.pid if self._proc else None,
            "worker_starts": self._proc_started_count,
        }

    # ─── RPC ─────────────────────────────────────────────────────────

    async def call(self, method: str, *args, _timeout: float | None = None,
                    **kwargs) -> Any:
        """Issue an RPC call to the worker. Spawns a worker if needed."""
        await self.ensure_worker()

        rid = self._next_id
        self._next_id += 1
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending[rid] = fut

        req = {"id": rid, "method": method, "args": list(args), "kwargs": kwargs}
        line = (json.dumps(req) + "\n").encode("utf-8")

        try:
            async with self._stdin_lock:
                proc = self._proc
                if proc is None or proc.poll() is not None:
                    raise WorkerDeadError(proc.poll() if proc else None)
                # subprocess stdin write is blocking; offload.
                await loop.run_in_executor(
                    None, lambda: (proc.stdin.write(line), proc.stdin.flush())
                )
        except Exception:
            self._pending.pop(rid, None)
            raise

        if _timeout is None:
            return await fut
        return await asyncio.wait_for(fut, timeout=_timeout)


_supervisor: Supervisor | None = None
_supervisor_lock = threading.Lock()


def get_supervisor() -> Supervisor:
    """Process-wide Supervisor singleton."""
    global _supervisor
    with _supervisor_lock:
        if _supervisor is None:
            _supervisor = Supervisor()
    return _supervisor
