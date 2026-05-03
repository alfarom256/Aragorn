"""Session & connection tools."""

import asyncio
import logging
import os
import re
import subprocess

from .. import config
from ..debugger import get_debugger, get_debugger_or_none, set_debugger, Debugger, run_on_com_thread, reset_com_executor
from ..sessions import get_registry
from ..supervisor import get_supervisor


def _supervisor_mode() -> bool:
    return os.environ.get("ARAGORN_SUPERVISOR_MODE", "1") == "1" \
        and os.environ.get("ARAGORN_WORKER", "0") != "1"

log = logging.getLogger("aragorn.tools.session")

# Hard ceiling so a tool call never hangs the MCP server
CONNECT_TIMEOUT = 90  # seconds

_TARGET_RE = re.compile(r"target=[^,\s]+")


def _patch_target(conn: str, ip: str) -> str:
    """Replace `target=<ip>` in a kdnet connection string."""
    if _TARGET_RE.search(conn):
        return _TARGET_RE.sub(f"target={ip}", conn)
    sep = "," if conn else ""
    return f"{conn}{sep}target={ip}"


def _resolve_vm_ipv4(vm_name: str, timeout: int = 15,
                      retries: int = 4, retry_delay_s: float = 2.0) -> dict:
    """Query Hyper-V for a VM's IPv4 address via Get-VMNetworkAdapter.

    Retries when the VM's integration services haven't yet reported an
    IPv4 — common for 1–2 minutes after a kdnet freeze or a fresh boot.
    Returns a dict with {vm_name, ip, all_ips} on success, or
    {error, vm_name, attempts} on failure.
    """
    import time as _time
    ps_cmd = (
        "$ips = Get-VMNetworkAdapter -VMName " + _ps_quote(vm_name) +
        " -ErrorAction Stop | ForEach-Object { $_.IPAddresses };"
        " $ips | Where-Object { $_ -match '^\\d{1,3}(\\.\\d{1,3}){3}$' }"
    )
    last_err = None
    attempts = 0
    for attempt in range(1, retries + 1):
        attempts = attempt
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=timeout,
                creationflags=0x08000000,
            )
        except subprocess.TimeoutExpired as e:
            last_err = f"powershell timeout after {timeout}s (attempt {attempt})"
        else:
            if proc.returncode != 0:
                last_err = proc.stderr.strip() or "powershell failed"
            else:
                ips = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
                if ips:
                    return {"vm_name": vm_name, "ip": ips[0],
                            "all_ips": ips, "attempts": attempts}
                last_err = ("no IPv4 reported by Hyper-V integration services "
                            "(VM booting, or recovering from kdnet freeze)")
        if attempt < retries:
            _time.sleep(retry_delay_s)
    return {"error": last_err or "vm_name resolution failed",
            "vm_name": vm_name, "attempts": attempts,
            "note": "Fall back to `connect(target_ip=...)` with the last known "
                    "IP if this persists."}


def _ps_quote(s: str) -> str:
    """Single-quote a string for PowerShell."""
    return "'" + s.replace("'", "''") + "'"


def register(mcp):

    @mcp.tool()
    async def connect(
        initial_break: bool = False,
        connection_string: str = "",
        target_ip: str = "",
        vm_name: str = "",
    ) -> dict:
        """Connect to the kernel debugger.

        By default uses the connection string baked into config (from .env).
        You can override per-call without editing .env or restarting:

          - `connection_string`: full kdnet string, e.g.
            "net:port=55555,key=...,target=10.0.0.5".
          - `target_ip`: replace only the `target=<ip>` portion. Handy
            when the VM rebooted and got a new DHCP lease.
          - `vm_name`: resolve the VM's current IPv4 via Hyper-V (same
            logic as `resolve_vm_target`) and patch `target=` with it.

        Resolution order: `connection_string` wins, then `vm_name`, then
        `target_ip`, then fall back to the stored/config value. The
        resolved string is persisted on the Debugger instance so
        subsequent `reconnect()` calls keep the new target.

        Args:
            initial_break: If True, break into the kernel on connect.
                           Default False — attach without freezing the VM.
            connection_string: Full kdnet override (see above).
            target_ip: Replace just `target=<ip>`; keep port/key as-is.
            vm_name: Resolve this Hyper-V VM's IPv4 and patch `target=`.
        """
        # In supervisor mode `dbg` is a process-local proxy; in legacy
        # mode it's a real Debugger.
        dbg = get_debugger_or_none()
        if dbg is None:
            dbg = Debugger()
            set_debugger(dbg)
        sup = get_supervisor() if _supervisor_mode() else None

        # Resolve effective connection string
        effective = None
        resolution_info: dict = {}
        if sup is not None:
            try:
                worker_state = await asyncio.wait_for(
                    sup.call("get_status"), timeout=5.0)
            except Exception:
                worker_state = {}
            base = worker_state.get("connection_string") or config.KD_CONNECTION
        else:
            base = dbg._kd_connection or config.KD_CONNECTION
        if connection_string:
            effective = connection_string
            resolution_info["source"] = "connection_string"
        elif vm_name:
            resolved = await asyncio.to_thread(_resolve_vm_ipv4, vm_name)
            resolution_info = {"source": "vm_name", **resolved}
            if "error" in resolved:
                return {"error": f"vm_name resolution failed: {resolved['error']}",
                        "vm_name": vm_name, "connected": False}
            effective = _patch_target(base, resolved["ip"])
        elif target_ip:
            effective = _patch_target(base, target_ip)
            resolution_info = {"source": "target_ip", "ip": target_ip}

        if effective:
            # Update module-level default so other callers (e.g. reconnect
            # without overrides) also pick up the new target.
            config.KD_CONNECTION = effective

        try:
            # Disconnect first if currently connected (best-effort).
            try:
                await asyncio.wait_for(
                    run_on_com_thread(dbg.disconnect), timeout=10)
            except Exception:
                pass
            await asyncio.wait_for(
                run_on_com_thread(dbg.connect,
                                   connection_string=effective,
                                   initial_break=initial_break),
                timeout=CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            # Connect hung. Under supervisor mode the right escape is
            # to restart the worker (kills the stuck dbgeng outright).
            # Under legacy mode, fall back to recover_from_wedge.
            if sup is not None:
                try:
                    await asyncio.wait_for(sup.restart(), timeout=10.0)
                except Exception:
                    pass
            else:
                try:
                    dbg.recover_from_wedge()
                except Exception:
                    pass
                reset_com_executor()
            return {
                "error": f"Connect timed out after {CONNECT_TIMEOUT}s",
                "connected": False,
                "_code_version": "v2-timeout",
            }
        except Exception as e:
            result = {
                "error": str(e),
                "connected": False,
                "_code_version": "v3-error",
            }
            return result

        # Fetch final state from worker (supervisor mode) or local dbg.
        if sup is not None:
            result = await sup.call("get_status")
        else:
            result = dbg.get_status()
        result["_code_version"] = "v2-ok"
        if resolution_info:
            result["target_resolution"] = resolution_info
        log.info("connect: %s", result)
        return result

    @mcp.tool()
    async def resolve_vm_target(vm_name: str, apply: bool = True) -> dict:
        """Resolve a Hyper-V VM's current IPv4 address and (by default)
        update the cached kdnet connection string so the next `connect()`
        targets the resolved IP.

        Uses `Get-VMNetworkAdapter` on the host. Useful when a VM
        rebooted and got a new DHCP lease: call this once, then
        `connect()` without args.

        Args:
            vm_name: Hyper-V VM name, e.g. "<vm-name>".
            apply: If True (default), update `config.KD_CONNECTION` with the
                   resolved `target=<ip>`. If False, just return the info.
        """
        resolved = await asyncio.to_thread(_resolve_vm_ipv4, vm_name)
        if "error" in resolved:
            return resolved
        ip = resolved["ip"]
        sup = get_supervisor() if _supervisor_mode() else None
        # Determine the base connection string.
        if sup is not None:
            try:
                worker_state = await asyncio.wait_for(
                    sup.call("get_status"), timeout=5.0)
            except Exception:
                worker_state = {}
            base = worker_state.get("connection_string") or config.KD_CONNECTION
        else:
            dbg = get_debugger_or_none()
            base = (getattr(dbg, "_kd_connection", None) if dbg else None) \
                   or config.KD_CONNECTION
        new_conn = _patch_target(base, ip)
        result = {
            "vm_name": vm_name,
            "ip": ip,
            "all_ips": resolved.get("all_ips", [ip]),
            "old_connection": base,
            "new_connection": new_conn,
            "applied": False,
        }
        if apply:
            config.KD_CONNECTION = new_conn
            if sup is not None:
                try:
                    await asyncio.wait_for(
                        sup.call("set_kd_connection", new_conn), timeout=3.0)
                except Exception:
                    pass
            else:
                dbg = get_debugger_or_none()
                if dbg is not None:
                    dbg._kd_connection = new_conn
            result["applied"] = True
        return result

    @mcp.tool()
    async def disconnect() -> dict:
        """Cleanly disconnect from the kernel debugger."""
        dbg = get_debugger_or_none()
        if dbg is None:
            return {"status": "was_not_connected"}
        try:
            await run_on_com_thread(dbg.disconnect)
            log.info("disconnected")
            return {"status": "disconnected"}
        except Exception as e:
            return {"status": "disconnect_error", "error": str(e)}

    @mcp.tool()
    async def status() -> dict:
        """Get debugger connection state, uptime, and configuration."""
        dbg = get_debugger_or_none()
        if dbg is None:
            return {"initialized": False, "connected": False}
        try:
            return await run_on_com_thread(dbg.get_status)
        except Exception as e:
            return {"initialized": False, "connected": False, "error": str(e)}

    @mcp.tool()
    async def target_info() -> dict:
        """Get debug target information: class, execution status, processors, page size."""
        return await run_on_com_thread(get_debugger().get_target_info)

    @mcp.tool()
    async def ensure_ready() -> dict:
        """Atomic: break into debugger, wait for stop, verify thread context, reload symbols."""
        dbg = get_debugger()
        sup = get_supervisor() if _supervisor_mode() else None
        try:
            return await asyncio.wait_for(
                run_on_com_thread(dbg.ensure_ready), timeout=60)
        except asyncio.TimeoutError:
            if sup is not None:
                try:
                    await asyncio.wait_for(sup.restart(), timeout=10.0)
                except Exception:
                    pass
            else:
                try:
                    dbg.recover_from_wedge()
                except Exception:
                    pass
                reset_com_executor()
            return {"error": "ensure_ready timed out after 60s",
                    "connected": False}

    @mcp.tool()
    async def health_check() -> dict:
        """Lightweight debugger health probe — does NOT break into the target."""
        dbg = get_debugger_or_none()
        if dbg is None:
            return {"initialized": False, "connected": False,
                    "execution_status": "no_debuggee"}
        try:
            return await run_on_com_thread(dbg.health_check)
        except Exception as e:
            return {"initialized": False, "connected": False, "error": str(e)}

    @mcp.tool()
    async def reset_engine() -> dict:
        """Reset the dbgeng state.

        In supervisor mode (default): kills the worker subprocess and
        spawns a fresh one. The Python process holding dbgeng dies and
        reincarnates, completely clearing dbgeng's internal kdnet
        state — including the "one direct attach per process" stickiness
        that's plagued earlier sessions. The MCP server stays up; no
        `/mcp` reconnect required.

        In legacy in-process mode (`ARAGORN_SUPERVISOR_MODE=0`): falls
        back to the old `Debugger.shutdown()` + executor-reset sequence,
        which doesn't fully unload dbgeng.dll but is the best we can do
        without a process boundary.
        """
        if _supervisor_mode():
            sup = get_supervisor()
            try:
                info = await asyncio.wait_for(sup.restart(), timeout=15.0)
            except Exception as e:
                return {"status": "restart_failed", "error": str(e)}
            return {"status": "worker_restarted", **info}
        # Legacy
        dbg = get_debugger_or_none()
        result = {"steps": []}
        if dbg is not None:
            try:
                await asyncio.wait_for(
                    run_on_com_thread(dbg.shutdown), timeout=5.0)
                result["steps"].append({"shutdown": "ok"})
            except (asyncio.TimeoutError, Exception) as e:
                result["steps"].append({"shutdown": f"failed: {e!r}"})
                try:
                    dbg.recover_from_wedge()
                except Exception:
                    pass
        set_debugger(None)
        result["steps"].append({"singleton": "cleared"})
        reset_com_executor()
        result["steps"].append({"com_executor": "reset"})
        result["status"] = "reset"
        return result

    @mcp.tool()
    async def restart_worker() -> dict:
        """Force-restart the dbgeng worker subprocess.

        Synonym for `reset_engine()` in supervisor mode — the worker
        process is killed and respawned, returning the new PID. Use
        this any time the underlying dbgeng state is wedged in a way
        that won't clear (notably the direct-transport "one attach per
        process" limit). MCP connection is unaffected.
        """
        if not _supervisor_mode():
            return {"status": "supervisor_mode_disabled",
                    "hint": "Set ARAGORN_SUPERVISOR_MODE=1 in .env or use reset_engine."}
        sup = get_supervisor()
        try:
            info = await asyncio.wait_for(sup.restart(), timeout=15.0)
        except Exception as e:
            return {"status": "failed", "error": str(e)}
        return {"status": "ok", **info}

    @mcp.tool()
    async def reconnect_debugger(session_id: str = "") -> dict:
        """Force a full reconnect to the kernel debugger.

        Tears down the COM session and re-initializes from scratch. Use this
        after connection loss or "partially initialized target" errors. The
        MCP server stays up — only the COM layer reconnects.

        Args:
            session_id: Session to reconnect (default: active session).
                        Falls back to legacy singleton if no sessions exist.
        """
        try:
            return await asyncio.wait_for(
                _reconnect_inner(session_id), timeout=CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            if _supervisor_mode():
                try:
                    await asyncio.wait_for(
                        get_supervisor().restart(), timeout=10.0)
                except Exception:
                    pass
            else:
                dbg = get_debugger_or_none()
                if dbg:
                    try:
                        dbg.recover_from_wedge()
                    except Exception:
                        pass
                reset_com_executor()
            return {
                "error": f"Reconnect timed out after {CONNECT_TIMEOUT}s",
                "connected": False,
            }

    async def _reconnect_inner(session_id: str = "") -> dict:
        reg = get_registry()
        sessions = reg.list_sessions()

        if sessions:
            result = await reg.disconnect_session(session_id)
            log.info("reconnect: disconnected session %s: %s", session_id or "(active)", result)
            result = await reg.connect_session(
                session_id, kd_wait_timeout=20, max_retries=1)
            log.info("reconnect: reconnected session %s: %s", session_id or "(active)", result)
            return result
        else:
            dbg = get_debugger_or_none()
            if dbg is None:
                dbg = Debugger()
                set_debugger(dbg)
            result = await run_on_com_thread(dbg.reconnect)
            log.info("reconnect: %s", result)
            return result

    @mcp.tool()
    async def test_kd_connection() -> dict:
        """Diagnostic: test kd.exe connection from within the MCP server process."""
        import subprocess, os, re, threading, queue, time
        from .. import config

        kd_exe = config.KD_EXE_PATH
        kd_conn = config.KD_CONNECTION
        port = 14500

        # Kill any stale kd.exe
        subprocess.run(["taskkill", "/F", "/IM", "kd.exe"],
                       capture_output=True, timeout=5)
        time.sleep(1)

        cmd = [kd_exe, "-server", f"tcp:port={port}", "-b", "-k", kd_conn]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE, creationflags=0x08000000)

        q: queue.Queue = queue.Queue()
        def reader():
            fd = proc.stdout.fileno()
            leftover = b""
            while True:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                data = leftover + chunk
                parts = re.split(rb"\r\n|\r|\n", data)
                leftover = parts.pop()
                for part in parts:
                    text = part.decode("utf-8", errors="replace").strip()
                    if text:
                        q.put(text)

        t = threading.Thread(target=reader, daemon=True)
        t.start()

        lines = []
        connected = False
        start = time.time()
        while time.time() - start < 20:
            try:
                line = q.get(timeout=1.0)
                lines.append(f"[{time.time()-start:.1f}s] {line}")
                if "Connected to target" in line:
                    connected = True
                    break
            except queue.Empty:
                lines.append(f"[{time.time()-start:.1f}s] (empty)")

        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

        return {
            "connected": connected,
            "lines": lines[-20:],
            "kd_cmd": " ".join(cmd),
            "elapsed": round(time.time() - start, 1),
        }

    @mcp.tool()
    async def get_debugger_state() -> dict:
        """Get full tracked debugger state including breakpoints, execution status, and last event.

        Returns the internal state dict used for cross-agent coordination.
        """
        dbg = get_debugger_or_none()
        if dbg is None:
            return {"connected": False, "initialized": False}
        return await run_on_com_thread(dbg.get_full_state)
