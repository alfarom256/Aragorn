"""Session & connection tools."""

import asyncio
import logging

from ..debugger import get_debugger, get_debugger_or_none, set_debugger, Debugger, run_on_com_thread, reset_com_executor
from ..sessions import get_registry

log = logging.getLogger("aragorn.tools.session")

# Hard ceiling so a tool call never hangs the MCP server
CONNECT_TIMEOUT = 90  # seconds


def register(mcp):

    @mcp.tool()
    async def connect(initial_break: bool = False) -> dict:
        """Connect to the kernel debugger.

        Launches kd.exe as a debug server (handles kdnet transport),
        then connects via DebugConnect. By default does NOT break into
        the target — the VM keeps running. Use initial_break=True to
        freeze the VM on connect, or call ensure_ready() after.

        Args:
            initial_break: If True, break into the kernel on connect.
                           Default False — attach without freezing the VM.
        """
        dbg = get_debugger_or_none()
        if dbg is None:
            dbg = Debugger()
            set_debugger(dbg)
        try:
            if dbg.is_connected:
                await asyncio.wait_for(
                    run_on_com_thread(dbg.disconnect), timeout=10)
            await asyncio.wait_for(
                run_on_com_thread(lambda: dbg.connect(initial_break=initial_break)),
                timeout=CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            # Kill kd.exe to unblock any pending COM calls, then
            # reset the COM executor since the old thread is stuck
            try:
                dbg._stop_kd_server()
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
            # Always include diagnostics
            kd_lines = getattr(dbg, '_kd_last_lines', [])
            result["kd_lines_seen"] = len(kd_lines)
            result["kd_output"] = kd_lines[-15:] if kd_lines else "(none)"
            kd_proc = getattr(dbg, '_kd_process', None)
            result["kd_pid"] = kd_proc.pid if kd_proc else None
            result["kd_alive"] = kd_proc.poll() is None if kd_proc else False
            return result
        result = dbg.get_status()
        result["_code_version"] = "v2-ok"
        log.info("connect: %s", result)
        return result

    @mcp.tool()
    async def disconnect() -> dict:
        """Cleanly disconnect from the kernel debugger."""
        dbg = get_debugger_or_none()
        if dbg and dbg.is_connected:
            await run_on_com_thread(dbg.disconnect)
            log.info("disconnected")
            return {"status": "disconnected"}
        return {"status": "was_not_connected"}

    @mcp.tool()
    async def status() -> dict:
        """Get debugger connection state, uptime, and configuration."""
        dbg = get_debugger_or_none()
        if dbg:
            return await run_on_com_thread(dbg.get_status)
        return {"initialized": False, "connected": False}

    @mcp.tool()
    async def target_info() -> dict:
        """Get debug target information: class, execution status, processors, page size."""
        dbg = get_debugger()  # raises if not connected
        return await run_on_com_thread(dbg.get_target_info)

    @mcp.tool()
    async def ensure_ready() -> dict:
        """Atomic: break into debugger, wait for stop, verify thread context, reload symbols.

        Eliminates the multi-step ceremony required to get the debugger into a
        usable state. Retries up to 5 times with increasing delays. Uses
        processor cycling and forced symbol reload to recover thread context.
        Call this before any operation that requires the target to be stopped.
        """
        dbg = get_debugger()  # raises if not connected
        try:
            return await asyncio.wait_for(
                run_on_com_thread(dbg.ensure_ready), timeout=60)
        except asyncio.TimeoutError:
            try:
                dbg._stop_kd_server()
            except Exception:
                pass
            reset_com_executor()
            return {"error": "ensure_ready timed out after 60s", "connected": False}

    @mcp.tool()
    async def health_check() -> dict:
        """Lightweight debugger health probe — does NOT break into the target.

        Returns connection state, execution status, processor count, and tracked
        breakpoint count. Safe to call at any time without disrupting a running VM.
        Use this for pre-flight checks before setting breakpoints or starting
        coordinated operations.
        """
        dbg = get_debugger_or_none()
        if dbg is None:
            return {
                "initialized": False,
                "connected": False,
                "execution_status": "no_debuggee",
            }
        return await run_on_com_thread(dbg.health_check)

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
            dbg = get_debugger_or_none()
            if dbg:
                try:
                    dbg._stop_kd_server()
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
