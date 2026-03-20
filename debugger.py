"""High-level Debugger class wrapping all DbgEng COM interfaces.

Architecture:
    kd.exe (debug server) handles the kdnet transport to the VM kernel.
    Aragorn connects to kd.exe via local TCP using DebugConnect().
    All COM operations go through the debug server transparently.

    kd.exe -server tcp:port=14500 -b -k net:port=55555,...
        ↑
    DebugConnect("tcp:port=14500,server=localhost")
        ↑
    Aragorn (this code)
"""

import asyncio
import concurrent.futures
import logging
import os
import signal
import subprocess
import threading
import time

from ctypes import c_void_p, byref

from . import config
from .dbgeng import (
    debug_connect,
    DbgEngError, check_hr, S_OK, S_FALSE, E_FAIL, E_UNEXPECTED,
    IID_IDebugControl, IID_IDebugDataSpaces2, IID_IDebugRegisters,
    IID_IDebugSymbols2, IID_IDebugSystemObjects,
    DebugClient, DebugControl, DebugDataSpaces, DebugRegisters,
    DebugSymbols, DebugSystemObjects, DebugBreakpoint,
    DEBUG_ATTACH_KERNEL_CONNECTION,
    DEBUG_END_ACTIVE_DETACH,
    DEBUG_ENGOPT_INITIAL_BREAK,
    DEBUG_INTERRUPT_ACTIVE, DEBUG_INTERRUPT_EXIT,
    DEBUG_STATUS_BREAK, DEBUG_STATUS_NO_DEBUGGEE, DEBUG_STATUS_GO,
    SYMOPT_UNDNAME, SYMOPT_DEFERRED_LOADS, SYMOPT_CASE_INSENSITIVE,
    INFINITE,
)
from .callbacks import OutputCallbacks, EventCallbacks

log = logging.getLogger("aragorn.debugger")


class Debugger:
    """Singleton managing the full DbgEng lifecycle via kd.exe debug server.

    Typical flow:
        dbg = Debugger()
        dbg.connect()           # launches kd.exe, waits for break, DebugConnects
        output = dbg.execute("vertarget")
        dbg.shutdown()
    """

    def __init__(self):
        # COM interfaces
        self.client: DebugClient | None = None
        self.control: DebugControl | None = None
        self.data: DebugDataSpaces | None = None
        self.registers: DebugRegisters | None = None
        self.symbols: DebugSymbols | None = None
        self.sysobj: DebugSystemObjects | None = None

        # DLL handle (needed for FreeLibrary on reconnect)
        self._dll = None

        # kd.exe subprocess
        self._kd_process: subprocess.Popen | None = None

        # Callbacks (must stay alive for the lifetime of the session)
        self.output_cb: OutputCallbacks | None = None
        self.event_cb: EventCallbacks | None = None

        # Connection params (set on connect, reused on reconnect)
        self._kd_connection: str | None = None
        self._kd_server_port: int | None = None

        # State
        self._initialized = False
        self._connected = False
        self._connect_time: float | None = None
        self._kd_broke_in = False
        self._initial_break = False  # set by connect(initial_break=True)

        # Tracked state (exposed via get_full_state)
        self._state = {
            "breakpoints": [],       # list of dicts: {id, address, expression}
            "execution_status": "no_debuggee",
            "last_event": None,
            "connected_since": None,
            "last_error": None,
        }

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def is_connected(self) -> bool:
        return self._connected

    # ─── kd.exe management ────────────────────────────────────────────

    def _kill_stale_kd(self):
        """Kill any orphaned kd.exe processes bound to our server port."""
        server_port = self._kd_server_port or config.KD_SERVER_PORT
        try:
            # Find PIDs listening on our port
            result = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for line in result.stdout.splitlines():
                if f":{server_port}" in line and "LISTENING" in line:
                    parts = line.split()
                    pid = int(parts[-1])
                    # Skip our own tracked kd.exe
                    if (self._kd_process is not None
                            and self._kd_process.poll() is None
                            and pid == self._kd_process.pid):
                        continue
                    log.info("Killing stale process on port %d (PID %d)",
                             server_port, pid)
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        capture_output=True, timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    time.sleep(0.5)
        except Exception as e:
            log.warning("Failed to check for stale kd.exe: %s", e)

    def _start_kd_server(self):
        """Launch kd.exe as a debug server with kdnet transport."""
        if self._kd_process is not None and self._kd_process.poll() is None:
            log.info("kd.exe already running (PID %d)", self._kd_process.pid)
            return

        # Kill any orphaned kd.exe still holding the port
        self._kill_stale_kd()

        kd_exe = config.KD_EXE_PATH
        server_port = self._kd_server_port or config.KD_SERVER_PORT
        kd_conn = self._kd_connection or config.KD_CONNECTION

        cmd = [
            kd_exe,
            "-server", f"tcp:port={server_port}",
            "-k", kd_conn,
        ]
        if self._initial_break:
            cmd.insert(-2, "-b")  # insert before -k

        log.info("Starting kd.exe: %s", " ".join(cmd))
        self._kd_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        log.info("kd.exe started (PID %d)", self._kd_process.pid)

    def _stop_kd_server(self):
        """Terminate kd.exe subprocess."""
        if self._kd_process is None:
            return

        pid = self._kd_process.pid
        try:
            self._kd_process.terminate()
            try:
                self._kd_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._kd_process.kill()
                self._kd_process.wait(timeout=3)
            log.info("kd.exe stopped (PID %d)", pid)
        except Exception as e:
            log.warning("Failed to stop kd.exe (PID %d): %s", pid, e)
        finally:
            self._kd_process = None

    # ─── Lifecycle ────────────────────────────────────────────────────

    def _wait_for_kd_ready(self, timeout: int = 60) -> bool:
        """Wait for kd.exe to connect to the target.

        Returns True as soon as kd.exe has established a connection to the
        target kernel (via kdnet).  Does NOT require an initial break — the
        caller is responsible for breaking in after DebugConnect.

        If kd.exe also reports a break (e.g. from the -b flag at boot), that
        is noted in self._kd_broke_in so the caller can skip SetInterrupt.
        """
        if self._kd_process is None:
            return False

        import re
        import threading
        import queue as _queue

        _break_re = re.compile(r"nt!\w+.*:")

        line_queue: _queue.Queue = _queue.Queue()

        def _reader():
            """Read kd.exe stdout using raw os.read() to avoid BufferedReader
            blocking on incomplete blocks.  Splits on \\r and \\n so that
            carriage-return status updates (retry counters) are delivered
            immediately instead of waiting for a newline that may never come."""
            try:
                import os as _os
                fd = self._kd_process.stdout.fileno()
                leftover = b""
                while True:
                    chunk = _os.read(fd, 4096)  # returns as soon as ANY data arrives
                    if not chunk:
                        break
                    data = leftover + chunk
                    # Split on \r\n, \r, or \n
                    parts = re.split(rb"\r\n|\r|\n", data)
                    leftover = parts.pop()  # last element may be incomplete
                    for part in parts:
                        text = part.decode("utf-8", errors="replace").strip()
                        if text:
                            line_queue.put(text)
            except (ValueError, OSError):
                pass

        self._kd_reader_queue = line_queue
        reader_thread = threading.Thread(target=_reader, daemon=True)
        reader_thread.start()

        self._kd_broke_in = False
        self._kd_last_lines = []  # track ALL lines seen
        deadline = time.time() + timeout

        while time.time() < deadline:
            if self._kd_process.poll() is not None:
                log.error("kd.exe exited prematurely (code %d)",
                          self._kd_process.returncode)
                self._kd_last_lines.append(
                    f"[EXITED code={self._kd_process.returncode}]")
                return False
            try:
                line = line_queue.get(timeout=1.0)
                log.info("kd.exe: %s", line)
                self._kd_last_lines.append(line)

                # Break indicators — kd.exe already broke in (boot-time -b)
                if ("kd>" in line or "Break instruction exception" in line
                        or _break_re.search(line)):
                    log.info("kd.exe: broken in (boot-time break)")
                    self._kd_broke_in = True
                    return True

                # Connection indicators — target is reachable
                if ("Kernel Debugger connection established" in line
                        or "Connected to target" in line):
                    log.info("kd.exe: connected to target (no break yet, "
                             "will use SetInterrupt after DebugConnect)")
                    return True

            except _queue.Empty:
                continue

        # Timeout — collect any stragglers
        while not line_queue.empty():
            try:
                self._kd_last_lines.append(line_queue.get_nowait())
            except _queue.Empty:
                break
        log.warning("Timed out waiting for kd.exe (%ds). Lines seen: %d",
                    timeout, len(self._kd_last_lines))
        return False

    def _drain_kd_output(self, seconds: float = 2.0):
        """Drain kd.exe output for a few seconds (log it)."""
        import queue as _queue
        q = getattr(self, '_kd_reader_queue', None)
        if q is None:
            return
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                line = q.get(timeout=0.5)
                log.info("kd.exe: %s", line)
            except _queue.Empty:
                continue

    def _validate_connection(self) -> bool:
        """Quick check that kd.exe is alive and COM is responsive.

        Does NOT break in or change execution state. Returns False if
        the connection is stale (e.g. after VM reboot).
        """
        if not self._connected:
            return False
        if self._kd_process is not None and self._kd_process.poll() is not None:
            log.warning("_validate_connection: kd.exe exited (code %d)",
                        self._kd_process.returncode)
            return False
        try:
            self.control.GetExecutionStatus()
            return True
        except (DbgEngError, OSError) as e:
            log.warning("_validate_connection: COM call failed: %s", e)
            return False

    def connect(self, connection_string: str | None = None,
                kd_wait_timeout: int = 30,
                server_port: int | None = None,
                initial_break: bool = False):
        """Launch kd.exe and connect via DebugConnect.

        1. Start kd.exe as a debug server (handles kdnet transport)
        2. Wait for kd.exe to connect to the target
        3. DebugConnect to kd.exe's debug server
        4. Optionally break into the target (only if initial_break=True)

        Args:
            connection_string: kdnet connection string override.
            kd_wait_timeout: Seconds to wait for kd.exe to connect (default 30).
            server_port: Local TCP port for kd.exe debug server override.
            initial_break: If True, pass -b to kd.exe and force break-in.
                           Default False — attach without freezing the VM.
        """
        self._initial_break = initial_break
        # Store connection params for reconnect
        if connection_string:
            self._kd_connection = connection_string
        if server_port:
            self._kd_server_port = server_port

        actual_port = self._kd_server_port or config.KD_SERVER_PORT
        remote = f"tcp:port={actual_port},server=localhost"

        last_error = None
        for attempt in range(1, config.CONNECT_RETRIES + 1):
            try:
                t0 = time.time()
                log.info("[%.1fs] Connection attempt %d/%d",
                         0.0, attempt, config.CONNECT_RETRIES)

                # Step 1: Start kd.exe
                self._start_kd_server()
                log.info("[%.1fs] kd.exe started", time.time() - t0)

                # Step 2: Wait for kd.exe to connect to the target
                if not self._wait_for_kd_ready(timeout=kd_wait_timeout):
                    raise DbgEngError(-1, "kd.exe failed to connect to target")
                log.info("[%.1fs] kd.exe connected", time.time() - t0)

                # Give kd.exe a moment to stabilize
                time.sleep(0.5)

                # Step 3: DebugConnect to kd.exe's debug server
                log.info("[%.1fs] DebugConnect to %s", time.time() - t0, remote)
                import os
                os.add_dll_directory(os.path.dirname(config.DBGENG_PATH))
                self.client, self._dll = debug_connect(remote, config.DBGENG_PATH)
                log.info("[%.1fs] DebugConnect succeeded", time.time() - t0)

                # Step 4: QI all interfaces
                self.control = DebugControl(
                    self.client.query_interface(IID_IDebugControl))
                self.data = DebugDataSpaces(
                    self.client.query_interface(IID_IDebugDataSpaces2))
                self.registers = DebugRegisters(
                    self.client.query_interface(IID_IDebugRegisters))
                self.symbols = DebugSymbols(
                    self.client.query_interface(IID_IDebugSymbols2))
                self.sysobj = DebugSystemObjects(
                    self.client.query_interface(IID_IDebugSystemObjects))
                log.info("[%.1fs] QI interfaces done", time.time() - t0)

                # Step 5: Set up callbacks
                self.output_cb = OutputCallbacks()
                self.event_cb = EventCallbacks(max_events=config.EVENT_QUEUE_SIZE)
                self.client.SetOutputCallbacks(self.output_cb.as_param())
                self.client.SetEventCallbacks(self.event_cb.as_param())
                log.info("[%.1fs] Callbacks set", time.time() - t0)

                # Step 6: Configure symbols
                self.symbols.AddSymbolOptions(
                    SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_CASE_INSENSITIVE)
                sym_path = config.SYMBOL_PATH.encode("utf-8")
                self.symbols.SetSymbolPath(sym_path)
                log.info("[%.1fs] Symbols configured", time.time() - t0)

                # Step 7: Break in only if requested
                log.info("[%.1fs] Getting execution status...", time.time() - t0)
                status = self.control.GetExecutionStatus()
                log.info("[%.1fs] Execution status: %s (%d)",
                         time.time() - t0, self._status_name(status), status)

                if initial_break and status != DEBUG_STATUS_BREAK:
                    log.info("[%.1fs] Target not broken — sending SetInterrupt",
                             time.time() - t0)
                    self.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE)
                    log.info("[%.1fs] SetInterrupt sent, WaitForEvent(10s)...",
                             time.time() - t0)
                    hr = self.control.WaitForEvent(10_000)
                    log.info("[%.1fs] WaitForEvent returned 0x%08X",
                             time.time() - t0, hr & 0xFFFFFFFF)
                    if hr == S_OK:
                        log.info("Break-in succeeded via SetInterrupt")
                    elif hr == S_FALSE:
                        log.warning("WaitForEvent timed out — target may not "
                                    "have broken in, proceeding anyway")
                    else:
                        log.warning("WaitForEvent returned 0x%08X",
                                    hr & 0xFFFFFFFF)
                elif not initial_break and status != DEBUG_STATUS_BREAK:
                    log.info("[%.1fs] Attached without break-in (VM still running)",
                             time.time() - t0)
                elif not initial_break and status == DEBUG_STATUS_BREAK:
                    # kdnet broke in automatically — resume immediately.
                    log.info("[%.1fs] kdnet auto-broke in, resuming (initial_break=False)",
                             time.time() - t0)
                    resume_result = self.resume_target(max_attempts=10)
                    log.info("[%.1fs] auto-resume: %s", time.time() - t0, resume_result)
                    if resume_result["status"] != "running":
                        log.warning("[%.1fs] Auto-resume FAILED — VM may be frozen",
                                    time.time() - t0)

                # Drain any remaining kd.exe output
                self._drain_kd_output(1.0)

                # Step 8: Verify connection
                log.info("[%.1fs] Verifying connection...", time.time() - t0)
                status = self.control.GetExecutionStatus()
                status_name = self._status_name(status)

                # GetPageSize / Reload only work when target is stopped
                if status == DEBUG_STATUS_BREAK:
                    page_size = self.control.GetPageSize()
                    log.info("[%.1fs] page_size=%d", time.time() - t0, page_size)
                    try:
                        self.symbols.Reload(b"")
                    except DbgEngError:
                        log.warning("Symbol reload failed (non-fatal)")

                self._initialized = True
                self._connected = True
                self._connect_time = time.time()
                self._state["connected_since"] = self._connect_time
                self._state["execution_status"] = status_name
                self._state["last_error"] = None

                log.info("Connected! status=%s", status_name)

                return

            except (DbgEngError, OSError) as e:
                log.warning("Attempt %d failed: %s", attempt, e)
                last_error = e
                self._cleanup_partial()
                if attempt < config.CONNECT_RETRIES:
                    log.info("Retrying in %ds...", config.CONNECT_BACKOFF_SECONDS)
                    time.sleep(config.CONNECT_BACKOFF_SECONDS)

        raise last_error or DbgEngError(-1, "Connection failed after all retries")

    def _cleanup_partial(self):
        """Clean up after a failed connection attempt."""
        # Stop kd.exe so the next attempt starts fresh
        self._stop_kd_server()

        for iface in [self.sysobj, self.symbols, self.registers,
                      self.data, self.control, self.client]:
            if iface is not None:
                try:
                    iface.release()
                except Exception:
                    pass
        self.client = None
        self.control = None
        self.data = None
        self.registers = None
        self.symbols = None
        self.sysobj = None
        self.output_cb = None
        self.event_cb = None
        self._initialized = False
        self._connected = False
        if self._dll is not None:
            try:
                import ctypes
                ctypes.windll.kernel32.FreeLibrary(self._dll._handle)
            except Exception:
                pass
            self._dll = None
        self._stop_kd_server()

    def disconnect(self):
        """Cleanly detach from the debug server."""
        if not self._connected:
            return

        try:
            self.client.DetachProcesses()
        except DbgEngError as e:
            log.warning("DetachProcesses failed: %s", e)

        try:
            self.client.EndSession(DEBUG_END_ACTIVE_DETACH)
        except DbgEngError as e:
            log.warning("EndSession failed: %s", e)

        self._connected = False
        self._connect_time = None
        log.info("Disconnected from debug server")

    def shutdown(self):
        """Release all COM interfaces, free DLL, and stop kd.exe."""
        import ctypes as _ctypes

        self.disconnect()

        for iface in [self.sysobj, self.symbols, self.registers,
                      self.data, self.control, self.client]:
            if iface is not None:
                try:
                    iface.release()
                except Exception:
                    pass

        self.client = None
        self.control = None
        self.data = None
        self.registers = None
        self.symbols = None
        self.sysobj = None
        self.output_cb = None
        self.event_cb = None
        self._initialized = False

        if self._dll is not None:
            try:
                _ctypes.windll.kernel32.FreeLibrary(self._dll._handle)
            except Exception:
                pass
            self._dll = None

        self._stop_kd_server()
        log.info("Shutdown complete")

    # ─── Command execution ───────────────────────────────────────────

    def execute(self, command: str, timeout_ms: int = None) -> str:
        """Execute with two-phase stall detection watchdog."""
        self._require_connected()
        if timeout_ms is None:
            timeout_ms = config.DEFAULT_TIMEOUT_MS

        log.info("exec: %s", command)
        self.output_cb.clear()
        cmd_bytes = command.encode("utf-8")

        grace_s = config.INITIAL_GRACE_S
        stall_s = config.STALL_TIMEOUT_S
        hard_s = config.HARD_TIMEOUT_S

        aborted = False
        reason = ""
        stop = threading.Event()

        def _kill_kd():
            if self._kd_process and self._kd_process.poll() is None:
                log.warning("Watchdog: killing kd.exe (PID %d)", self._kd_process.pid)
                self._kd_process.kill()

        def _wd():
            nonlocal aborted, reason
            t0 = time.monotonic()
            while not stop.wait(2.0):
                elapsed = time.monotonic() - t0
                # Hard timeout — always kill
                if elapsed >= hard_s:
                    reason = f"hard timeout ({hard_s}s)"
                    aborted = True
                    log.warning("Watchdog: %s for '%s'", reason, command)
                    _kill_kd()
                    return
                # After grace period, check for stall
                if elapsed >= grace_s:
                    last = self.output_cb.last_output_time
                    if last is None:
                        # No output at all after grace period
                        reason = f"no output after {grace_s}s grace"
                        aborted = True
                        log.warning("Watchdog: %s for '%s'", reason, command)
                        _kill_kd()
                        return
                    if time.monotonic() - last >= stall_s:
                        reason = f"output stalled for {stall_s}s"
                        aborted = True
                        log.warning("Watchdog: %s for '%s'", reason, command)
                        _kill_kd()
                        return

        wd_thread = threading.Thread(target=_wd, daemon=True, name="wd-execute")
        wd_thread.start()
        try:
            self.control.Execute(cmd_bytes)
        except (DbgEngError, OSError) as e:
            if not aborted:
                raise
            log.warning("Execute() raised after watchdog kill: %s", e)
        finally:
            stop.set()
            wd_thread.join(timeout=3.0)

        output = self.output_cb.get_text()
        if aborted:
            output += f"\n\n[ARAGORN] Command aborted: {reason}.\n"
            self._connected = False
        if output:
            first_line = output.split("\n")[0][:120]
            log.info("  → %s", first_line)
        return output

    def evaluate(self, expression: str) -> int:
        """Evaluate a debugger expression and return the numeric result."""
        self._require_connected()
        expr_bytes = expression.encode("utf-8")
        return self.control.Evaluate(expr_bytes)

    # ─── Readiness ───────────────────────────────────────────────────

    def ensure_ready(self) -> dict:
        """Break → wait → verify thread context → reload symbols.

        Retries up to 5 times with increasing delays.
        """
        self._require_connected()

        delays = [0.5, 1, 2, 3, 5]
        diagnostics = []

        for attempt in range(1, 6):
            step_results = {"attempt": attempt}

            # Step 1: Break into the debugger (skip if already broken)
            try:
                pre_status = self.control.GetExecutionStatus()
                if pre_status == DEBUG_STATUS_BREAK:
                    step_results["interrupt"] = "already_broken"
                else:
                    self.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE)
                    step_results["interrupt"] = "ok"
            except DbgEngError as e:
                step_results["interrupt"] = f"skipped ({e})"

            # Step 2: Wait for the break event
            hr = self.control.WaitForEvent(5_000)
            if hr == S_OK:
                step_results["wait"] = "ok"
            elif hr == S_FALSE:
                step_results["wait"] = "timeout"
            elif hr < 0:
                try:
                    status = self.control.GetExecutionStatus()
                    if status == DEBUG_STATUS_BREAK:
                        step_results["wait"] = "already_broken"
                    else:
                        step_results["wait"] = f"failed (hr=0x{hr & 0xFFFFFFFF:08X})"
                        diagnostics.append(step_results)
                        if attempt < 5:
                            time.sleep(delays[attempt - 1])
                            continue
                except DbgEngError:
                    step_results["wait"] = f"failed (hr=0x{hr & 0xFFFFFFFF:08X})"
                    diagnostics.append(step_results)
                    if attempt < 5:
                        time.sleep(delays[attempt - 1])
                        continue

            # Step 3: Set process context to System (always valid)
            try:
                self.output_cb.clear()
                self.control.Execute(
                    b".process /r /p poi(nt!PsInitialSystemProcess)")
                step_results["process_context"] = "ok"
            except DbgEngError as e:
                step_results["process_context"] = f"failed ({e})"

            # Step 4: Verify we have a valid thread context
            try:
                tid = self.sysobj.GetCurrentThreadId()
                step_results["thread_context"] = f"ok (tid={tid})"
            except DbgEngError:
                step_results["thread_context"] = "failed"
                tid = self._recover_thread_context(step_results)
                if tid is None:
                    diagnostics.append(step_results)
                    if attempt < 5:
                        time.sleep(delays[attempt - 1])
                        continue
                    # Check for dead connection — auto-reconnect if detected
                    wait_fails = sum(
                        1 for d in diagnostics
                        if isinstance(d, dict)
                        and "failed" in str(d.get("wait", ""))
                    )
                    kd_dead = (self._kd_process is not None
                               and self._kd_process.poll() is not None)
                    if wait_fails >= 2 or kd_dead:
                        log.warning(
                            "ensure_ready: connection appears dead "
                            "(%d wait failures, kd_dead=%s), reconnecting...",
                            wait_fails, kd_dead)
                        try:
                            self.reconnect(kd_wait_timeout=30)
                            self.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE)
                            rhr = self.control.WaitForEvent(10_000)
                            if (rhr == S_OK
                                    or self.control.GetExecutionStatus()
                                    == DEBUG_STATUS_BREAK):
                                try:
                                    self.symbols.Reload(b"")
                                except DbgEngError:
                                    pass
                                st = self.control.GetExecutionStatus()
                                new_tid = self.sysobj.GetCurrentThreadId()
                                self._state["execution_status"] = (
                                    self._status_name(st))
                                self._state["last_error"] = None
                                return {
                                    "status": "ready",
                                    "thread_id": new_tid,
                                    "execution_status": self._status_name(st),
                                    "execution_status_raw": st,
                                    "attempt": attempt,
                                    "reconnected": True,
                                    "diagnostics": diagnostics,
                                }
                        except Exception as re_err:
                            log.error("Auto-reconnect failed: %s", re_err)
                            diagnostics.append(
                                {"reconnect": f"failed: {re_err}"})

                    self._state["last_error"] = (
                        "No thread context after 5 attempts")
                    raise DbgEngError(-1,
                        f"No thread context after 5 attempts. "
                        f"Diagnostics: {diagnostics}")

            # Step 5: Reload symbols
            try:
                self.symbols.Reload(b"")
                step_results["symbols"] = "ok"
            except DbgEngError:
                step_results["symbols"] = "failed (non-fatal)"

            # Step 6: Get execution status
            status = self.control.GetExecutionStatus()
            status_name = self._status_name(status)
            self._state["execution_status"] = status_name
            self._state["last_error"] = None
            log.info("ready: status=%s tid=%d attempt=%d", status_name, tid, attempt)

            return {
                "status": "ready",
                "thread_id": tid,
                "execution_status": status_name,
                "execution_status_raw": status,
                "attempt": attempt,
                "diagnostics": diagnostics if diagnostics else None,
            }

        raise DbgEngError(-1, "ensure_ready failed after all attempts")

    def _recover_thread_context(self, step_results: dict) -> int | None:
        """Try to recover thread context via process switching and symbol reload."""
        try:
            self.symbols.Reload(b"/f")
            step_results["force_reload"] = "ok"
        except DbgEngError as e:
            step_results["force_reload"] = f"failed ({e})"

        try:
            self.output_cb.clear()
            self.control.Execute(
                b".process /r /p poi(nt!PsInitialSystemProcess)")
            step_results["system_process_retry"] = "ok"
        except DbgEngError as e:
            step_results["system_process_retry"] = f"failed ({e})"
            try:
                self.output_cb.clear()
                self.control.Execute(b".process /r /p")
                step_results["bare_process_switch"] = "ok"
            except DbgEngError as e2:
                step_results["bare_process_switch"] = f"failed ({e2})"

        try:
            self.output_cb.clear()
            self.control.Execute(b"~0s")
            step_results["thread_switch"] = "ok"
        except DbgEngError as e:
            step_results["thread_switch"] = f"failed ({e})"

        try:
            tid = self.sysobj.GetCurrentThreadId()
            step_results["thread_context_after_recovery"] = f"ok (tid={tid})"
            return tid
        except DbgEngError:
            step_results["thread_context_after_recovery"] = "failed"
            return None

    # ─── Resume target ───────────────────────────────────────────────

    def resume_target(self, max_attempts: int = 10, verify_timeout_ms: int = 2000) -> dict:
        """Reliably resume target execution, draining pending break events.

        kd.exe/kdnet can inject spurious break events that cause a single
        SetExecutionStatus(GO) to fail. This method loops until the target
        is genuinely running or max_attempts is exhausted.

        Args:
            max_attempts: Maximum GO+drain cycles (default 10).
            verify_timeout_ms: WaitForEvent timeout per attempt (default 2000).
        """
        self._require_connected()

        for attempt in range(1, max_attempts + 1):
            status = self.control.GetExecutionStatus()
            if status != DEBUG_STATUS_BREAK:
                name = self._status_name(status)
                self._state["execution_status"] = name
                log.info("resume_target: already running (status=%s)", name)
                return {"status": "running", "attempts": attempt - 1}

            log.info("resume_target: attempt %d — sending GO", attempt)
            self.control.SetExecutionStatus(DEBUG_STATUS_GO)
            hr = self.control.WaitForEvent(verify_timeout_ms)

            if hr == S_FALSE:
                # Timeout — but verify target actually left BREAK state.
                # A stale kd.exe connection can silently drop the GO,
                # making WaitForEvent timeout look like success.
                try:
                    verify_status = self.control.GetExecutionStatus()
                except DbgEngError as e:
                    self._state["execution_status"] = "unknown"
                    self._state["last_error"] = (
                        f"Connection error during resume verify: {e}")
                    return {
                        "status": "connection_error",
                        "error": str(e),
                        "attempts": attempt,
                    }
                if verify_status == DEBUG_STATUS_BREAK:
                    log.warning(
                        "resume_target: attempt %d — WaitForEvent timed out "
                        "but still in BREAK (GO was ineffective)", attempt)
                    continue  # retry
                name = self._status_name(verify_status)
                self._state["execution_status"] = name
                log.info("resume_target: verified running after %d attempt(s) "
                         "(status=%s)", attempt, name)
                return {"status": "running", "attempts": attempt}
            elif hr == S_OK:
                # Event fired — check post-status
                post = self.control.GetExecutionStatus()
                name = self._status_name(post)
                log.info("resume_target: attempt %d — event fired, post-status=%s",
                         attempt, name)
                if post != DEBUG_STATUS_BREAK:
                    self._state["execution_status"] = name
                    return {"status": "running", "attempts": attempt}
                # Still in BREAK — spurious kdnet break, retry
            else:
                log.warning("resume_target: attempt %d — WaitForEvent=0x%08X",
                            attempt, hr & 0xFFFFFFFF)

        # Failed to resume after all attempts
        status = self.control.GetExecutionStatus()
        name = self._status_name(status)
        self._state["execution_status"] = name
        log.error("resume_target: FAILED after %d attempts, status=%s",
                  max_attempts, name)
        return {
            "status": "stuck_in_break",
            "attempts": max_attempts,
            "execution_status": name,
        }

    # ─── Status info ─────────────────────────────────────────────────

    def get_status(self) -> dict:
        """Return connection state and uptime."""
        result = {
            "initialized": self._initialized,
            "connected": self._connected,
            "dbgeng_path": config.DBGENG_PATH,
            "connection_string": self._kd_connection or config.KD_CONNECTION,
            "kd_server_port": self._kd_server_port or config.KD_SERVER_PORT,
        }
        if self._kd_process is not None:
            result["kd_pid"] = self._kd_process.pid
            result["kd_running"] = self._kd_process.poll() is None
        if self._connect_time:
            result["uptime_seconds"] = round(time.time() - self._connect_time, 1)
        return result

    def get_target_info(self) -> dict:
        """Return debug class, execution status, processors, page size."""
        self._require_connected()

        dbg_class, qualifier = self.control.GetDebuggeeType()
        status = self.control.GetExecutionStatus()
        nproc = self.control.GetNumberProcessors()
        page_size = self.control.GetPageSize()

        class_names = {0: "uninitialized", 1: "kernel", 2: "user", 3: "image_file"}
        status_names = {
            0: "no_change", 1: "go", 2: "go_handled", 3: "go_not_handled",
            4: "step_over", 5: "step_into", 6: "break", 7: "no_debuggee",
        }

        return {
            "debug_class": class_names.get(dbg_class, str(dbg_class)),
            "debug_class_raw": dbg_class,
            "qualifier": qualifier,
            "execution_status": status_names.get(status, str(status)),
            "execution_status_raw": status,
            "processors": nproc,
            "page_size": page_size,
        }

    # ─── Health check (no break-in) ─────────────────────────────────

    def health_check(self) -> dict:
        """Lightweight probe — checks connection without breaking in."""
        result = {
            "initialized": self._initialized,
            "connected": self._connected,
        }
        if self._connect_time:
            result["uptime_seconds"] = round(time.time() - self._connect_time, 1)
        if self._kd_process is not None:
            result["kd_running"] = self._kd_process.poll() is None

        if not self._connected:
            result["execution_status"] = "no_debuggee"
            return result

        try:
            status = self.control.GetExecutionStatus()
            status_name = self._status_name(status)
            result["execution_status"] = status_name
            result["execution_status_raw"] = status
            self._state["execution_status"] = status_name
        except DbgEngError as e:
            result["execution_status"] = "error"
            result["error"] = str(e)
            self._state["last_error"] = str(e)

        try:
            nproc = self.control.GetNumberProcessors()
            result["processors"] = nproc
        except DbgEngError:
            pass

        result["tracked_breakpoints"] = len(self._state["breakpoints"])
        result["last_error"] = self._state["last_error"]

        return result

    # ─── Full state ──────────────────────────────────────────────────

    def get_full_state(self) -> dict:
        """Return complete tracked state for external consumers."""
        state = dict(self._state)
        state["connected"] = self._connected
        state["initialized"] = self._initialized
        if self._connect_time:
            state["uptime_seconds"] = round(time.time() - self._connect_time, 1)
        return state

    def track_breakpoint(self, bp_id: int, address: str = "", expression: str = ""):
        self._state["breakpoints"].append({
            "id": bp_id, "address": address, "expression": expression,
        })

    def untrack_breakpoint(self, bp_id: int):
        self._state["breakpoints"] = [
            bp for bp in self._state["breakpoints"] if bp["id"] != bp_id
        ]

    def record_event(self, event: dict):
        self._state["last_event"] = event

    # ─── Auto-reconnect ──────────────────────────────────────────────

    def reconnect(self, kd_wait_timeout: int = 20, max_retries: int = 1) -> dict:
        """Tear down everything and reconnect from scratch.

        Args:
            kd_wait_timeout: Seconds to wait for kd.exe to connect (default 20,
                             shorter than initial connect since VM should be up).
            max_retries: Number of connection retries (default 1 to fail fast).
        """
        log.info("Attempting reconnect (kd_wait=%ds, retries=%d)...",
                 kd_wait_timeout, max_retries)
        self._state["last_error"] = None

        # Clean up existing session
        self._cleanup_partial()

        # Reconnect with reduced timeouts to avoid hanging
        saved_retries = config.CONNECT_RETRIES
        try:
            config.CONNECT_RETRIES = max_retries
            self.connect(kd_wait_timeout=kd_wait_timeout)
        finally:
            config.CONNECT_RETRIES = saved_retries

        self._state["breakpoints"] = []
        self._state["last_event"] = None

        return self.get_status()

    def safe_execute(self, command: str, timeout_ms: int = None) -> str:
        """Execute with auto-reconnect on connection loss."""
        try:
            return self.execute(command, timeout_ms)
        except DbgEngError as e:
            hr = getattr(e, 'hr', None)
            if hr in (E_FAIL, E_UNEXPECTED):
                log.warning("COM call failed (0x%08X), attempting reconnect...",
                            hr & 0xFFFFFFFF)
                self._state["last_error"] = f"COM failure, reconnecting: {e}"
                try:
                    self.reconnect()
                    self.ensure_ready()
                    return self.execute(command, timeout_ms)
                except DbgEngError as re_err:
                    self._state["last_error"] = f"Reconnect failed: {re_err}"
                    raise
            raise

    # ─── Helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _status_name(status: int) -> str:
        names = {
            0: "no_change", 1: "go", 2: "go_handled", 3: "go_not_handled",
            4: "step_over", 5: "step_into", 6: "break", 7: "no_debuggee",
        }
        return names.get(status, str(status))

    def _require_connected(self):
        if not self._connected:
            raise DbgEngError(-1, "Not connected to kernel debugger. Call connect() first.")


# ─── COM thread affinity ─────────────────────────────────────────
#
# DbgEng COM interfaces have thread affinity — they MUST be called
# from the same thread that created them.  All tool functions route
# their COM work through this single-thread executor so every call
# lands on the same thread.
#

_com_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=1,
    thread_name_prefix="dbgeng-com",
)


def reset_com_executor():
    """Kill the stuck COM thread and create a fresh executor.

    Call this after a timeout to recover from a permanently blocked
    COM thread (ThreadPoolExecutor can't cancel running threads).
    Killing kd.exe first unblocks any pending COM calls.
    """
    global _com_executor
    log.warning("Resetting COM executor (stuck thread recovery)")
    # Shut down old executor without waiting for the stuck thread
    try:
        _com_executor.shutdown(wait=False, cancel_futures=True)
    except Exception as e:
        log.warning("Old executor shutdown error: %s", e)
    # Create fresh executor
    _com_executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=1,
        thread_name_prefix="dbgeng-com",
    )
    log.info("COM executor reset complete")


def status_name(code: int) -> str:
    """Map numeric execution status to a human-readable name."""
    return Debugger._status_name(code)


async def run_on_com_thread(func, *args, timeout: float = 0):
    """Run *func* on the dedicated DbgEng COM thread.

    Every DbgEng COM call MUST go through this helper to maintain
    thread affinity and avoid RPC_E_WRONG_THREAD (0x8001010E).

    If multi-session is active, routes to the active session's COM thread.

    Args:
        func: Callable to run on the COM thread.
        *args: Arguments to pass to func.
        timeout: Seconds before giving up (0 = use config.HARD_TIMEOUT_S).
    """
    # Check if multi-session registry has sessions — use their COM thread
    try:
        from .sessions import get_registry
        reg = get_registry()
        if reg.list_sessions():
            active_id = reg.active_session_id
            if active_id:
                return await reg.run_on_com_thread(active_id, func, *args,
                                                   timeout=timeout)
    except (ImportError, KeyError):
        pass

    # Fallback to singleton COM thread
    loop = asyncio.get_running_loop()
    fname = getattr(func, "__name__", repr(func))
    log.debug("COM→ %s", fname)
    ceiling = timeout if timeout > 0 else config.HARD_TIMEOUT_S
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(_com_executor, func, *args),
            timeout=ceiling,
        )
        return result
    except asyncio.TimeoutError:
        log.error("COM timeout (%ss) for %s — killing kd.exe", ceiling, fname)
        dbg = get_debugger_or_none()
        if dbg and dbg._kd_process and dbg._kd_process.poll() is None:
            dbg._kd_process.kill()
            dbg._connected = False
        raise DbgEngError(-1, f"COM thread timeout ({ceiling}s) for {fname}")
    except Exception as e:
        log.warning("COM✗ %s: %s", fname, e)
        raise


# Module-level singleton (used when no multi-session registry is active)
_debugger: Debugger | None = None


def get_debugger(auto_connect: bool = False) -> Debugger:
    """Get or create the global Debugger instance.

    If multi-session is active (sessions exist in the registry), returns
    the active session's debugger. Otherwise falls back to the singleton.

    Args:
        auto_connect: If True AND not connected, calls connect().
                      Default False — raises if not connected.
    """
    # Check if multi-session registry has sessions
    try:
        from .sessions import get_registry
        reg = get_registry()
        if reg.list_sessions():
            return reg.get_debugger()
    except (ImportError, KeyError):
        pass

    # Fallback to singleton
    global _debugger
    if _debugger is None:
        _debugger = Debugger()
    if not _debugger.is_connected:
        if auto_connect:
            _debugger.connect()
        else:
            raise DbgEngError(-1, "Not connected. Call connect() first.")
    return _debugger


def get_debugger_or_none() -> Debugger | None:
    """Return the current Debugger without creating or connecting.

    Checks multi-session registry first, then falls back to singleton.
    """
    try:
        from .sessions import get_registry
        reg = get_registry()
        if reg.list_sessions():
            try:
                return reg.get_debugger()
            except KeyError:
                return None
    except ImportError:
        pass
    return _debugger


def set_debugger(dbg: Debugger | None):
    """Replace the global Debugger singleton."""
    global _debugger
    _debugger = dbg
