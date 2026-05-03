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
    debug_connect, debug_create,
    DbgEngError, check_hr, S_OK, S_FALSE, E_FAIL, E_UNEXPECTED,
    IID_IDebugClient5,
    IID_IDebugControl, IID_IDebugDataSpaces2, IID_IDebugRegisters,
    IID_IDebugSymbols2, IID_IDebugSystemObjects,
    DebugClient, DebugControl, DebugDataSpaces, DebugRegisters,
    DebugSymbols, DebugSystemObjects, DebugBreakpoint,
    DEBUG_ATTACH_KERNEL_CONNECTION,
    DEBUG_END_ACTIVE_DETACH, DEBUG_END_DISCONNECT,
    DEBUG_ENGOPT_INITIAL_BREAK,
    DEBUG_INTERRUPT_ACTIVE, DEBUG_INTERRUPT_EXIT,
    DEBUG_STATUS_BREAK, DEBUG_STATUS_NO_DEBUGGEE, DEBUG_STATUS_GO,
    SYMOPT_UNDNAME, SYMOPT_DEFERRED_LOADS, SYMOPT_CASE_INSENSITIVE,
    INFINITE,
)
from .callbacks import OutputCallbacks, EventCallbacks

log = logging.getLogger("aragorn.debugger")


def _hr_name(hr: int) -> str:
    """Map well-known HRESULT values to human-readable names."""
    names = {
        0x00000000: "S_OK",
        0x00000001: "S_FALSE",
        0x80004001: "E_NOTIMPL",
        0x80004002: "E_NOINTERFACE",
        0x80004003: "E_POINTER",
        0x80004004: "E_ABORT",
        0x80004005: "E_FAIL",
        0x80070005: "E_ACCESSDENIED",
        0x80070057: "E_INVALIDARG",
        0x8000FFFF: "E_UNEXPECTED",
        0x80040205: "DBGENG_E_TARGET_INDETERMINATE_STATE",
        0x80040206: "DBGENG_E_DEBUG_SESSION_ONGOING",
    }
    u = hr & 0xFFFFFFFF
    return names.get(u, f"0x{u:08X}")


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
        self.client5: DebugClient | None = None   # IDebugClient5 upgrade for AttachKernelWide
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
        """Connect to the kernel debugger using the configured transport.

        Dispatches to either `_connect_direct()` (in-process AttachKernel)
        or `_connect_via_kd_server()` (legacy kd.exe subprocess + DebugConnect)
        based on `config.ARAGORN_TRANSPORT`.
        """
        self._initial_break = initial_break
        if connection_string:
            self._kd_connection = connection_string
        if server_port:
            self._kd_server_port = server_port

        transport = getattr(config, "ARAGORN_TRANSPORT", "direct").lower()
        log.info("Connect: transport=%s initial_break=%s",
                 transport, initial_break)

        if transport == "direct":
            return self._connect_direct(
                kd_wait_timeout=kd_wait_timeout,
                initial_break=initial_break,
            )
        if transport == "kd_server":
            return self._connect_via_kd_server(
                kd_wait_timeout=kd_wait_timeout,
                initial_break=initial_break,
            )
        raise DbgEngError(
            -1,
            f"Unknown ARAGORN_TRANSPORT={transport!r} "
            f"(expected 'direct' or 'kd_server')",
        )

    # ─── Transport: kd.exe debug server (legacy) ─────────────────────

    @staticmethod
    def _ensure_kdnet_transport() -> dict:
        """Advisory preflight for the kdnet transport.

        Modern dbgeng.dll (10.0.29xxx+) has the kdnet transport compiled
        in — no separate `kdnet*.dll` is required, and `AttachKernel` with
        a `net:…` connection string Just Works. This helper exists to:
          1. Verify `dbgeng.dll` is actually at `config.DBGENG_PATH`.
          2. Opportunistically copy any `kdnet*.dll` / `kdstub*.dll` helper
             files from the kd.exe install dir to `dbgeng_bin/` — needed
             only for older dbgeng versions that didn't bundle the transport.
          3. Return an informational dict for logging; never fails the
             connect path (AttachKernel is the real test).
        """
        import os
        import glob
        import shutil

        dbgeng_dir = os.path.dirname(os.path.abspath(config.DBGENG_PATH))
        info: dict = {
            "dbgeng_exists": os.path.isfile(config.DBGENG_PATH),
            "dbgeng_dir": dbgeng_dir,
        }
        if not info["dbgeng_exists"]:
            info["status"] = "dbgeng_missing"
            return info

        patterns = ("kdnet*.dll", "kdstub*.dll")
        existing = []
        for p in patterns:
            existing.extend(glob.glob(os.path.join(dbgeng_dir, p)))
        if existing:
            info["status"] = "already_present"
            info["files"] = [os.path.basename(p) for p in existing]
            return info

        kd_dir = os.path.dirname(os.path.abspath(config.KD_EXE_PATH))
        if not os.path.isdir(kd_dir):
            # dbgeng probably has transport built-in; not fatal.
            info["status"] = "no_helpers_needed"
            info["note"] = f"kd_dir unavailable ({kd_dir}); " \
                           "relying on built-in kdnet in dbgeng.dll"
            return info

        copied, failures = [], []
        for p in patterns:
            for src in glob.glob(os.path.join(kd_dir, p)):
                name = os.path.basename(src)
                dst = os.path.join(dbgeng_dir, name)
                if os.path.exists(dst):
                    continue
                try:
                    shutil.copy2(src, dst)
                    copied.append(name)
                except (OSError, shutil.SameFileError) as e:
                    failures.append({"name": name, "error": str(e)})
        if copied:
            log.info("Copied kdnet helpers to %s: %s", dbgeng_dir, copied)
            info["status"] = "copied"
        else:
            info["status"] = "no_helpers_needed"
            info["note"] = ("no kdnet helper DLLs in kd_dir; "
                           "relying on built-in kdnet in dbgeng.dll")
        info["copied"] = copied
        info["failures"] = failures
        return info

    def _connect_via_kd_server(self, kd_wait_timeout: int = 30,
                                initial_break: bool = False):
        """Launch kd.exe and connect via DebugConnect (legacy transport).

        1. Start kd.exe as a debug server (handles kdnet transport)
        2. Wait for kd.exe to connect to the target
        3. DebugConnect to kd.exe's debug server
        4. Optionally break into the target (only if initial_break=True)
        """
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
                    resume_result = self.resume_target()
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

    # ─── Transport: direct AttachKernel (no kd.exe subprocess) ──────

    def _connect_direct(self, kd_wait_timeout: int = 30,
                        initial_break: bool = False):
        """Connect in-process via IDebugClient::AttachKernel.

        Replaces the kd.exe + DebugConnect dance with a single AttachKernel
        call; dbgeng.dll handles kdnet transport natively. `kd_wait_timeout`
        is used as a floor for the first WaitForEvent (the call that actually
        drives the kdnet handshake), bounded by config.KD_SYNC_TIMEOUT_MS.
        """
        import os

        transport_info = self._ensure_kdnet_transport()
        log.info("[direct] kdnet transport: %s", transport_info)

        kd_conn = self._kd_connection or config.KD_CONNECTION
        conn_options = kd_conn.encode("utf-8")
        sync_ms = max(
            int(kd_wait_timeout * 1000),
            getattr(config, "KD_SYNC_TIMEOUT_MS", 30_000),
        )
        ib_ms = getattr(config, "INITIAL_BREAK_TIMEOUT_MS", 10_000)

        # Reset per-connect diagnostic trail — each entry is a step dict.
        self._direct_diag = [{"transport_info": transport_info,
                              "kd_conn": kd_conn,
                              "sync_ms": sync_ms,
                              "ib_ms": ib_ms}]

        last_error = None
        for attempt in range(1, config.CONNECT_RETRIES + 1):
            attempt_diag: dict = {"attempt": attempt, "steps": []}
            self._direct_diag.append(attempt_diag)
            try:
                t0 = time.time()
                log.info("[direct][%.1fs] Attempt %d/%d — conn=%s",
                         0.0, attempt, config.CONNECT_RETRIES, kd_conn)

                # Step 1: DebugCreate
                os.add_dll_directory(os.path.dirname(config.DBGENG_PATH))
                self.client, self._dll = debug_create(config.DBGENG_PATH)
                log.info("[direct][%.1fs] DebugCreate OK", time.time() - t0)

                # Step 2: QI all sub-interfaces (must happen before AttachKernel
                # so the callbacks and symbol path are set before any event fires)
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
                log.info("[direct][%.1fs] QI interfaces done", time.time() - t0)

                # Step 3: Callbacks (gated — env var can disable for diagnosis)
                import os as _os
                skip_cb = _os.environ.get("ARAGORN_SKIP_CALLBACKS", "0") == "1"
                if skip_cb:
                    log.warning("[direct] ARAGORN_SKIP_CALLBACKS=1 — "
                                "not registering IDebug*Callbacks")
                    attempt_diag["steps"].append({
                        "step": "callbacks", "result": "SKIPPED_BY_ENV"})
                    self.output_cb = None
                    self.event_cb = None
                else:
                    self.output_cb = OutputCallbacks()
                    self.event_cb = EventCallbacks(max_events=config.EVENT_QUEUE_SIZE)
                    self.client.SetOutputCallbacks(self.output_cb.as_param())
                    self.client.SetEventCallbacks(self.event_cb.as_param())

                # Step 4: Symbols
                self.symbols.AddSymbolOptions(
                    SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_CASE_INSENSITIVE)
                self.symbols.SetSymbolPath(config.SYMBOL_PATH.encode("utf-8"))
                log.info("[direct][%.1fs] Callbacks + symbols configured",
                         time.time() - t0)

                # Step 4b: Upgrade our IDebugClient to IDebugClient5.
                # kd.exe uses IDebugClient5 + AttachKernelWide internally,
                # and some dbgeng builds stub the ANSI AttachKernel entry
                # (returns S_OK but silently no-ops the kdnet session init).
                try:
                    client5_ptr = self.client.query_interface(IID_IDebugClient5)
                    self.client5 = DebugClient(client5_ptr)
                    attempt_diag["steps"].append({
                        "step": "QI_IDebugClient5", "result": "OK"})
                    log.info("[direct][%.1fs] QI IDebugClient5 OK",
                             time.time() - t0)
                except DbgEngError as e:
                    attempt_diag["steps"].append({
                        "step": "QI_IDebugClient5", "result": "FAIL",
                        "error": str(e)})
                    log.warning("[direct] QI IDebugClient5 failed: %s — "
                                "falling back to ANSI AttachKernel", e)
                    self.client5 = None

                # Step 4c: DEBUG_ENGOPT_INITIAL_BREAK before AttachKernel.
                # This is the documented kd.exe `-b` equivalent — the
                # engine asks the VM to break at the earliest opportunity
                # during the kdnet handshake, which is what causes the
                # first WaitForEvent to actually return on an idle VM.
                # Must be set before AttachKernel — engine reads it as
                # part of session setup.
                try:
                    self.control.AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK)
                    log.info("[direct][%.1fs] AddEngineOptions(INITIAL_BREAK) OK",
                             time.time() - t0)
                    attempt_diag["steps"].append({
                        "step": "AddEngineOptions_INITIAL_BREAK",
                        "result": "OK"})
                except DbgEngError as e:
                    log.warning("[direct] AddEngineOptions(INITIAL_BREAK) "
                                "failed: %s", e)
                    attempt_diag["steps"].append({
                        "step": "AddEngineOptions_INITIAL_BREAK",
                        "result": "FAIL", "error": str(e)})

                # Step 5: AttachKernelWide (Wide/UTF-16) via IDebugClient5,
                # falling back to ANSI AttachKernel if QI failed.
                t_ak = time.time()
                if self.client5 is not None:
                    log.info("[direct][%.1fs] AttachKernelWide…",
                             time.time() - t0)
                    self.client5.AttachKernelWide(kd_conn)
                    step_label = "AttachKernelWide"
                else:
                    log.info("[direct][%.1fs] AttachKernel (ANSI)…",
                             time.time() - t0)
                    self.client.AttachKernel(conn_options)
                    step_label = "AttachKernel"
                ak_elapsed = time.time() - t_ak
                log.info("[direct][%.1fs] %s returned OK (%.2fs)",
                         time.time() - t0, step_label, ak_elapsed)
                attempt_diag["steps"].append({
                    "step": step_label, "result": "OK",
                    "elapsed_ms": round(ak_elapsed * 1000, 1)})

                # Step 6: First WaitForEvent drives the kdnet handshake.
                # CRITICAL: dbgeng returns E_NOTIMPL instantly if a finite
                # timeout is passed to the first kernel-mode WaitForEvent.
                # Only INFINITE engages the polling/sync loop. Watchdog is
                # enforced by the outer asyncio.wait_for on the tool caller
                # + cross-thread abort_wait() if we actually need to bail.
                log.info("[direct][%.1fs] WaitForEvent(INFINITE) — initial sync",
                         time.time() - t0)
                t_wfe = time.time()
                hr = self.control.WaitForEvent(INFINITE)
                wfe_elapsed = time.time() - t_wfe
                log.info("[direct][%.1fs] WaitForEvent → hr=0x%08X (%.2fs)",
                         time.time() - t0, hr & 0xFFFFFFFF, wfe_elapsed)
                attempt_diag["steps"].append({
                    "step": "WaitForEvent_initial",
                    "hr": f"0x{hr & 0xFFFFFFFF:08X}",
                    "hr_name": _hr_name(hr),
                    "elapsed_ms": round(wfe_elapsed * 1000, 1),
                    "timeout_ms": "INFINITE",
                })

                status = self.control.GetExecutionStatus()
                status_name = self._status_name(status)
                log.info("[direct][%.1fs] post-attach status=%s",
                         time.time() - t0, status_name)
                attempt_diag["steps"].append({
                    "step": "GetExecutionStatus_post_attach",
                    "status": status_name, "status_raw": status})

                # Mark connected now so helpers like resume_target() that
                # call _require_connected() work during step 7. The outer
                # try/except still tears this down on failure below.
                self._initialized = True
                self._connected = True

                # Step 7: Honor initial_break semantics.
                if initial_break and status != DEBUG_STATUS_BREAK:
                    log.info("[direct][%.1fs] Forcing break-in via SetInterrupt",
                             time.time() - t0)
                    self.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE)
                    t_ib = time.time()
                    hr = self.control.WaitForEvent(ib_ms)
                    ib_elapsed = time.time() - t_ib
                    log.info("[direct][%.1fs] forced-break WaitForEvent → 0x%08X (%.2fs)",
                             time.time() - t0, hr & 0xFFFFFFFF, ib_elapsed)
                    status = self.control.GetExecutionStatus()
                    status_name = self._status_name(status)
                    attempt_diag["steps"].append({
                        "step": "SetInterrupt+WaitForEvent",
                        "hr": f"0x{hr & 0xFFFFFFFF:08X}",
                        "hr_name": _hr_name(hr),
                        "elapsed_ms": round(ib_elapsed * 1000, 1),
                        "post_status": status_name,
                    })
                elif not initial_break and status == DEBUG_STATUS_BREAK:
                    # kdnet handshake broke us in — resume so VM keeps running.
                    log.info("[direct][%.1fs] Unexpected break, resuming",
                             time.time() - t0)
                    resume_result = self.resume_target()
                    log.info("[direct][%.1fs] auto-resume: %s",
                             time.time() - t0, resume_result)
                    status = self.control.GetExecutionStatus()
                    status_name = self._status_name(status)
                    attempt_diag["steps"].append({
                        "step": "auto_resume",
                        "resume_result": resume_result,
                        "post_status": status_name,
                    })

                # Step 8: If broken, load symbols for this session.
                if status == DEBUG_STATUS_BREAK:
                    try:
                        page_size = self.control.GetPageSize()
                        log.info("[direct][%.1fs] page_size=%d",
                                 time.time() - t0, page_size)
                    except DbgEngError:
                        pass
                    try:
                        self.symbols.Reload(b"")
                    except DbgEngError:
                        log.warning("[direct] Symbol reload failed (non-fatal)")

                self._initialized = True
                self._connected = True
                self._connect_time = time.time()
                self._state["connected_since"] = self._connect_time
                self._state["execution_status"] = status_name
                self._state["last_error"] = None
                attempt_diag["outcome"] = "success"
                attempt_diag["final_status"] = status_name
                log.info("[direct] Connected! status=%s", status_name)
                return

            except (DbgEngError, OSError) as e:
                log.warning("[direct] Attempt %d failed: %s", attempt, e)
                attempt_diag["outcome"] = "exception"
                attempt_diag["exception"] = str(e)
                last_error = e
                self._cleanup_partial()
                if attempt < config.CONNECT_RETRIES:
                    log.info("[direct] Retrying in %ds…",
                             config.CONNECT_BACKOFF_SECONDS)
                    time.sleep(config.CONNECT_BACKOFF_SECONDS)

        raise last_error or DbgEngError(
            -1, "Direct AttachKernel failed after all retries")

    # ─── Cross-thread wedge recovery ────────────────────────────────

    def abort_wait(self) -> dict:
        """Break a wedged WaitForEvent from a thread other than the COM thread.

        `IDebugControl::SetInterrupt(DEBUG_INTERRUPT_EXIT)` is documented as
        thread-safe and is the official escape hatch when the engine's
        main thread is blocked inside WaitForEvent. Used by the MCP layer
        in place of "kill kd.exe" under the direct transport (where there
        is no kd.exe to kill).
        """
        if self.control is None:
            return {"status": "no_control"}
        try:
            self.control.SetInterrupt(DEBUG_INTERRUPT_EXIT)
            return {"status": "interrupt_exit_sent"}
        except DbgEngError as e:
            # Last-resort — disconnect the session entirely.
            try:
                if self.client is not None:
                    self.client.EndSession(DEBUG_END_DISCONNECT)
                    return {"status": "end_session_disconnect",
                            "interrupt_error": str(e)}
            except DbgEngError as e2:
                return {"status": "both_failed",
                        "interrupt_error": str(e),
                        "end_session_error": str(e2)}
            return {"status": "no_client_to_end",
                    "interrupt_error": str(e)}

    def recover_from_wedge(self) -> dict:
        """Transport-aware escape hatch for a stuck COM thread.

        Under `kd_server` transport, killing kd.exe tears down the TCP
        transport and forces the COM call to return. Under `direct`
        transport there's no kd.exe — we use the documented thread-safe
        COM escape (`SetInterrupt(EXIT)` → `EndSession(DISCONNECT)`).
        """
        transport = getattr(config, "ARAGORN_TRANSPORT", "direct").lower()
        if transport == "kd_server":
            if self._kd_process and self._kd_process.poll() is None:
                pid = self._kd_process.pid
                log.warning("recover_from_wedge: killing kd.exe (PID %d)", pid)
                try:
                    self._kd_process.kill()
                except Exception as e:
                    return {"status": "kd_kill_failed", "error": str(e)}
                self._connected = False
                return {"status": "kd_killed", "pid": pid}
            return {"status": "kd_not_running"}
        # direct
        result = self.abort_wait()
        self._connected = False
        return result

    def _cleanup_partial(self):
        """Clean up after a failed connection attempt.

        Explicitly tears down the dbgeng session (EndSession) before
        releasing interfaces, so the kdnet transport releases its port
        and session-ID state on both sides. Releases `client5` too (it's
        a separate AddRef'd pointer even though it aliases `client`).
        """
        # Stop kd.exe so the next attempt starts fresh (kd_server path).
        self._stop_kd_server()

        # Explicitly end the session so kdnet transport state unwinds.
        if self.client is not None:
            for flag_name, flag in (
                ("DETACH", DEBUG_END_ACTIVE_DETACH),
                ("DISCONNECT", DEBUG_END_DISCONNECT),
            ):
                try:
                    self.client.EndSession(flag)
                    log.debug("_cleanup_partial: EndSession(%s) ok", flag_name)
                    break
                except Exception as e:
                    log.debug("_cleanup_partial: EndSession(%s) failed: %s",
                              flag_name, e)
            try:
                self.client.DetachProcesses()
            except Exception:
                pass

        for iface in [self.sysobj, self.symbols, self.registers,
                      self.data, self.control, self.client5, self.client]:
            if iface is not None:
                try:
                    iface.release()
                except Exception:
                    pass
        self.client = None
        self.client5 = None
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

    # ─── Shared pump primitive ──────────────────────────────────────

    def _pump_until(self, predicate, budget_ms: int = 10_000,
                     pump_ms: int = 100) -> tuple[bool, dict]:
        """Drive the engine event loop until `predicate()` returns truthy,
        or `budget_ms` elapses.

        ## The dbgeng quirk this works around

        On kdnet, calling `WaitForEvent(finite_ms)` on a target in a state
        with no pending events typically returns `E_FAIL (0x80004005)`
        immediately rather than blocking for the requested timeout. A
        naive "loop pump" turns into a ~6000 failed-calls-per-second busy
        wait that never actually drives the transport.

        ## The solution

        Use `WaitForEvent(INFINITE)` backed by a cross-thread abort
        timer. INFINITE actually blocks until kdnet delivers an event
        (break, module-load, exception, etc.), which also serves as the
        natural wakeup for our `predicate()` check. If the predicate
        becomes true before any event (already-broken case), it returns
        early.

        We use a watchdog thread that calls `SetInterrupt(EXIT)` after
        `budget_ms` to unstick a WaitForEvent that's still blocking, so
        total wall time is always bounded.

        Returns (ok, diag) where diag has {iterations, elapsed_ms,
        last_status, last_hr, aborted}.
        """
        import time as _time
        import threading as _threading
        diag = {"iterations": 0, "elapsed_ms": 0,
                "last_status": None, "last_hr": None, "aborted": False}

        # Fast path — predicate already true.
        try:
            if predicate():
                try:
                    diag["last_status"] = self._status_name(
                        self.control.GetExecutionStatus())
                except DbgEngError:
                    pass
                diag["already_true"] = True
                return True, diag
        except DbgEngError:
            pass

        t0 = _time.monotonic()
        stop = _threading.Event()

        def _watchdog():
            if stop.wait(budget_ms / 1000.0):
                return
            diag["aborted"] = True
            try:
                self.control.SetInterrupt(DEBUG_INTERRUPT_EXIT)
            except Exception:
                pass

        wd = _threading.Thread(target=_watchdog, daemon=True,
                                name="pump-watchdog")
        wd.start()
        try:
            while True:
                diag["iterations"] += 1
                try:
                    diag["last_hr"] = self.control.WaitForEvent(INFINITE) & 0xFFFFFFFF
                except DbgEngError as e:
                    diag["last_hr"] = getattr(e, "hr", -1) & 0xFFFFFFFF
                try:
                    if predicate():
                        diag["elapsed_ms"] = round(
                            (_time.monotonic() - t0) * 1000, 1)
                        try:
                            diag["last_status"] = self._status_name(
                                self.control.GetExecutionStatus())
                        except DbgEngError:
                            pass
                        return True, diag
                except DbgEngError:
                    pass
                if diag["aborted"] or (_time.monotonic() - t0) * 1000 >= budget_ms:
                    diag["elapsed_ms"] = round(
                        (_time.monotonic() - t0) * 1000, 1)
                    try:
                        diag["last_status"] = self._status_name(
                            self.control.GetExecutionStatus())
                    except DbgEngError:
                        pass
                    return False, diag
        finally:
            stop.set()
            wd.join(timeout=2)

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
        """Release all COM interfaces, free DLL, and stop kd.exe.

        Goes through DetachProcesses + EndSession first so the kdnet
        transport (UDP socket, session-ID negotiation state) unwinds
        before the ComPtr refcounts drop. Note that `FreeLibrary` does
        not truly unload dbgeng.dll — the engine keeps itself loaded
        via internal loader callbacks — so a full "fresh engine" still
        requires a process restart.
        """
        import ctypes as _ctypes

        self.disconnect()

        # Belt-and-suspenders EndSession in case disconnect() didn't.
        if self.client is not None:
            for flag in (DEBUG_END_ACTIVE_DETACH, DEBUG_END_DISCONNECT):
                try:
                    self.client.EndSession(flag)
                    break
                except Exception:
                    pass

        for iface in [self.sysobj, self.symbols, self.registers,
                      self.data, self.control, self.client5, self.client]:
            if iface is not None:
                try:
                    iface.release()
                except Exception:
                    pass

        self.client = None
        self.client5 = None
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

        grace = getattr(config, "INITIAL_GRACE_S", 60)
        stall = getattr(config, "STALL_TIMEOUT_S", 30)
        hard = getattr(config, "HARD_TIMEOUT_S", 600)
        aborted = [False]
        reason = [""]
        stop = threading.Event()

        def _abort_transport():
            """Unblock a stuck Execute() COM call by tearing down the
            transport. `SetInterrupt(EXIT)` only works for WaitForEvent,
            not Execute — so we use `recover_from_wedge` which does the
            transport-appropriate thing (kill kd.exe for kd_server mode,
            or EndSession(DISCONNECT) for direct mode)."""
            log.warning("Watchdog: aborting transport")
            try:
                self.recover_from_wedge()
            except Exception as e:
                log.warning("Watchdog: recover_from_wedge failed: %s", e)

        def _wd():
            t0 = time.monotonic()
            while not stop.is_set():
                now = time.monotonic()
                el = now - t0
                if el >= hard:
                    aborted[0] = True
                    reason[0] = f"hard timeout ({hard:.0f}s)"
                    log.warning("Watchdog: %s", reason[0])
                    _abort_transport()
                    return
                lo = self.output_cb.last_output_time
                if lo is not None:
                    si = now - lo
                    if si >= stall:
                        aborted[0] = True
                        reason[0] = f"output stall ({si:.1f}s silence)"
                        log.warning("Watchdog: %s", reason[0])
                        _abort_transport()
                        return
                elif el >= grace:
                    aborted[0] = True
                    reason[0] = f"no output for {el:.1f}s (grace expired)"
                    log.warning("Watchdog: %s", reason[0])
                    _abort_transport()
                    return
                stop.wait(2.0)

        th = threading.Thread(target=_wd, daemon=True, name="stall-wd")
        th.start()
        try:
            self.control.Execute(cmd_bytes)
        except (DbgEngError, OSError) as e:
            if not aborted[0]:
                raise  # genuine error, not watchdog-induced
            log.info("Execute raised after watchdog kill (expected): %s", e)
        finally:
            stop.set()
            th.join(timeout=3)

        output = self.output_cb.get_text()
        if aborted[0]:
            output += f"\n\n[ARAGORN] Command interrupted: {reason[0]}"
            output += "\n[ARAGORN] kd.exe killed. Call ensure_ready() to reconnect."
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

            # Step 2: Pump the engine event loop until the target actually
            # reaches BREAK (or the budget expires). Uses the shared
            # `_pump_until` primitive that tolerates WaitForEvent's flaky
            # finite-timeout HRs on kdnet.
            #
            # Budget scales per-attempt: 3s, 5s, 8s, 10s, 15s. The total
            # worst case is ~41s (vs the old 5×5s = 25s with a tight 5s
            # cap that often timed out). More importantly: each individual
            # pump is driven in 100ms slices that always call WaitForEvent,
            # which is what actually propagates the SetInterrupt through
            # the kdnet transport.
            budgets = [3_000, 5_000, 8_000, 10_000, 15_000]
            ok, pump_diag = self._pump_until(
                lambda: self.control.GetExecutionStatus() == DEBUG_STATUS_BREAK,
                budget_ms=budgets[attempt - 1], pump_ms=100,
            )
            step_results["wait"] = (
                "ok" if ok
                else f"budget_expired (elapsed_ms={pump_diag.get('elapsed_ms')}, "
                     f"last_status={pump_diag.get('last_status')})"
            )
            step_results["pump_diag"] = pump_diag
            if not ok:
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

    def resume_target(self, budget_ms: int = 5_000,
                      pump_ms: int = 100) -> dict:
        """Reliably resume target execution.

        Uses `SetExecutionStatus(DEBUG_STATUS_GO)` — the raw COM primitive,
        not `Execute("g")` which is a text-command roundabout. Then pumps
        the engine via `_pump_until` until the target actually leaves BREAK.

        The dbgeng/kdnet event loop does not propagate the GO to the target
        without a WaitForEvent pump. Without it, GetExecutionStatus can
        report BREAK forever even though the intent is GO. The pump loop
        handles this deterministically.
        """
        self._require_connected()

        status = self.control.GetExecutionStatus()
        if status != DEBUG_STATUS_BREAK:
            name = self._status_name(status)
            self._state["execution_status"] = name
            return {"status": "running", "already_go": True,
                    "execution_status": name}

        # Queue the GO intent. SetExecutionStatus returns immediately.
        try:
            self.control.SetExecutionStatus(DEBUG_STATUS_GO)
        except DbgEngError as e:
            return {"status": "set_execution_status_failed", "error": str(e)}

        # Pump until the target actually left BREAK.
        ok, diag = self._pump_until(
            lambda: self.control.GetExecutionStatus() != DEBUG_STATUS_BREAK,
            budget_ms=budget_ms, pump_ms=pump_ms,
        )
        if ok:
            name = diag.get("last_status") or "go"
            self._state["execution_status"] = name
            return {"status": "running", "execution_status": name,
                    "pump_diag": diag}

        # Still BREAK after full poll window
        try:
            status = self.control.GetExecutionStatus()
            name = self._status_name(status)
        except DbgEngError:
            name = "unknown"
        self._state["execution_status"] = name
        log.error("resume_target: FAILED after %d polls, status=%s",
                  max_attempts, name)
        return {"status": "stuck_in_break", "attempts": max_attempts,
                "execution_status": name}

    # ─── Status info ─────────────────────────────────────────────────

    def set_kd_connection(self, conn: str) -> dict:
        """Update the cached kdnet connection string used on next reconnect."""
        self._kd_connection = conn
        return {"connection_string": conn}

    def get_status(self) -> dict:
        """Return connection state and uptime."""
        result = {
            "initialized": self._initialized,
            "connected": self._connected,
            "dbgeng_path": config.DBGENG_PATH,
            "connection_string": self._kd_connection or config.KD_CONNECTION,
            "kd_server_port": self._kd_server_port or config.KD_SERVER_PORT,
            "transport": getattr(config, "ARAGORN_TRANSPORT", "direct"),
        }
        if self._kd_process is not None:
            result["kd_pid"] = self._kd_process.pid
            result["kd_running"] = self._kd_process.poll() is None
        if self._connect_time:
            result["uptime_seconds"] = round(time.time() - self._connect_time, 1)
        diag = getattr(self, "_direct_diag", None)
        if diag:
            result["direct_diag"] = diag
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

    # ─── Breakpoint operations (in-process; called via supervisor RPC) ──

    def add_breakpoint(self, bp_type: str = "code",
                        expression: str = "", address: str = "",
                        access: str = "write", data_size: int = 1,
                        condition: str = "") -> dict:
        """Create a breakpoint and return its descriptor.

        Combines AddBreakpoint + SetOffsetExpression/SetOffset +
        SetDataParameters + SetCommand + AddFlags into a single COM
        thread-bound operation. Mirrors the logic the legacy in-process
        tools/breakpoints.py used in its closure, exposed as a Debugger
        method so the supervisor can dispatch it as a single RPC.
        """
        from .dbgeng import (
            DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_DATA,
            DEBUG_BREAKPOINT_ENABLED, DEBUG_ANY_ID,
            DEBUG_BREAK_READ, DEBUG_BREAK_WRITE,
            DEBUG_BREAK_EXECUTE, DEBUG_BREAK_IO,
        )
        if bp_type == "data":
            raw_type = DEBUG_BREAKPOINT_DATA
        else:
            raw_type = DEBUG_BREAKPOINT_CODE
        bp_ptr = self.control.AddBreakpoint(raw_type, DEBUG_ANY_ID)
        bp = DebugBreakpoint(bp_ptr)
        if expression:
            bp.SetOffsetExpression(expression.encode("utf-8"))
        elif address:
            bp.SetOffset(int(address, 0))
        else:
            raise ValueError("Must provide either expression or address")
        if bp_type == "data":
            access_map = {
                "read": DEBUG_BREAK_READ,
                "write": DEBUG_BREAK_WRITE,
                "execute": DEBUG_BREAK_EXECUTE,
                "read_write": DEBUG_BREAK_READ | DEBUG_BREAK_WRITE,
                "io": DEBUG_BREAK_IO,
            }
            bp.SetDataParameters(data_size,
                                  access_map.get(access, DEBUG_BREAK_WRITE))
        if condition:
            bp.SetCommand(condition.encode("utf-8"))
        bp.AddFlags(DEBUG_BREAKPOINT_ENABLED)
        bp_id = bp.GetId()
        try:
            offset = bp.GetOffset()
            addr_str = f"0x{offset:016X}"
        except DbgEngError:
            addr_str = "(deferred)"
        self.track_breakpoint(bp_id, address=addr_str, expression=expression)
        return {
            "id": bp_id,
            "type": bp_type,
            "address": addr_str,
            "expression": expression,
            "enabled": True,
        }

    def remove_breakpoint_by_id(self, bp_id: int) -> dict:
        bp_ptr = self.control.GetBreakpointById(bp_id)
        self.control.RemoveBreakpoint(bp_ptr)
        self.untrack_breakpoint(bp_id)
        return {"removed": bp_id}

    def list_all_breakpoints(self) -> list:
        from .dbgeng import (
            DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_ENABLED,
        )
        count = self.control.GetNumberBreakpoints()
        out = []
        for i in range(count):
            try:
                bp_ptr = self.control.GetBreakpointByIndex(i)
                bp = DebugBreakpoint(bp_ptr)
                params = bp.GetParameters()
                entry = {
                    "id": params.Id,
                    "type": ("code" if params.BreakType == DEBUG_BREAKPOINT_CODE
                             else "data"),
                    "address": f"0x{params.Offset:016X}",
                    "enabled": bool(params.Flags & DEBUG_BREAKPOINT_ENABLED),
                    "hit_count": params.CurrentPassCount,
                }
                try:
                    name, disp = self.symbols.GetNameByOffset(params.Offset)
                    entry["symbol"] = name + (f"+0x{disp:X}" if disp else "")
                except DbgEngError:
                    entry["symbol"] = ""
                out.append(entry)
            except DbgEngError:
                continue
        return out

    def resolve_symbol_name(self, name: str = "",
                              address: str = "") -> dict:
        if name:
            offset = self.symbols.GetOffsetByName(name.encode("utf-8"))
            return {
                "name": name,
                "address": f"0x{offset:016X}",
                "displacement": 0,
            }
        if address:
            offset = int(address, 0)
            sym, disp = self.symbols.GetNameByOffset(offset)
            return {
                "name": sym,
                "address": f"0x{offset:016X}",
                "displacement": disp,
            }
        raise ValueError("Must provide name or address")

    # ─── Memory operations (issue #2) ────────────────────────────────

    def read_virtual_formatted(self, address: str, size: int = 64,
                                 format: str = "hex") -> str:
        """Read virtual memory at *address* and format the result.

        Lifted from `tools/memory.py::read_memory._impl` so the supervisor
        can dispatch this as a single named RPC call.
        """
        from .tools.memory import _format_bytes
        addr = int(address, 0)
        sz = min(size, 1024 * 1024)
        data = self.data.ReadVirtual(addr, sz)
        return _format_bytes(data, format, addr)

    def write_virtual_bytes(self, address: str, hex_data: str) -> dict:
        addr = int(address, 0)
        data = bytes.fromhex(hex_data.replace(" ", ""))
        written = self.data.WriteVirtual(addr, data)
        return {"address": f"0x{addr:016X}", "bytes_written": written}

    def search_virtual(self, address: str, pattern: str,
                        length: int = 4096) -> dict:
        addr = int(address, 0)
        pat = bytes.fromhex(pattern.replace(" ", ""))
        match = self.data.SearchVirtual(addr, length, pat)
        return {"match_address": f"0x{match:016X}"}

    def read_physical_formatted(self, address: str, size: int = 64) -> str:
        from .tools.memory import _format_bytes
        addr = int(address, 0)
        sz = min(size, 1024 * 1024)
        data = self.data.ReadPhysical(addr, sz)
        return _format_bytes(data, "hex", addr)

    def write_physical_bytes(self, address: str, hex_data: str) -> dict:
        addr = int(address, 0)
        data = bytes.fromhex(hex_data.replace(" ", ""))
        written = self.data.WritePhysical(addr, data)
        return {"address": f"0x{addr:016X}", "bytes_written": written}

    def translate_v2p(self, address: str) -> dict:
        addr = int(address, 0)
        phys = self.data.VirtualToPhysical(addr)
        return {
            "virtual": f"0x{addr:016X}",
            "physical": f"0x{phys:016X}",
        }

    def read_msr_value(self, msr_id: int) -> dict:
        value = self.data.ReadMsr(msr_id)
        return {
            "msr": f"0x{msr_id:X}",
            "value": f"0x{value:016X}",
            "decimal": value,
        }

    # ─── Register operations (issue #2) ──────────────────────────────

    def read_all_registers(self) -> dict:
        from .tools.context import _read_all_registers
        return _read_all_registers(self.registers)

    def write_register_value(self, name: str, value: str) -> dict:
        from .dbgeng import DEBUG_VALUE, DEBUG_VALUE_INT64
        idx = self.registers.GetIndexByName(name.encode("utf-8"))
        val = DEBUG_VALUE()
        val.I64 = int(value, 0)
        val.Type = DEBUG_VALUE_INT64
        self.registers.SetValue(idx, val)
        return {"register": name, "value": f"0x{val.I64:016X}"}

    # ─── Execution operations (issue #2) ─────────────────────────────

    def do_step_into(self) -> dict:
        from .dbgeng import DEBUG_STATUS_STEP_INTO
        log.info("step_into")
        self.control.SetExecutionStatus(DEBUG_STATUS_STEP_INTO)
        self.control.WaitForEvent(5_000)
        return self._post_step_state()

    def do_step_over(self) -> dict:
        from .dbgeng import DEBUG_STATUS_STEP_OVER
        log.info("step_over")
        self.control.SetExecutionStatus(DEBUG_STATUS_STEP_OVER)
        self.control.WaitForEvent(5_000)
        return self._post_step_state()

    def _post_step_state(self) -> dict:
        result = {"status": "stepped"}
        try:
            idx = self.registers.GetIndexByName(b"rip")
            val = self.registers.GetValue(idx)
            rip = val.I64
            result["rip"] = f"0x{rip:016X}"
            try:
                name, disp = self.symbols.GetNameByOffset(rip)
                result["symbol"] = name + (f"+0x{disp:X}" if disp else "")
            except DbgEngError:
                pass
        except DbgEngError:
            pass
        try:
            st = self.control.GetExecutionStatus()
            self._state["execution_status"] = status_name(st)
        except DbgEngError:
            pass
        return result

    def request_break(self) -> dict:
        from .dbgeng import DEBUG_INTERRUPT_ACTIVE
        log.info("break_in: SetInterrupt")
        self.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE)
        return {"status": "break_requested"}

    # ─── Event operations (issue #2) ─────────────────────────────────

    def wait_for_one_event(self, timeout: int = 30) -> dict:
        from .dbgeng import S_OK, S_FALSE
        timeout_ms = timeout * 1000
        hr = self.control.WaitForEvent(timeout_ms)
        if hr == S_OK:
            try:
                event_info = self.control.GetLastEventInformation()
            except DbgEngError:
                event_info = {}
            queued = self.event_cb.pop_events()
            return {
                "status": "event_received",
                "last_event": event_info,
                "queued_events": queued,
            }
        elif hr == S_FALSE:
            return {"status": "timeout", "timeout_seconds": timeout}
        return {"status": "error", "hresult": f"0x{hr & 0xFFFFFFFF:08X}"}

    def drain_events(self) -> list:
        return self.event_cb.pop_events()

    def clear_event_queue(self) -> dict:
        self.event_cb.clear()
        return {"status": "cleared"}

    # ─── Inspection operations (issue #2) ────────────────────────────

    def enumerate_modules(self) -> list:
        from .dbgeng import DEBUG_MODNAME_MODULE, DEBUG_MODNAME_IMAGE
        loaded, _unloaded = self.symbols.GetNumberModules()
        result = []
        for i in range(loaded):
            try:
                base = self.symbols.GetModuleByIndex(i)
                params = self.symbols.GetModuleParameters([base])[0]
                entry = {
                    "index": i,
                    "base": f"0x{base:016X}",
                    "size": f"0x{params.Size:X}",
                    "size_bytes": params.Size,
                }
                try:
                    entry["name"] = self.symbols.GetModuleNameString(
                        DEBUG_MODNAME_MODULE, i, base)
                except DbgEngError:
                    entry["name"] = ""
                try:
                    entry["image"] = self.symbols.GetModuleNameString(
                        DEBUG_MODNAME_IMAGE, i, base)
                except DbgEngError:
                    entry["image"] = ""
                result.append(entry)
            except DbgEngError:
                continue
        return result

    def enumerate_threads(self) -> list:
        num = self.sysobj.GetNumberThreads()
        if num == 0:
            return []
        engine_ids, sys_ids = self.sysobj.GetThreadIdsByIndex(0, num)
        result = [{"engine_id": engine_ids[i], "system_id": sys_ids[i]}
                  for i in range(num)]
        try:
            current = self.sysobj.GetCurrentThreadId()
            for entry in result:
                entry["current"] = entry["engine_id"] == current
        except DbgEngError:
            pass
        return result

    def enumerate_processes(self) -> list:
        num = self.sysobj.GetNumberProcesses()
        if num == 0:
            return []
        engine_ids, sys_ids = self.sysobj.GetProcessIdsByIndex(0, num)
        result = [{"engine_id": engine_ids[i], "system_id": sys_ids[i]}
                  for i in range(num)]
        try:
            current = self.sysobj.GetCurrentProcessId()
            for entry in result:
                entry["current"] = entry["engine_id"] == current
        except DbgEngError:
            pass
        return result

    def switch_to_process(self, address: str) -> dict:
        cmd = f".process /i {address}"
        output = self.execute(cmd)
        try:
            self.control.WaitForEvent(10_000)
        except DbgEngError:
            pass
        return {
            "command": cmd,
            "output": output,
            "address": address,
        }

    # ─── Stack operations (issue #2) ─────────────────────────────────

    def get_stack_frames(self, max_frames: int = 50) -> list:
        frames = self.control.GetStackTrace(max_frames)
        result = []
        for frame in frames:
            entry = {
                "frame": frame.FrameNumber,
                "instruction": f"0x{frame.InstructionOffset:016X}",
                "return": f"0x{frame.ReturnOffset:016X}",
                "stack": f"0x{frame.StackOffset:016X}",
            }
            try:
                name, disp = self.symbols.GetNameByOffset(frame.InstructionOffset)
                entry["symbol"] = name
                entry["displacement"] = f"+0x{disp:X}" if disp else ""
            except DbgEngError:
                entry["symbol"] = ""
                entry["displacement"] = ""
            result.append(entry)
        return result

    # ─── Symbol operations (issue #2) ────────────────────────────────

    def get_field_offset_value(self, type_name: str, field_name: str) -> dict:
        parts = type_name.split("!")
        if len(parts) == 2:
            module_name, type_only = parts
        else:
            module_name = "nt"
            type_only = type_name
        _, mod_base = self.symbols.GetModuleByModuleName(
            module_name.encode("utf-8"))
        type_id = self.symbols.GetTypeId(mod_base, type_only.encode("utf-8"))
        offset = self.symbols.GetFieldOffset(
            mod_base, type_id, field_name.encode("utf-8"))
        return {
            "type": type_name,
            "field": field_name,
            "offset": offset,
            "offset_hex": f"0x{offset:X}",
        }

    def get_type_size_value(self, type_name: str) -> dict:
        parts = type_name.split("!")
        if len(parts) == 2:
            module_name, type_only = parts
        else:
            module_name = "nt"
            type_only = type_name
        _, mod_base = self.symbols.GetModuleByModuleName(
            module_name.encode("utf-8"))
        type_id = self.symbols.GetTypeId(mod_base, type_only.encode("utf-8"))
        size = self.symbols.GetTypeSize(mod_base, type_id)
        return {
            "type": type_name,
            "size": size,
            "size_hex": f"0x{size:X}",
        }

    def disassemble_instructions(self, address: str, count: int = 10) -> list:
        try:
            addr = int(address, 0)
        except ValueError:
            addr = self.symbols.GetOffsetByName(address.encode("utf-8"))
        result = []
        current = addr
        for _ in range(count):
            try:
                text, end = self.control.Disassemble(current)
                result.append({
                    "address": f"0x{current:016X}",
                    "instruction": text.strip(),
                })
                if end <= current:
                    break
                current = end
            except DbgEngError:
                break
        return result

    # ─── Breakpoint operations cont'd (issue #2) ─────────────────────

    def configure_exception_filter(self, code: str,
                                     handling: str = "break") -> dict:
        from .dbgeng import (
            DEBUG_EXCEPTION_FILTER_PARAMETERS,
            DEBUG_FILTER_BREAK, DEBUG_FILTER_SECOND_CHANCE_BREAK,
            DEBUG_FILTER_OUTPUT, DEBUG_FILTER_IGNORE,
        )
        handling_map = {
            "break": DEBUG_FILTER_BREAK,
            "second_chance_break": DEBUG_FILTER_SECOND_CHANCE_BREAK,
            "output": DEBUG_FILTER_OUTPUT,
            "ignore": DEBUG_FILTER_IGNORE,
        }
        exec_option = handling_map.get(handling, DEBUG_FILTER_BREAK)
        exc_code = int(code, 0)
        param = DEBUG_EXCEPTION_FILTER_PARAMETERS()
        param.ExecutionOption = exec_option
        param.ContinueOption = DEBUG_FILTER_IGNORE
        param.TextSize = 0
        param.CommandSize = 0
        param.SecondCommandSize = 0
        param.ExceptionCode = exc_code
        self.control.SetExceptionFilterParameters([param])
        return {"exception_code": f"0x{exc_code:08X}", "handling": handling}

    # ─── Workflow operations (issue #2) ──────────────────────────────

    def inspect_at_break(self, commands: list | None = None,
                          resume_after: bool = False) -> dict:
        from .dbgeng import DEBUG_STATUS_GO, S_OK
        cmds = commands if commands is not None else ["r", "k", "u @rip L5"]
        results: dict = {}
        for cmd in cmds:
            try:
                results[cmd] = self.execute(cmd)
            except DbgEngError as e:
                results[cmd] = f"ERROR: {e}"
        if resume_after:
            try:
                log.info("inspect: resuming after inspection")
                self.control.SetExecutionStatus(DEBUG_STATUS_GO)
                hr = self.control.WaitForEvent(1_000)
                if hr == S_OK:
                    st = self.control.GetExecutionStatus()
                    self._state["execution_status"] = status_name(st)
                    results["_resumed"] = True
                    results["_status"] = status_name(st)
                else:
                    self._state["execution_status"] = "go"
                    results["_resumed"] = True
            except DbgEngError as e:
                results["_resumed"] = False
                results["_resume_error"] = str(e)
        return results

    # ─── Context operations (issue #2) ───────────────────────────────

    def get_cpu_state_full(self) -> dict:
        from .tools.context import _read_all_registers, _read_named
        result = _read_all_registers(self.registers)
        for name in ("cr0", "cr2", "cr3", "cr4", "cr8", "efer",
                     "gs.base", "kernel_gs_base"):
            v = _read_named(self.registers, name)
            if v is not None:
                result.setdefault(name, v)
        return result

    def disassemble_at(self, address: str, count: int = 16) -> list:
        from .tools.context import _disasm_n
        addr = self.evaluate(address)
        return _disasm_n(self, addr, count)

    def read_qwords_resolved(self, address: str, count: int = 16,
                              resolve_symbols: bool = True) -> list:
        import struct
        from .tools.context import _KERNEL_MIN, _symbolize
        addr = self.evaluate(address)
        try:
            raw = self.data.ReadVirtual(addr, count * 8)
        except DbgEngError as e:
            return [{"error": str(e), "addr": f"0x{addr:016X}"}]
        out = []
        for i in range(min(count, len(raw) // 8)):
            val = struct.unpack_from("<Q", raw, i * 8)[0]
            entry = {
                "addr": f"0x{addr + i * 8:016X}",
                "value": f"0x{val:016X}",
            }
            if resolve_symbols and val >= _KERNEL_MIN:
                sym = _symbolize(self.symbols, val)
                if sym:
                    entry["symbol"] = sym
            out.append(entry)
        return out

    def get_current_process_info(self) -> dict:
        from .tools.context import _current_process_block
        return _current_process_block(self)

    def get_current_thread_info(self) -> dict:
        from .tools.context import _current_thread_block
        return _current_thread_block(self)

    def get_full_snapshot(self, max_frames: int = 20, disasm_count: int = 8,
                           stack_qwords: int = 32) -> dict:
        from .tools.context import _build_full_snapshot
        return _build_full_snapshot(self, max_frames, disasm_count, stack_qwords)

    # ─── Workflow operations (issue #2 follow-up) ────────────────────

    def execute_batch_commands(self, commands: list, stop_on_error: bool = False,
                                timeout_ms: int = 30_000) -> list:
        """Run multiple debugger commands sequentially. Lifts core.py::execute_batch._run."""
        results = []
        for cmd in commands:
            try:
                output = self.execute(cmd, timeout_ms=timeout_ms)
                results.append({"command": cmd, "output": output, "success": True})
            except Exception as e:
                results.append({
                    "command": cmd, "output": "", "success": False, "error": str(e),
                })
                if stop_on_error:
                    break
        return results

    def workflow_bp_setup(self, bp_expression: str) -> dict:
        """Lifts workflow.py::breakpoint_and_run._setup. Returns dict with bp_id, early_break flag, etc."""
        from .dbgeng import (
            DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_ENABLED, DEBUG_ANY_ID,
            DEBUG_STATUS_GO, DEBUG_STATUS_BREAK, S_OK, S_FALSE,
        )
        result: dict = {}

        if not self._validate_connection():
            log.warning("workflow_bp_setup: dead connection, reconnecting...")
            try:
                self.reconnect(kd_wait_timeout=30)
            except DbgEngError as e:
                return {"error": f"Dead connection, reconnect failed: {e}", "step": "reconnect"}

        try:
            ready = self.ensure_ready()
            result["debugger_ready"] = ready
        except DbgEngError as e:
            return {"error": f"Debugger not ready: {e}", "step": "ensure_ready"}

        try:
            bp_ptr = self.control.AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID)
            bp = DebugBreakpoint(bp_ptr)
            if bp_expression.startswith("0x") or bp_expression.startswith("0X"):
                bp.SetOffset(int(bp_expression, 0))
            else:
                bp.SetOffsetExpression(bp_expression.encode("utf-8"))
            bp.AddFlags(DEBUG_BREAKPOINT_ENABLED)
            bp_id = bp.GetId()
            try:
                offset = bp.GetOffset()
                bp_addr = f"0x{offset:016X}"
            except DbgEngError:
                bp_addr = "(deferred)"
            result["breakpoint"] = {
                "id": bp_id, "expression": bp_expression, "address": bp_addr,
            }
            result["_bp_id"] = bp_id
            self.track_breakpoint(bp_id, bp_addr, bp_expression)
            log.info("breakpoint set: %s @ %s (id=%d)", bp_expression, bp_addr, bp_id)
        except DbgEngError as e:
            return {"error": f"Failed to set breakpoint: {e}", "step": "set_breakpoint"}

        try:
            log.info("resuming target for VM command")
            for _resume in range(3):
                self.control.SetExecutionStatus(DEBUG_STATUS_GO)
                hr = self.control.WaitForEvent(500)
                if hr == S_FALSE:
                    post_s = self.control.GetExecutionStatus()
                    if post_s == DEBUG_STATUS_BREAK:
                        log.warning("workflow_bp_setup: resume %d still BREAK", _resume + 1)
                        continue
                    self._state["execution_status"] = status_name(post_s)
                    result["resumed"] = True
                    break
                post = self.control.GetExecutionStatus()
                if post != DEBUG_STATUS_BREAK:
                    self._state["execution_status"] = status_name(post)
                    result["resumed"] = True
                    break
                log.info("workflow_bp_setup: resume %d still in break", _resume + 1)
            else:
                result["_early_break"] = True
                st = self.control.GetExecutionStatus()
                self._state["execution_status"] = status_name(st)
                result["resumed"] = True
        except DbgEngError as e:
            try:
                bp_ptr2 = self.control.GetBreakpointById(bp_id)
                self.control.RemoveBreakpoint(bp_ptr2)
                self.untrack_breakpoint(bp_id)
            except DbgEngError:
                pass
            return {"error": f"Failed to resume: {e}", "step": "resume"}
        return result

    def workflow_bp_capture_early(self, setup: dict) -> dict:
        """Capture state when target broke immediately after BP setup (no VM trigger needed)."""
        from .tools.workflow import (
            _capture_registers, _capture_stack, _capture_current_instruction,
        )
        result = dict(setup)
        result.pop("_bp_id", None)
        result.pop("_early_break", None)
        result["breakpoint_hit"] = True
        result["note"] = "breakpoint fired before VM command was sent"
        try:
            result["registers"] = _capture_registers(self)
        except DbgEngError as e:
            result["registers_error"] = str(e)
        try:
            result["stack"] = _capture_stack(self)
        except DbgEngError as e:
            result["stack_error"] = str(e)
        try:
            result["instruction"] = _capture_current_instruction(self)
        except DbgEngError as e:
            result["instruction_error"] = str(e)
        return result

    def workflow_bp_wait_capture(self, bp_id: int, bp_expression: str,
                                   bp_timeout_ms: int) -> dict:
        """Wait for the previously-set breakpoint to fire, capture state."""
        from .dbgeng import S_OK, S_FALSE
        from .tools.workflow import (
            _capture_registers, _capture_stack, _capture_current_instruction,
        )
        import time as _time
        result: dict = {}
        try:
            hr = self.control.WaitForEvent(bp_timeout_ms)
            if hr == S_OK:
                result["breakpoint_hit"] = True
                self._state["execution_status"] = "break"
                log.info("breakpoint hit!")
                try:
                    result["registers"] = _capture_registers(self)
                except DbgEngError as e:
                    result["registers_error"] = str(e)
                try:
                    result["stack"] = _capture_stack(self)
                except DbgEngError as e:
                    result["stack_error"] = str(e)
                try:
                    result["instruction"] = _capture_current_instruction(self)
                except DbgEngError as e:
                    result["instruction_error"] = str(e)
                self.record_event({
                    "type": "breakpoint_hit", "bp_id": bp_id,
                    "expression": bp_expression, "time": _time.time(),
                })
            elif hr == S_FALSE:
                result["breakpoint_hit"] = False
                result["note"] = f"Timeout after {bp_timeout_ms}ms — breakpoint not hit"
                log.info("breakpoint timeout after %dms", bp_timeout_ms)
            else:
                result["breakpoint_hit"] = False
                result["wait_error"] = f"WaitForEvent returned 0x{hr & 0xFFFFFFFF:08X}"
        except DbgEngError as e:
            result["breakpoint_hit"] = False
            result["wait_error"] = str(e)
        return result

    def workflow_trace_setup(self, trace_addresses: list) -> dict:
        """Set logging breakpoints at multiple addresses, resume target. Lifts run_and_trace._setup."""
        from .dbgeng import (
            DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_ENABLED, DEBUG_ANY_ID,
        )
        result: dict = {"trace_points": []}
        bp_ids: list = []
        try:
            self.ensure_ready()
        except DbgEngError as e:
            return {"error": f"Debugger not ready: {e}", "_bp_ids": bp_ids}
        for addr_expr in trace_addresses:
            try:
                bp_ptr = self.control.AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID)
                bp = DebugBreakpoint(bp_ptr)
                if addr_expr.startswith("0x") or addr_expr.startswith("0X"):
                    bp.SetOffset(int(addr_expr, 0))
                else:
                    bp.SetOffsetExpression(addr_expr.encode("utf-8"))
                bp.SetCommand(f".echo TRACE_HIT:{addr_expr}; gc".encode("utf-8"))
                bp.AddFlags(DEBUG_BREAKPOINT_ENABLED)
                bp_id = bp.GetId()
                bp_ids.append([bp_id, addr_expr])
                result["trace_points"].append({"expression": addr_expr, "bp_id": bp_id})
            except DbgEngError as e:
                result["trace_points"].append({"expression": addr_expr, "error": str(e)})
        try:
            resume_result = self.resume_target()
            if resume_result.get("status") != "running":
                log.warning("workflow_trace_setup: resume may have failed: %s", resume_result)
        except DbgEngError as e:
            self._cleanup_breakpoints_by_id([bid for bid, _ in bp_ids])
            return {"error": f"Failed to resume: {e}", "_bp_ids": []}
        result["_bp_ids"] = bp_ids
        return result

    def workflow_trace_collect(self, bp_ids_with_expr: list) -> list:
        """Break in, harvest TRACE_HIT log lines, clean up breakpoints. Lifts run_and_trace._collect."""
        from .dbgeng import DEBUG_INTERRUPT_ACTIVE
        try:
            self.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE)
            self.control.WaitForEvent(2_000)
        except DbgEngError:
            pass
        trace_output = self.output_cb.get_text()
        hits: list = []
        for line in trace_output.split("\n"):
            line = line.strip()
            if line.startswith("TRACE_HIT:"):
                hits.append(line[len("TRACE_HIT:"):])
        self._cleanup_breakpoints_by_id([bid for bid, _ in bp_ids_with_expr])
        return hits

    def _cleanup_breakpoints_by_id(self, bp_ids: list) -> None:
        for bp_id in bp_ids:
            try:
                bp_ptr = self.control.GetBreakpointById(bp_id)
                self.control.RemoveBreakpoint(bp_ptr)
                self.untrack_breakpoint(bp_id)
            except DbgEngError:
                pass

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


# ─── COM thread affinity + background event pump ────────────────
#
# DbgEng COM interfaces have thread affinity — they MUST be called
# from the same thread that created them. So we own a single
# long-running worker thread that both (a) runs serialized tool
# calls, and (b) keeps pumping events via WaitForEvent(INFINITE)
# whenever the target is in GO state and no task is queued.
#
# Without (b), aragorn is a silent kernel debugger: when a BP fires
# on the target, the kdnet driver on the VM sends a break packet,
# our dbgeng receives it, but nothing dispatches it because nobody
# is calling WaitForEvent. The VM kernel waits for us to ack. kdnet
# retransmits. Hyper-V integration services miss their heartbeat
# deadline. VM userspace wedges. This is the exact behavior we've
# been fighting.
#
# With (b), BP events get dispatched within milliseconds of firing.
# If the BP command contains `gc` (and our _breakpoint callback
# returns NO_CHANGE, which it does), the `gc` updates execution
# status to GO, WaitForEvent returns, and the pump re-enters
# WaitForEvent immediately. Net effect: the VM is never waiting.

class _DbgEngWorker:
    """Single-threaded worker that serializes tool calls and pumps
    debugger events when idle.

    Python code submits work via `submit(fn, *args)` which returns a
    concurrent.futures.Future. The worker thread runs queued work
    first; when the queue is empty AND the target is running, it
    blocks in `WaitForEvent(INFINITE)` so BP/exception events are
    dispatched in real time.

    `submit` signals work availability by (a) enqueueing the task and
    (b) calling `SetInterrupt(DEBUG_INTERRUPT_EXIT)` on the control
    interface if there is one — SetInterrupt is documented as thread-
    safe and will unblock any pending WaitForEvent immediately.
    """

    def __init__(self):
        self._queue: "queue.Queue" = None
        self._thread: threading.Thread | None = None
        self._shutdown = False
        self._start()

    def _start(self):
        import queue as _q
        self._queue = _q.Queue()
        self._shutdown = False
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="dbgeng-com")
        self._thread.start()

    def _run(self):
        import queue as _q
        while not self._shutdown:
            # Drain queued tool calls first.
            try:
                task = self._queue.get(timeout=0.0)
            except _q.Empty:
                task = None

            if task is not None:
                fn, args, fut = task
                try:
                    fut.set_result(fn(*args))
                except BaseException as e:
                    fut.set_exception(e)
                continue

            # No task pending — pump events if a target is running.
            dbg = globals().get("_debugger")
            if dbg is None or not dbg.is_connected or dbg.control is None:
                # No active session to pump. Briefly sleep to avoid busy-wait.
                try:
                    task = self._queue.get(timeout=0.1)
                    if task is not None:
                        fn, args, fut = task
                        try:
                            fut.set_result(fn(*args))
                        except BaseException as e:
                            fut.set_exception(e)
                except _q.Empty:
                    pass
                continue

            try:
                status = dbg.control.GetExecutionStatus()
            except Exception:
                # COM in a bad state; yield and retry
                try:
                    task = self._queue.get(timeout=0.1)
                    if task is not None:
                        fn, args, fut = task
                        try:
                            fut.set_result(fn(*args))
                        except BaseException as e:
                            fut.set_exception(e)
                except _q.Empty:
                    pass
                continue

            if status == DEBUG_STATUS_BREAK or status == DEBUG_STATUS_NO_DEBUGGEE:
                # Nothing to pump — just wait for a task.
                try:
                    task = self._queue.get(timeout=0.1)
                    if task is not None:
                        fn, args, fut = task
                        try:
                            fut.set_result(fn(*args))
                        except BaseException as e:
                            fut.set_exception(e)
                except _q.Empty:
                    pass
                continue

            # Target is running. Tight inner pump — minimize per-iteration
            # Python work between WaitForEvent returns. Each call returns
            # when (a) a break event arrives + the BP command auto-continues
            # (state stays GO), (b) a real break occurs (state -> BREAK),
            # or (c) submit() called SetInterrupt(EXIT) for a new task.
            #
            # Per-iteration cost matters: at minifilter callback rates the
            # outer loop's queue.get(timeout=0.0) + extra COM checks add
            # 100-200µs per BP hit, which compounds into the wedge. The
            # inner loop drops the queue.get(timeout=0.0) lock acquire in
            # favor of queue.empty() (atomic read, no lock), but still
            # checks status on every WaitForEvent return so a real BREAK
            # is detected immediately (otherwise we'd block forever on
            # WaitForEvent against a broken kernel).
            while not self._shutdown:
                try:
                    dbg.control.WaitForEvent(INFINITE)
                except Exception as e:
                    log.debug("pump WaitForEvent: %s", e)
                    break
                # Cheap: queue.empty() is an atomic read, no lock acquire.
                if not self._queue.empty():
                    break
                # Detect GO→BREAK transitions (real BP, exception,
                # SetInterrupt(ACTIVE)) so we can stop spinning.
                try:
                    st = dbg.control.GetExecutionStatus()
                except Exception:
                    break
                if st != DEBUG_STATUS_GO:
                    break

    def submit(self, fn, *args):
        """Enqueue a task, wake the pump if it's in WaitForEvent."""
        fut = concurrent.futures.Future()
        self._queue.put((fn, args, fut))
        # Poke the pump so it returns from WaitForEvent.
        dbg = globals().get("_debugger")
        if dbg is not None and dbg.control is not None:
            try:
                dbg.control.SetInterrupt(DEBUG_INTERRUPT_EXIT)
            except Exception:
                pass
        return fut

    def shutdown(self, wait: bool = False):
        self._shutdown = True
        # Poke the pump so it notices shutdown.
        dbg = globals().get("_debugger")
        if dbg is not None and dbg.control is not None:
            try:
                dbg.control.SetInterrupt(DEBUG_INTERRUPT_EXIT)
            except Exception:
                pass
        if wait and self._thread is not None:
            self._thread.join(timeout=5)


_com_executor = _DbgEngWorker()


def reset_com_executor():
    """Replace the worker with a fresh thread (stuck-thread recovery)."""
    global _com_executor
    log.warning("Resetting COM worker (stuck thread recovery)")
    try:
        _com_executor.shutdown(wait=False)
    except Exception as e:
        log.warning("Old worker shutdown error: %s", e)
    _com_executor = _DbgEngWorker()
    log.info("COM worker reset complete")


def status_name(code: int) -> str:
    """Map numeric execution status to a human-readable name."""
    return Debugger._status_name(code)


def _is_supervisor_mode() -> bool:
    """True iff this process is the MCP server using a worker subprocess."""
    return os.environ.get("ARAGORN_SUPERVISOR_MODE", "1") == "1" \
        and os.environ.get("ARAGORN_WORKER", "0") != "1"


async def _dispatch_via_supervisor(func, *args, **kwargs):
    """Route a `run_on_com_thread`-style call through the supervisor."""
    from .supervisor import get_supervisor
    sup = get_supervisor()
    # Identify the method name from the various forms callers pass:
    method_name = None
    bound_args = ()
    bound_kwargs = {}
    if isinstance(func, _ProxyCallable):
        method_name = func._proxy_name
        bound_args = func._proxy_args
        bound_kwargs = func._proxy_kwargs
    elif isinstance(func, _ProxyMethod):
        method_name = func._proxy_name
    elif hasattr(func, "_proxy_name"):
        method_name = func._proxy_name
    elif hasattr(func, "__name__"):
        n = func.__name__
        if n and not n.startswith("<"):
            method_name = n
    if method_name is None:
        raise NotImplementedError(
            f"Cannot dispatch {func!r} via supervisor — pass a Debugger "
            f"method (dbg.method) or use sup.call('name', ...) directly.")
    full_args = list(bound_args) + list(args)
    full_kwargs = {**bound_kwargs, **kwargs}
    return await sup.call(method_name, *full_args, **full_kwargs)


async def run_on_com_thread(func, *args, timeout: float = 0, **kwargs):
    """Run *func* on the dedicated DbgEng COM thread with timeout.

    In supervisor mode (default), the call is forwarded over JSON-RPC
    to the worker subprocess that owns dbgeng — `func` is expected to
    be either a Debugger-bound method (`dbg.health_check`), a string
    method name, or a proxy-callable produced by DebuggerProxy. The
    worker's own `run_on_com_thread` then schedules it on the worker's
    COM thread.

    In legacy in-process mode (`ARAGORN_SUPERVISOR_MODE=0`), the call
    runs on this process's COM thread directly.
    """
    # Multi-session registry path (legacy, kept for backward compat)
    try:
        from .sessions import get_registry
        reg = get_registry()
        if reg.list_sessions():
            active_id = reg.active_session_id
            if active_id:
                return await reg.run_on_com_thread(active_id, func, *args, timeout=timeout)
    except (ImportError, KeyError):
        pass

    # Supervisor mode: dispatch via JSON-RPC to the worker subprocess.
    if _is_supervisor_mode():
        return await _dispatch_via_supervisor(func, *args, **kwargs)

    # Legacy in-process COM dispatch.
    ceiling = timeout if timeout > 0 else getattr(config, "HARD_TIMEOUT_S", 600)
    loop = asyncio.get_running_loop()
    name = getattr(func, "__name__", repr(func))
    log.debug("COM→ %s", name)
    # _DbgEngWorker.submit returns a concurrent.futures.Future.
    # asyncio.wrap_future lets us await it from the event loop.
    cf = _com_executor.submit(func, *args)
    try:
        return await asyncio.wait_for(
            asyncio.wrap_future(cf, loop=loop),
            timeout=ceiling,
        )
    except asyncio.TimeoutError:
        log.error("COM timeout (%s, %.0fs) — aborting transport", name, ceiling)
        dbg = get_debugger_or_none()
        recovery = None
        if dbg is not None:
            recovery = dbg.recover_from_wedge()
        raise DbgEngError(-1,
            f"COM call '{name}' timed out after {ceiling:.0f}s. "
            f"Transport aborted ({recovery}). Call ensure_ready() to reconnect.")
    except Exception as e:
        log.warning("COM✗ %s: %s", name, e)
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


def set_debugger(dbg) -> None:
    """Replace the global Debugger singleton."""
    global _debugger
    _debugger = dbg


# ─── Supervisor-mode proxy ────────────────────────────────────────
#
# In supervisor mode the MCP server process does NOT own a Debugger;
# the worker subprocess does. Tool code still wants to write
# `dbg.method` and pass it to `run_on_com_thread`. The proxy below
# satisfies that pattern: every attribute access produces a callable
# that captures its bound name + args + kwargs, which
# `_dispatch_via_supervisor` then unpacks into a JSON-RPC call.
#
# Synchronous attribute reads on the proxy (`dbg.is_connected`,
# `dbg._kd_connection`) are NOT supported — they were never sane to
# do across a process boundary anyway. Tool code that needs that
# state should call `await sup.call("get_status")` etc.

class _ProxyCallable:
    """A captured `proxy.method(*args, **kwargs)` invocation.

    Created by calling a `_ProxyMethod`. Holds the method name plus the
    bound args/kwargs. `_dispatch_via_supervisor` unpacks both the
    bound and any extra args supplied at run_on_com_thread time.
    """

    __slots__ = ("_proxy_name", "_proxy_args", "_proxy_kwargs", "__name__")

    def __init__(self, name: str, args: tuple, kwargs: dict):
        self._proxy_name = name
        self._proxy_args = args
        self._proxy_kwargs = kwargs
        self.__name__ = name


class _ProxyMethod:
    """An unbound method on the proxy. Call it to bind args."""

    __slots__ = ("_proxy_name", "__name__")

    def __init__(self, name: str):
        self._proxy_name = name
        self.__name__ = name

    def __call__(self, *args, **kwargs) -> _ProxyCallable:
        return _ProxyCallable(self._proxy_name, args, kwargs)


class DebuggerProxy:
    """Process-local stand-in for a Debugger when running in supervisor mode."""

    def __getattr__(self, name: str):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return _ProxyMethod(name)

    def __repr__(self) -> str:
        return "<DebuggerProxy (worker-backed)>"


_proxy_singleton = DebuggerProxy()


# Re-export `get_debugger` / `get_debugger_or_none` so tool code
# transparently gets the proxy in supervisor mode without any
# behavioral change at call sites.

_real_get_debugger = get_debugger
_real_get_debugger_or_none = get_debugger_or_none


def get_debugger(auto_connect: bool = False):
    if _is_supervisor_mode():
        return _proxy_singleton
    return _real_get_debugger(auto_connect)


def get_debugger_or_none():
    if _is_supervisor_mode():
        return _proxy_singleton
    return _real_get_debugger_or_none()
