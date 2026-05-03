"""Python COM callback objects for DbgEng — OutputCallbacks and EventCallbacks.

These are pure-ctypes implementations of IDebugOutputCallbacks and
IDebugEventCallbacks. DbgEng calls into these vtables during Execute()
and WaitForEvent(). The "objects" are hand-built: a ctypes array serves
as the vtable, and the first word of the "instance" points to it.

The Debugger class MUST hold strong references to these objects and their
WINFUNCTYPE closures to prevent garbage collection (which would crash
DbgEng when it tries to call freed memory).
"""

import ctypes
import queue
import threading
import time
from ctypes import (
    c_void_p, c_char_p, c_ulong, c_long, c_ulonglong,
    POINTER, WINFUNCTYPE,
)

from .dbgeng import (
    HRESULT, S_OK, GUID, IID_IUnknown,
    DEBUG_STATUS_BREAK, DEBUG_STATUS_NO_CHANGE,
)

# Callback GUIDs
IID_IDebugOutputCallbacks = GUID()
IID_IDebugOutputCallbacks.Data1 = 0x4bf58045
IID_IDebugOutputCallbacks.Data2 = 0xd654
IID_IDebugOutputCallbacks.Data3 = 0x4c40
for i, b in enumerate(bytes.fromhex("b0af683090f356dc")):
    IID_IDebugOutputCallbacks.Data4[i] = b

IID_IDebugEventCallbacks = GUID()
IID_IDebugEventCallbacks.Data1 = 0x337be28b
IID_IDebugEventCallbacks.Data2 = 0x5036
IID_IDebugEventCallbacks.Data3 = 0x4d72
for i, b in enumerate(bytes.fromhex("b6bfc45fbb9f2eaa")):
    IID_IDebugEventCallbacks.Data4[i] = b


def _guid_eq(a: GUID, b: GUID) -> bool:
    """Compare two GUIDs."""
    if a.Data1 != b.Data1 or a.Data2 != b.Data2 or a.Data3 != b.Data3:
        return False
    for i in range(8):
        if a.Data4[i] != b.Data4[i]:
            return False
    return True


# ──────────────────────────────────────────────────────────────────────
# OutputCallbacks — captures text output from Execute()
# ──────────────────────────────────────────────────────────────────────
#
# IDebugOutputCallbacks vtable (4 slots):
#   0: QueryInterface(REFIID, void**)
#   1: AddRef()
#   2: Release()
#   3: Output(ULONG Mask, PCSTR Text)
# ──────────────────────────────────────────────────────────────────────

# Callback signatures
_QI_TYPE    = WINFUNCTYPE(c_long, c_void_p, POINTER(GUID), POINTER(c_void_p))
_ADDREF_TYPE = WINFUNCTYPE(c_ulong, c_void_p)
_RELEASE_TYPE = WINFUNCTYPE(c_ulong, c_void_p)
_OUTPUT_TYPE = WINFUNCTYPE(c_long, c_void_p, c_ulong, c_char_p)


class OutputCallbacks:
    """IDebugOutputCallbacks implementation that captures text to a buffer.

    Usage:
        cb = OutputCallbacks()
        client.SetOutputCallbacks(cb.as_param())
        ...
        control.Execute(command)
        text = cb.get_text()  # returns captured output and clears buffer
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._parts: list[str] = []
        self.last_output_time: float | None = None
        self.output_count: int = 0

        # prevent GC of closures
        self._qi_fn = _QI_TYPE(self._query_interface)
        self._addref_fn = _ADDREF_TYPE(self._add_ref)
        self._release_fn = _RELEASE_TYPE(self._release)
        self._output_fn = _OUTPUT_TYPE(self._output)

        # build vtable: array of 4 function pointers
        self._vtable = (c_void_p * 4)(
            ctypes.cast(self._qi_fn, c_void_p),
            ctypes.cast(self._addref_fn, c_void_p),
            ctypes.cast(self._release_fn, c_void_p),
            ctypes.cast(self._output_fn, c_void_p),
        )

        # "object": a single c_void_p whose value is the address of the vtable
        self._obj = c_void_p(ctypes.addressof(self._vtable))

    def as_param(self) -> c_void_p:
        """Return pointer suitable for SetOutputCallbacks()."""
        return ctypes.pointer(self._obj)

    def get_text(self) -> str:
        """Return accumulated output and clear the buffer."""
        with self._lock:
            text = "".join(self._parts)
            self._parts.clear()
            return text

    def clear(self):
        """Discard accumulated output and reset progress tracking."""
        with self._lock:
            self._parts.clear()
            self.last_output_time = None
            self.output_count = 0

    # COM methods ──────────────────────────────────────────────────────

    def _query_interface(self, this, riid, ppv):
        riid_val = riid[0]
        if (_guid_eq(riid_val, IID_IUnknown) or
                _guid_eq(riid_val, IID_IDebugOutputCallbacks)):
            ppv[0] = this
            return S_OK
        ppv[0] = None
        return c_long(0x80004002).value  # E_NOINTERFACE

    def _add_ref(self, this):
        return 1

    def _release(self, this):
        return 0

    def _output(self, this, mask, text):
        if text:
            try:
                decoded = text.decode("utf-8", errors="replace")
            except Exception:
                decoded = str(text)
            with self._lock:
                self._parts.append(decoded)
                self.last_output_time = time.monotonic()
                self.output_count += 1
        return S_OK


# ──────────────────────────────────────────────────────────────────────
# EventCallbacks — pushes debug events to a queue
# ──────────────────────────────────────────────────────────────────────
#
# IDebugEventCallbacks vtable (17 slots):
#   0:  QueryInterface
#   1:  AddRef
#   2:  Release
#   3:  QueryInterface (hmm, actually GetInterestMask)
#
# Corrected layout:
#   0:  QueryInterface(REFIID, void**)
#   1:  AddRef()
#   2:  Release()
#   3:  GetInterestMask(PULONG Mask)
#   4:  Breakpoint(IDebugBreakpoint*)
#   5:  Exception(PEXCEPTION_RECORD64, ULONG FirstChance)
#   6:  CreateThread(ULONG64 Handle, ULONG64 DataOffset, ULONG64 StartOffset)
#   7:  ExitThread(ULONG ExitCode)
#   8:  CreateProcess(...)  — 10 params
#   9:  ExitProcess(ULONG ExitCode)
#   10: LoadModule(ULONG64 ImageFileHandle, ULONG64 BaseOffset, ULONG ModuleSize,
#                  PCSTR ModuleName, PCSTR ImageName, ULONG CheckSum, ULONG TimeDateStamp)
#   11: UnloadModule(PCSTR ImageBaseName, ULONG64 BaseOffset)
#   12: SystemError(ULONG Error, ULONG Level)
#   13: SessionStatus(ULONG Status)
#   14: ChangeDebuggeeState(ULONG Flags, ULONG64 Argument)
#   15: ChangeEngineState(ULONG Flags, ULONG64 Argument)
#   16: ChangeSymbolState(ULONG Flags, ULONG64 Argument)
# ──────────────────────────────────────────────────────────────────────

# Interest mask bits (which events we want)
DEBUG_EVENT_BREAKPOINT_BIT    = 0x00000001
DEBUG_EVENT_EXCEPTION_BIT     = 0x00000002
DEBUG_EVENT_CREATE_THREAD_BIT = 0x00000004
DEBUG_EVENT_EXIT_THREAD_BIT   = 0x00000008
DEBUG_EVENT_CREATE_PROCESS_BIT = 0x00000010
DEBUG_EVENT_EXIT_PROCESS_BIT  = 0x00000020
DEBUG_EVENT_LOAD_MODULE_BIT   = 0x00000040
DEBUG_EVENT_UNLOAD_MODULE_BIT = 0x00000080
DEBUG_EVENT_SYSTEM_ERROR_BIT  = 0x00000100
DEBUG_EVENT_SESSION_STATUS_BIT = 0x00000200
DEBUG_EVENT_CHANGE_DEBUGGEE_STATE_BIT = 0x00000400
DEBUG_EVENT_CHANGE_ENGINE_STATE_BIT   = 0x00000800
DEBUG_EVENT_CHANGE_SYMBOL_STATE_BIT   = 0x00001000

ALL_EVENTS = (
    # DEBUG_EVENT_BREAKPOINT_BIT intentionally NOT set: registering for BP
    # events forces every BP hit through our Python WINFUNCTYPE callback,
    # which acquires the GIL and pushes to a Python queue. At high BP rates
    # (e.g. minifilter callbacks fielding all-system FltMgr I/O), that
    # per-hit Python cost saturates the COM thread and starves the VM's
    # user-mode HTTP listener — what we colloquially call "the wedge".
    # DbgEng handles BP events fine without our callback: it evaluates the
    # BP command (`.if .else gc` / `bp /w`) entirely in C++ and only
    # actually breaks when the condition is true. We detect a real break
    # via GetExecutionStatus polling.
    DEBUG_EVENT_EXCEPTION_BIT |
    DEBUG_EVENT_LOAD_MODULE_BIT |
    DEBUG_EVENT_UNLOAD_MODULE_BIT |
    DEBUG_EVENT_CREATE_PROCESS_BIT |
    DEBUG_EVENT_EXIT_PROCESS_BIT |
    DEBUG_EVENT_SESSION_STATUS_BIT |
    DEBUG_EVENT_SYSTEM_ERROR_BIT
)

# Callback type signatures for event methods
_GET_INTEREST_MASK_TYPE = WINFUNCTYPE(c_long, c_void_p, POINTER(c_ulong))
_BREAKPOINT_TYPE = WINFUNCTYPE(c_long, c_void_p, c_void_p)
_EXCEPTION_TYPE = WINFUNCTYPE(c_long, c_void_p, c_void_p, c_ulong)
_CREATE_THREAD_TYPE = WINFUNCTYPE(c_long, c_void_p, c_ulonglong, c_ulonglong, c_ulonglong)
_EXIT_THREAD_TYPE = WINFUNCTYPE(c_long, c_void_p, c_ulong)
_CREATE_PROCESS_TYPE = WINFUNCTYPE(c_long, c_void_p, c_ulonglong, c_ulonglong,
                                   c_ulonglong, c_ulong, c_char_p, c_char_p,
                                   c_ulong, c_ulong, c_ulonglong, c_ulonglong)
_EXIT_PROCESS_TYPE = WINFUNCTYPE(c_long, c_void_p, c_ulong)
_LOAD_MODULE_TYPE = WINFUNCTYPE(c_long, c_void_p, c_ulonglong, c_ulonglong,
                                c_ulong, c_char_p, c_char_p, c_ulong, c_ulong)
_UNLOAD_MODULE_TYPE = WINFUNCTYPE(c_long, c_void_p, c_char_p, c_ulonglong)
_SYSTEM_ERROR_TYPE = WINFUNCTYPE(c_long, c_void_p, c_ulong, c_ulong)
_SESSION_STATUS_TYPE = WINFUNCTYPE(c_long, c_void_p, c_ulong)
_CHANGE_STATE_TYPE = WINFUNCTYPE(c_long, c_void_p, c_ulong, c_ulonglong)


class EventCallbacks:
    """IDebugEventCallbacks implementation that queues debug events.

    Events are pushed to an internal queue (max 1000 entries).
    The Debugger class reads from this queue via pop_events()/wait_event().
    """

    def __init__(self, max_events: int = 1000):
        self._queue: queue.Queue = queue.Queue(maxsize=max_events)

        # prevent GC of all closures
        self._qi_fn = _QI_TYPE(self._query_interface)
        self._addref_fn = _ADDREF_TYPE(self._add_ref)
        self._release_fn = _RELEASE_TYPE(self._release)
        self._interest_fn = _GET_INTEREST_MASK_TYPE(self._get_interest_mask)
        self._bp_fn = _BREAKPOINT_TYPE(self._breakpoint)
        self._exc_fn = _EXCEPTION_TYPE(self._exception)
        self._ct_fn = _CREATE_THREAD_TYPE(self._create_thread)
        self._et_fn = _EXIT_THREAD_TYPE(self._exit_thread)
        self._cp_fn = _CREATE_PROCESS_TYPE(self._create_process)
        self._ep_fn = _EXIT_PROCESS_TYPE(self._exit_process)
        self._lm_fn = _LOAD_MODULE_TYPE(self._load_module)
        self._um_fn = _UNLOAD_MODULE_TYPE(self._unload_module)
        self._se_fn = _SYSTEM_ERROR_TYPE(self._system_error)
        self._ss_fn = _SESSION_STATUS_TYPE(self._session_status)
        self._cds_fn = _CHANGE_STATE_TYPE(self._change_debuggee_state)
        self._ces_fn = _CHANGE_STATE_TYPE(self._change_engine_state)
        self._css_fn = _CHANGE_STATE_TYPE(self._change_symbol_state)

        # vtable: 17 slots
        self._vtable = (c_void_p * 17)(
            ctypes.cast(self._qi_fn, c_void_p),       # 0
            ctypes.cast(self._addref_fn, c_void_p),    # 1
            ctypes.cast(self._release_fn, c_void_p),   # 2
            ctypes.cast(self._interest_fn, c_void_p),  # 3
            ctypes.cast(self._bp_fn, c_void_p),        # 4
            ctypes.cast(self._exc_fn, c_void_p),       # 5
            ctypes.cast(self._ct_fn, c_void_p),        # 6
            ctypes.cast(self._et_fn, c_void_p),        # 7
            ctypes.cast(self._cp_fn, c_void_p),        # 8
            ctypes.cast(self._ep_fn, c_void_p),        # 9
            ctypes.cast(self._lm_fn, c_void_p),        # 10
            ctypes.cast(self._um_fn, c_void_p),        # 11
            ctypes.cast(self._se_fn, c_void_p),        # 12
            ctypes.cast(self._ss_fn, c_void_p),        # 13
            ctypes.cast(self._cds_fn, c_void_p),       # 14
            ctypes.cast(self._ces_fn, c_void_p),       # 15
            ctypes.cast(self._css_fn, c_void_p),       # 16
        )

        self._obj = c_void_p(ctypes.addressof(self._vtable))

    def as_param(self) -> c_void_p:
        """Return pointer suitable for SetEventCallbacks()."""
        return ctypes.pointer(self._obj)

    def pop_events(self) -> list[dict]:
        """Return all queued events without blocking."""
        events = []
        while True:
            try:
                events.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return events

    def clear(self):
        """Discard all queued events."""
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break

    def _push(self, event: dict):
        """Push event to queue, dropping oldest if full."""
        event["timestamp"] = time.time()
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                pass

    # COM methods ──────────────────────────────────────────────────────

    def _query_interface(self, this, riid, ppv):
        riid_val = riid[0]
        if (_guid_eq(riid_val, IID_IUnknown) or
                _guid_eq(riid_val, IID_IDebugEventCallbacks)):
            ppv[0] = this
            return S_OK
        ppv[0] = None
        return c_long(0x80004002).value

    def _add_ref(self, this):
        return 1

    def _release(self, this):
        return 0

    def _get_interest_mask(self, this, mask_ptr):
        mask_ptr[0] = ALL_EVENTS
        return S_OK

    def _breakpoint(self, this, bp_ptr):
        self._push({"event": "breakpoint_hit"})
        # Return DEBUG_STATUS_GO (vote: continue), not NO_CHANGE.
        # Per dbgeng's "Monitoring Events" docs, BP events break into
        # the debugger by default and the engine takes the highest-
        # precedence return value across all registered callbacks.
        # NO_CHANGE doesn't contribute, so the default BREAK wins —
        # which means /w "false" conditions ALSO break to the user
        # (the engine's own /w "false → continue" verdict can't out-
        # vote the default). Voting GO here lets /w false take effect:
        #   - /w false: engine internal vote = GO, ours = GO → continue
        #   - /w true:  engine internal vote = BREAK, ours = GO → BREAK wins
        #   - no /w, plain BP: engine default = BREAK, ours = GO → BREAK wins
        # Net effect: conditional BPs work, unconditional BPs still break.
        return DEBUG_STATUS_GO

    def _exception(self, this, exception_record, first_chance):
        self._push({
            "event": "exception",
            "first_chance": bool(first_chance),
        })
        return DEBUG_STATUS_BREAK

    def _create_thread(self, this, handle, data_offset, start_offset):
        self._push({
            "event": "create_thread",
            "data_offset": f"0x{data_offset:016X}",
            "start_offset": f"0x{start_offset:016X}",
        })
        return DEBUG_STATUS_NO_CHANGE

    def _exit_thread(self, this, exit_code):
        self._push({
            "event": "exit_thread",
            "exit_code": exit_code,
        })
        return DEBUG_STATUS_NO_CHANGE

    def _create_process(self, this, image_handle, handle, base_offset,
                        module_size, module_name, image_name,
                        checksum, timestamp, initial_thread_handle,
                        thread_data_offset):
        name = ""
        if image_name:
            try:
                name = image_name.decode("utf-8", errors="replace")
            except Exception:
                pass
        self._push({
            "event": "create_process",
            "base": f"0x{base_offset:016X}",
            "name": name,
        })
        return DEBUG_STATUS_NO_CHANGE

    def _exit_process(self, this, exit_code):
        self._push({
            "event": "exit_process",
            "exit_code": exit_code,
        })
        return DEBUG_STATUS_NO_CHANGE

    def _load_module(self, this, image_file_handle, base_offset,
                     module_size, module_name, image_name,
                     checksum, timestamp):
        name = ""
        if module_name:
            try:
                name = module_name.decode("utf-8", errors="replace")
            except Exception:
                pass
        self._push({
            "event": "module_load",
            "base": f"0x{base_offset:016X}",
            "size": module_size,
            "name": name,
        })
        return DEBUG_STATUS_NO_CHANGE

    def _unload_module(self, this, image_base_name, base_offset):
        self._push({
            "event": "module_unload",
            "base": f"0x{base_offset:016X}",
        })
        return DEBUG_STATUS_NO_CHANGE

    def _system_error(self, this, error, level):
        self._push({
            "event": "system_error",
            "error": error,
            "level": level,
        })
        return DEBUG_STATUS_BREAK

    def _session_status(self, this, status):
        self._push({
            "event": "session_status",
            "status": status,
        })
        return S_OK

    def _change_debuggee_state(self, this, flags, argument):
        return S_OK

    def _change_engine_state(self, this, flags, argument):
        return S_OK

    def _change_symbol_state(self, this, flags, argument):
        return S_OK
