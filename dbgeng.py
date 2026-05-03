"""DbgEng COM interface definitions — pure ctypes, zero dependencies.

Vtable slot indices verified against Windows SDK DbgEng.h and
Microsoft DbgShell COM interop definitions (github.com/microsoft/DbgShell).
Each slot is annotated with the method name for verification.
"""

import ctypes
from ctypes import (
    c_void_p, c_char_p, c_ulong, c_long, c_ulonglong, c_longlong,
    c_ushort, c_ubyte, c_uint64, c_int, c_float, c_double,
    POINTER, byref, sizeof, Structure, Union, WINFUNCTYPE,
)

# ──────────────────────────────────────────────────────────────────────
# Type aliases (matching Windows SDK)
# ──────────────────────────────────────────────────────────────────────
HRESULT = c_long
ULONG = c_ulong
ULONG64 = c_ulonglong
LONG64 = c_longlong
BOOL = c_int
PVOID = c_void_p
PCSTR = c_char_p
PULONG = POINTER(c_ulong)
PULONG64 = POINTER(c_ulonglong)
INFINITE = 0xFFFFFFFF

# ──────────────────────────────────────────────────────────────────────
# HRESULT codes
# ──────────────────────────────────────────────────────────────────────
S_OK = 0
S_FALSE = 1
E_FAIL = 0x80004005
E_NOINTERFACE = 0x80004002
E_NOTIMPL = 0x80004001
E_UNEXPECTED = 0x8000FFFF

# ──────────────────────────────────────────────────────────────────────
# Debug constants
# ──────────────────────────────────────────────────────────────────────

# AttachKernel flags
DEBUG_ATTACH_KERNEL_CONNECTION = 0

# SetInterrupt flags
DEBUG_INTERRUPT_ACTIVE = 0
DEBUG_INTERRUPT_PASSIVE = 1
DEBUG_INTERRUPT_EXIT = 2

# Execute output control
DEBUG_OUTCTL_THIS_CLIENT = 0
DEBUG_OUTCTL_ALL_CLIENTS = 1

# Execute flags
DEBUG_EXECUTE_DEFAULT = 0
DEBUG_EXECUTE_ECHO = 1
DEBUG_EXECUTE_NOT_LOGGED = 2
DEBUG_EXECUTE_NO_REPEAT = 4

# Execution status
DEBUG_STATUS_NO_CHANGE = 0
DEBUG_STATUS_GO = 1
DEBUG_STATUS_GO_HANDLED = 2
DEBUG_STATUS_GO_NOT_HANDLED = 3
DEBUG_STATUS_STEP_OVER = 4
DEBUG_STATUS_STEP_INTO = 5
DEBUG_STATUS_BREAK = 6
DEBUG_STATUS_NO_DEBUGGEE = 7
DEBUG_STATUS_STEP_BRANCH = 8
DEBUG_STATUS_IGNORE = 9
DEBUG_STATUS_RESTART_REQUESTED = 10

# Breakpoint types
DEBUG_BREAKPOINT_CODE = 0
DEBUG_BREAKPOINT_DATA = 1
DEBUG_ANY_ID = 0xFFFFFFFF

# Breakpoint flags
DEBUG_BREAKPOINT_ENABLED = 4
DEBUG_BREAKPOINT_GO_ONLY = 1
DEBUG_BREAKPOINT_DEFERRED = 2

# Data breakpoint access types
DEBUG_BREAK_READ = 1
DEBUG_BREAK_WRITE = 2
DEBUG_BREAK_EXECUTE = 4
DEBUG_BREAK_IO = 8

# EndSession flags
DEBUG_END_PASSIVE = 0
DEBUG_END_ACTIVE_TERMINATE = 1
DEBUG_END_ACTIVE_DETACH = 2
DEBUG_END_REENTRANT = 3
DEBUG_END_DISCONNECT = 4

# Debuggee class
DEBUG_CLASS_UNINITIALIZED = 0
DEBUG_CLASS_KERNEL = 1
DEBUG_CLASS_USER_WINDOWS = 2
DEBUG_CLASS_IMAGE_FILE = 3

# Value types
DEBUG_VALUE_INVALID = 0
DEBUG_VALUE_INT8 = 1
DEBUG_VALUE_INT16 = 2
DEBUG_VALUE_INT32 = 3
DEBUG_VALUE_INT64 = 4
DEBUG_VALUE_FLOAT32 = 5
DEBUG_VALUE_FLOAT64 = 6
DEBUG_VALUE_FLOAT80 = 7
DEBUG_VALUE_FLOAT128 = 8

# Symbol options
SYMOPT_CASE_INSENSITIVE = 0x1
SYMOPT_UNDNAME = 0x2
SYMOPT_DEFERRED_LOADS = 0x4
SYMOPT_LOAD_LINES = 0x10
SYMOPT_DEBUG = 0x80000000

# Module name types (GetModuleNameString)
DEBUG_MODNAME_IMAGE = 0
DEBUG_MODNAME_MODULE = 1
DEBUG_MODNAME_LOADED_IMAGE = 2
DEBUG_MODNAME_SYMBOL_FILE = 3
DEBUG_MODNAME_MAPPED_IMAGE = 4

# Output mask
DEBUG_OUTPUT_NORMAL = 1
DEBUG_OUTPUT_ERROR = 2
DEBUG_OUTPUT_WARNING = 4
DEBUG_OUTPUT_VERBOSE = 8
DEBUG_OUTPUT_PROMPT = 16

# Engine options
DEBUG_ENGOPT_INITIAL_BREAK = 0x20
DEBUG_ENGOPT_INITIAL_MODULE_BREAK = 0x04

# Disassemble flags
DEBUG_DISASM_EFFECTIVE_ADDRESS = 1
DEBUG_DISASM_MATCHING_SYMBOLS = 2
DEBUG_DISASM_SOURCE_LINE_NUMBER = 4
DEBUG_DISASM_SOURCE_FILE_NAME = 8

# Event types (GetLastEventInformation)
DEBUG_EVENT_BREAKPOINT = 0x1
DEBUG_EVENT_EXCEPTION = 0x2
DEBUG_EVENT_CREATE_THREAD = 0x4
DEBUG_EVENT_EXIT_THREAD = 0x8
DEBUG_EVENT_CREATE_PROCESS = 0x10
DEBUG_EVENT_EXIT_PROCESS = 0x20
DEBUG_EVENT_LOAD_MODULE = 0x40
DEBUG_EVENT_UNLOAD_MODULE = 0x80
DEBUG_EVENT_SYSTEM_ERROR = 0x100

# Filter handling options
DEBUG_FILTER_BREAK = 0
DEBUG_FILTER_SECOND_CHANCE_BREAK = 1
DEBUG_FILTER_OUTPUT = 2
DEBUG_FILTER_IGNORE = 3
DEBUG_FILTER_REMOVE = 4

# ──────────────────────────────────────────────────────────────────────
# GUID
# ──────────────────────────────────────────────────────────────────────
class GUID(Structure):
    _fields_ = [
        ("Data1", c_ulong),
        ("Data2", c_ushort),
        ("Data3", c_ushort),
        ("Data4", c_ubyte * 8),
    ]

def _guid(s: str) -> GUID:
    """Parse '{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}' to GUID struct."""
    s = s.strip("{}")
    p = s.split("-")
    g = GUID()
    g.Data1 = int(p[0], 16)
    g.Data2 = int(p[1], 16)
    g.Data3 = int(p[2], 16)
    d4 = bytes.fromhex(p[3] + p[4])
    for i in range(8):
        g.Data4[i] = d4[i]
    return g

# Interface IIDs
IID_IUnknown             = _guid("{00000000-0000-0000-C000-000000000046}")
IID_IDebugClient         = _guid("{27fe5639-8407-4f47-8364-ee118fb08ac8}")
IID_IDebugClient2        = _guid("{edbed635-372e-4dab-bbfe-ed0d2f63be81}")
IID_IDebugClient3        = _guid("{dd492d7f-71b8-4ad6-a8dc-1c887479ff91}")
IID_IDebugClient4        = _guid("{ca83c3de-5089-4cf8-93c8-d892387f2a5e}")
IID_IDebugClient5        = _guid("{e3acb9d7-7ec2-4f0c-a0da-e81e0cbbe628}")
IID_IDebugControl        = _guid("{5182e668-105e-416e-ad92-24ef800424ba}")
IID_IDebugDataSpaces     = _guid("{88f7dfab-3ea7-4c3a-aefb-c4e8106173aa}")
IID_IDebugDataSpaces2    = _guid("{7a5e852f-96e9-468f-ac1b-0b3addc4a049}")
IID_IDebugRegisters      = _guid("{ce289126-9e84-45a7-937e-67bb18691493}")
IID_IDebugSymbols        = _guid("{8c31e98c-983a-48a5-9016-6fe5d667a950}")
IID_IDebugSymbols2       = _guid("{3a707211-afdd-4495-ad4f-56fecdf8163f}")
IID_IDebugSystemObjects  = _guid("{6b86fe2c-2c4f-4f0c-9da2-174311acc327}")
IID_IDebugBreakpoint     = _guid("{5bd9d474-5975-423a-b88b-65a8e7110e65}")

# ──────────────────────────────────────────────────────────────────────
# Structures
# ──────────────────────────────────────────────────────────────────────

class _DEBUG_VALUE_U(Union):
    _fields_ = [
        ("I8",  c_ubyte),
        ("I16", c_ushort),
        ("I32", c_ulong),
        ("I64", c_ulonglong),
        ("F32", c_float),
        ("F64", c_double),
        ("RawBytes", c_ubyte * 24),
    ]

class DEBUG_VALUE(Structure):
    _anonymous_ = ("_u",)
    _fields_ = [
        ("_u",             _DEBUG_VALUE_U),
        ("TailOfRawBytes", c_ulong),
        ("Type",           c_ulong),
    ]

class DEBUG_STACK_FRAME(Structure):
    _fields_ = [
        ("InstructionOffset", c_ulonglong),
        ("ReturnOffset",      c_ulonglong),
        ("FrameOffset",       c_ulonglong),
        ("StackOffset",       c_ulonglong),
        ("FuncTableEntry",    c_ulonglong),
        ("Params",            c_ulonglong * 4),
        ("Reserved",          c_ulonglong * 6),
        ("Virtual",           c_int),
        ("FrameNumber",       c_ulong),
    ]

class DEBUG_BREAKPOINT_PARAMETERS(Structure):
    _fields_ = [
        ("Offset",               c_ulonglong),
        ("Id",                   c_ulong),
        ("BreakType",            c_ulong),
        ("ProcType",             c_ulong),
        ("Flags",                c_ulong),
        ("DataSize",             c_ulong),
        ("DataAccessType",       c_ulong),
        ("PassCount",            c_ulong),
        ("CurrentPassCount",     c_ulong),
        ("MatchThread",          c_ulong),
        ("CommandSize",          c_ulong),
        ("OffsetExpressionSize", c_ulong),
    ]

class DEBUG_MODULE_PARAMETERS(Structure):
    _fields_ = [
        ("Base",                c_ulonglong),
        ("Size",                c_ulong),
        ("TimeDateStamp",       c_ulong),
        ("Checksum",            c_ulong),
        ("Flags",               c_ulong),
        ("SymbolType",          c_ulong),
        ("ImageNameSize",       c_ulong),
        ("ModuleNameSize",      c_ulong),
        ("LoadedImageNameSize", c_ulong),
        ("SymbolFileNameSize",  c_ulong),
        ("MappedImageNameSize", c_ulong),
        ("Reserved",            c_ulonglong * 2),
    ]

class DEBUG_REGISTER_DESCRIPTION(Structure):
    _fields_ = [
        ("Type",         c_ulong),
        ("Flags",        c_ulong),
        ("SubregMaster", c_ulong),
        ("SubregLength", c_ulong),
        ("SubregMask",   c_ulonglong),
        ("SubregShift",  c_ulong),
        ("Reserved0",    c_ulong),
    ]

class DEBUG_EXCEPTION_FILTER_PARAMETERS(Structure):
    _fields_ = [
        ("ExecutionOption",  c_ulong),
        ("ContinueOption",   c_ulong),
        ("TextSize",         c_ulong),
        ("CommandSize",      c_ulong),
        ("SecondCommandSize", c_ulong),
        ("ExceptionCode",    c_ulong),
    ]

# ──────────────────────────────────────────────────────────────────────
# Error handling
# ──────────────────────────────────────────────────────────────────────

class DbgEngError(Exception):
    """COM HRESULT error from DbgEng."""
    def __init__(self, hr: int, method: str = ""):
        self.hr = hr
        unsigned = hr & 0xFFFFFFFF
        prefix = f"{method}: " if method else ""
        super().__init__(f"{prefix}HRESULT 0x{unsigned:08X}")

def check_hr(hr: int, method: str = "") -> int:
    """Raise DbgEngError if hr indicates failure (negative HRESULT)."""
    if hr < 0:
        raise DbgEngError(hr, method)
    return hr

# ──────────────────────────────────────────────────────────────────────
# ComPtr — base class for COM interface wrappers
# ──────────────────────────────────────────────────────────────────────

class ComPtr:
    """Wrapper around a raw COM interface pointer with vtable slot access."""

    def __init__(self, ptr: c_void_p):
        if not ptr:
            raise ValueError("NULL COM pointer")
        self._ptr = ptr

    def _call(self, slot: int, argtypes: list, *args):
        """Call vtable[slot](this, *args). Returns raw HRESULT (c_long)."""
        functype = WINFUNCTYPE(HRESULT, c_void_p, *argtypes)
        vtbl = ctypes.cast(self._ptr, POINTER(c_void_p))[0]
        fn = functype(ctypes.cast(vtbl, POINTER(c_void_p))[slot])
        return fn(self._ptr, *args)

    def query_interface(self, iid: GUID) -> c_void_p:
        """IUnknown::QueryInterface (slot 0)."""
        out = c_void_p()
        hr = self._call(0, [POINTER(GUID), POINTER(c_void_p)],
                        byref(iid), byref(out))
        check_hr(hr, "QueryInterface")
        return out

    def add_ref(self) -> int:
        """IUnknown::AddRef (slot 1)."""
        functype = WINFUNCTYPE(c_ulong, c_void_p)
        vtbl = ctypes.cast(self._ptr, POINTER(c_void_p))[0]
        fn = functype(ctypes.cast(vtbl, POINTER(c_void_p))[1])
        return fn(self._ptr)

    def release(self) -> int:
        """IUnknown::Release (slot 2)."""
        functype = WINFUNCTYPE(c_ulong, c_void_p)
        vtbl = ctypes.cast(self._ptr, POINTER(c_void_p))[0]
        fn = functype(ctypes.cast(vtbl, POINTER(c_void_p))[2])
        return fn(self._ptr)


# ══════════════════════════════════════════════════════════════════════
# IDebugClient
# ══════════════════════════════════════════════════════════════════════

class DebugClient(ComPtr):
    """IDebugClient — session management, kernel attach, callbacks."""

    def AttachKernel(self, connect_options: bytes):
        """Slot 3: AttachKernel(ULONG Flags, PCSTR ConnectOptions)"""
        hr = self._call(3, [c_ulong, c_char_p],
                        c_ulong(DEBUG_ATTACH_KERNEL_CONNECTION), connect_options)
        check_hr(hr, "AttachKernel")

    def AttachKernelWide(self, connect_options: str):
        """Slot 66 (IDebugClient5): AttachKernelWide(ULONG Flags, PCWSTR ConnectOptions).

        kd.exe uses this Wide variant internally after QI-ing for
        IDebugClient5. Some dbgeng builds appear to stub the ANSI
        AttachKernel (returns S_OK but silently no-ops), while the
        Wide variant actually initializes the kdnet session.
        """
        from ctypes import c_wchar_p
        hr = self._call(66, [c_ulong, c_wchar_p],
                        c_ulong(DEBUG_ATTACH_KERNEL_CONNECTION), connect_options)
        check_hr(hr, "AttachKernelWide")

    def DetachProcesses(self):
        """Slot 25: DetachProcesses()"""
        hr = self._call(25, [])
        check_hr(hr, "DetachProcesses")

    def EndSession(self, flags: int = DEBUG_END_ACTIVE_DETACH):
        """Slot 26: EndSession(ULONG Flags)"""
        hr = self._call(26, [c_ulong], c_ulong(flags))
        check_hr(hr, "EndSession")

    def SetOutputCallbacks(self, callbacks: c_void_p):
        """Slot 34: SetOutputCallbacks(IDebugOutputCallbacks*)"""
        hr = self._call(34, [c_void_p], callbacks)
        check_hr(hr, "SetOutputCallbacks")

    def SetEventCallbacks(self, callbacks: c_void_p):
        """Slot 46: SetEventCallbacks(IDebugEventCallbacks*)"""
        hr = self._call(46, [c_void_p], callbacks)
        check_hr(hr, "SetEventCallbacks")


# ══════════════════════════════════════════════════════════════════════
# IDebugControl
# ══════════════════════════════════════════════════════════════════════

class DebugControl(ComPtr):
    """IDebugControl — execution control, commands, breakpoints."""

    def GetInterrupt(self):
        """Slot 3: GetInterrupt() -> S_OK if interrupt pending."""
        return self._call(3, [])

    def SetInterrupt(self, flags: int = DEBUG_INTERRUPT_ACTIVE):
        """Slot 4: SetInterrupt(ULONG Flags)"""
        hr = self._call(4, [c_ulong], c_ulong(flags))
        check_hr(hr, "SetInterrupt")

    def Disassemble(self, offset: int, flags: int = 0,
                    buf_size: int = 1024) -> tuple[str, int]:
        """Slot 26: Disassemble(...) -> (text, end_offset)"""
        buf = ctypes.create_string_buffer(buf_size)
        size = c_ulong()
        end = c_ulonglong()
        hr = self._call(26, [c_ulonglong, c_ulong, c_char_p, c_ulong,
                             PULONG, PULONG64],
                        c_ulonglong(offset), c_ulong(flags),
                        buf, c_ulong(buf_size), byref(size), byref(end))
        check_hr(hr, "Disassemble")
        return buf.value.decode("utf-8", errors="replace"), end.value

    def GetStackTrace(self, max_frames: int = 50) -> list[DEBUG_STACK_FRAME]:
        """Slot 31: GetStackTrace(...) -> list of stack frames"""
        frames = (DEBUG_STACK_FRAME * max_frames)()
        filled = c_ulong()
        hr = self._call(31, [c_ulonglong, c_ulonglong, c_ulonglong,
                             POINTER(DEBUG_STACK_FRAME), c_ulong, PULONG],
                        c_ulonglong(0), c_ulonglong(0), c_ulonglong(0),
                        frames, c_ulong(max_frames), byref(filled))
        check_hr(hr, "GetStackTrace")
        return list(frames[:filled.value])

    def GetDebuggeeType(self) -> tuple[int, int]:
        """Slot 34: GetDebuggeeType(PULONG Class, PULONG Qualifier)"""
        cls = c_ulong()
        qual = c_ulong()
        hr = self._call(34, [PULONG, PULONG], byref(cls), byref(qual))
        check_hr(hr, "GetDebuggeeType")
        return cls.value, qual.value

    def GetNumberProcessors(self) -> int:
        """Slot 39: GetNumberProcessors(PULONG Number)"""
        num = c_ulong()
        hr = self._call(39, [PULONG], byref(num))
        check_hr(hr, "GetNumberProcessors")
        return num.value

    def GetPageSize(self) -> int:
        """Slot 41: GetPageSize(PULONG Size)"""
        size = c_ulong()
        hr = self._call(41, [PULONG], byref(size))
        check_hr(hr, "GetPageSize")
        return size.value

    def GetExecutionStatus(self) -> int:
        """Slot 49: GetExecutionStatus(PULONG Status)"""
        status = c_ulong()
        hr = self._call(49, [PULONG], byref(status))
        check_hr(hr, "GetExecutionStatus")
        return status.value

    def SetExecutionStatus(self, status: int):
        """Slot 50: SetExecutionStatus(ULONG Status)"""
        hr = self._call(50, [c_ulong], c_ulong(status))
        check_hr(hr, "SetExecutionStatus")

    def AddEngineOptions(self, options: int):
        """Slot 54: AddEngineOptions(ULONG Options)"""
        hr = self._call(54, [c_ulong], c_ulong(options))
        check_hr(hr, "AddEngineOptions")

    def Evaluate(self, expression: bytes, desired_type: int = DEBUG_VALUE_INT64) -> int:
        """Slot 63: Evaluate(...) -> numeric value"""
        val = DEBUG_VALUE()
        remainder = c_ulong()
        hr = self._call(63, [c_char_p, c_ulong, POINTER(DEBUG_VALUE), PULONG],
                        expression, c_ulong(desired_type),
                        byref(val), byref(remainder))
        check_hr(hr, "Evaluate")
        return val.I64

    def Execute(self, command: bytes, output_control: int = DEBUG_OUTCTL_THIS_CLIENT,
                flags: int = DEBUG_EXECUTE_DEFAULT):
        """Slot 66: Execute(ULONG OutputControl, PCSTR Command, ULONG Flags)"""
        hr = self._call(66, [c_ulong, c_char_p, c_ulong],
                        c_ulong(output_control), command, c_ulong(flags))
        check_hr(hr, "Execute")

    def GetNumberBreakpoints(self) -> int:
        """Slot 68: GetNumberBreakpoints(PULONG Number)"""
        num = c_ulong()
        hr = self._call(68, [PULONG], byref(num))
        check_hr(hr, "GetNumberBreakpoints")
        return num.value

    def GetBreakpointByIndex(self, index: int) -> c_void_p:
        """Slot 69: GetBreakpointByIndex(ULONG Index, IDebugBreakpoint**)"""
        bp = c_void_p()
        hr = self._call(69, [c_ulong, POINTER(c_void_p)],
                        c_ulong(index), byref(bp))
        check_hr(hr, "GetBreakpointByIndex")
        return bp

    def GetBreakpointById(self, bp_id: int) -> c_void_p:
        """Slot 70: GetBreakpointById(ULONG Id, IDebugBreakpoint**)"""
        bp = c_void_p()
        hr = self._call(70, [c_ulong, POINTER(c_void_p)],
                        c_ulong(bp_id), byref(bp))
        check_hr(hr, "GetBreakpointById")
        return bp

    def AddBreakpoint(self, bp_type: int = DEBUG_BREAKPOINT_CODE,
                      desired_id: int = DEBUG_ANY_ID) -> c_void_p:
        """Slot 72: AddBreakpoint(ULONG Type, ULONG DesiredId, IDebugBreakpoint**)"""
        bp = c_void_p()
        hr = self._call(72, [c_ulong, c_ulong, POINTER(c_void_p)],
                        c_ulong(bp_type), c_ulong(desired_id), byref(bp))
        check_hr(hr, "AddBreakpoint")
        return bp

    def RemoveBreakpoint(self, bp_ptr: c_void_p):
        """Slot 73: RemoveBreakpoint(IDebugBreakpoint*)"""
        hr = self._call(73, [c_void_p], bp_ptr)
        check_hr(hr, "RemoveBreakpoint")

    def GetNumberEventFilters(self) -> tuple[int, int, int]:
        """Slot 81: GetNumberEventFilters(PULONG, PULONG, PULONG)"""
        specific = c_ulong()
        exceptions = c_ulong()
        arbitrary = c_ulong()
        hr = self._call(81, [PULONG, PULONG, PULONG],
                        byref(specific), byref(exceptions), byref(arbitrary))
        check_hr(hr, "GetNumberEventFilters")
        return specific.value, exceptions.value, arbitrary.value

    def SetExceptionFilterParameters(self, params: list[DEBUG_EXCEPTION_FILTER_PARAMETERS]):
        """Slot 90: SetExceptionFilterParameters(ULONG Count, params*)"""
        count = len(params)
        arr = (DEBUG_EXCEPTION_FILTER_PARAMETERS * count)(*params)
        hr = self._call(90, [c_ulong, POINTER(DEBUG_EXCEPTION_FILTER_PARAMETERS)],
                        c_ulong(count), arr)
        check_hr(hr, "SetExceptionFilterParameters")

    def WaitForEvent(self, timeout_ms: int = INFINITE) -> int:
        """Slot 93: WaitForEvent(ULONG Flags=0, ULONG Timeout) -> HRESULT
        Returns S_OK on event, S_FALSE on timeout."""
        return self._call(93, [c_ulong, c_ulong],
                          c_ulong(0), c_ulong(timeout_ms))

    def GetLastEventInformation(self) -> dict:
        """Slot 94: GetLastEventInformation(...) -> event info dict"""
        etype = c_ulong()
        pid = c_ulong()
        tid = c_ulong()
        extra = ctypes.create_string_buffer(256)
        extra_used = c_ulong()
        desc = ctypes.create_string_buffer(256)
        desc_used = c_ulong()
        hr = self._call(94, [PULONG, PULONG, PULONG,
                             c_void_p, c_ulong, PULONG,
                             c_char_p, c_ulong, PULONG],
                        byref(etype), byref(pid), byref(tid),
                        extra, c_ulong(256), byref(extra_used),
                        desc, c_ulong(256), byref(desc_used))
        check_hr(hr, "GetLastEventInformation")
        return {
            "type": etype.value,
            "process_id": pid.value,
            "thread_id": tid.value,
            "description": desc.value.decode("utf-8", errors="replace"),
        }


# ══════════════════════════════════════════════════════════════════════
# IDebugDataSpaces / IDebugDataSpaces2
# ══════════════════════════════════════════════════════════════════════

class DebugDataSpaces(ComPtr):
    """IDebugDataSpaces2 — memory read/write/search, MSR, VA→PA."""

    def ReadVirtual(self, offset: int, size: int) -> bytes:
        """Slot 3: ReadVirtual(ULONG64, PVOID, ULONG, PULONG)"""
        buf = ctypes.create_string_buffer(size)
        read = c_ulong()
        hr = self._call(3, [c_ulonglong, c_void_p, c_ulong, PULONG],
                        c_ulonglong(offset), buf, c_ulong(size), byref(read))
        check_hr(hr, "ReadVirtual")
        return buf.raw[:read.value]

    def WriteVirtual(self, offset: int, data: bytes) -> int:
        """Slot 4: WriteVirtual(ULONG64, PVOID, ULONG, PULONG)"""
        written = c_ulong()
        hr = self._call(4, [c_ulonglong, c_void_p, c_ulong, PULONG],
                        c_ulonglong(offset), data, c_ulong(len(data)),
                        byref(written))
        check_hr(hr, "WriteVirtual")
        return written.value

    def SearchVirtual(self, offset: int, length: int,
                      pattern: bytes, granularity: int = 1) -> int:
        """Slot 5: SearchVirtual(...) -> match offset"""
        match = c_ulonglong()
        hr = self._call(5, [c_ulonglong, c_ulonglong, c_void_p,
                            c_ulong, c_ulong, PULONG64],
                        c_ulonglong(offset), c_ulonglong(length),
                        pattern, c_ulong(len(pattern)),
                        c_ulong(granularity), byref(match))
        check_hr(hr, "SearchVirtual")
        return match.value

    def ReadPhysical(self, offset: int, size: int) -> bytes:
        """Slot 10: ReadPhysical(ULONG64, PVOID, ULONG, PULONG)"""
        buf = ctypes.create_string_buffer(size)
        read = c_ulong()
        hr = self._call(10, [c_ulonglong, c_void_p, c_ulong, PULONG],
                        c_ulonglong(offset), buf, c_ulong(size), byref(read))
        check_hr(hr, "ReadPhysical")
        return buf.raw[:read.value]

    def WritePhysical(self, offset: int, data: bytes) -> int:
        """Slot 11: WritePhysical(ULONG64, PVOID, ULONG, PULONG)"""
        written = c_ulong()
        hr = self._call(11, [c_ulonglong, c_void_p, c_ulong, PULONG],
                        c_ulonglong(offset), data, c_ulong(len(data)),
                        byref(written))
        check_hr(hr, "WritePhysical")
        return written.value

    def ReadMsr(self, msr: int) -> int:
        """Slot 16: ReadMsr(ULONG Msr, PULONG64 Value)"""
        val = c_ulonglong()
        hr = self._call(16, [c_ulong, PULONG64],
                        c_ulong(msr), byref(val))
        check_hr(hr, "ReadMsr")
        return val.value

    def VirtualToPhysical(self, virtual: int) -> int:
        """Slot 23 (IDebugDataSpaces2): VirtualToPhysical(ULONG64, PULONG64)"""
        physical = c_ulonglong()
        hr = self._call(23, [c_ulonglong, PULONG64],
                        c_ulonglong(virtual), byref(physical))
        check_hr(hr, "VirtualToPhysical")
        return physical.value


# ══════════════════════════════════════════════════════════════════════
# IDebugRegisters
# ══════════════════════════════════════════════════════════════════════

class DebugRegisters(ComPtr):
    """IDebugRegisters — register read/write."""

    def GetNumberRegisters(self) -> int:
        """Slot 3"""
        num = c_ulong()
        hr = self._call(3, [PULONG], byref(num))
        check_hr(hr, "GetNumberRegisters")
        return num.value

    def GetDescription(self, index: int) -> tuple[str, DEBUG_REGISTER_DESCRIPTION]:
        """Slot 4: GetDescription(ULONG, PSTR, ULONG, PULONG, DESC*)"""
        buf = ctypes.create_string_buffer(64)
        name_size = c_ulong()
        desc = DEBUG_REGISTER_DESCRIPTION()
        hr = self._call(4, [c_ulong, c_char_p, c_ulong, PULONG,
                            POINTER(DEBUG_REGISTER_DESCRIPTION)],
                        c_ulong(index), buf, c_ulong(64),
                        byref(name_size), byref(desc))
        check_hr(hr, "GetDescription")
        return buf.value.decode("utf-8", errors="replace"), desc

    def GetIndexByName(self, name: bytes) -> int:
        """Slot 5: GetIndexByName(PCSTR, PULONG)"""
        idx = c_ulong()
        hr = self._call(5, [c_char_p, PULONG], name, byref(idx))
        check_hr(hr, "GetIndexByName")
        return idx.value

    def GetValue(self, index: int) -> DEBUG_VALUE:
        """Slot 6: GetValue(ULONG, PDEBUG_VALUE)"""
        val = DEBUG_VALUE()
        hr = self._call(6, [c_ulong, POINTER(DEBUG_VALUE)],
                        c_ulong(index), byref(val))
        check_hr(hr, "GetValue")
        return val

    def SetValue(self, index: int, value: DEBUG_VALUE):
        """Slot 7: SetValue(ULONG, PDEBUG_VALUE)"""
        hr = self._call(7, [c_ulong, POINTER(DEBUG_VALUE)],
                        c_ulong(index), byref(value))
        check_hr(hr, "SetValue")


# ══════════════════════════════════════════════════════════════════════
# IDebugSymbols / IDebugSymbols2
# ══════════════════════════════════════════════════════════════════════

class DebugSymbols(ComPtr):
    """IDebugSymbols2 — symbol resolution, module info, type info."""

    def AddSymbolOptions(self, options: int):
        """Slot 4: AddSymbolOptions(ULONG)"""
        hr = self._call(4, [c_ulong], c_ulong(options))
        check_hr(hr, "AddSymbolOptions")

    def GetNameByOffset(self, offset: int) -> tuple[str, int]:
        """Slot 7: GetNameByOffset(...) -> (name, displacement)"""
        buf = ctypes.create_string_buffer(512)
        name_size = c_ulong()
        disp = c_ulonglong()
        hr = self._call(7, [c_ulonglong, c_char_p, c_ulong, PULONG, PULONG64],
                        c_ulonglong(offset), buf, c_ulong(512),
                        byref(name_size), byref(disp))
        check_hr(hr, "GetNameByOffset")
        return buf.value.decode("utf-8", errors="replace"), disp.value

    def GetOffsetByName(self, symbol: bytes) -> int:
        """Slot 8: GetOffsetByName(PCSTR, PULONG64)"""
        offset = c_ulonglong()
        hr = self._call(8, [c_char_p, PULONG64], symbol, byref(offset))
        check_hr(hr, "GetOffsetByName")
        return offset.value

    def GetNumberModules(self) -> tuple[int, int]:
        """Slot 12: GetNumberModules(PULONG Loaded, PULONG Unloaded)"""
        loaded = c_ulong()
        unloaded = c_ulong()
        hr = self._call(12, [PULONG, PULONG], byref(loaded), byref(unloaded))
        check_hr(hr, "GetNumberModules")
        return loaded.value, unloaded.value

    def GetModuleByIndex(self, index: int) -> int:
        """Slot 13: GetModuleByIndex(ULONG, PULONG64) -> base address"""
        base = c_ulonglong()
        hr = self._call(13, [c_ulong, PULONG64],
                        c_ulong(index), byref(base))
        check_hr(hr, "GetModuleByIndex")
        return base.value

    def GetModuleByModuleName(self, name: bytes, start: int = 0) -> tuple[int, int]:
        """Slot 14: GetModuleByModuleName(...) -> (index, base)"""
        idx = c_ulong()
        base = c_ulonglong()
        hr = self._call(14, [c_char_p, c_ulong, PULONG, PULONG64],
                        name, c_ulong(start), byref(idx), byref(base))
        check_hr(hr, "GetModuleByModuleName")
        return idx.value, base.value

    def GetModuleParameters(self, bases: list[int]) -> list[DEBUG_MODULE_PARAMETERS]:
        """Slot 17: GetModuleParameters(Count, Bases*, Start, Params*)"""
        count = len(bases)
        bases_arr = (c_ulonglong * count)(*bases)
        params = (DEBUG_MODULE_PARAMETERS * count)()
        hr = self._call(17, [c_ulong, POINTER(c_ulonglong), c_ulong,
                             POINTER(DEBUG_MODULE_PARAMETERS)],
                        c_ulong(count), bases_arr, c_ulong(0), params)
        check_hr(hr, "GetModuleParameters")
        return list(params)

    def GetTypeId(self, module: int, name: bytes) -> int:
        """Slot 20: GetTypeId(ULONG64 Module, PCSTR Name, PULONG TypeId)"""
        tid = c_ulong()
        hr = self._call(20, [c_ulonglong, c_char_p, PULONG],
                        c_ulonglong(module), name, byref(tid))
        check_hr(hr, "GetTypeId")
        return tid.value

    def GetTypeSize(self, module: int, type_id: int) -> int:
        """Slot 21: GetTypeSize(ULONG64 Module, ULONG TypeId, PULONG Size)"""
        size = c_ulong()
        hr = self._call(21, [c_ulonglong, c_ulong, PULONG],
                        c_ulonglong(module), c_ulong(type_id), byref(size))
        check_hr(hr, "GetTypeSize")
        return size.value

    def GetFieldOffset(self, module: int, type_id: int, field: bytes) -> int:
        """Slot 22: GetFieldOffset(ULONG64, ULONG, PCSTR, PULONG)"""
        offset = c_ulong()
        hr = self._call(22, [c_ulonglong, c_ulong, c_char_p, PULONG],
                        c_ulonglong(module), c_ulong(type_id),
                        field, byref(offset))
        check_hr(hr, "GetFieldOffset")
        return offset.value

    def Reload(self, module: bytes = b""):
        """Slot 39: Reload(PCSTR Module)"""
        hr = self._call(39, [c_char_p], module)
        check_hr(hr, "Reload")

    def GetSymbolPath(self) -> str:
        """Slot 40: GetSymbolPath(PSTR, ULONG, PULONG)"""
        buf = ctypes.create_string_buffer(1024)
        size = c_ulong()
        hr = self._call(40, [c_char_p, c_ulong, PULONG],
                        buf, c_ulong(1024), byref(size))
        check_hr(hr, "GetSymbolPath")
        return buf.value.decode("utf-8", errors="replace")

    def SetSymbolPath(self, path: bytes):
        """Slot 41: SetSymbolPath(PCSTR Path)"""
        hr = self._call(41, [c_char_p], path)
        check_hr(hr, "SetSymbolPath")

    def GetModuleNameString(self, which: int, index: int, base: int) -> str:
        """Slot 53 (IDebugSymbols2): GetModuleNameString(...)"""
        buf = ctypes.create_string_buffer(512)
        size = c_ulong()
        hr = self._call(53, [c_ulong, c_ulong, c_ulonglong,
                             c_char_p, c_ulong, PULONG],
                        c_ulong(which), c_ulong(index),
                        c_ulonglong(base), buf, c_ulong(512), byref(size))
        check_hr(hr, "GetModuleNameString")
        return buf.value.decode("utf-8", errors="replace")


# ══════════════════════════════════════════════════════════════════════
# IDebugSystemObjects
# ══════════════════════════════════════════════════════════════════════

class DebugSystemObjects(ComPtr):
    """IDebugSystemObjects — threads and processes."""

    def GetCurrentThreadId(self) -> int:
        """Slot 5"""
        tid = c_ulong()
        hr = self._call(5, [PULONG], byref(tid))
        check_hr(hr, "GetCurrentThreadId")
        return tid.value

    def SetCurrentThreadId(self, tid: int):
        """Slot 6"""
        hr = self._call(6, [c_ulong], c_ulong(tid))
        check_hr(hr, "SetCurrentThreadId")

    def GetCurrentProcessId(self) -> int:
        """Slot 7"""
        pid = c_ulong()
        hr = self._call(7, [PULONG], byref(pid))
        check_hr(hr, "GetCurrentProcessId")
        return pid.value

    def SetCurrentProcessId(self, pid: int):
        """Slot 8"""
        hr = self._call(8, [c_ulong], c_ulong(pid))
        check_hr(hr, "SetCurrentProcessId")

    def GetNumberThreads(self) -> int:
        """Slot 9"""
        num = c_ulong()
        hr = self._call(9, [PULONG], byref(num))
        check_hr(hr, "GetNumberThreads")
        return num.value

    def GetThreadIdsByIndex(self, start: int, count: int) -> tuple[list[int], list[int]]:
        """Slot 11: GetThreadIdsByIndex(Start, Count, EngineIds*, SysIds*)"""
        ids = (c_ulong * count)()
        sys_ids = (c_ulong * count)()
        hr = self._call(11, [c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong)],
                        c_ulong(start), c_ulong(count), ids, sys_ids)
        check_hr(hr, "GetThreadIdsByIndex")
        return list(ids), list(sys_ids)

    def GetCurrentThreadDataOffset(self) -> int:
        """Slot 13: GetCurrentThreadDataOffset(PULONG64) -> ETHREAD/TEB address"""
        offset = c_ulonglong()
        hr = self._call(13, [PULONG64], byref(offset))
        check_hr(hr, "GetCurrentThreadDataOffset")
        return offset.value

    def GetThreadIdByDataOffset(self, offset: int) -> int:
        """Slot 14"""
        tid = c_ulong()
        hr = self._call(14, [c_ulonglong, PULONG],
                        c_ulonglong(offset), byref(tid))
        check_hr(hr, "GetThreadIdByDataOffset")
        return tid.value

    def GetNumberProcesses(self) -> int:
        """Slot 21"""
        num = c_ulong()
        hr = self._call(21, [PULONG], byref(num))
        check_hr(hr, "GetNumberProcesses")
        return num.value

    def GetProcessIdsByIndex(self, start: int, count: int) -> tuple[list[int], list[int]]:
        """Slot 22: GetProcessIdsByIndex(Start, Count, EngineIds*, SysIds*)"""
        ids = (c_ulong * count)()
        sys_ids = (c_ulong * count)()
        hr = self._call(22, [c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong)],
                        c_ulong(start), c_ulong(count), ids, sys_ids)
        check_hr(hr, "GetProcessIdsByIndex")
        return list(ids), list(sys_ids)

    def GetCurrentProcessDataOffset(self) -> int:
        """Slot 23: GetCurrentProcessDataOffset(PULONG64) -> EPROCESS/PEB address"""
        offset = c_ulonglong()
        hr = self._call(23, [PULONG64], byref(offset))
        check_hr(hr, "GetCurrentProcessDataOffset")
        return offset.value

    def GetProcessIdByDataOffset(self, offset: int) -> int:
        """Slot 24"""
        pid = c_ulong()
        hr = self._call(24, [c_ulonglong, PULONG],
                        c_ulonglong(offset), byref(pid))
        check_hr(hr, "GetProcessIdByDataOffset")
        return pid.value

    def GetCurrentThreadSystemId(self) -> int:
        """Slot 17: GetCurrentThreadSystemId(PULONG SysId) -> OS thread id"""
        sid = c_ulong()
        hr = self._call(17, [PULONG], byref(sid))
        check_hr(hr, "GetCurrentThreadSystemId")
        return sid.value

    def GetCurrentProcessSystemId(self) -> int:
        """Slot 27: GetCurrentProcessSystemId(PULONG SysId) -> OS pid"""
        sid = c_ulong()
        hr = self._call(27, [PULONG], byref(sid))
        check_hr(hr, "GetCurrentProcessSystemId")
        return sid.value

    def GetCurrentProcessExecutableName(self) -> str:
        """Slot 31: GetCurrentProcessExecutableName(PSTR, ULONG, PULONG)"""
        buf = ctypes.create_string_buffer(512)
        size = c_ulong()
        hr = self._call(31, [c_char_p, c_ulong, PULONG],
                        buf, c_ulong(512), byref(size))
        check_hr(hr, "GetCurrentProcessExecutableName")
        return buf.value.decode("utf-8", errors="replace")


# ══════════════════════════════════════════════════════════════════════
# IDebugBreakpoint
# ══════════════════════════════════════════════════════════════════════

class DebugBreakpoint(ComPtr):
    """IDebugBreakpoint — individual breakpoint control."""

    def GetId(self) -> int:
        """Slot 3"""
        bp_id = c_ulong()
        hr = self._call(3, [PULONG], byref(bp_id))
        check_hr(hr, "GetId")
        return bp_id.value

    def GetType(self) -> tuple[int, int]:
        """Slot 4: GetType(PULONG BreakType, PULONG ProcType)"""
        btype = c_ulong()
        ptype = c_ulong()
        hr = self._call(4, [PULONG, PULONG], byref(btype), byref(ptype))
        check_hr(hr, "GetType")
        return btype.value, ptype.value

    def GetFlags(self) -> int:
        """Slot 6"""
        flags = c_ulong()
        hr = self._call(6, [PULONG], byref(flags))
        check_hr(hr, "GetFlags")
        return flags.value

    def AddFlags(self, flags: int):
        """Slot 7"""
        hr = self._call(7, [c_ulong], c_ulong(flags))
        check_hr(hr, "AddFlags")

    def RemoveFlags(self, flags: int):
        """Slot 8"""
        hr = self._call(8, [c_ulong], c_ulong(flags))
        check_hr(hr, "RemoveFlags")

    def GetOffset(self) -> int:
        """Slot 10"""
        offset = c_ulonglong()
        hr = self._call(10, [PULONG64], byref(offset))
        check_hr(hr, "GetOffset")
        return offset.value

    def SetOffset(self, offset: int):
        """Slot 11"""
        hr = self._call(11, [c_ulonglong], c_ulonglong(offset))
        check_hr(hr, "SetOffset")

    def SetDataParameters(self, size: int, access_type: int):
        """Slot 13: SetDataParameters(ULONG Size, ULONG AccessType)"""
        hr = self._call(13, [c_ulong, c_ulong],
                        c_ulong(size), c_ulong(access_type))
        check_hr(hr, "SetDataParameters")

    def GetMatchThreadId(self) -> int:
        """Slot 17"""
        tid = c_ulong()
        hr = self._call(17, [PULONG], byref(tid))
        check_hr(hr, "GetMatchThreadId")
        return tid.value

    def SetCommand(self, command: bytes):
        """Slot 20"""
        hr = self._call(20, [c_char_p], command)
        check_hr(hr, "SetCommand")

    def SetOffsetExpression(self, expression: bytes):
        """Slot 22"""
        hr = self._call(22, [c_char_p], expression)
        check_hr(hr, "SetOffsetExpression")

    def GetParameters(self) -> DEBUG_BREAKPOINT_PARAMETERS:
        """Slot 23"""
        params = DEBUG_BREAKPOINT_PARAMETERS()
        hr = self._call(23, [POINTER(DEBUG_BREAKPOINT_PARAMETERS)],
                        byref(params))
        check_hr(hr, "GetParameters")
        return params


# ══════════════════════════════════════════════════════════════════════
# DebugCreate — factory function
# ══════════════════════════════════════════════════════════════════════

def debug_create(dbgeng_path: str) -> tuple["DebugClient", ctypes.WinDLL]:
    """Load dbgeng.dll and call DebugCreate() to get IDebugClient.

    Returns (DebugClient wrapper, DLL handle). Store the DLL handle
    so it can be freed on reconnect to release pipe handles.
    """
    dll = ctypes.WinDLL(dbgeng_path)
    fn = dll.DebugCreate
    fn.restype = HRESULT
    fn.argtypes = [POINTER(GUID), POINTER(c_void_p)]

    ptr = c_void_p()
    hr = fn(byref(IID_IDebugClient), byref(ptr))
    check_hr(hr, "DebugCreate")
    return DebugClient(ptr), dll


def debug_connect(remote: str, dbgeng_path: str) -> tuple["DebugClient", ctypes.WinDLL]:
    """Load dbgeng.dll and call DebugConnect() to attach to a debug server.

    Args:
        remote: Connection string, e.g. "tcp:port=14500,server=localhost"
        dbgeng_path: Path to dbgeng.dll.

    Returns (DebugClient wrapper, DLL handle).
    """
    dll = ctypes.WinDLL(dbgeng_path)
    fn = dll.DebugConnect
    fn.restype = HRESULT
    fn.argtypes = [c_char_p, POINTER(GUID), POINTER(c_void_p)]

    ptr = c_void_p()
    hr = fn(remote.encode("utf-8"), byref(IID_IDebugClient), byref(ptr))
    check_hr(hr, "DebugConnect")
    return DebugClient(ptr), dll
