"""Rich structured-state tools — one-shot context dumps via direct COM.

These tools prefer direct COM reads over Execute() text parsing. Safe to
call any time the target is broken in; most degrade gracefully if a piece
of state can't be read (e.g., control registers not exposed on some builds).
"""

import logging
import struct

from ..debugger import get_debugger, run_on_com_thread
from ..dbgeng import DbgEngError, DEBUG_STATUS_BREAK

log = logging.getLogger("aragorn.tools.context")


_STATUS_NAMES = {
    0: "no_change", 1: "go", 2: "go_handled", 3: "go_not_handled",
    4: "step_over", 5: "step_into", 6: "break", 7: "no_debuggee",
}

_EVENT_TYPE_NAMES = {
    0x1: "breakpoint", 0x2: "exception",
    0x4: "create_thread", 0x8: "exit_thread",
    0x10: "create_process", 0x20: "exit_process",
    0x40: "load_module", 0x80: "unload_module",
    0x100: "system_error",
}

# Kernel address space starts here on x64
_KERNEL_MIN = 0xFFFF800000000000


def _read_all_registers(regs) -> dict:
    out = {}
    try:
        num = regs.GetNumberRegisters()
    except DbgEngError:
        return out
    for i in range(num):
        try:
            name, _desc = regs.GetDescription(i)
            val = regs.GetValue(i)
            out[name] = f"0x{val.I64:016X}"
        except DbgEngError:
            continue
    return out


def _read_named(regs, name: str) -> str | None:
    try:
        idx = regs.GetIndexByName(name.encode("utf-8"))
        val = regs.GetValue(idx)
        return f"0x{val.I64:016X}"
    except DbgEngError:
        return None


def _symbolize(symbols, offset: int) -> str:
    try:
        name, disp = symbols.GetNameByOffset(offset)
    except DbgEngError:
        return ""
    if not name:
        return ""
    return f"{name}+0x{disp:X}" if disp else name


def _read_struct_field(dbg, nt_base: int, type_id: int, field: bytes,
                      base_addr: int, size: int) -> int | bytes | None:
    try:
        off = dbg.symbols.GetFieldOffset(nt_base, type_id, field)
    except DbgEngError:
        return None
    try:
        raw = dbg.data.ReadVirtual(base_addr + off, size)
    except DbgEngError:
        return None
    if size == 8:
        return struct.unpack_from("<Q", raw)[0]
    if size == 4:
        return struct.unpack_from("<I", raw)[0]
    if size == 2:
        return struct.unpack_from("<H", raw)[0]
    return raw


def _nt_type_id(dbg, type_name: bytes) -> tuple[int, int] | None:
    """Return (nt_base, type_id) for an nt-module type, or None."""
    try:
        _idx, nt_base = dbg.symbols.GetModuleByModuleName(b"nt")
        tid = dbg.symbols.GetTypeId(nt_base, type_name)
        return nt_base, tid
    except DbgEngError:
        return None


def _current_process_block(dbg) -> dict:
    block = {}
    try:
        eprocess = dbg.sysobj.GetCurrentProcessDataOffset()
        block["eprocess"] = f"0x{eprocess:016X}"
    except DbgEngError:
        return block

    try:
        block["engine_id"] = dbg.sysobj.GetCurrentProcessId()
    except DbgEngError:
        pass
    try:
        block["pid"] = dbg.sysobj.GetCurrentProcessSystemId()
    except (DbgEngError, AttributeError):
        pass
    try:
        exe = dbg.sysobj.GetCurrentProcessExecutableName()
        if exe:
            block["image"] = exe
    except (DbgEngError, AttributeError):
        pass

    info = _nt_type_id(dbg, b"_EPROCESS")
    if info is not None:
        nt_base, tid = info
        dtb = _read_struct_field(dbg, nt_base, tid, b"DirectoryTableBase",
                                 eprocess, 8)
        if isinstance(dtb, int):
            block["dirbase"] = f"0x{dtb:016X}"
        if "pid" not in block:
            pid = _read_struct_field(dbg, nt_base, tid, b"UniqueProcessId",
                                    eprocess, 8)
            if isinstance(pid, int):
                block["pid"] = pid
        if "image" not in block:
            name = _read_struct_field(dbg, nt_base, tid, b"ImageFileName",
                                      eprocess, 15)
            if isinstance(name, (bytes, bytearray)):
                block["image"] = name.split(b"\x00")[0].decode(
                    "ascii", errors="replace")
    return block


def _current_thread_block(dbg) -> dict:
    block = {}
    try:
        ethread = dbg.sysobj.GetCurrentThreadDataOffset()
        block["ethread"] = f"0x{ethread:016X}"
    except DbgEngError:
        return block
    try:
        block["engine_id"] = dbg.sysobj.GetCurrentThreadId()
    except DbgEngError:
        pass
    try:
        block["tid"] = dbg.sysobj.GetCurrentThreadSystemId()
    except (DbgEngError, AttributeError):
        pass

    info = _nt_type_id(dbg, b"_KTHREAD")
    if info is not None:
        nt_base, tid = info
        for field, key in [
            (b"InitialStack", "kstack_base"),
            (b"StackLimit", "kstack_limit"),
            (b"Process", "kprocess"),
            (b"Teb", "teb"),
        ]:
            val = _read_struct_field(dbg, nt_base, tid, field, ethread, 8)
            if isinstance(val, int):
                block[key] = f"0x{val:016X}"
    return block


def _disasm_n(dbg, addr: int, count: int) -> list[dict]:
    out = []
    cur = addr
    for _ in range(count):
        try:
            text, end = dbg.control.Disassemble(cur, 0, 1024)
        except DbgEngError as e:
            out.append({"addr": f"0x{cur:016X}", "error": str(e)})
            break
        out.append({"addr": f"0x{cur:016X}", "text": text.strip()})
        if end <= cur:
            break
        cur = end
    return out


def _stack_top_qwords(dbg, rsp: int, count: int) -> list[dict]:
    out = []
    try:
        raw = dbg.data.ReadVirtual(rsp, count * 8)
    except DbgEngError:
        return out
    for i in range(min(count, len(raw) // 8)):
        val = struct.unpack_from("<Q", raw, i * 8)[0]
        entry = {"addr": f"0x{rsp + i * 8:016X}", "value": f"0x{val:016X}"}
        if val >= _KERNEL_MIN:
            sym = _symbolize(dbg.symbols, val)
            if sym:
                entry["symbol"] = sym
        out.append(entry)
    return out


def _stack_frames(dbg, max_frames: int) -> list[dict]:
    try:
        frames = dbg.control.GetStackTrace(max_frames)
    except DbgEngError:
        return []
    out = []
    for f in frames:
        entry = {
            "frame": f.FrameNumber,
            "instruction": f"0x{f.InstructionOffset:016X}",
            "return": f"0x{f.ReturnOffset:016X}",
            "stack": f"0x{f.StackOffset:016X}",
        }
        sym = _symbolize(dbg.symbols, f.InstructionOffset)
        if sym:
            entry["symbol"] = sym
        out.append(entry)
    return out


def _last_event(dbg) -> dict | None:
    try:
        info = dbg.control.GetLastEventInformation()
    except DbgEngError:
        return None
    info["type_name"] = _EVENT_TYPE_NAMES.get(info["type"], str(info["type"]))
    return info


def _build_full_snapshot(dbg, max_frames: int = 20, disasm_count: int = 8,
                         stack_qwords: int = 32) -> dict:
    """Compose the get_full_context dict. Module-level so Debugger can call it."""
    result: dict = {}

    try:
        status = dbg.control.GetExecutionStatus()
        result["execution_status"] = _STATUS_NAMES.get(status, str(status))
        result["execution_status_raw"] = status
    except DbgEngError as e:
        result["execution_status"] = "error"
        result["execution_status_error"] = str(e)
        status = None

    cpu = _read_all_registers(dbg.registers)
    for name in ("cr0", "cr2", "cr3", "cr4", "cr8", "efer",
                 "gs.base", "kernel_gs_base"):
        v = _read_named(dbg.registers, name)
        if v is not None:
            cpu.setdefault(name, v)
    if cpu:
        result["cpu"] = cpu

    rip_hex = cpu.get("rip")
    if rip_hex:
        rip = int(rip_hex, 16)
        sym = _symbolize(dbg.symbols, rip)
        if sym:
            result["rip_symbol"] = sym
        if disasm_count > 0:
            result["disasm"] = _disasm_n(dbg, rip, disasm_count)

    rsp_hex = cpu.get("rsp")
    if rsp_hex and stack_qwords > 0:
        rsp = int(rsp_hex, 16)
        result["stack_top"] = _stack_top_qwords(dbg, rsp, stack_qwords)

    if max_frames > 0:
        result["stack_frames"] = _stack_frames(dbg, max_frames)

    thread = _current_thread_block(dbg)
    if thread:
        result["current_thread"] = thread
    process = _current_process_block(dbg)
    if process:
        result["current_process"] = process

    evt = _last_event(dbg)
    if evt:
        result["last_event"] = evt

    return result


def register(mcp):

    @mcp.tool()
    async def get_cpu_state() -> dict:
        """Return all registers (GPRs + segment + control) in one call.

        Direct COM register reads — no Execute() text parsing. Explicitly
        probes cr0/cr2/cr3/cr4/cr8/efer by name in case they aren't in
        the default register iteration on this target.
        """
        return await run_on_com_thread(get_debugger().get_cpu_state_full)

    @mcp.tool()
    async def disasm_at(address: str, count: int = 16) -> list[dict]:
        """Disassemble `count` instructions starting at `address`.

        Args:
            address: Start address — hex, symbolic (e.g. "nt!NtOpenFile"),
                     or any expression DbgEng can evaluate.
            count: Number of instructions (default 16).
        """
        return await run_on_com_thread(
            get_debugger().disassemble_at, address, count)

    @mcp.tool()
    async def read_qwords(address: str, count: int = 16,
                           resolve_symbols: bool = True) -> list[dict]:
        """Read `count` 8-byte qwords from `address`, optionally resolving
        kernel pointers to symbols.
        """
        return await run_on_com_thread(
            get_debugger().read_qwords_resolved,
            address, count, resolve_symbols)

    @mcp.tool()
    async def get_current_process() -> dict:
        """EPROCESS + engine id + OS pid + image name + DirectoryTableBase
        for the current process context.

        Prefers `GetCurrentProcessExecutableName` / `GetCurrentProcessSystemId`
        COM calls; falls back to reading `_EPROCESS` fields (`ImageFileName`,
        `UniqueProcessId`, `DirectoryTableBase`) via `GetFieldOffset` + `ReadVirtual`.
        """
        return await run_on_com_thread(
            get_debugger().get_current_process_info)

    @mcp.tool()
    async def get_current_thread() -> dict:
        """ETHREAD + engine id + OS tid + kernel stack bounds + PKPROCESS
        for the current thread context.

        Reads `_KTHREAD` fields (`InitialStack`, `StackLimit`, `Process`,
        `Teb`) via `GetFieldOffset` + `ReadVirtual`.
        """
        return await run_on_com_thread(
            get_debugger().get_current_thread_info)

    @mcp.tool()
    async def get_full_context(max_frames: int = 20, disasm_count: int = 8,
                                stack_qwords: int = 32) -> dict:
        """One-shot execution snapshot — registers, disasm at RIP, stack top,
        stack frames, current thread/process, last event.

        Intended to replace "read_registers + get_stack + list_processes +
        execute('u @rip L10') + execute('!process -1 0')" with a single call
        that does the equivalent via direct COM, no text parsing.

        Args:
            max_frames: Max stack frames (default 20).
            disasm_count: Instructions to disassemble at RIP (default 8).
            stack_qwords: Qwords of raw stack top to dump (default 32).

        Returns:
            Dict with keys: execution_status, cpu, rip_symbol, disasm,
            stack_top, stack_frames, current_thread, current_process,
            last_event. Any individual section may be absent if the
            relevant COM call failed.
        """
        return await run_on_com_thread(
            get_debugger().get_full_snapshot,
            max_frames, disasm_count, stack_qwords)
