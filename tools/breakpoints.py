"""Breakpoint management tools."""

from ..debugger import get_debugger, run_on_com_thread
from ..dbgeng import (
    DebugBreakpoint,
    DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_DATA, DEBUG_BREAKPOINT_ENABLED,
    DEBUG_ANY_ID, DEBUG_BREAK_READ, DEBUG_BREAK_WRITE,
    DEBUG_BREAK_EXECUTE, DEBUG_BREAK_IO,
    DEBUG_EXCEPTION_FILTER_PARAMETERS,
    DEBUG_FILTER_BREAK, DEBUG_FILTER_SECOND_CHANCE_BREAK,
    DEBUG_FILTER_OUTPUT, DEBUG_FILTER_IGNORE,
    DbgEngError,
)


def register(mcp):

    @mcp.tool()
    async def set_breakpoint(expression: str = "", address: str = "",
                       bp_type: str = "code", access: str = "write",
                       data_size: int = 1, condition: str = "") -> dict:
        """Set a code or data/hardware breakpoint.

        Args:
            expression: Symbol expression (e.g., "nt!NtCreateFile"). Use this OR address.
            address: Hex address (e.g., "0xfffff80012345000"). Use this OR expression.
            bp_type: "code" for software breakpoint, "data" for hardware/data breakpoint.
            access: For data breakpoints: "read", "write", "execute", "read_write" (default "write").
            data_size: For data breakpoints: bytes to watch — 1, 2, 4, or 8 (default 1).
            condition: Optional command to run when breakpoint hits.

        Returns:
            Dict with breakpoint id, address, and type.
        """
        def _impl():
            dbg = get_debugger()
            if bp_type == "data":
                raw_type = DEBUG_BREAKPOINT_DATA
            else:
                raw_type = DEBUG_BREAKPOINT_CODE
            bp_ptr = dbg.control.AddBreakpoint(raw_type, DEBUG_ANY_ID)
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
                access_flags = access_map.get(access, DEBUG_BREAK_WRITE)
                bp.SetDataParameters(data_size, access_flags)
            if condition:
                bp.SetCommand(condition.encode("utf-8"))
            bp.AddFlags(DEBUG_BREAKPOINT_ENABLED)
            bp_id = bp.GetId()
            try:
                offset = bp.GetOffset()
                addr_str = f"0x{offset:016X}"
            except DbgEngError:
                addr_str = "(deferred)"
            return {
                "id": bp_id,
                "type": bp_type,
                "address": addr_str,
                "expression": expression,
                "enabled": True,
            }
        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def remove_breakpoint(bp_id: int) -> dict:
        """Remove a breakpoint by its ID.

        Args:
            bp_id: Breakpoint ID returned by set_breakpoint.
        """
        def _impl():
            dbg = get_debugger()
            bp_ptr = dbg.control.GetBreakpointById(bp_id)
            dbg.control.RemoveBreakpoint(bp_ptr)
            return {"removed": bp_id}
        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def list_breakpoints() -> list[dict]:
        """List all breakpoints with their IDs, addresses, types, and status."""
        def _impl():
            dbg = get_debugger()
            count = dbg.control.GetNumberBreakpoints()
            result = []
            for i in range(count):
                try:
                    bp_ptr = dbg.control.GetBreakpointByIndex(i)
                    bp = DebugBreakpoint(bp_ptr)
                    params = bp.GetParameters()
                    entry = {
                        "id": params.Id,
                        "type": "code" if params.BreakType == DEBUG_BREAKPOINT_CODE else "data",
                        "address": f"0x{params.Offset:016X}",
                        "enabled": bool(params.Flags & DEBUG_BREAKPOINT_ENABLED),
                        "hit_count": params.CurrentPassCount,
                    }
                    try:
                        name, disp = dbg.symbols.GetNameByOffset(params.Offset)
                        entry["symbol"] = name + (f"+0x{disp:X}" if disp else "")
                    except DbgEngError:
                        entry["symbol"] = ""
                    result.append(entry)
                except DbgEngError:
                    continue
            return result
        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def set_exception_filter(code: str, handling: str = "break") -> dict:
        """Configure how an exception is handled (first/second chance).

        Args:
            code: Exception code as hex string (e.g., "0xC0000005" for access violation).
            handling: How to handle — "break", "second_chance_break", "output", or "ignore".

        Returns:
            Confirmation dict.
        """
        def _impl():
            dbg = get_debugger()
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
            dbg.control.SetExceptionFilterParameters([param])
            return {"exception_code": f"0x{exc_code:08X}", "handling": handling}
        return await run_on_com_thread(_impl)
