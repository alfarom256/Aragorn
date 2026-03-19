"""Register read/write tools."""

from ..debugger import get_debugger, run_on_com_thread
from ..dbgeng import DEBUG_VALUE, DEBUG_VALUE_INT64


def register(mcp):

    @mcp.tool()
    async def read_registers() -> dict:
        """Read all general-purpose register values.

        Returns:
            Dict mapping register names to hex value strings.
            Example: {"rax": "0x0000000000000001", "rbx": "0x...", ...}
        """
        def _impl():
            dbg = get_debugger()
            regs = dbg.registers
            num = regs.GetNumberRegisters()
            result = {}
            for i in range(num):
                try:
                    name, desc = regs.GetDescription(i)
                    val = regs.GetValue(i)
                    result[name] = f"0x{val.I64:016X}"
                except Exception:
                    continue
            return result
        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def write_register(name: str, value: str) -> dict:
        """Write a value to a register.

        Args:
            name: Register name (e.g., "rax", "rcx", "rip").
            value: Value to write (hex string, e.g., "0x1234").

        Returns:
            Confirmation dict.
        """
        def _impl():
            dbg = get_debugger()
            regs = dbg.registers
            idx = regs.GetIndexByName(name.encode("utf-8"))
            val = DEBUG_VALUE()
            val.I64 = int(value, 0)
            val.Type = DEBUG_VALUE_INT64
            regs.SetValue(idx, val)
            return {"register": name, "value": f"0x{val.I64:016X}"}
        return await run_on_com_thread(_impl)
