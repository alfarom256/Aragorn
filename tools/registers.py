"""Register read/write tools."""

from ..debugger import get_debugger, run_on_com_thread


def register(mcp):

    @mcp.tool()
    async def read_registers() -> dict:
        """Read all general-purpose register values.

        Returns:
            Dict mapping register names to hex value strings.
            Example: {"rax": "0x0000000000000001", "rbx": "0x...", ...}
        """
        return await run_on_com_thread(get_debugger().read_all_registers)

    @mcp.tool()
    async def write_register(name: str, value: str) -> dict:
        """Write a value to a register.

        Args:
            name: Register name (e.g., "rax", "rcx", "rip").
            value: Value to write (hex string, e.g., "0x1234").

        Returns:
            Confirmation dict.
        """
        return await run_on_com_thread(
            get_debugger().write_register_value, name, value)
