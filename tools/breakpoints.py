"""Breakpoint management tools."""

from ..debugger import get_debugger, run_on_com_thread


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
        return await run_on_com_thread(
            get_debugger().add_breakpoint,
            bp_type=bp_type, expression=expression, address=address,
            access=access, data_size=data_size, condition=condition,
        )

    @mcp.tool()
    async def remove_breakpoint(bp_id: int) -> dict:
        """Remove a breakpoint by its ID.

        Args:
            bp_id: Breakpoint ID returned by set_breakpoint.
        """
        return await run_on_com_thread(
            get_debugger().remove_breakpoint_by_id, bp_id)

    @mcp.tool()
    async def list_breakpoints() -> list[dict]:
        """List all breakpoints with their IDs, addresses, types, and status."""
        return await run_on_com_thread(
            get_debugger().list_all_breakpoints)

    @mcp.tool()
    async def set_exception_filter(code: str, handling: str = "break") -> dict:
        """Configure how an exception is handled (first/second chance).

        Args:
            code: Exception code as hex string (e.g., "0xC0000005" for access violation).
            handling: How to handle — "break", "second_chance_break", "output", or "ignore".

        Returns:
            Confirmation dict.
        """
        return await run_on_com_thread(
            get_debugger().configure_exception_filter, code, handling)
