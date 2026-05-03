"""Inspection tools — modules, threads, processes."""

from ..debugger import get_debugger, run_on_com_thread


def register(mcp):

    @mcp.tool()
    async def list_modules() -> list[dict]:
        """List all loaded modules with base address, size, name, and image path."""
        return await run_on_com_thread(get_debugger().enumerate_modules)

    @mcp.tool()
    async def list_threads() -> list[dict]:
        """List all threads with engine ID, system ID, and data offset (ETHREAD)."""
        return await run_on_com_thread(get_debugger().enumerate_threads)

    @mcp.tool()
    async def list_processes() -> list[dict]:
        """List all processes with engine ID, system ID, and data offset (EPROCESS)."""
        return await run_on_com_thread(get_debugger().enumerate_processes)

    @mcp.tool()
    async def switch_process(address: str) -> dict:
        """Switch to a process context for per-process memory access.

        Uses .process /i <addr> which does an invasive process switch,
        making the target process's virtual address space accessible.

        Args:
            address: EPROCESS address (hex string).

        Returns:
            Confirmation dict.
        """
        return await run_on_com_thread(
            get_debugger().switch_to_process, address)
