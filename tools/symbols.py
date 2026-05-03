"""Symbol and type information tools."""

from ..debugger import get_debugger, run_on_com_thread


def register(mcp):

    @mcp.tool()
    async def resolve_symbol(name: str = "", address: str = "") -> dict:
        """Resolve between symbol names and addresses (bidirectional).

        Args:
            name: Symbol name to resolve to address (e.g., "nt!NtCreateFile").
            address: Address to resolve to symbol name (e.g., "0xfffff80012345000").
            Provide one or the other.

        Returns:
            Dict with symbol name, address, and displacement.
        """
        return await run_on_com_thread(
            get_debugger().resolve_symbol_name, name=name, address=address)

    @mcp.tool()
    async def get_field_offset(type_name: str, field_name: str) -> dict:
        """Get the byte offset of a field within a structure type.

        Args:
            type_name: Full type name (e.g., "nt!_EPROCESS").
            field_name: Field name (e.g., "UniqueProcessId").

        Returns:
            Dict with offset value.
        """
        return await run_on_com_thread(
            get_debugger().get_field_offset_value, type_name, field_name)

    @mcp.tool()
    async def get_type_size(type_name: str) -> dict:
        """Get the size of a type in bytes.

        Args:
            type_name: Full type name (e.g., "nt!_EPROCESS", "nt!_KTHREAD").

        Returns:
            Dict with size value.
        """
        return await run_on_com_thread(
            get_debugger().get_type_size_value, type_name)

    @mcp.tool()
    async def disassemble(address: str, count: int = 10) -> list[dict]:
        """Disassemble instructions at an address.

        Args:
            address: Start address (hex string, or symbol like "nt!NtCreateFile").
            count: Number of instructions to disassemble (default 10).

        Returns:
            List of {address, instruction} dicts.
        """
        return await run_on_com_thread(
            get_debugger().disassemble_instructions, address, count)
