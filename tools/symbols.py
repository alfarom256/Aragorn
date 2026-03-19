"""Symbol and type information tools."""

from ..debugger import get_debugger, run_on_com_thread
from ..dbgeng import DbgEngError


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
        def _impl():
            dbg = get_debugger()
            if name:
                offset = dbg.symbols.GetOffsetByName(name.encode("utf-8"))
                return {
                    "name": name,
                    "address": f"0x{offset:016X}",
                }
            elif address:
                addr = int(address, 0)
                sym_name, disp = dbg.symbols.GetNameByOffset(addr)
                return {
                    "address": f"0x{addr:016X}",
                    "name": sym_name,
                    "displacement": f"+0x{disp:X}" if disp else "",
                }
            else:
                raise ValueError("Must provide either name or address")
        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def get_field_offset(type_name: str, field_name: str) -> dict:
        """Get the byte offset of a field within a structure type.

        Args:
            type_name: Full type name (e.g., "nt!_EPROCESS").
            field_name: Field name (e.g., "UniqueProcessId").

        Returns:
            Dict with offset value.
        """
        def _impl():
            dbg = get_debugger()
            parts = type_name.split("!")
            if len(parts) == 2:
                module_name, type_only = parts
            else:
                module_name = "nt"
                type_only = type_name
            _, mod_base = dbg.symbols.GetModuleByModuleName(
                module_name.encode("utf-8"))
            type_id = dbg.symbols.GetTypeId(mod_base, type_only.encode("utf-8"))
            offset = dbg.symbols.GetFieldOffset(
                mod_base, type_id, field_name.encode("utf-8"))
            return {
                "type": type_name,
                "field": field_name,
                "offset": offset,
                "offset_hex": f"0x{offset:X}",
            }
        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def get_type_size(type_name: str) -> dict:
        """Get the size of a type in bytes.

        Args:
            type_name: Full type name (e.g., "nt!_EPROCESS", "nt!_KTHREAD").

        Returns:
            Dict with size value.
        """
        def _impl():
            dbg = get_debugger()
            parts = type_name.split("!")
            if len(parts) == 2:
                module_name, type_only = parts
            else:
                module_name = "nt"
                type_only = type_name
            _, mod_base = dbg.symbols.GetModuleByModuleName(
                module_name.encode("utf-8"))
            type_id = dbg.symbols.GetTypeId(mod_base, type_only.encode("utf-8"))
            size = dbg.symbols.GetTypeSize(mod_base, type_id)
            return {
                "type": type_name,
                "size": size,
                "size_hex": f"0x{size:X}",
            }
        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def disassemble(address: str, count: int = 10) -> list[dict]:
        """Disassemble instructions at an address.

        Args:
            address: Start address (hex string, or symbol like "nt!NtCreateFile").
            count: Number of instructions to disassemble (default 10).

        Returns:
            List of {address, instruction} dicts.
        """
        def _impl():
            dbg = get_debugger()
            try:
                addr = int(address, 0)
            except ValueError:
                addr = dbg.symbols.GetOffsetByName(address.encode("utf-8"))
            result = []
            current = addr
            for _ in range(count):
                try:
                    text, end = dbg.control.Disassemble(current)
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
        return await run_on_com_thread(_impl)
