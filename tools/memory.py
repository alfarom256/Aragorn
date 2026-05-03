"""Memory read/write/search tools."""

import struct
from ..debugger import get_debugger, run_on_com_thread


def _format_bytes(data: bytes, fmt: str, base_addr: int) -> str:
    """Format raw bytes into a display string."""
    if fmt == "ascii":
        return data.decode("ascii", errors=".")
    elif fmt == "qwords":
        lines = []
        for i in range(0, len(data), 8):
            chunk = data[i:i+8]
            if len(chunk) == 8:
                val = struct.unpack_from("<Q", chunk)[0]
                lines.append(f"0x{base_addr + i:016X}: 0x{val:016X}")
        return "\n".join(lines)
    elif fmt == "dwords":
        lines = []
        for i in range(0, len(data), 4):
            chunk = data[i:i+4]
            if len(chunk) == 4:
                val = struct.unpack_from("<I", chunk)[0]
                lines.append(f"0x{base_addr + i:016X}: 0x{val:08X}")
        return "\n".join(lines)
    else:  # hex
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"0x{base_addr + i:016X}: {hex_part:<48s} {ascii_part}")
        return "\n".join(lines)


def register(mcp):

    @mcp.tool()
    async def read_memory(address: str, size: int = 64, format: str = "hex") -> str:
        """Read virtual memory at an address.

        Args:
            address: Virtual address (hex string, e.g., "0xfffff80012345000").
            size: Number of bytes to read (default 64, max 1MB).
            format: Display format — "hex", "qwords", "dwords", or "ascii".

        Returns:
            Formatted memory contents.
        """
        return await run_on_com_thread(
            get_debugger().read_virtual_formatted, address, size, format)

    @mcp.tool()
    async def write_memory(address: str, hex_data: str) -> dict:
        """Write bytes to virtual memory.

        Args:
            address: Virtual address (hex string).
            hex_data: Hex-encoded bytes to write (e.g., "90909090" for NOPs).

        Returns:
            Dict with bytes_written count.
        """
        return await run_on_com_thread(
            get_debugger().write_virtual_bytes, address, hex_data)

    @mcp.tool()
    async def search_memory(address: str, pattern: str, length: int = 4096) -> dict:
        """Search for a byte pattern in virtual memory.

        Args:
            address: Start address (hex string).
            pattern: Hex-encoded byte pattern to find.
            length: Number of bytes to search through (default 4096).

        Returns:
            Dict with match_address if found.
        """
        return await run_on_com_thread(
            get_debugger().search_virtual, address, pattern, length)

    @mcp.tool()
    async def read_physical(address: str, size: int = 64) -> str:
        """Read physical memory.

        Args:
            address: Physical address (hex string).
            size: Number of bytes (default 64, max 1MB).

        Returns:
            Hex-formatted memory dump.
        """
        return await run_on_com_thread(
            get_debugger().read_physical_formatted, address, size)

    @mcp.tool()
    async def write_physical(address: str, hex_data: str) -> dict:
        """Write bytes to physical memory.

        Args:
            address: Physical address (hex string).
            hex_data: Hex-encoded bytes to write.
        """
        return await run_on_com_thread(
            get_debugger().write_physical_bytes, address, hex_data)

    @mcp.tool()
    async def virtual_to_physical(address: str) -> dict:
        """Translate a virtual address to its physical address.

        Args:
            address: Virtual address (hex string).

        Returns:
            Dict with physical address.
        """
        return await run_on_com_thread(
            get_debugger().translate_v2p, address)

    @mcp.tool()
    async def read_msr(msr_id: int) -> dict:
        """Read a Model-Specific Register.

        Args:
            msr_id: MSR number. Common values:
                - 0xC0000082: LSTAR (syscall handler)
                - 0x176: IA32_SYSENTER_EIP
                - 0xC0000100: FS_BASE
                - 0xC0000101: GS_BASE
                - 0xC0000102: KERNEL_GS_BASE

        Returns:
            Dict with MSR value.
        """
        return await run_on_com_thread(
            get_debugger().read_msr_value, msr_id)
