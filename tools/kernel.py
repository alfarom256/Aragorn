"""Kernel object inspection tools — structs, PTE, pool, driver objects, IDT, SSDT."""

from ..debugger import get_debugger, run_on_com_thread


def register(mcp):

    @mcp.tool()
    async def read_struct(type_name: str, address: str) -> str:
        """Read a typed kernel structure at a memory address (dt equivalent).

        Args:
            type_name: Structure type (e.g., "nt!_EPROCESS", "nt!_KTHREAD").
            address: Memory address (hex string).

        Returns:
            Formatted structure output (same as WinDbg's dt command).
        """
        dbg = get_debugger()
        return await run_on_com_thread(dbg.execute, f"dt {type_name} {address}")

    @mcp.tool()
    async def get_pte(address: str) -> str:
        """Get page table entry information for a virtual address.

        Shows PDE and PTE values, page frame number, and page attributes.

        Args:
            address: Virtual address to query.

        Returns:
            PTE information (same as !pte command).
        """
        dbg = get_debugger()
        return await run_on_com_thread(dbg.execute, f"!pte {address}")

    @mcp.tool()
    async def pool_info(address: str) -> str:
        """Get pool allocation metadata for a kernel address.

        Args:
            address: Address within a pool allocation.

        Returns:
            Pool information (same as !pool command).
        """
        dbg = get_debugger()
        return await run_on_com_thread(dbg.execute, f"!pool {address}")

    @mcp.tool()
    async def get_driver_object(name: str) -> str:
        """Display a driver object including its full dispatch table (IRP handlers).

        Args:
            name: Driver name (e.g., "\\\\Driver\\\\Ntfs", "Ntfs").

        Returns:
            Driver object details with IRP handler addresses.
        """
        dbg = get_debugger()
        return await run_on_com_thread(dbg.execute, f"!drvobj {name} 7")

    @mcp.tool()
    async def get_device_objects(address: str) -> str:
        """Display device object information.

        Args:
            address: Address of the device object.

        Returns:
            Device object details.
        """
        dbg = get_debugger()
        return await run_on_com_thread(dbg.execute, f"!devobj {address}")

    @mcp.tool()
    async def get_object_info(path: str) -> str:
        """Display kernel object information from the object directory.

        Args:
            path: Object path (e.g., "\\\\Device", "\\\\Driver\\\\Ntfs", "\\\\ObjectTypes").

        Returns:
            Object information.
        """
        dbg = get_debugger()
        return await run_on_com_thread(dbg.execute, f"!object {path}")

    @mcp.tool()
    async def dump_ssdt(count: int = 512) -> str:
        """Dump the System Service Descriptor Table (SSDT).

        Shows kernel syscall handler addresses and their symbol names.

        Args:
            count: Number of SSDT entries to dump (default 512).

        Returns:
            SSDT entries with addresses and symbols.
        """
        dbg = get_debugger()
        return await run_on_com_thread(dbg.execute, f"dps nt!KiServiceTable L{count}")

    @mcp.tool()
    async def get_idt() -> str:
        """Dump the Interrupt Descriptor Table (IDT).

        Shows interrupt handlers and their associated routines.

        Returns:
            IDT entries.
        """
        dbg = get_debugger()
        return await run_on_com_thread(dbg.execute, "!idt")
