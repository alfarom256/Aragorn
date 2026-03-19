"""Inspection tools — modules, threads, processes."""

from ..debugger import get_debugger, run_on_com_thread
from ..dbgeng import DEBUG_MODNAME_MODULE, DEBUG_MODNAME_IMAGE, DbgEngError, S_OK


def register(mcp):

    @mcp.tool()
    async def list_modules() -> list[dict]:
        """List all loaded modules with base address, size, name, and image path."""
        def _impl():
            dbg = get_debugger()
            loaded, unloaded = dbg.symbols.GetNumberModules()
            result = []
            for i in range(loaded):
                try:
                    base = dbg.symbols.GetModuleByIndex(i)
                    params_list = dbg.symbols.GetModuleParameters([base])
                    params = params_list[0]
                    entry = {
                        "index": i,
                        "base": f"0x{base:016X}",
                        "size": f"0x{params.Size:X}",
                        "size_bytes": params.Size,
                    }
                    try:
                        entry["name"] = dbg.symbols.GetModuleNameString(
                            DEBUG_MODNAME_MODULE, i, base)
                    except DbgEngError:
                        entry["name"] = ""
                    try:
                        entry["image"] = dbg.symbols.GetModuleNameString(
                            DEBUG_MODNAME_IMAGE, i, base)
                    except DbgEngError:
                        entry["image"] = ""
                    result.append(entry)
                except DbgEngError:
                    continue
            return result
        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def list_threads() -> list[dict]:
        """List all threads with engine ID, system ID, and data offset (ETHREAD)."""
        def _impl():
            dbg = get_debugger()
            num = dbg.sysobj.GetNumberThreads()
            if num == 0:
                return []
            engine_ids, sys_ids = dbg.sysobj.GetThreadIdsByIndex(0, num)
            result = []
            for i in range(num):
                result.append({
                    "engine_id": engine_ids[i],
                    "system_id": sys_ids[i],
                })
            try:
                current = dbg.sysobj.GetCurrentThreadId()
                for entry in result:
                    entry["current"] = entry["engine_id"] == current
            except DbgEngError:
                pass
            return result
        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def list_processes() -> list[dict]:
        """List all processes with engine ID, system ID, and data offset (EPROCESS)."""
        def _impl():
            dbg = get_debugger()
            num = dbg.sysobj.GetNumberProcesses()
            if num == 0:
                return []
            engine_ids, sys_ids = dbg.sysobj.GetProcessIdsByIndex(0, num)
            result = []
            for i in range(num):
                result.append({
                    "engine_id": engine_ids[i],
                    "system_id": sys_ids[i],
                })
            try:
                current = dbg.sysobj.GetCurrentProcessId()
                for entry in result:
                    entry["current"] = entry["engine_id"] == current
            except DbgEngError:
                pass
            return result
        return await run_on_com_thread(_impl)

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
        def _impl():
            dbg = get_debugger()
            cmd = f".process /i {address}"
            output = dbg.execute(cmd)
            hr = dbg.control.WaitForEvent(10_000)
            return {
                "command": cmd,
                "output": output,
                "address": address,
            }
        return await run_on_com_thread(_impl)
