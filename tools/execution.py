"""Execution control tools — continue, step, break."""

import asyncio
import logging

from ..debugger import get_debugger, run_on_com_thread, reset_com_executor, status_name
from ..dbgeng import (
    DEBUG_STATUS_GO, DEBUG_STATUS_STEP_INTO, DEBUG_STATUS_STEP_OVER,
    DEBUG_INTERRUPT_ACTIVE, S_OK, DbgEngError,
)

log = logging.getLogger("aragorn.tools.execution")


def register(mcp):

    @mcp.tool()
    async def continue_exec() -> dict:
        """Resume execution of the debug target (equivalent to 'g' command).

        Uses a robust resume loop that drains pending break events from
        kdnet/kd.exe. Retries up to 10 times to ensure the target is
        genuinely running.

        Returns:
            Confirmation that execution was resumed, including attempt count.
            If target cannot be resumed after all attempts, returns
            status='stuck_in_break'.
        """
        def _impl():
            dbg = get_debugger()
            return dbg.resume_target()

        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def step_into() -> dict:
        """Single-step into calls (equivalent to 't' command).

        Returns:
            Current instruction address and symbol after stepping.
        """
        def _impl():
            dbg = get_debugger()
            log.info("step_into")
            dbg.control.SetExecutionStatus(DEBUG_STATUS_STEP_INTO)
            hr = dbg.control.WaitForEvent(5_000)

            result = {"status": "stepped"}
            try:
                idx = dbg.registers.GetIndexByName(b"rip")
                val = dbg.registers.GetValue(idx)
                rip = val.I64
                result["rip"] = f"0x{rip:016X}"

                try:
                    name, disp = dbg.symbols.GetNameByOffset(rip)
                    result["symbol"] = name + (f"+0x{disp:X}" if disp else "")
                except DbgEngError:
                    pass
            except DbgEngError:
                pass

            st = dbg.control.GetExecutionStatus()
            dbg._state["execution_status"] = status_name(st)
            log.info("step_into → %s", result.get("symbol", result.get("rip", "?")))
            return result

        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def step_over() -> dict:
        """Single-step over calls (equivalent to 'p' command).

        Returns:
            Current instruction address and symbol after stepping.
        """
        def _impl():
            dbg = get_debugger()
            log.info("step_over")
            dbg.control.SetExecutionStatus(DEBUG_STATUS_STEP_OVER)
            hr = dbg.control.WaitForEvent(5_000)

            result = {"status": "stepped"}
            try:
                idx = dbg.registers.GetIndexByName(b"rip")
                val = dbg.registers.GetValue(idx)
                rip = val.I64
                result["rip"] = f"0x{rip:016X}"

                try:
                    name, disp = dbg.symbols.GetNameByOffset(rip)
                    result["symbol"] = name + (f"+0x{disp:X}" if disp else "")
                except DbgEngError:
                    pass
            except DbgEngError:
                pass

            st = dbg.control.GetExecutionStatus()
            dbg._state["execution_status"] = status_name(st)
            log.info("step_over → %s", result.get("symbol", result.get("rip", "?")))
            return result

        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def break_in() -> dict:
        """Break into the debugger — interrupt target execution.

        Returns:
            Confirmation that the break was requested.
        """
        def _impl():
            dbg = get_debugger()  # raises if not connected
            log.info("break_in: SetInterrupt")
            dbg.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE)
            return {"status": "break_requested"}

        try:
            return await asyncio.wait_for(
                run_on_com_thread(_impl), timeout=30)
        except asyncio.TimeoutError:
            reset_com_executor()
            return {"error": "break_in timed out after 30s"}
