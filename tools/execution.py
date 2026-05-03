"""Execution control tools — continue, step, break."""

import asyncio
import logging

from ..debugger import get_debugger, run_on_com_thread, reset_com_executor

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
        return await run_on_com_thread(get_debugger().resume_target)

    @mcp.tool()
    async def step_into() -> dict:
        """Single-step into calls (equivalent to 't' command).

        Returns:
            Current instruction address and symbol after stepping.
        """
        return await run_on_com_thread(get_debugger().do_step_into)

    @mcp.tool()
    async def step_over() -> dict:
        """Single-step over calls (equivalent to 'p' command).

        Returns:
            Current instruction address and symbol after stepping.
        """
        return await run_on_com_thread(get_debugger().do_step_over)

    @mcp.tool()
    async def break_in() -> dict:
        """Break into the debugger — interrupt target execution.

        Returns:
            Confirmation that the break was requested.
        """
        try:
            return await asyncio.wait_for(
                run_on_com_thread(get_debugger().request_break), timeout=30)
        except asyncio.TimeoutError:
            reset_com_executor()
            return {"error": "break_in timed out after 30s"}
