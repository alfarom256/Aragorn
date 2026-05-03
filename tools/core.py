"""Core command execution tools."""

import asyncio
import os

from .. import config
from ..debugger import get_debugger, run_on_com_thread


def _supervisor_mode() -> bool:
    return os.environ.get("ARAGORN_SUPERVISOR_MODE", "1") == "1" \
        and os.environ.get("ARAGORN_WORKER", "0") != "1"


def register(mcp):

    @mcp.tool()
    async def execute(command: str, timeout: int = 10000) -> str:
        """Execute a raw debugger command and return its text output.

        The worker's `Debugger.execute` has its own stall-detection
        watchdog (see debugger.py — INITIAL_GRACE_S / STALL_TIMEOUT_S /
        HARD_TIMEOUT_S). We just dispatch and let it run, with a single
        outer asyncio timeout as the absolute ceiling.

        Args:
            command: Any WinDbg/DbgEng command (e.g., "lm", "!process 0 0",
                     "dt nt!_EPROCESS @$proc").
            timeout: Timeout in milliseconds for the WinDbg command itself.
        """
        hard_s = getattr(config, 'HARD_TIMEOUT_S', 600)
        # Outer ceiling — worker timeout + a little buffer.
        ceiling = max(timeout / 1000.0 + 5.0, hard_s)
        try:
            return await asyncio.wait_for(
                run_on_com_thread(get_debugger().execute, command, timeout),
                timeout=ceiling,
            )
        except asyncio.TimeoutError:
            # Outer ceiling hit — worker is wedged. In supervisor mode,
            # restart the worker. In legacy, abort transport.
            if _supervisor_mode():
                from ..supervisor import get_supervisor
                try:
                    info = await asyncio.wait_for(
                        get_supervisor().restart(), timeout=10.0)
                except Exception as e:
                    info = f"restart_failed: {e}"
                return (f"\n[ARAGORN] Command exceeded outer ceiling "
                        f"({ceiling:.0f}s). Worker restarted ({info}).")
            return (f"\n[ARAGORN] Command exceeded outer ceiling "
                    f"({ceiling:.0f}s). Call reset_engine().")

    @mcp.tool()
    async def execute_batch(commands: list[str], stop_on_error: bool = False,
                      timeout: int = 30000) -> list[dict]:
        """Execute multiple debugger commands sequentially.

        Args:
            commands: List of commands to execute.
            stop_on_error: Stop if any command fails (default False).
            timeout: Timeout per command in milliseconds.

        Returns:
            List of {command, output, success, error?} dicts.
        """
        return await run_on_com_thread(
            get_debugger().execute_batch_commands,
            commands, stop_on_error, timeout)

    @mcp.tool()
    async def evaluate(expression: str) -> dict:
        """Evaluate a debugger expression and return its numeric value.

        Args:
            expression: Expression to evaluate. Examples:
                - "poi(rsp+8)" — dereference pointer at rsp+8
                - "nt!PsInitialSystemProcess" — address of global
                - "@rax+0x10" — register arithmetic
                - "0n1234" — decimal literal

        Returns:
            Dict with hex and decimal values.
        """
        dbg = get_debugger()
        value = await run_on_com_thread(dbg.evaluate, expression)
        return {
            "value": value,
            "hex": f"0x{value:016X}",
            "decimal": value,
        }
