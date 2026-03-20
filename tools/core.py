"""Core command execution tools."""

import asyncio
import logging

from .. import config
from ..debugger import get_debugger, run_on_com_thread

log = logging.getLogger("aragorn.tools.core")


def register(mcp):

    @mcp.tool()
    async def execute(command: str, timeout: int = 10000) -> str:
        """Execute a raw debugger command and return its text output.

        Args:
            command: Any WinDbg/DbgEng command (e.g., "lm", "!process 0 0",
                     "dt nt!_EPROCESS @$proc").
            timeout: Timeout in milliseconds (default 10000).

        Returns:
            The command's text output.
        """
        dbg = get_debugger()

        timeout_s = timeout / 1000.0
        stall_s = config.STALL_TIMEOUT_S
        hard_s = config.HARD_TIMEOUT_S

        task = asyncio.ensure_future(
            run_on_com_thread(dbg.execute, command, timeout)
        )

        # Wait for initial grace period
        done, _ = await asyncio.wait({task}, timeout=timeout_s)
        if done:
            return task.result()

        # Not done yet — check if any output arrived
        count_at_check = dbg.output_cb.output_count if dbg.output_cb else 0
        if count_at_check == 0:
            # No output at all — kill immediately
            log.warning("execute: no output after %ss for '%s', killing",
                        timeout_s, command)
            if dbg._kd_process and dbg._kd_process.poll() is None:
                dbg._kd_process.kill()
                dbg._connected = False
            # Wait briefly for the task to finish after kill
            done, _ = await asyncio.wait({task}, timeout=5.0)
            partial = ""
            if done:
                try:
                    partial = task.result()
                except Exception:
                    pass
            return (partial +
                    f"\n\n[ARAGORN] Command timed out ({timeout_s}s) with "
                    f"no output.\n")

        # Output is flowing — monitor for stalls up to hard deadline
        deadline = asyncio.get_event_loop().time() + hard_s
        last_count = count_at_check
        while asyncio.get_event_loop().time() < deadline:
            done, _ = await asyncio.wait({task}, timeout=stall_s)
            if done:
                return task.result()
            current_count = (dbg.output_cb.output_count
                             if dbg.output_cb else 0)
            if current_count == last_count:
                # Output stalled
                log.warning("execute: output stalled for %ss on '%s', killing",
                            stall_s, command)
                if dbg._kd_process and dbg._kd_process.poll() is None:
                    dbg._kd_process.kill()
                    dbg._connected = False
                done, _ = await asyncio.wait({task}, timeout=5.0)
                partial = ""
                if done:
                    try:
                        partial = task.result()
                    except Exception:
                        pass
                return (partial +
                        f"\n\n[ARAGORN] Command aborted: output stalled "
                        f"for {stall_s}s.\n")
            last_count = current_count

        # Hard deadline exceeded
        log.warning("execute: hard timeout (%ss) for '%s', killing",
                    hard_s, command)
        if dbg._kd_process and dbg._kd_process.poll() is None:
            dbg._kd_process.kill()
            dbg._connected = False
        done, _ = await asyncio.wait({task}, timeout=5.0)
        partial = ""
        if done:
            try:
                partial = task.result()
            except Exception:
                pass
        return (partial +
                f"\n\n[ARAGORN] Command aborted: hard timeout ({hard_s}s).\n")

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
        def _run():
            dbg = get_debugger()
            results = []
            for cmd in commands:
                try:
                    output = dbg.execute(cmd, timeout_ms=timeout)
                    results.append({
                        "command": cmd,
                        "output": output,
                        "success": True,
                    })
                except Exception as e:
                    results.append({
                        "command": cmd,
                        "output": "",
                        "success": False,
                        "error": str(e),
                    })
                    if stop_on_error:
                        break
            return results

        return await run_on_com_thread(_run)

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
