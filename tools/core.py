"""Core command execution tools."""

from ..debugger import get_debugger, run_on_com_thread


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
        return await run_on_com_thread(dbg.execute, command, timeout)

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
