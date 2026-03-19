"""Stack trace tool."""

from ..debugger import get_debugger, run_on_com_thread
from ..dbgeng import DbgEngError


def register(mcp):

    @mcp.tool()
    async def get_stack(max_frames: int = 50) -> list[dict]:
        """Get a structured stack trace.

        Args:
            max_frames: Maximum number of frames to return (default 50).

        Returns:
            List of frame dicts with address, return_address, symbol, displacement.
        """
        def _impl():
            dbg = get_debugger()
            frames = dbg.control.GetStackTrace(max_frames)
            result = []
            for frame in frames:
                entry = {
                    "frame": frame.FrameNumber,
                    "instruction": f"0x{frame.InstructionOffset:016X}",
                    "return": f"0x{frame.ReturnOffset:016X}",
                    "stack": f"0x{frame.StackOffset:016X}",
                }
                try:
                    name, disp = dbg.symbols.GetNameByOffset(frame.InstructionOffset)
                    entry["symbol"] = name
                    entry["displacement"] = f"+0x{disp:X}" if disp else ""
                except DbgEngError:
                    entry["symbol"] = ""
                    entry["displacement"] = ""
                result.append(entry)
            return result
        return await run_on_com_thread(_impl)
