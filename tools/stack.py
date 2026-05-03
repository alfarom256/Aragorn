"""Stack trace tool."""

from ..debugger import get_debugger, run_on_com_thread


def register(mcp):

    @mcp.tool()
    async def get_stack(max_frames: int = 50) -> list[dict]:
        """Get a structured stack trace.

        Args:
            max_frames: Maximum number of frames to return (default 50).

        Returns:
            List of frame dicts with address, return_address, symbol, displacement.
        """
        return await run_on_com_thread(
            get_debugger().get_stack_frames, max_frames)
