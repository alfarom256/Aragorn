"""Debug event tools — wait, poll, clear."""

from ..debugger import get_debugger, run_on_com_thread


def register(mcp):

    @mcp.tool()
    async def wait_for_event(timeout: int = 30) -> dict:
        """Block until the next debug event (breakpoint, exception, module load, etc.).

        Args:
            timeout: Maximum seconds to wait (default 30).

        Returns:
            Dict with event info, or timeout indication.
        """
        return await run_on_com_thread(
            get_debugger().wait_for_one_event, timeout)

    @mcp.tool()
    async def poll_events() -> list[dict]:
        """Return all queued debug events without blocking.

        Events are queued by the EventCallbacks during WaitForEvent() or
        other operations. This returns any accumulated events immediately.
        """
        return await run_on_com_thread(get_debugger().drain_events)

    @mcp.tool()
    async def clear_events() -> dict:
        """Discard all queued debug events."""
        return await run_on_com_thread(get_debugger().clear_event_queue)
