"""Debug event tools — wait, poll, clear."""

from ..debugger import get_debugger, run_on_com_thread
from ..dbgeng import S_OK, S_FALSE, DbgEngError


def register(mcp):

    @mcp.tool()
    async def wait_for_event(timeout: int = 30) -> dict:
        """Block until the next debug event (breakpoint, exception, module load, etc.).

        Args:
            timeout: Maximum seconds to wait (default 30).

        Returns:
            Dict with event info, or timeout indication.
        """
        def _impl():
            dbg = get_debugger()
            timeout_ms = timeout * 1000
            hr = dbg.control.WaitForEvent(timeout_ms)
            if hr == S_OK:
                try:
                    event_info = dbg.control.GetLastEventInformation()
                except DbgEngError:
                    event_info = {}
                queued = dbg.event_cb.pop_events()
                return {
                    "status": "event_received",
                    "last_event": event_info,
                    "queued_events": queued,
                }
            elif hr == S_FALSE:
                return {
                    "status": "timeout",
                    "timeout_seconds": timeout,
                }
            else:
                return {
                    "status": "error",
                    "hresult": f"0x{hr & 0xFFFFFFFF:08X}",
                }
        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def poll_events() -> list[dict]:
        """Return all queued debug events without blocking.

        Events are queued by the EventCallbacks during WaitForEvent() or
        other operations. This returns any accumulated events immediately.
        """
        def _impl():
            dbg = get_debugger()
            return dbg.event_cb.pop_events()
        return await run_on_com_thread(_impl)

    @mcp.tool()
    async def clear_events() -> dict:
        """Discard all queued debug events."""
        def _impl():
            dbg = get_debugger()
            dbg.event_cb.clear()
            return {"status": "cleared"}
        return await run_on_com_thread(_impl)
