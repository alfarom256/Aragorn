"""State-aware wrapping of Aragorn MCP tools.

Every Aragorn tool gets wrapped so that:
  - On exception, the raised error's message is augmented with a snapshot
    of the current debugger state (connected, execution_status, last_event,
    tracked_breakpoints, last_error). Makes it impossible to mistake
    "VM is at a break" for "VM is dead" when a tool fails.
  - On success, if the tool returned a dict that contains an "error" key
    but no "aragorn_state", the state snapshot is merged in so soft-error
    returns carry the same context as hard exceptions.

The state snapshot only reads the Debugger's in-process `_state` dict —
no COM calls — so it is safe to call from any thread and never adds
latency to a failing tool.
"""

import asyncio
import functools
import logging
import os

from ..debugger import get_debugger_or_none

log = logging.getLogger("aragorn.tools._state")


def _supervisor_mode() -> bool:
    return os.environ.get("ARAGORN_SUPERVISOR_MODE", "1") == "1" \
        and os.environ.get("ARAGORN_WORKER", "0") != "1"


async def current_state_snapshot() -> dict:
    """Snapshot of Debugger state. RPC call in supervisor mode; in-process
    dict read in legacy mode. Never raises — returns a partial snapshot
    on failure so the state-wrap decorator never makes errors worse.
    """
    if _supervisor_mode():
        from ..supervisor import get_supervisor
        try:
            return await asyncio.wait_for(
                get_supervisor().call("get_full_state"), timeout=2.0)
        except Exception as e:
            return {"note": "no_state_from_worker", "error": str(e)}

    dbg = get_debugger_or_none()
    if dbg is None:
        return {"connected": False, "initialized": False, "note": "no_debugger"}
    snap: dict = {
        "connected": bool(dbg.is_connected),
        "initialized": bool(dbg.is_initialized),
    }
    state = getattr(dbg, "_state", {}) or {}
    exec_status = state.get("execution_status")
    if exec_status is not None:
        snap["execution_status"] = exec_status
    bps = state.get("breakpoints") or []
    snap["tracked_breakpoints"] = len(bps)
    last_event = state.get("last_event")
    if last_event:
        snap["last_event"] = last_event
    last_error = state.get("last_error")
    if last_error:
        snap["last_error"] = last_error
    return snap


async def _snapshot_to_suffix() -> str:
    """Compact one-line rendering for error messages."""
    snap = await current_state_snapshot()
    parts = [f"connected={snap.get('connected')}"]
    if "execution_status" in snap:
        parts.append(f"execution_status={snap['execution_status']}")
    parts.append(f"tracked_bps={snap.get('tracked_breakpoints', 0)}")
    if "last_event" in snap:
        evt = snap["last_event"]
        if isinstance(evt, dict):
            name = evt.get("event") or evt.get("type_name") or "event"
            parts.append(f"last_event={name}")
        else:
            parts.append(f"last_event={evt}")
    if "last_error" in snap:
        le = str(snap["last_error"])
        if len(le) > 80:
            le = le[:80] + "…"
        parts.append(f"last_error={le!r}")
    if "note" in snap:
        parts.append(f"note={snap['note']}")
    return "; ".join(parts)


def wrap_tool(fn):
    """Decorator: on exception, append aragorn state to the error message;
    on soft-error dict returns, merge state in.
    """
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            result = await fn(*args, **kwargs)
        except Exception as e:
            try:
                suffix = await _snapshot_to_suffix()
            except Exception:
                suffix = "snapshot_unavailable"
            new_msg = f"{e}\n[aragorn_state: {suffix}]"
            try:
                # Re-raise same exception type with augmented message
                raise type(e)(new_msg) from e
            except TypeError:
                # Some exception types don't accept a single-string ctor —
                # fall back to a plain exception that preserves the chain.
                raise RuntimeError(new_msg) from e
        # Soft-error path: dict with "error" and no existing state.
        if isinstance(result, dict) and "error" in result \
                and "aragorn_state" not in result:
            try:
                result["aragorn_state"] = await current_state_snapshot()
            except Exception:
                pass
        return result
    # Mark so we don't accidentally double-wrap later.
    wrapper.__aragorn_state_wrapped__ = True
    return wrapper


class StateWrappingMCP:
    """Proxy around FastMCP that wraps every registered tool with
    `wrap_tool` before handing the function off to the real `mcp.tool`
    decorator.
    """

    def __init__(self, inner):
        self._inner = inner

    def tool(self, *args, **kwargs):
        inner_decorator = self._inner.tool(*args, **kwargs)

        def wrap_then_register(fn):
            if getattr(fn, "__aragorn_state_wrapped__", False):
                return inner_decorator(fn)
            return inner_decorator(wrap_tool(fn))

        return wrap_then_register

    def __getattr__(self, name):
        return getattr(self._inner, name)
