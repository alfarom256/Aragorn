"""Aragorn debugger worker — child process that owns dbgeng.

The MCP server (the "supervisor") spawns this as a subprocess and talks
to it via JSON-RPC over stdio. All dbgeng state — the loaded DLL, COM
interfaces, kdnet session — lives here. When this worker wedges (which
in practice happens after dbgeng's "one direct attach per process"
limit hits), the supervisor kills it and spawns a fresh one without
ever disturbing the MCP pipe to Claude.

Wire format: newline-delimited JSON, one request/response per line.

Request:  `{"id": int, "method": str, "args": list, "kwargs": dict}`
Response: `{"id": int, "ok": true,  "result": <json>}`
       OR `{"id": int, "ok": false, "error_type": str, "error_message": str, "traceback": str}`

Special methods (don't need a Debugger instance):
    "_ping"           → echoes back; latency probe
    "_shutdown"       → graceful exit
    "_pid"            → returns os.getpid()

Everything else is dispatched as `getattr(debugger_singleton, method)(*args, **kwargs)`.
The singleton is constructed lazily on first non-special method call,
or explicitly via "_init_debugger".
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import traceback
from typing import Any

# Make sure the project root is importable when launched as a script.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from dotenv import load_dotenv

load_dotenv(os.path.join(_HERE, ".env"))

# Configure logging to stderr so it doesn't pollute the stdio JSON channel.
logging.basicConfig(
    level=os.environ.get("ARAGORN_WORKER_LOG_LEVEL", "INFO"),
    format="%(asctime)s [worker.%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("aragorn.worker")

from Aragorn import debugger as _dbg_mod
from Aragorn.dbgeng import DbgEngError


# Single Debugger instance for the worker.
_debugger: _dbg_mod.Debugger | None = None
_lock = threading.Lock()


def _ensure_debugger() -> _dbg_mod.Debugger:
    global _debugger
    with _lock:
        if _debugger is None:
            _debugger = _dbg_mod.Debugger()
            _dbg_mod.set_debugger(_debugger)
    return _debugger


def _serialize(obj: Any) -> Any:
    """Best-effort JSON serialization for arbitrary Python values."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (list, tuple)):
        return [_serialize(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _serialize(v) for k, v in obj.items()}
    # Fallback — repr it.
    return repr(obj)


def _dispatch(method: str, args: list, kwargs: dict) -> Any:
    if method == "_ping":
        return {"pong": True, "pid": os.getpid()}
    if method == "_shutdown":
        log.info("Shutdown requested")
        os._exit(0)
    if method == "_pid":
        return os.getpid()
    if method == "_init_debugger":
        _ensure_debugger()
        return True

    dbg = _ensure_debugger()

    # Allow reading attributes (e.g., is_connected) without parens.
    if method.startswith("@"):
        attr = method[1:]
        return getattr(dbg, attr)

    fn = getattr(dbg, method, None)
    if fn is None or not callable(fn):
        raise AttributeError(f"Debugger has no method {method!r}")
    return fn(*args, **kwargs)


def _handle_request(line: str) -> str:
    try:
        req = json.loads(line)
    except json.JSONDecodeError as e:
        log.warning("Bad JSON request: %s", e)
        return json.dumps({"id": None, "ok": False,
                           "error_type": "JSONDecodeError",
                           "error_message": str(e),
                           "traceback": ""})

    rid = req.get("id")
    method = req.get("method", "")
    args = req.get("args", []) or []
    kwargs = req.get("kwargs", {}) or {}

    try:
        result = _dispatch(method, args, kwargs)
        return json.dumps({"id": rid, "ok": True,
                           "result": _serialize(result)},
                          default=str)
    except SystemExit:
        raise
    except DbgEngError as e:
        return json.dumps({"id": rid, "ok": False,
                           "error_type": "DbgEngError",
                           "error_message": str(e),
                           "hr": getattr(e, "hr", None),
                           "traceback": traceback.format_exc()})
    except Exception as e:
        return json.dumps({"id": rid, "ok": False,
                           "error_type": type(e).__name__,
                           "error_message": str(e),
                           "traceback": traceback.format_exc()})


def main() -> None:
    log.info("Worker starting (pid=%d)", os.getpid())
    # Make sure stdout is line-buffered text (Python defaults are usually fine
    # but we want certainty).
    out = sys.stdout
    while True:
        line = sys.stdin.readline()
        if not line:                       # EOF — supervisor closed pipe
            log.info("stdin EOF — exiting")
            break
        line = line.strip()
        if not line:
            continue
        resp = _handle_request(line)
        out.write(resp + "\n")
        out.flush()


if __name__ == "__main__":
    main()
