"""Multi-session debugger management.

Manages multiple Debugger instances, each with its own kd.exe subprocess
and COM thread. Follows the boneless-ida session pattern — tools take an
optional session_id, defaulting to the active session.

Each session represents an independent kernel debugger connection to a
different VM (or the same VM on different ports).
"""

import asyncio
import concurrent.futures
import logging
import time
from dataclasses import dataclass, field

from . import config
from .debugger import Debugger

log = logging.getLogger("aragorn.sessions")


@dataclass
class SessionInfo:
    """Metadata and runtime state for a debugger session."""
    session_id: str
    label: str                          # human-readable label (e.g. "vm-01")
    kd_connection: str                  # kdnet connection string
    kd_server_port: int                 # local TCP port for kd.exe debug server
    vm_agent_url: str = ""            # VM agent REST URL for this VM
    vm_agent_api_key: str = ""
    debugger: Debugger | None = None
    com_executor: concurrent.futures.ThreadPoolExecutor | None = None
    created_at: float = field(default_factory=time.time)
    vm_name: str = ""                   # Hyper-V VM name

    @property
    def is_connected(self) -> bool:
        return self.debugger is not None and self.debugger.is_connected


class SessionRegistry:
    """Registry of debugger sessions.

    Thread-safe management of multiple Debugger instances, each with its own
    dedicated COM thread (DbgEng has thread affinity).
    """

    def __init__(self):
        self._sessions: dict[str, SessionInfo] = {}
        self._active_session: str | None = None
        self._lock = asyncio.Lock()

    @property
    def active_session_id(self) -> str | None:
        return self._active_session

    def resolve_session(self, session_id: str = "") -> SessionInfo:
        """Resolve a session_id to a SessionInfo.

        If session_id is empty, returns the active session.
        Raises KeyError if not found.
        """
        sid = session_id or self._active_session
        if not sid:
            raise KeyError("No active session. Create one with session_create().")
        if sid not in self._sessions:
            raise KeyError(
                f"Session '{sid}' not found. "
                f"Available: {list(self._sessions.keys())}"
            )
        return self._sessions[sid]

    def get_debugger(self, session_id: str = "") -> Debugger:
        """Get the Debugger instance for a session. Raises if not connected."""
        info = self.resolve_session(session_id)
        if info.debugger is None:
            raise KeyError(f"Session '{info.session_id}' has no debugger. Call session_connect().")
        return info.debugger

    async def run_on_com_thread(self, session_id: str, func, *args, timeout: float = 0):
        """Run func on the session's dedicated COM thread with timeout."""
        import asyncio
        from . import config
        info = self.resolve_session(session_id)
        if info.com_executor is None:
            raise KeyError(f"Session '{info.session_id}' has no COM executor.")
        loop = asyncio.get_running_loop()
        ceiling = timeout if timeout > 0 else getattr(config, "HARD_TIMEOUT_S", 600)
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(info.com_executor, func, *args),
                timeout=ceiling,
            )
        except asyncio.TimeoutError:
            # Abort transport (transport-aware) to unblock the stuck COM thread.
            recovery = None
            if info.debugger is not None:
                try:
                    recovery = info.debugger.recover_from_wedge()
                except Exception as e:
                    recovery = {"status": "recover_failed", "error": str(e)}
            from .dbgeng import DbgEngError
            raise DbgEngError(-1,
                f"COM call timed out after {ceiling:.0f}s. "
                f"Transport aborted ({recovery}). "
                f"Call ensure_ready() to reconnect.")

    async def create_session(
        self,
        session_id: str,
        label: str = "",
        kd_connection: str = "",
        kd_server_port: int = 0,
        vm_agent_url: str = "",
        vm_agent_api_key: str = "",
        vm_name: str = "",
        auto_connect: bool = True,
    ) -> dict:
        """Create a new debugger session.

        Args:
            session_id: Unique session identifier (e.g. "vm-01")
            label: Human-readable label
            kd_connection: kdnet connection string (e.g. "net:port=55555,key=...,target=...")
            kd_server_port: Local TCP port for kd.exe (must be unique per session)
            vm_agent_url: VM agent REST URL for this VM
            vm_agent_api_key: API key for VM agent
            vm_name: Hyper-V VM name
            auto_connect: Connect immediately after creation
        """
        async with self._lock:
            if session_id in self._sessions:
                return {"error": f"Session '{session_id}' already exists"}

            info = SessionInfo(
                session_id=session_id,
                label=label or session_id,
                kd_connection=kd_connection or config.KD_CONNECTION,
                kd_server_port=kd_server_port or config.KD_SERVER_PORT,
                vm_agent_url=vm_agent_url or config.VM_AGENT_URL,
                vm_agent_api_key=vm_agent_api_key or config.VM_AGENT_API_KEY,
                vm_name=vm_name,
            )

            # Each session gets its own COM thread (DbgEng thread affinity)
            info.com_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=1,
                thread_name_prefix=f"dbgeng-{session_id}",
            )

            self._sessions[session_id] = info

            if self._active_session is None:
                self._active_session = session_id

            log.info("Session '%s' created (port=%d, conn=%s)",
                     session_id, info.kd_server_port, info.kd_connection)

        if auto_connect:
            return await self.connect_session(session_id)

        return self._session_status(info)

    async def connect_session(self, session_id: str = "",
                              kd_wait_timeout: int = 60,
                              max_retries: int | None = None) -> dict:
        """Connect a session's debugger to the target kernel.

        Args:
            session_id: Session to connect (default: active session).
            kd_wait_timeout: Seconds to wait for kd.exe to connect (default 60).
            max_retries: Override CONNECT_RETRIES (default: use config value).
        """
        info = self.resolve_session(session_id)

        if info.debugger is not None and info.debugger.is_connected:
            return {"status": "already_connected", **self._session_status(info)}

        # Create a new Debugger with session-specific config
        dbg = Debugger()
        info.debugger = dbg

        def _connect():
            # Temporarily override config for this session's connection
            orig_conn = config.KD_CONNECTION
            orig_port = config.KD_SERVER_PORT
            orig_lb_url = config.VM_AGENT_URL
            orig_lb_key = config.VM_AGENT_API_KEY
            orig_retries = config.CONNECT_RETRIES
            try:
                config.KD_CONNECTION = info.kd_connection
                config.KD_SERVER_PORT = info.kd_server_port
                config.VM_AGENT_URL = info.vm_agent_url
                config.VM_AGENT_API_KEY = info.vm_agent_api_key
                if max_retries is not None:
                    config.CONNECT_RETRIES = max_retries
                dbg.connect(kd_wait_timeout=kd_wait_timeout)
            finally:
                config.KD_CONNECTION = orig_conn
                config.KD_SERVER_PORT = orig_port
                config.VM_AGENT_URL = orig_lb_url
                config.VM_AGENT_API_KEY = orig_lb_key
                config.CONNECT_RETRIES = orig_retries

        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(info.com_executor, _connect)
            log.info("Session '%s' connected", info.session_id)
            return self._session_status(info)
        except Exception as e:
            log.error("Session '%s' connection failed: %s", info.session_id, e)
            info.debugger = None
            return {"error": str(e), "session_id": info.session_id}

    async def disconnect_session(self, session_id: str = "") -> dict:
        """Disconnect a session's debugger without destroying the session."""
        info = self.resolve_session(session_id)
        if info.debugger is None or not info.debugger.is_connected:
            return {"status": "not_connected", "session_id": info.session_id}

        # Abort transport first to unblock any stuck COM call.
        try:
            info.debugger.recover_from_wedge()
        except Exception as e:
            log.warning("disconnect_session '%s': recover_from_wedge: %s",
                        info.session_id, e)

        def _disconnect():
            info.debugger.shutdown()

        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(info.com_executor, _disconnect),
                timeout=5.0,
            )
        except (asyncio.TimeoutError, Exception) as e:
            log.warning("disconnect_session '%s': %s", info.session_id, e)
        info.debugger = None
        log.info("Session '%s' disconnected", info.session_id)
        return {"status": "disconnected", "session_id": info.session_id}

    async def destroy_session(self, session_id: str) -> dict:
        """Destroy a session — disconnect, clean up COM thread, remove from registry."""
        async with self._lock:
            if session_id not in self._sessions:
                return {"error": f"Session '{session_id}' not found"}

            info = self._sessions[session_id]

            # Abort transport first to unblock any stuck COM calls.
            if info.debugger is not None:
                try:
                    recovery = info.debugger.recover_from_wedge()
                    log.info("destroy_session '%s': %s", session_id, recovery)
                except Exception as e:
                    log.warning("destroy_session '%s': recover_from_wedge: %s",
                                session_id, e)

            # Disconnect debugger (with timeout — COM thread may be stuck)
            if info.debugger is not None and info.com_executor is not None:
                try:
                    loop = asyncio.get_running_loop()
                    await asyncio.wait_for(
                        loop.run_in_executor(info.com_executor, info.debugger.shutdown),
                        timeout=5.0,
                    )
                except (asyncio.TimeoutError, Exception) as e:
                    log.warning("Session '%s' shutdown: %s (proceeding)", session_id, e)

            # Shutdown COM thread
            if info.com_executor is not None:
                info.com_executor.shutdown(wait=False)

            del self._sessions[session_id]

            # Update active session
            if self._active_session == session_id:
                self._active_session = next(iter(self._sessions), None)

            log.info("Session '%s' destroyed", session_id)
            return {"status": "destroyed", "session_id": session_id}

    def set_active(self, session_id: str) -> dict:
        """Set the active session."""
        if session_id not in self._sessions:
            return {"error": f"Session '{session_id}' not found"}
        self._active_session = session_id
        return {"active_session": session_id}

    def list_sessions(self) -> list[dict]:
        """List all sessions with their status."""
        return [self._session_status(info) for info in self._sessions.values()]

    def _session_status(self, info: SessionInfo) -> dict:
        result = {
            "session_id": info.session_id,
            "label": info.label,
            "vm_name": info.vm_name,
            "kd_connection": info.kd_connection,
            "kd_server_port": info.kd_server_port,
            "vm_agent_url": info.vm_agent_url,
            "connected": info.is_connected,
            "active": info.session_id == self._active_session,
            "created_at": info.created_at,
        }
        if info.debugger and info.is_connected:
            try:
                result["uptime_seconds"] = round(
                    time.time() - (info.debugger._connect_time or time.time()), 1
                )
            except Exception:
                pass
        return result


# Module-level singleton registry
_registry = SessionRegistry()


def get_registry() -> SessionRegistry:
    """Get the global session registry."""
    return _registry


# ── Compatibility layer ──────────────────────────────────────────────
#
# These functions maintain backward compatibility with existing tools
# that call get_debugger() / run_on_com_thread().  They delegate to
# the registry, resolving session_id="" to the active session.
# The original debugger.py singleton functions still work for the
# single-session case.
#

def get_debugger_for_session(session_id: str = "") -> Debugger:
    """Get debugger for a session (backward-compat wrapper)."""
    return _registry.get_debugger(session_id)


async def run_on_session_com_thread(session_id: str, func, *args):
    """Run on a session's COM thread (backward-compat wrapper)."""
    return await _registry.run_on_com_thread(session_id, func, *args)
