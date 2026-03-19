"""Multi-session debugger management tools.

Create sessions with session_create(),
then target them with session_id on any tool. If session_id is omitted,
the active session is used.
"""

import json
import logging

from ..sessions import get_registry

log = logging.getLogger("aragorn.tools.multi_session")


def register(mcp):

    @mcp.tool()
    async def session_create(
        session_id: str,
        kd_connection: str,
        kd_server_port: int,
        label: str = "",
        vm_agent_url: str = "",
        vm_agent_api_key: str = "",
        vm_name: str = "",
        auto_connect: bool = True,
    ) -> str:
        """Create a new debugger session for a VM.

        Each session gets its own kd.exe subprocess and COM thread, fully
        isolated from other sessions. Use this to parallelize exploit dev
        across multiple VMs.

        Args:
            session_id: Unique identifier (e.g. "vm-01", "info-leak-agent")
            kd_connection: kdnet connection string (e.g. "net:port=55556,key=...,target=172.26.50.192")
            kd_server_port: Local TCP port for this session's kd.exe (must be unique, e.g. 14501)
            label: Human-readable label
            vm_agent_url: VM agent URL for this VM (e.g. "http://172.26.50.192:8080")
            vm_agent_api_key: API key for the VM agent
            vm_name: Hyper-V VM name
            auto_connect: Connect to the kernel immediately (default True)
        """
        reg = get_registry()
        result = await reg.create_session(
            session_id=session_id,
            label=label,
            kd_connection=kd_connection,
            kd_server_port=kd_server_port,
            vm_agent_url=vm_agent_url,
            vm_agent_api_key=vm_agent_api_key,
            vm_name=vm_name,
            auto_connect=auto_connect,
        )
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def session_connect(session_id: str = "") -> str:
        """Connect a session's debugger to the target kernel.

        Args:
            session_id: Session to connect (default: active session)
        """
        reg = get_registry()
        result = await reg.connect_session(session_id)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def session_disconnect(session_id: str = "") -> str:
        """Disconnect a session's debugger without destroying the session.

        Args:
            session_id: Session to disconnect (default: active session)
        """
        reg = get_registry()
        result = await reg.disconnect_session(session_id)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def session_destroy(session_id: str) -> str:
        """Destroy a session — disconnect, clean up, and remove from registry.

        Args:
            session_id: Session to destroy
        """
        reg = get_registry()
        result = await reg.destroy_session(session_id)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def session_list() -> str:
        """List all debugger sessions with their connection status."""
        reg = get_registry()
        return json.dumps(reg.list_sessions(), indent=2, default=str)

    @mcp.tool()
    async def session_set_active(session_id: str) -> str:
        """Set the active session. Tools that omit session_id will use this one.

        Args:
            session_id: Session to make active
        """
        reg = get_registry()
        result = reg.set_active(session_id)
        return json.dumps(result, indent=2, default=str)
