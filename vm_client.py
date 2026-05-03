"""HTTP client to VM agent for coordinated debugger+VM operations.

This lets Aragorn directly execute VM commands, read/write files, etc. without
needing a separate vm-executor delegate. Used by the workflow tools module.
"""

import base64
import logging
from pathlib import Path

import httpx

from . import config

log = logging.getLogger("aragorn.vm_client")


class VMClient:
    """Async HTTP client for the VM agent REST API on the VM."""

    def __init__(self, url: str = None, api_key: str = None):
        self.url = (url or config.VM_AGENT_URL).rstrip("/")
        self.api_key = api_key or config.VM_AGENT_API_KEY
        self._headers = {"X-API-Key": self.api_key, "Accept": "application/json"}

    async def status(self) -> dict:
        """Check if the VM is reachable."""
        return await self._get("/status")

    async def exec(self, command: str, args: list[str] = None,
                   cwd: str = None, timeout: int = 30,
                   capture_output: bool = True, env: dict = None) -> dict:
        """Execute a process on the VM.

        Args:
            command: Executable path or name.
            args: Command-line arguments.
            cwd: Working directory.
            timeout: Seconds before process is killed.
            capture_output: Whether to capture stdout/stderr.
            env: Extra environment variables.
        """
        body = {
            "executable": command,
            "args": args or [],
            "timeout": timeout,
            "capture_output": capture_output,
        }
        if cwd:
            body["cwd"] = cwd
        if env:
            body["env"] = env
        return await self._post("/exec", body, timeout=timeout + 10)

    async def read_file(self, path: str) -> dict:
        """Read a file from the VM."""
        return await self._get("/file", params={"path": path})

    async def write_file(self, path: str, content: str, overwrite: bool = True) -> dict:
        """Write text content to a file on the VM."""
        content_b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        return await self._post("/upload", {
            "path": path,
            "content_b64": content_b64,
            "overwrite": overwrite,
        })

    async def upload_file(self, local_path: str, remote_path: str,
                          overwrite: bool = False) -> dict:
        """Upload a file from the host to the VM."""
        p = Path(local_path)
        if not p.exists():
            return {"error": f"Local file not found: {local_path}"}
        if not p.is_file():
            return {"error": f"Not a file: {local_path}"}

        raw = p.read_bytes()
        content_b64 = base64.b64encode(raw).decode("ascii")
        return await self._post("/upload", {
            "path": remote_path,
            "content_b64": content_b64,
            "overwrite": overwrite,
        })

    async def list_files(self, path: str) -> dict:
        """List directory contents on the VM."""
        return await self._get("/files", params={"path": path})

    async def list_processes(self) -> dict:
        """List running processes on the VM."""
        return await self._get("/processes")

    # ─── HTTP helpers ────────────────────────────────────────────────

    async def _get(self, path: str, params: dict = None, timeout: float = 60) -> dict:
        url = f"{self.url}{path}"
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url, headers=self._headers, params=params)
                return self._handle(resp, path)
        except httpx.ConnectError:
            return {"error": f"VM unreachable: cannot connect to {url}", "infrastructure_error": True}
        except httpx.TimeoutException:
            return {"error": f"VM timeout: {url} timed out after {timeout}s", "infrastructure_error": True}

    async def _post(self, path: str, body: dict, timeout: float = 60) -> dict:
        url = f"{self.url}{path}"
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, headers=self._headers, json=body)
                return self._handle(resp, path)
        except httpx.ConnectError:
            return {"error": f"VM unreachable: cannot connect to {url}", "infrastructure_error": True}
        except httpx.TimeoutException:
            return {"error": f"VM timeout: {url} timed out after {timeout}s", "infrastructure_error": True}

    @staticmethod
    def _handle(resp, path: str) -> dict:
        if resp.status_code == 404:
            return {"error": f"Endpoint not found: {path}", "infrastructure_error": True}
        if resp.status_code >= 400:
            try:
                return resp.json()
            except Exception:
                return {"error": f"HTTP {resp.status_code} from {path}: {resp.text[:500]}"}
        return resp.json()


# Module-level cache (keyed by URL to avoid stale singletons)
_client: VMClient | None = None
_client_url: str | None = None


def get_vm_client(url: str | None = None, api_key: str | None = None) -> VMClient:
    """Get or create a VMClient.

    If url is provided and differs from the cached client's URL,
    a new client is created. This prevents stale singletons when
    switching between VMs or sessions.
    """
    global _client, _client_url
    target_url = url or config.VM_AGENT_URL
    if _client is None or (_client_url and target_url != _client_url):
        _client = VMClient(url=target_url, api_key=api_key)
        _client_url = target_url
    return _client
