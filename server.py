"""Aragorn — Direct DbgEng COM kernel debugger MCP server.

This process IS the debugger. It launches kd.exe as a debug server for
kdnet transport, then connects via DebugConnect() for full COM access.

Architecture:
    MCP Client ──MCP/stdio──► Aragorn ──DebugConnect(TCP)──► kd.exe ──kdnet──► VM kernel

Usage:
    # Launch via .mcp.json (stdio) or run directly for HTTP mode:
    python server.py --http
"""

import logging
import os
import sys

from dotenv import load_dotenv

# Load .env before any config imports
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from mcp.server.fastmcp import FastMCP

# Ensure package imports work when run as a script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Aragorn import config
from Aragorn.tools import (
    core,
    session,
    multi_session,
    memory,
    registers,
    stack,
    breakpoints,
    execution,
    inspection,
    symbols,
    events,
    kernel,
    workflow,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)

# Create the MCP server
mcp = FastMCP(
    "Aragorn",
    host=config.ARAGORN_HOST,
    port=config.ARAGORN_PORT,
    instructions=(
        "Direct kernel debugger for Windows VM security research. "
        "Connects to the VM kernel via COM pipe using DbgEng COM interfaces. "
        "No WinDbg dependency — this server IS the debugger.\n\n"
        "Start by calling status() to check connection state, then "
        "ensure_ready() to break in and verify the debugger is usable. "
        "Use execute() for raw debugger commands, or the specialized tools "
        "for structured access to memory, registers, breakpoints, etc.\n\n"
        "For coordinated exploit testing, use breakpoint_and_run() — it sets "
        "a breakpoint, runs a VM command, and captures results in one atomic "
        "operation. Direct VM access is available via vm_exec, vm_read_file, "
        "vm_write_file without needing a separate VM agent."
    ),
)

# Register all tool modules
for mod in [core, session, multi_session, memory, registers, stack,
            breakpoints, execution, inspection, symbols, events, kernel,
            workflow]:
    mod.register(mcp)


if __name__ == "__main__":
    print(f"[Aragorn] DbgEng: {config.DBGENG_PATH}", file=sys.stderr)
    print(f"[Aragorn] Connection: {config.KD_CONNECTION}", file=sys.stderr)

    if "--http" in sys.argv:
        print(f"[Aragorn] HTTP mode on http://{config.ARAGORN_HOST}:{config.ARAGORN_PORT}/mcp",
              file=sys.stderr)
        mcp.run(transport="streamable-http")
    else:
        print("[Aragorn] stdio mode", file=sys.stderr)
        mcp.run(transport="stdio")
