"""Aragorn configuration — settings from environment variables."""

import os

# DbgEng DLL path — WinDbg Preview's version (has extension support)
DBGENG_PATH = os.environ.get(
    "DBGENG_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "dbgeng_bin", "dbgeng.dll"),
)

# kd.exe path — WinDbg Preview's kernel debugger (handles kdnet transport)
KD_EXE_PATH = os.environ.get(
    "KD_EXE_PATH",
    r"C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2601.12001.0_x64__8wekyb3d8bbwe\amd64\kd.exe",
)

# Kernel debug connection string (kdnet for Hyper-V)
KD_CONNECTION = os.environ.get("KD_CONNECTION", "")

# Local TCP port for kd.exe debug server (Aragorn connects here via DebugConnect)
KD_SERVER_PORT = int(os.environ.get("KD_SERVER_PORT", "14500"))

# Symbol search path
SYMBOL_PATH = os.environ.get(
    "SYMBOL_PATH",
    r"srv*C:\Symbols*https://msdl.microsoft.com/download/symbols",
)

# WinDbg extension directory (for !analyze, !process, etc.)
EXTENSION_PATH = os.environ.get(
    "EXTENSION_PATH",
    r"C:\Program Files\Windows Kits\10\Debuggers\x64\winext",
)

# Streamable-HTTP server settings
ARAGORN_HOST = os.environ.get("ARAGORN_HOST", "127.0.0.1")
ARAGORN_PORT = int(os.environ.get("ARAGORN_PORT", "14401"))

# Connection retry settings
CONNECT_RETRIES = 2
CONNECT_BACKOFF_SECONDS = 3

# Default command timeout (milliseconds)
DEFAULT_TIMEOUT_MS = 10_000

# Event queue max size
EVENT_QUEUE_SIZE = 1000

# VM agent connection — enables coordinated workflow tools
# (breakpoint_and_run, vm_exec, vm_read_file, etc.)
VM_AGENT_URL = os.environ.get("VM_AGENT_URL", "")
VM_AGENT_API_KEY = os.environ.get("VM_AGENT_API_KEY", "")
