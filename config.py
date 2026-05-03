"""Aragorn configuration — settings from environment variables."""

import os

# DbgEng DLL path — WinDbg Preview's version (has extension support)
DBGENG_PATH = os.environ.get(
    "DBGENG_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "dbgeng_bin", "dbgeng.dll"),
)

# kd.exe path — WinDbg Preview's kernel debugger (handles kdnet transport).
# Override via env var if your install path differs.
KD_EXE_PATH = os.environ.get(
    "KD_EXE_PATH",
    r"C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2601.12001.0_x64__8wekyb3d8bbwe\amd64\kd.exe",
)

# Kernel debug connection string (kdnet for Hyper-V)
KD_CONNECTION = os.environ.get(
    "KD_CONNECTION",
    r"net:port=55555,key=YOUR_KDNET_KEY,target=YOUR_VM_IP",
)

# Local TCP port for kd.exe debug server (Aragorn connects here via DebugConnect)
KD_SERVER_PORT = int(os.environ.get("KD_SERVER_PORT", "14500"))

# Transport for the kernel debugger.
#   "direct"    — in-process IDebugClient::AttachKernel, no kd.exe subprocess.
#   "kd_server" — launch kd.exe as a debug server, connect via DebugConnect (legacy).
ARAGORN_TRANSPORT = os.environ.get("ARAGORN_TRANSPORT", "direct").lower()

# Initial kdnet sync timeout — first WaitForEvent after AttachKernel (ms).
KD_SYNC_TIMEOUT_MS = int(os.environ.get("KD_SYNC_TIMEOUT_MS", "30000"))

# SetInterrupt + WaitForEvent timeout when initial_break=True (ms).
INITIAL_BREAK_TIMEOUT_MS = int(os.environ.get("INITIAL_BREAK_TIMEOUT_MS", "10000"))

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

# Stall detection (two-phase watchdog for Execute() calls)
INITIAL_GRACE_S = int(os.environ.get("INITIAL_GRACE_S", "60"))
STALL_TIMEOUT_S = int(os.environ.get("STALL_TIMEOUT_S", "30"))
HARD_TIMEOUT_S = int(os.environ.get("HARD_TIMEOUT_S", "600"))
AUTO_RESUME_S = int(os.environ.get("AUTO_RESUME_S", "15"))

# Event queue max size
EVENT_QUEUE_SIZE = 1000

# VM agent connection — enables coordinated workflow tools
VM_AGENT_URL = os.environ.get("VM_AGENT_URL", "http://YOUR_VM_IP:8080")
VM_AGENT_API_KEY = os.environ.get("VM_AGENT_API_KEY", "")
