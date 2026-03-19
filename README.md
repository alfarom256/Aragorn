# Aragorn

Direct kernel debugger MCP server for Windows security research. Connects to Windows VM kernels via kdnet and exposes 63 tools over the [Model Context Protocol](https://modelcontextprotocol.io/).

This process **is** the debugger. It spawns `kd.exe` as a subprocess for kdnet transport, then connects via `DebugConnect()` for full DbgEng COM access. No WinDbg GUI required.

```
MCP Client ──stdio/http──► Aragorn ──DebugConnect(TCP)──► kd.exe ──kdnet──► VM kernel
```

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy DbgEng DLLs from WinDbg Preview into dbgeng_bin/
#    (dbgeng.dll, dbghelp.dll, dbgmodel.dll, dbgcore.dll, symsrv.dll, srcsrv.dll)

# 3. Configure
cp .env.example .env
# Edit .env: set KD_CONNECTION, KD_EXE_PATH, etc.

# 4. Run (stdio mode — for MCP clients like Claude Code)
python server.py

# Or HTTP mode (for remote/shared access)
python server.py --http
```

### .mcp.json integration

```json
{
  "aragorn": {
    "type": "stdio",
    "command": "python",
    "args": ["path/to/Aragorn/server.py"]
  }
}
```

## Configuration

All settings are via environment variables (or `.env` file):

| Variable | Default | Description |
|---|---|---|
| `KD_CONNECTION` | `net:port=55555,key=...,target=...` | kdnet connection string |
| `KD_EXE_PATH` | WinDbg Preview's kd.exe | Path to kd.exe |
| `KD_SERVER_PORT` | `14500` | Local TCP port for kd.exe debug server |
| `DBGENG_PATH` | `./dbgeng_bin/dbgeng.dll` | Path to DbgEng DLL |
| `SYMBOL_PATH` | Microsoft symbol server | Symbol search path |
| `ARAGORN_HOST` | `127.0.0.1` | HTTP mode bind address |
| `ARAGORN_PORT` | `14401` | HTTP mode port |
| `VM_AGENT_URL` | `http://YOUR_VM_IP:8080` | VM agent URL (for workflow tools) |
| `VM_AGENT_API_KEY` | *(empty)* | VM agent API key |

## DbgEng Binaries

The `dbgeng_bin/` directory is gitignored. Copy these DLLs from your WinDbg Preview installation:

```
C:\Program Files\WindowsApps\Microsoft.WinDbg_*\amd64\
  ├── dbgeng.dll
  ├── dbghelp.dll
  ├── dbgmodel.dll
  ├── dbgcore.dll
  ├── symsrv.dll
  └── srcsrv.dll
```

## VM Agent

The `vm_agent/` directory contains a lightweight Flask server that runs **inside the target VM**. It exposes process execution, file I/O, and driver service management over HTTP. Aragorn's workflow tools (`breakpoint_and_run`, `vm_exec`, etc.) use it to coordinate kernel debugging with VM-side actions.

```bash
# On the VM:
cd vm_agent
pip install -r requirements.txt
cp .env.example .env
# Edit .env: set VM_AGENT_API_KEY
python server.py
```

The VM agent is optional — all pure debugger tools work without it. You only need it for the coordinated workflow tools.

## Tools

### Session & Connection (9)

| Tool | Description |
|---|---|
| `connect` | Connect to kernel debugger via kd.exe |
| `disconnect` | Cleanly disconnect |
| `status` | Get connection state and config |
| `target_info` | Get debug target info (class, processors, page size) |
| `ensure_ready` | Break in, verify context, reload symbols (retries 5x) |
| `health_check` | Lightweight probe without breaking into target |
| `reconnect_debugger` | Force full reconnect |
| `test_kd_connection` | Diagnostic kd.exe connection test |
| `get_debugger_state` | Full tracked state for cross-agent coordination |

### Multi-Session (6)

| Tool | Description |
|---|---|
| `session_create` | Create isolated debugger session for a VM |
| `session_connect` | Connect a session's debugger |
| `session_disconnect` | Disconnect without destroying |
| `session_destroy` | Destroy and clean up a session |
| `session_list` | List all sessions with status |
| `session_set_active` | Set active session for tool routing |

### Command Execution (3)

| Tool | Description |
|---|---|
| `execute` | Execute raw debugger command (e.g., `lm`, `!process 0 0`) |
| `execute_batch` | Execute multiple commands sequentially |
| `evaluate` | Evaluate expression, return numeric value |

### Memory (7)

| Tool | Description |
|---|---|
| `read_memory` | Read virtual memory (hex/qwords/dwords/ascii) |
| `write_memory` | Write bytes to virtual memory |
| `search_memory` | Search for byte pattern |
| `read_physical` | Read physical memory |
| `write_physical` | Write to physical memory |
| `virtual_to_physical` | Translate virtual to physical address |
| `read_msr` | Read Model-Specific Register |

### Registers (2)

| Tool | Description |
|---|---|
| `read_registers` | Read all general-purpose registers |
| `write_register` | Write a register value |

### Stack (1)

| Tool | Description |
|---|---|
| `get_stack` | Get structured stack trace with symbols |

### Breakpoints (4)

| Tool | Description |
|---|---|
| `set_breakpoint` | Set code or data/hardware breakpoint |
| `remove_breakpoint` | Remove breakpoint by ID |
| `list_breakpoints` | List all breakpoints with status |
| `set_exception_filter` | Configure exception handling (break/ignore/output) |

### Execution Control (4)

| Tool | Description |
|---|---|
| `continue_exec` | Resume execution (robust, retries to drain kdnet breaks) |
| `step_into` | Single-step into calls |
| `step_over` | Single-step over calls |
| `break_in` | Interrupt target execution |

### Inspection (4)

| Tool | Description |
|---|---|
| `list_modules` | List loaded modules with base/size/name |
| `list_threads` | List threads with engine/system IDs |
| `list_processes` | List processes with engine/system IDs |
| `switch_process` | Switch to process context (.process /i) |

### Symbols (4)

| Tool | Description |
|---|---|
| `resolve_symbol` | Bidirectional symbol/address resolution |
| `get_field_offset` | Get struct field byte offset |
| `get_type_size` | Get type size in bytes |
| `disassemble` | Disassemble instructions at address |

### Events (3)

| Tool | Description |
|---|---|
| `wait_for_event` | Block until next debug event |
| `poll_events` | Return queued events without blocking |
| `clear_events` | Discard all queued events |

### Kernel Objects (8)

| Tool | Description |
|---|---|
| `read_struct` | Read typed structure (dt equivalent) |
| `get_pte` | Get page table entry info |
| `pool_info` | Get pool allocation metadata |
| `get_driver_object` | Display driver object + dispatch table |
| `get_device_objects` | Display device object info |
| `get_object_info` | Display kernel object from object directory |
| `dump_ssdt` | Dump System Service Descriptor Table |
| `get_idt` | Dump Interrupt Descriptor Table |

### Workflow (8)

| Tool | Description |
|---|---|
| `breakpoint_and_run` | Atomic: set BP, resume, run VM command, wait for hit, capture state |
| `run_and_trace` | Set logging BPs at multiple addresses, run command, capture trace |
| `inspect_at_breakpoint` | Batch post-breakpoint inspection commands |
| `vm_exec` | Execute command on VM |
| `vm_read_file` | Read file from VM |
| `vm_write_file` | Write file to VM |
| `vm_upload_file` | Upload file from host to VM |
| `vm_status` | Check VM reachability |

## Architecture

```
Aragorn/
├── server.py          # FastMCP entry point, registers all tool modules
├── config.py          # Environment variable configuration
├── debugger.py        # High-level Debugger class (lifecycle, commands, reconnect)
├── dbgeng.py          # Pure ctypes COM interface definitions (6 interfaces)
├── callbacks.py       # IDebugOutputCallbacks + IDebugEventCallbacks
├── sessions.py        # Multi-session registry (parallel VM debugging)
├── vm_client.py       # Async HTTP client to VM agent
├── dbgeng_bin/        # DbgEng DLLs (gitignored, ~15MB)
├── vm_agent/          # REST server for target VM (Flask + psutil)
│   ├── server.py      # VM agent HTTP server
│   ├── requirements.txt
│   └── .env.example
└── tools/             # MCP tool modules (one per domain)
    ├── core.py        # execute, execute_batch, evaluate
    ├── session.py     # connect, disconnect, status, ensure_ready
    ├── multi_session.py  # session_create/connect/destroy/list
    ├── memory.py      # read/write virtual + physical memory, MSR
    ├── registers.py   # read/write registers
    ├── stack.py       # get_stack
    ├── breakpoints.py # set/remove/list breakpoints, exception filters
    ├── execution.py   # continue, step_into, step_over, break_in
    ├── inspection.py  # list modules/threads/processes, switch context
    ├── symbols.py     # resolve symbols, field offsets, disassemble
    ├── events.py      # wait/poll/clear debug events
    ├── kernel.py      # read_struct, PTE, pool, driver/device objects, SSDT, IDT
    └── workflow.py    # breakpoint_and_run, run_and_trace, VM proxy tools
```

### COM Interface Stack

Aragorn wraps six DbgEng COM interfaces via ctypes (no C++ extension needed):

- **IDebugClient** — Session lifecycle, callback registration
- **IDebugControl** — Command execution, breakpoints, execution status
- **IDebugDataSpaces2** — Virtual/physical memory, address translation
- **IDebugRegisters** — Register read/write
- **IDebugSymbols2** — Symbol resolution, type info, disassembly
- **IDebugSystemObjects** — Process/thread/module enumeration

All blocking COM operations are wrapped in `asyncio.to_thread()` for MCP stdio compatibility. Each session gets a dedicated COM thread (DbgEng has thread affinity).

## License

[WTFPL](LICENSE)
