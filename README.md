# Aragorn

Direct kernel debugger MCP server for Windows security research. Connects to Windows VM kernels via kdnet and exposes 72 tools over the [Model Context Protocol](https://modelcontextprotocol.io/).

This process **is** the debugger. There's no WinDbg GUI in the loop — Aragorn loads `dbgeng.dll` directly via ctypes COM and either drives the kernel attach in-process (`AttachKernelWide`, the default) or shells out to `kd.exe` as a debug server. Either way you get full DbgEng COM access — memory, registers, breakpoints, symbols, events — exposed as MCP tools.

```
MCP Client ──stdio/http──► Aragorn ──┬─► (direct)   AttachKernelWide ──kdnet──► VM kernel
                                      └─► (kd_server) DebugConnect(TCP) ──► kd.exe ──kdnet──► VM kernel
```

## Architecture

Aragorn runs as a two-process system:

- **Supervisor** — the MCP server that talks to your client. Stays alive across debugger crashes/wedges.
- **Worker** — a child Python subprocess that owns `dbgeng.dll` and the kernel connection.

The worker exists because `dbgeng.dll` enforces a **one-direct-attach-per-process** limit. After a wedge or a transport reset, the only reliable fix is a fresh process. Doing that in a worker means the supervisor (and your MCP pipe) keeps running. `restart_worker()` kills and respawns the worker — your client never has to reconnect.

Each multi-session debugger instance gets its own dedicated COM thread (DbgEng has thread affinity), and all blocking COM calls are wrapped in `asyncio.to_thread()` so the MCP stdio loop stays responsive.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Drop DbgEng DLLs into dbgeng_bin/ (see "DbgEng Binaries" below)

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
| `KD_EXE_PATH` | WinDbg Preview's kd.exe | Path to kd.exe (only used by `kd_server` transport) |
| `KD_SERVER_PORT` | `14500` | Local TCP port for kd.exe debug server |
| `ARAGORN_TRANSPORT` | `direct` | `direct` (in-process AttachKernel) or `kd_server` (legacy) |
| `KD_SYNC_TIMEOUT_MS` | `30000` | First WaitForEvent timeout after AttachKernel |
| `INITIAL_BREAK_TIMEOUT_MS` | `10000` | SetInterrupt timeout when `initial_break=True` |
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

### Session & Connection (12)

| Tool | Description |
|---|---|
| `connect` | Connect to kernel debugger (in-process AttachKernel by default) |
| `disconnect` | Cleanly disconnect |
| `status` | Get connection state and config |
| `target_info` | Get debug target info (class, processors, page size) |
| `ensure_ready` | Atomic: break in, verify thread context, reload symbols (retries 5x) |
| `health_check` | Lightweight probe without breaking into target |
| `restart_worker` | Kill the worker subprocess and spawn a fresh one (use after wedge) |
| `reset_engine` | Soft reset of the in-process engine state |
| `reconnect_debugger` | Force full reconnect |
| `test_kd_connection` | Diagnostic kd.exe connection test |
| `get_debugger_state` | Full tracked state for cross-agent coordination |
| `resolve_vm_target` | Resolve a Hyper-V VM name to its current IPv4 + update KD_CONNECTION |

### Multi-Session (6)

Run multiple isolated debugger sessions in one Aragorn process — one per VM. Each gets its own kd.exe / COM thread / state. Tools take an optional `session_id`; the active session is used if omitted.

| Tool | Description |
|---|---|
| `session_create` | Create an isolated debugger session for a VM |
| `session_connect` | Connect a session's debugger |
| `session_disconnect` | Disconnect without destroying |
| `session_destroy` | Destroy and clean up a session |
| `session_list` | List all sessions with status |
| `session_set_active` | Set the active session for tool routing |

### Command Execution (3)

| Tool | Description |
|---|---|
| `execute` | Execute raw debugger command (e.g., `lm`, `!process 0 0`) |
| `execute_batch` | Execute multiple commands sequentially |
| `evaluate` | Evaluate an expression, return numeric value |

### Memory (7)

| Tool | Description |
|---|---|
| `read_memory` | Read virtual memory (hex / qwords / dwords / ascii) |
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
| `get_stack` | Structured stack trace with symbols |

### Breakpoints (4)

| Tool | Description |
|---|---|
| `set_breakpoint` | Set code, data, or hardware breakpoint (with optional MASM `.if` condition) |
| `remove_breakpoint` | Remove breakpoint by ID |
| `list_breakpoints` | List all breakpoints with status |
| `set_exception_filter` | Configure exception handling (break / ignore / output) |

### Execution Control (4)

| Tool | Description |
|---|---|
| `continue_exec` | Resume execution (robust — drains spurious kdnet breaks, retries up to 10x) |
| `step_into` | Single-step into calls |
| `step_over` | Single-step over calls |
| `break_in` | Interrupt running target |

### Inspection (4)

| Tool | Description |
|---|---|
| `list_modules` | List loaded modules with base / size / name |
| `list_threads` | List threads with engine / system IDs |
| `list_processes` | List processes with engine / system IDs |
| `switch_process` | Switch to process context (`.process /i`) |

### Symbols (4)

| Tool | Description |
|---|---|
| `resolve_symbol` | Bidirectional symbol / address resolution |
| `get_field_offset` | Struct field byte offset |
| `get_type_size` | Type size in bytes |
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
| `read_struct` | Read typed structure (`dt` equivalent) |
| `get_pte` | Page table entry info |
| `pool_info` | Pool allocation metadata |
| `get_driver_object` | Driver object + dispatch table |
| `get_device_objects` | Device object info |
| `get_object_info` | Kernel object from object directory |
| `dump_ssdt` | System Service Descriptor Table |
| `get_idt` | Interrupt Descriptor Table |

### Structured Context (6)

One-shot context dumps via direct COM (no Execute() text parsing). Safe to call any time the target is broken in.

| Tool | Description |
|---|---|
| `get_cpu_state` | All GPRs + control regs + execution status in one call |
| `disasm_at` | Disassemble at address with structured output |
| `read_qwords` | Read N qwords with symbol resolution per slot |
| `get_current_process` | Current `_EPROCESS` summary (image name, PID, etc.) |
| `get_current_thread` | Current `_ETHREAD` summary |
| `get_full_context` | Combined CPU + process + thread + module snapshot |

### Workflow (8)

Coordinated debugger + VM operations. Require a running [VM agent](#vm-agent).

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

## Conditional breakpoints

Aragorn passes MASM `.if` conditions through to dbgeng natively:

```python
set_breakpoint(
    expression="<module>!<function>",
    condition=".if (poi(@rcx+0x10) == 0x1234) {} .else {gc}",
)
```

Two non-obvious gotchas (each one looks like a "spurious break" until you find it):

- **Use bitwise `&` and `|`, not logical `&&` / `||`.** `.if (1 && 0)` returns `HRESULT 0x80040205`; the engine falls back to its default action (break). Bitwise `&` / `|` work correctly on the `0`/`1` booleans that `==` produces.
- **Inline all reads.** Don't try to cache subexpressions with `r @$tN=expr`. The pseudo-register assignment also triggers fallback-to-break.

See `Claude-Docs/SKILL.md` for the full breakpoint playbook (rate-budget reasoning, JS predicates via `bp /w`, validation workflow, common patterns).

## Layout

```
Aragorn/
├── server.py             # FastMCP entry point, registers all tool modules
├── supervisor.py         # Owns the worker subprocess; survives crashes
├── worker.py             # Child process that owns dbgeng + COM state
├── debugger.py           # High-level Debugger class (lifecycle, commands, reconnect)
├── dbgeng.py             # Pure ctypes COM interface definitions (6 interfaces)
├── callbacks.py          # IDebugOutputCallbacks + IDebugEventCallbacks
├── sessions.py           # Multi-session registry (parallel VM debugging)
├── vm_client.py          # Async HTTP client to VM agent
├── config.py             # Environment-variable configuration
├── bp_helpers.js         # JS predicates for `bp /w` conditional breakpoints
├── start_engine.bat      # Launch HTTP-mode server (must be admin)
├── dbgeng_bin/           # DbgEng DLLs (gitignored, ~15MB)
├── vm_agent/             # REST agent for the target VM (Flask + psutil)
│   ├── server.py
│   └── requirements.txt
├── Claude-Docs/
│   └── SKILL.md          # Skill for kernel debug-assisted tracing
├── tests/
│   └── test_supervisor_methods_present.py
└── tools/
    ├── _state.py         # State-snapshot wrapper applied to every tool
    ├── core.py           # execute, execute_batch, evaluate
    ├── session.py        # connect, disconnect, status, ensure_ready, restart_worker, ...
    ├── multi_session.py  # session_create / connect / destroy / list
    ├── memory.py         # read/write virtual + physical memory, MSR
    ├── registers.py      # read/write registers
    ├── stack.py          # get_stack
    ├── breakpoints.py    # set/remove/list breakpoints, exception filters
    ├── execution.py      # continue, step_into, step_over, break_in
    ├── inspection.py     # list modules/threads/processes, switch context
    ├── symbols.py        # resolve symbols, field offsets, disassemble
    ├── events.py         # wait/poll/clear debug events
    ├── kernel.py         # read_struct, PTE, pool, driver/device objects, SSDT, IDT
    ├── context.py        # one-shot structured context dumps via direct COM
    └── workflow.py       # breakpoint_and_run, run_and_trace, VM proxy tools
```

### COM Interface Stack

Aragorn wraps six DbgEng COM interfaces via ctypes (no C++ extension needed):

- **IDebugClient** — Session lifecycle, callback registration
- **IDebugControl** — Command execution, breakpoints, execution status
- **IDebugDataSpaces2** — Virtual / physical memory, address translation
- **IDebugRegisters** — Register read / write
- **IDebugSymbols2** — Symbol resolution, type info, disassembly
- **IDebugSystemObjects** — Process / thread / module enumeration

## License

[WTFPL](LICENSE)
