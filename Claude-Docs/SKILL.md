---
name: kernel-debug
description: This skill should be used when the user wants to "debug a kernel", "set a breakpoint", "read memory", "inspect a driver", "attach to a VM", "analyze a crash", "trace execution", "dump SSDT", "read registers", or discusses any kernel debugging workflow including breakpoint coordination, driver inspection, IOCTL tracing, exploit testing, or multi-VM parallel debugging. Use this skill for any Windows kernel debugging task via Aragorn.
---

# Kernel Debugging with Aragorn

Aragorn is a direct DbgEng COM kernel debugger exposed as an MCP server. It spawns kd.exe for kdnet transport and connects via DebugConnect() — no WinDbg GUI needed.

## Getting Started

Every session begins with connection verification:

1. **Check status:** `status()` — returns connection state without disturbing the target
2. **Break in and verify:** `ensure_ready()` — atomic: break in, verify thread context, reload symbols. Retries 5x. Call this before any operation requiring the target to be stopped.
3. **Lightweight check:** `health_check()` — probe connection without breaking in. Safe while target is running.

## Core Debugging Workflow

### Setting Breakpoints

```
# By symbol
set_breakpoint(expression="nt!NtCreateFile")

# By address
set_breakpoint(address="0xfffff80012345000")

# Data/hardware breakpoint (break on write to address)
set_breakpoint(address="0xfffff80012345000", bp_type="data", access="write", data_size=8)

# Conditional breakpoint
set_breakpoint(expression="nt!NtCreateFile", condition=".if (rcx == 0) { } .else { gc }")
```

### Execution Control

- `continue_exec()` — Resume (robust: drains spurious kdnet breaks, retries up to 10x)
- `step_into()` — Single-step into calls
- `step_over()` — Single-step over calls
- `break_in()` — Interrupt running target

### Waiting for Events

After setting a breakpoint and resuming:
```
continue_exec()
wait_for_event(timeout=30)  # blocks until BP hit, exception, etc.
# Then inspect:
read_registers()
get_stack()
disassemble(address="@rip", count=10)
```

### Batch Inspection

Use `inspect_at_breakpoint()` to run multiple commands at once:
```
inspect_at_breakpoint(commands=["r", "k", "u @rip L10", "!process -1 0"])
# Returns dict mapping each command to its output
```

Pass `resume_after=True` to automatically continue after inspection.

## Coordinated Exploit Testing

The workflow tools combine debugger operations with VM-side command execution. These require the VM agent (`vm_agent/server.py`) running inside the target VM.

### breakpoint_and_run — The Key Tool

Atomic operation that:
1. Breaks in and verifies debugger context
2. Sets a breakpoint
3. Resumes execution
4. Runs a command on the VM (triggers the code path)
5. Waits for the breakpoint to fire
6. Captures registers, stack trace, and VM command output

```
breakpoint_and_run(
    bp_expression="mydriver+0x1234",
    vm_command="C:\\test\\exploit.exe",
    vm_args=["--trigger"],
    bp_timeout_ms=15000,
)
```

### run_and_trace — Multi-Address Logging

Sets logging breakpoints at multiple addresses that continue automatically. Captures which addresses were hit and in what order:
```
run_and_trace(
    vm_command="C:\\test\\exploit.exe",
    trace_addresses=["mydriver+0x100", "mydriver+0x200", "mydriver+0x300"],
)
```

### VM Proxy Tools

Direct VM access without needing a separate VM agent MCP:
- `vm_exec(command, args, cwd, timeout)` — Run process on VM
- `vm_read_file(path)` — Read file from VM
- `vm_write_file(path, content)` — Write file to VM
- `vm_upload_file(local_path, remote_path)` — Upload file host→VM
- `vm_status()` — Check VM reachability

## Driver Analysis

### Inspect a Driver Object
```
get_driver_object(name="\\\\Driver\\\\MyDriver")
# Returns: driver object address, dispatch table (IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, etc.)
```

### Read Kernel Structures
```
read_struct(type_name="nt!_EPROCESS", address="0xffff...")
read_struct(type_name="nt!_DRIVER_OBJECT", address="0xffff...")
```

### Field Offsets and Type Sizes
```
get_field_offset(type_name="nt!_EPROCESS", field_name="UniqueProcessId")
get_type_size(type_name="nt!_EPROCESS")
```

### Kernel Tables
```
dump_ssdt(count=512)     # System Service Descriptor Table
get_idt()                # Interrupt Descriptor Table
```

## Memory Operations

```
read_memory(address="0xfffff800...", size=64, format="hex")     # hex dump
read_memory(address="0xfffff800...", size=64, format="qwords")  # 8-byte values
read_memory(address="0xfffff800...", size=256, format="ascii")  # ASCII view

write_memory(address="0xfffff800...", hex_data="90909090")  # NOP sled

search_memory(address="0xfffff800...", pattern="4d5a", length=0x10000)

# Physical memory
read_physical(address="0x1000", size=64)
virtual_to_physical(address="0xfffff800...")

# MSRs
read_msr(msr_id=0xC0000082)  # LSTAR (syscall entry)
```

## Multi-Session (Parallel VM Debugging)

Create isolated debugger sessions for multiple VMs, each with its own kd.exe + COM thread:

```
session_create(
    session_id="vm-01",
    kd_connection="net:port=55556,key=...,target=172.26.50.192",
    kd_server_port=14501,
    vm_agent_url="http://172.26.50.192:8080",
)

session_create(
    session_id="vm-02",
    kd_connection="net:port=55557,key=...,target=172.26.50.193",
    kd_server_port=14502,
)

session_set_active(session_id="vm-01")
# All tools now route to vm-01's debugger
```

## Raw Commands

For anything not covered by specialized tools:
```
execute(command="!analyze -v")
execute(command="!process 0 0 explorer.exe")
execute(command=".reload /f")
execute(command="!object \\Device")

# Multiple commands
execute_batch(commands=["!process 0 0", "!vm", ".reload /f"], stop_on_error=False)

# Evaluate expression
evaluate(expression="nt!PsInitialSystemProcess")
```

## Common Patterns

### IOCTL Handler Analysis
```
# 1. Find the driver's dispatch table
get_driver_object(name="\\\\Driver\\\\TargetDriver")

# 2. Set BP on IRP_MJ_DEVICE_CONTROL handler
set_breakpoint(address="0x<IRP_MJ_DEVICE_CONTROL_addr>")
continue_exec()

# 3. Trigger IOCTL from VM
vm_exec(command="C:\\test\\send_ioctl.exe")

# 4. Wait and inspect
wait_for_event(timeout=15)
inspect_at_breakpoint(commands=[
    "r",
    "dt nt!_IRP @rcx",
    "dt nt!_IO_STACK_LOCATION poi(@rcx+0xb8)",
])
```

### Process Context Switch
```
# List processes
list_processes()

# Switch to a specific process for per-process memory access
switch_process(address="0xffff...")

# Now memory reads resolve in that process's address space
read_memory(address="0x7ff...", size=64)
```

## Troubleshooting

- **"partially initialized target"** — Call `reconnect_debugger()` to force full reconnect
- **Target won't resume** — `continue_exec()` handles this with retry logic, but if stuck call `break_in()` then `continue_exec()`
- **Symbols not loading** — `execute(command=".reload /f")` or `ensure_ready()` which includes symbol reload
- **Connection dropped** — `reconnect_debugger()` tears down and rebuilds the COM session
- **kd.exe won't connect** — `test_kd_connection()` runs diagnostics
