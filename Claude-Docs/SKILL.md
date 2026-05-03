---
name: aragorn-debug
description: Use Aragorn (direct DbgEng MCP server) to do debug-assisted tracing of any Windows kernel driver — set conditional breakpoints by symbolic offset or address, capture register and memory state at each hit, walk a function's flow with annotated decompilation, and recover cleanly when dbgeng or the VM wedges. Works for minifilters, WDM dispatch routines, kernel APIs, completion routines, work items — any kernel code path you can find an entry point for.
---

# Aragorn — Kernel Debug-Assisted Tracing

Aragorn is an in-process DbgEng kernel debugger exposed as an MCP server.
It connects to a Hyper-V VM via kdnet (`AttachKernelWide`), runs all
dbgeng calls in a worker subprocess, and exposes structured tools for
memory, registers, stack, breakpoints, symbols, and events.

This skill is the playbook for doing **debug-assisted tracing of an
arbitrary kernel function** — picking a target, arming a conditional
BP, capturing live state at the hit, and walking the function body
with decompilation. It applies equally to minifilter callbacks, WDM
`IRP_MJ_*` dispatch routines, kernel-mode APIs, completion routines,
DPC handlers, and work items. The mechanics are the same; only the
target-selection criteria change.

## When to reach for this skill

You're answering a question like:
- "What does *driver X*'s function at offset Y actually do for input Z?"
- "Is *condition C* hit in this driver's code path?"
- "What state does this kernel function see when called by a specific
  user-mode action?"
- "Where in this driver's IRP handler does it make the verdict
  decision?"

Static decompilation alone leaves these unanswered when:
- Function args are pointers into kernel structs whose values matter
- Behavior depends on global config bytes set elsewhere
- The driver references kernel objects that you need to dereference live

For that, you need to break in *at the function*, capture state, and
walk forward. That's what this skill is for.

## Connecting

Always connect with `initial_break=True` for clean state:

```
mcp__aragorn__connect(initial_break=True)
```

This sets `DEBUG_ENGOPT_INITIAL_BREAK` *before* `AttachKernelWide` so
the engine drives the kdnet handshake to a deterministic break.
Without it, the first `WaitForEvent(INFINITE)` waits forever on an
idle VM.

After `connect`, `health_check` should report `connected=true,
execution_status=break`. From here you can read kernel memory, list
modules, etc. Resume with `execute("g")` to let the VM run.

## Recovery from wedge

If dbgeng goes into `DBGENG_E_TARGET_INDETERMINATE_STATE` (HRESULT
`0x80040205`), `ensure_ready` times out, or commands all return
E_UNEXPECTED:

```
mcp__aragorn__restart_worker()
mcp__aragorn__connect(initial_break=True)
```

`restart_worker` kills the worker subprocess and respawns it — fresh
dbgeng, fresh COM state. The MCP connection itself stays up; no
`/mcp` reconnect needed.

If the **VM** itself is wedged (kernel responsive to kdnet but
user-mode dead — VM agent HTTP and PowerShell Direct both
unreachable), hard-reset the VM from the host (e.g. via Hyper-V
PowerShell: `Stop-VM -Force` then `Start-VM`). Wait for the VM
agent's `/status` to return OK before reconnecting Aragorn.

## Conditional breakpoints — pick the form by per-hit cost

There are three working forms in this harness. **The choice determines
whether the BP wedges user-mode or not** at high hit rates. Pick by
cost, not convenience:

| Form | Per-hit cost | Use when |
|---|---|---|
| **Native MASM `.if`** | ~5-50µs eval + N×~150µs per `poi`/`wo`/`qwo` (kdnet memory read) | DEFAULT for all conditional BPs. Use unless the predicate genuinely needs JS. |
| `bp /w "JS_expr"` | ~100-300µs JS eval per hit | Only when the predicate truly needs JS — deep object-model traversal, regex, etc. |
| `.scriptrun helper.js` | ~200-500µs per hit (script reload overhead) | Avoid. Use `bp /w` if you need JS at all. |

The wedge isn't fundamental — WinDbg fields conditional BPs at the
same kdnet rates without choking. It comes from making each hit
expensive enough that the kernel-pause-per-hit aggregate saturates the
debug transport, which back-pressures user-mode HTTP/PowerShell-Direct
into nothing.

### MASM `.if` — the right default

```
bp <addr> ".if (<predicate>) {} .else {gc}"
```

Predicate is a MASM expression. Reads kernel memory via `poi(addr)`
(qword, 8 bytes), `qwo(addr)` (qword), `dwo(addr)` (dword), `wo(addr)`
(word, 2 bytes), `by(addr)` (byte). Each read is a fresh kdnet
round-trip — minimize total reads.

**Critical syntax pitfalls** (each one of these will look like a
"spurious break" or "wedge" until you find it):

1. **Use `&` and `|`, NOT `&&` and `||`.** `.if (1 && 0)` returns
   `HRESULT 0x80040205`, the engine FALLS BACK TO DEFAULT BP behavior,
   which is BREAK. The BP appears to fire on every hit despite the
   condition being "obviously false." Use bitwise `&` / `|` — they
   work correctly when operands are 0/1 booleans (which `==` produces).
   No short-circuit; both sides always evaluated.

2. **Inline all memory reads.** Do NOT use `r @$t0=expr; r @$t1=...`
   to cache repeated subexpressions inside a BP command. The
   pseudo-reg assignment also triggers fallback-to-break in this
   harness. Cost of duplicating reads is real but fixable; cost of
   stuck breaks is hours of debugging.

3. **64-bit constants use backtick at the 32-bit boundary** —
   `0x00740078`0074002e` parses as `0x0074007800740 02e`. The
   no-backtick form (`0x007400780074002e`) also works. Mixed forms
   in one expression are fine.

4. **Always `{} .else {gc}`** — don't omit the `{}` true-branch even
   when empty. The engine won't pick a sensible default.

### Worked example — match a FileName UTF-16 suffix

For a minifilter callback where `rcx` is `PFLT_CALLBACK_DATA` and we
want to break only on operations against `\Users\Mike\Desktop\test.txt`:

```
bp <addr> ".if (
    (qwo(poi(poi(poi(@rcx+0x10)+0x8)+0x60)+wo(poi(poi(@rcx+0x10)+0x8)+0x58)-0x10)==0x0074007300650074)
  & (qwo(poi(poi(poi(@rcx+0x10)+0x8)+0x60)+wo(poi(poi(@rcx+0x10)+0x8)+0x58)-0x8)==0x007400780074002e)
) {} .else {gc}"
```

Decoding the chase:
- `poi(@rcx+0x10)` — `_FLT_CALLBACK_DATA.Iopb`
- `poi(...+0x8)` — `_FLT_IO_PARAMETER_BLOCK.TargetFileObject`
- `wo(...+0x58)` — `_FILE_OBJECT.FileName.Length` (USHORT)
- `poi(...+0x60)` — `_FILE_OBJECT.FileName.Buffer`
- last 16 bytes (4 UTF-16 wchars) at `Buffer + Length - 16` → compare
  to `"test"` as qword `0x0074007300650074`
- last 8 bytes at `Buffer + Length - 8` → compare to `".txt"` as
  qword `0x007400780074002e`

Six memory reads per hit — borderline at ~5k hits/sec but workable.
Drop to fewer with a deeper-in-handler BP (see "Picking BP targets").

Verify offsets for any kernel struct via `aragorn.execute("?? #FIELD_OFFSET(<mod>!<TYPE>, <Field>)")` before building the chase.

### MASM `.if` validation workflow

When the BP appears to spuriously break, **always test the predicate
standalone** before assuming it's a per-hit-rate issue:

1. Break the kernel anywhere (e.g., `ensure_ready`)
2. From a thread that hit your BP, run the same expression as a
   bare `.if (predicate) {.echo MATCH} .else {.echo NOMATCH}`
3. If you get `HRESULT 0x80040205`, you have a syntax bug — most
   likely `&&` vs `&`, or `r @$tN=` inside the command
4. If you get MATCH on a target you expected NOMATCH on, your
   chase or constants are wrong — break it down piece by piece
   with `? <subexpression>` to see what each read returns

### `bp /w "JS_expr"` — when you actually need JS

Same per-hit transport cost as `.if`, plus ~100-300µs of JS engine
eval. Reasonable for predicates that would be unwieldy in MASM
(deep object-model traversal, fancy string ops). Load the helper
once, then:

```
bp /w "isMatch()" <addr>
```

`isMatch()` is a function exposed via `host.functionAlias` from a
loaded `.js` file (via `.scriptload`). Returns truthy to break, falsy
to continue.

The historical `bp /w` "fail-open" issue was fixed by changing
`Aragorn/callbacks.py:_breakpoint` to return `DEBUG_STATUS_GO` instead
of `DEBUG_STATUS_NO_CHANGE`. `bp /w` now works correctly — but it's
still slower per-hit than `.if`, so default to `.if` and reach for
`bp /w` only when you must.

### JS helper template (for `bp /w` predicates)

```javascript
"use strict";

function isMatch() {
    try {
        var rcx = host.currentThread.Registers.User.rcx;
        // typed-object dereference:
        //   var s = host.createTypedObject(rcx, "<module>", "<_TYPE>");
        // raw memory read:
        //   var bytes = host.memory.readMemoryValues(addr, length, 1);
        // cast a register to a number:
        //   var n = rcx.asNumber ? rcx.asNumber() : rcx;
        return /* your condition */ ? 1 : 0;
    } catch (e) {
        return 0;       // never let an exception turn into a break
    }
}

function initializeScript() {
    return [
        new host.functionAlias(isMatch, "isMatch"),
    ];
}
```

Load once, attach via `bp /w`:

```
mcp__aragorn__execute(".scriptload C:\\path\\to\\helper.js")
mcp__aragorn__execute("bp /w \"isMatch()\" <addr>")
mcp__aragorn__execute("g")
```

### Common predicate patterns

- **Match a UTF-16 string field at the end of a UNICODE_STRING** —
  use the MASM `.if` form above. For non-suffix matches or
  case-insensitive compares, JS is cleaner.

- **Match an IRP's MajorFunction** — MASM:
  `.if (by(poi(@rcx+0xb8)+1)==<TARGET_MAJOR>) {} .else {gc}` (offset
  0xb8 is `_IRP.Tail.Overlay.CurrentStackLocation` on x64; +1 is
  `MinorFunction` while +0 is the offset/flags byte; double-check via
  `?? #FIELD_OFFSET`).

- **Match a process by image name** — JS is easier here because
  `PsGetProcessImageFileName` is at a build-dependent offset and you
  want a string compare, not a fixed-byte-equal compare.

- **Match a DesiredAccess flag** — MASM:
  `.if ((dwo(<sec_ptr>+<offset>) & <FLAG>) != 0) {} .else {gc}`

## Picking BP targets — rate is everything

Even when `gc` correctly auto-continues, **a BP placed on a high-rate
function will saturate kdnet** with per-hit packets, which starves
user-mode (VM agent + PowerShell Direct stop responding). The kernel
itself stays fine — kdnet packets keep flowing — but the VM as a whole
becomes unusable.

The principle: **per-hit cost = kdnet RTT (~200µs) + condition eval +
N × kdnet memory reads**. A native MASM `.if` with 6 memory reads runs
~1ms/hit. A JS predicate adds ~150µs. At hit rates above ~5000/sec
(typical for unified minifilter dispatch handlers, syscall-fast-path
NT calls, high-rate DPCs) you'll wedge user-mode regardless of which
condition mechanism you use. Drop the rate at the BP-target level,
not the predicate level.

### Concrete rules

- **Avoid** any function that's on the path of every syscall in its
  class. Examples:
  - The unified pre-op/post-op dispatcher of a minifilter (called for
    CREATE *and* WRITE *and* SET_INFO across every volume the filter
    is attached to)
  - `nt!NtCreateFile`, `nt!NtWriteFile`, `nt!IofCallDriver` — anything
    on the syscall fast-path
  - DPC routines for high-rate devices (network, storage)
- **Prefer** the per-major-function handler from the dispatcher's
  dispatch table — already filtered to one operation type. Find the
  table by disassembling the dispatcher: look for
  `lea rdi, [<table>]; mov rdi, [rdi+rax*8]; call rdi`. Index by
  the major function you want, dereference, that's your handler.
- **Best**: a "verdict" or "decision" function that runs only after
  the driver's allowlists/early gates have triaged the request. These
  are the points where business logic actually executes — and they're
  usually called on the order of tens of times per second, not
  thousands. Find them via IDA decompilation, not by guessing.
- For one-off triggering of a known object: **hardware data BP** on a
  specific kernel address (e.g., a known FILE_OBJECT or DRIVER_OBJECT
  field). Bounded by silicon, fires once.

### Why decompile first, then BP

The temptation is to BP whatever function is easy to symbolicate. The
right move is the opposite: decompile the entry point, follow the
control flow until you find the *narrowest* function that still
encompasses the behavior you want to observe, then BP there.

A 30-second IDA decompile of a dispatcher is faster than 30 minutes of
rebooting from BP-storm wedges.

## End-to-end tracing pattern

The validated full flow for "trace what driver X does for input Y":

1. **Static prep (host-side, no VM needed):**
   - Pull the driver from the VM (e.g. via the VM agent's `/file`
     endpoint or any host-side file copy); decompile it in IDA / your
     reverser of choice
   - Walk the decomp from the entry point (the registered FltMgr
     callback, the WDM `MajorFunction` slot, etc.); identify the
     narrowest function that captures the behavior; note its file
     offset (e.g. `0x1E150` from `0x14001E150` minus image base)

2. **Live setup:**
   - Restart the VM for a clean baseline if its state is uncertain
   - Wait for the VM agent's `/status` to return OK
   - `restart_worker()` then `connect(initial_break=True)`
   - `lm m <driver>` for fresh load address (shifts every boot)
   - Compute target = `<base> + <file-offset>`

3. **Arm the BP:**
   - First-choice: native MASM `.if`. Compose the predicate from
     `poi`/`wo`/`qwo`/`by` reads off the register-passed args; use
     bitwise `&` and `|` for AND/OR (NOT `&&`/`||` — see syntax
     pitfalls). Inline all reads (no `r @$tN=...` assignments).
     `bp <target> ".if (<predicate>) {} .else {gc}"`
   - Validate the predicate standalone before `g`: break the kernel,
     `.if (<predicate>) {.echo M} .else {.echo N}`. If you get
     `HRESULT 0x80040205`, fix the syntax — the BP will fall back to
     break on every hit otherwise.
   - Only if the predicate genuinely needs JS (deep object traversal,
     regex, etc.): write a `.js` helper exposing an alias via
     `host.functionAlias`, `.scriptload` it, then
     `bp /w "isMatch()" <target>`.
   - `g` to resume.

4. **Trigger from VM:**
   - Whatever produces your input — `vm_write_file` for FS ops,
     `vm_exec` for binary launches, etc.
   - If the VM-side call times out, the BP is too hot — pick a
     deeper target

5. **Capture at the hit:**
   - `health_check` for execution status
   - `.lastevent` to confirm it's *your* BP (not kdnic, not
     `KdCheckForDebugBreak`)
   - `r` (all regs) or `r rcx, rdx, r8, r9` for x64 fastcall args
   - `dx <typed expression>` to dereference structs cleanly
   - `dq <ptr> L<count>`, `db <ptr> L<count>`, `du <ptr>` for raw
     memory
   - `k <N>` for the call stack
   - `!process -1 7` for the calling process+thread context

6. **Walk forward (optional):**
   - For multi-step traces, set additional BPs at strategic
     points inside the function (e.g. just past each `call`
     instruction so you can read return values from `eax`/`rax`)
   - `g` between hits, capture state at each
   - For finer-grain stepping, `t` (single-step into) or `p`
     (step over). These are slow over kdnet — use them sparingly,
     and only inside functions where you need instruction-level
     fidelity

7. **Document as you go:**
   - Write the trace into a markdown file at capture time, not from
     memory. Include the actual hex addresses, the actual `dx`
     output, side-by-side decomp.
   - When you can't get a live capture (driver didn't load, VM
     wedged, etc.), note it explicitly — never present static
     decomp as if it's live data

## Inspecting state at a break — common one-liners

All via `aragorn.execute`:

| Command | Purpose |
|---------|---------|
| `.lastevent` | Why we're at a break (your BP, exception, kernel assertion) |
| `r [list]` | Read all GP regs, or a specific subset |
| `k <N>` | Call stack, top N frames |
| `kp` | Stack with arg lists shown |
| `dx <expr>` | Data-model expression eval (struct deref + display) |
| `dx -r3 <expr>` | Same but recurse 3 levels |
| `dt <module>!<type> <addr>` | Typed structure dump |
| `dt <module>!<type> <addr> -y <field>` | Just the named field |
| `db <addr> L<bytes>` | Raw byte dump |
| `dq <addr> L<qwords>` | Raw qword dump (with sym resolution) |
| `dps <addr> L<count>` | Pointer-sized dump, sym-resolved |
| `du <addr>` | Wide string from address |
| `da <addr>` | ANSI string from address |
| `u <addr> L<count>` | Disassemble |
| `bl` | List active breakpoints |
| `bc *` | Clear all breakpoints |
| `!process -1 7` | Full info on current process + threads |
| `!process 0 0 <name>` | Find process by image name |
| `!fltkd.filters` | List FltMgr minifilters and FLT_FILTER addrs |
| `!drvobj <addr> 7` | Driver object detail (dispatch table, devices) |
| `!devobj <addr>` | Device object detail |
| `!irp <addr>` | IRP detail with stack |
| `!handle <h> 7` | Handle table entry detail |
| `!locks` | Outstanding ERESOURCE locks |
| `!running` | What each CPU is currently doing |

## Things that look like Aragorn bugs but aren't

- **`Target is not responding. Attempting to reconnect...`** in the
  middle of an `execute` output — kdnet packet loss/reorder. Usually
  self-heals; if a command returns partial output, just re-run it.
- **`Break instruction exception - code 80000003 (first chance)`**
  with `kdnic!Tx*`, `nt!KdCheckForDebugBreak`, or
  `nt!DbgBreakPointWithStatus` in the stack — kdnet/transport
  assertions or kernel periodic debug probes, not your BP. Just `g`.
- **`Hit breakpoint 0` with a target that doesn't match your
  predicate, MASM `.if` form** — by far the most common cause is a
  syntax error in the `.if` expression that causes
  `HRESULT 0x80040205`, which falls back to default BP behavior
  (BREAK). Top suspects, in order: (a) `&&` or `||` instead of `&` /
  `|`; (b) `r @$tN=...` pseudo-reg assignment inside the BP command;
  (c) missing `{}` for the true-branch. Validate by running the same
  predicate as a bare `.if (predicate) {.echo M} .else {.echo N}`
  while at break — if you get HRESULT 0x80040205, that's your bug,
  not a predicate or rate issue.
- **`Hit breakpoint 0` with a target that doesn't match, JS form** —
  your `bp /w` or `.scriptrun` script raised an exception during
  `isMatch()` and the function returned undefined (truthy by some
  paths). Add `try/catch` around every memory read; reload via
  `.scriptunload` + `.scriptload` after every JS edit.
- **VM uptime climbing but `health_check` says `break`** — the engine
  is at a break but you haven't checked `.lastevent`. Always pair
  `health_check` with `.lastevent` to know *why* you're broken.
- **VM agent HTTP timing out but kernel is GO** — the BP rate is
  too high. Switch to a deeper target (per-major-function handler
  instead of unified dispatcher; verdict function instead of pre-op
  entry). Reducing the predicate cost won't help — the kdnet RTT per
  hit is the floor.

## Cleanup

When you're done with a session:

- `.scriptunload <path>` then `bc *` if you want to leave the worker
  attached to the same VM for future use
- Close any open IDA / decompiler sessions on the .sys — IDA holds
  the file open and you won't be able to delete it otherwise
- Remove temporary binary samples / IDA databases from your host
  scratch dir; they bloat the repo working set and IDA databases
  are huge
