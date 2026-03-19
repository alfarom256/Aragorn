"""Coordinated workflow tools — atomic debugger + VM operations.

These tools combine kernel debugger operations with VM command execution
in a single tool call, eliminating the delegate coordination problem where
one agent sets breakpoints and another runs exploits.
"""

import logging
import time

from ..debugger import get_debugger, get_debugger_or_none, run_on_com_thread, status_name
from ..vm_client import get_vm_client
from ..sessions import get_registry
from ..dbgeng import (
    DebugBreakpoint,
    DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_ENABLED, DEBUG_ANY_ID,
    DEBUG_STATUS_GO, DEBUG_STATUS_BREAK, DEBUG_INTERRUPT_ACTIVE,
    S_OK, S_FALSE, DbgEngError,
)

log = logging.getLogger("aragorn.tools.workflow")


def _session_vm_client():
    """Get a VM client using the active session's the VM agent URL if available."""
    try:
        reg = get_registry()
        info = reg.resolve_session()
        return get_vm_client(url=info.vm_agent_url, api_key=info.vm_agent_api_key)
    except KeyError:
        return get_vm_client()


def register(mcp):

    @mcp.tool()
    async def breakpoint_and_run(
        bp_expression: str,
        vm_command: str,
        vm_args: list[str] = None,
        vm_cwd: str = None,
        bp_timeout_ms: int = 15000,
        vm_timeout: int = 30,
    ) -> dict:
        """Atomic: set breakpoint, continue target, run VM command, wait for BP hit.

        This is the key tool for coordinated exploit testing. It:
        1. Breaks into the debugger and verifies context
        2. Sets a breakpoint at bp_expression
        3. Resumes execution (target running)
        4. Runs vm_command on the VM via the VM agent (triggers the code path)
        5. Waits for the breakpoint to fire (with timeout)
        6. Captures registers, stack trace, and VM command output

        Args:
            bp_expression: Symbol or address for breakpoint (e.g., "nt!NtCreateFile",
                          "tmnciesc+0x1234", "0xfffff80012345000")
            vm_command: Executable to run on the VM (e.g., "cmd.exe", "C:\\exploit.exe")
            vm_args: Arguments for the VM command
            vm_cwd: Working directory on the VM
            bp_timeout_ms: How long to wait for breakpoint hit (default 15s)
            vm_timeout: VM command timeout in seconds (default 30)

        Returns:
            Combined results: breakpoint info, hit status, registers, stack, VM output.
        """
        dbg = get_debugger()
        vm = _session_vm_client()

        # Phase 1 (COM): ensure ready + set breakpoint + resume
        def _setup():
            result = {}

            # Step 0: Validate connection, auto-reconnect if stale
            if not dbg._validate_connection():
                log.warning("breakpoint_and_run: dead connection, reconnecting...")
                try:
                    dbg.reconnect(kd_wait_timeout=30)
                except DbgEngError as e:
                    return {
                        "error": f"Dead connection, reconnect failed: {e}",
                        "step": "reconnect",
                    }

            # Step 1: Ensure debugger is ready
            try:
                ready = dbg.ensure_ready()
                result["debugger_ready"] = ready
            except DbgEngError as e:
                return {"error": f"Debugger not ready: {e}", "step": "ensure_ready"}

            # Step 2: Set breakpoint
            try:
                bp_ptr = dbg.control.AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID)
                bp = DebugBreakpoint(bp_ptr)
                if bp_expression.startswith("0x") or bp_expression.startswith("0X"):
                    bp.SetOffset(int(bp_expression, 0))
                else:
                    bp.SetOffsetExpression(bp_expression.encode("utf-8"))
                bp.AddFlags(DEBUG_BREAKPOINT_ENABLED)
                bp_id = bp.GetId()
                try:
                    offset = bp.GetOffset()
                    bp_addr = f"0x{offset:016X}"
                except DbgEngError:
                    bp_addr = "(deferred)"

                result["breakpoint"] = {
                    "id": bp_id,
                    "expression": bp_expression,
                    "address": bp_addr,
                }
                result["_bp_id"] = bp_id
                result["_bp_ptr"] = bp_ptr
                dbg.track_breakpoint(bp_id, bp_addr, bp_expression)
                log.info("breakpoint set: %s @ %s (id=%d)", bp_expression, bp_addr, bp_id)
            except DbgEngError as e:
                return {"error": f"Failed to set breakpoint: {e}", "step": "set_breakpoint"}

            # Step 3: Resume execution (drain spurious kdnet breaks)
            try:
                log.info("resuming target for VM command")
                for _resume in range(3):
                    dbg.control.SetExecutionStatus(DEBUG_STATUS_GO)
                    hr = dbg.control.WaitForEvent(500)
                    if hr == S_FALSE:
                        # Timeout — verify target actually left BREAK
                        post_s = dbg.control.GetExecutionStatus()
                        if post_s == DEBUG_STATUS_BREAK:
                            log.warning("breakpoint_and_run: resume %d — "
                                        "still BREAK after timeout", _resume + 1)
                            continue
                        dbg._state["execution_status"] = status_name(post_s)
                        result["resumed"] = True
                        break
                    # S_OK — event fired, check if target stopped
                    post = dbg.control.GetExecutionStatus()
                    if post != DEBUG_STATUS_BREAK:
                        dbg._state["execution_status"] = status_name(post)
                        result["resumed"] = True
                        break
                    log.info("breakpoint_and_run: resume attempt %d — "
                             "still in break, retrying", _resume + 1)
                else:
                    # All resume attempts failed — early break (BP or stuck)
                    result["_early_break"] = True
                    st = dbg.control.GetExecutionStatus()
                    dbg._state["execution_status"] = status_name(st)
                    result["resumed"] = True
            except DbgEngError as e:
                try:
                    dbg.control.RemoveBreakpoint(bp_ptr)
                    dbg.untrack_breakpoint(bp_id)
                except DbgEngError:
                    pass
                return {"error": f"Failed to resume: {e}", "step": "resume"}

            return result

        setup = await run_on_com_thread(_setup)
        if "error" in setup:
            return setup

        # If target broke in immediately, skip VM command
        if setup.get("_early_break"):
            log.info("target broke immediately, capturing state")
            def _capture_early():
                result = dict(setup)
                result.pop("_bp_id", None)
                result.pop("_bp_ptr", None)
                result.pop("_early_break", None)
                result["breakpoint_hit"] = True
                result["note"] = "breakpoint fired before VM command was sent"
                try:
                    result["registers"] = _capture_registers(dbg)
                except DbgEngError as e:
                    result["registers_error"] = str(e)
                try:
                    result["stack"] = _capture_stack(dbg)
                except DbgEngError as e:
                    result["stack_error"] = str(e)
                try:
                    result["instruction"] = _capture_current_instruction(dbg)
                except DbgEngError as e:
                    result["instruction_error"] = str(e)
                return result
            return await run_on_com_thread(_capture_early)

        result = dict(setup)
        bp_id = result.pop("_bp_id", None)
        bp_ptr = result.pop("_bp_ptr", None)
        result.pop("_early_break", None)

        # Phase 2 (async): Run VM command
        log.info("running VM command: %s %s", vm_command, vm_args or [])
        vm_result = await vm.exec(
            command=vm_command,
            args=vm_args or [],
            cwd=vm_cwd,
            timeout=vm_timeout,
        )
        result["vm_output"] = vm_result

        # Phase 3 (COM): Wait for breakpoint hit + capture state
        def _wait_and_capture():
            try:
                hr = dbg.control.WaitForEvent(bp_timeout_ms)
                if hr == S_OK:
                    result["breakpoint_hit"] = True
                    dbg._state["execution_status"] = "break"
                    log.info("breakpoint hit!")

                    try:
                        result["registers"] = _capture_registers(dbg)
                    except DbgEngError as e:
                        result["registers_error"] = str(e)
                    try:
                        result["stack"] = _capture_stack(dbg)
                    except DbgEngError as e:
                        result["stack_error"] = str(e)
                    try:
                        result["instruction"] = _capture_current_instruction(dbg)
                    except DbgEngError as e:
                        result["instruction_error"] = str(e)

                    dbg.record_event({
                        "type": "breakpoint_hit",
                        "bp_id": bp_id,
                        "expression": bp_expression,
                        "time": time.time(),
                    })
                elif hr == S_FALSE:
                    result["breakpoint_hit"] = False
                    result["note"] = f"Timeout after {bp_timeout_ms}ms — breakpoint not hit"
                    log.info("breakpoint timeout after %dms", bp_timeout_ms)
                else:
                    result["breakpoint_hit"] = False
                    result["wait_error"] = f"WaitForEvent returned 0x{hr & 0xFFFFFFFF:08X}"
            except DbgEngError as e:
                result["breakpoint_hit"] = False
                result["wait_error"] = str(e)

        await run_on_com_thread(_wait_and_capture)
        return result

    @mcp.tool()
    async def run_and_trace(
        vm_command: str,
        vm_args: list[str] = None,
        trace_addresses: list[str] = None,
        vm_cwd: str = None,
        timeout: int = 30,
    ) -> dict:
        """Set logging breakpoints at multiple addresses, run a VM command, capture trace.

        Like breakpoint_and_run but with multiple breakpoints that log and continue
        (don't halt). Captures which addresses were hit and in what order.

        Args:
            vm_command: Executable to run on the VM.
            vm_args: Arguments for the VM command.
            trace_addresses: List of symbol expressions or addresses to trace.
            vm_cwd: Working directory on the VM.
            timeout: Overall timeout in seconds.

        Returns:
            Trace of hit addresses and VM command output.
        """
        dbg = get_debugger()
        vm = _session_vm_client()
        trace_addresses = trace_addresses or []

        # Phase 1 (COM): ensure ready + set trace breakpoints + resume
        def _setup():
            result = {"trace_points": []}
            bp_ids = []

            try:
                dbg.ensure_ready()
            except DbgEngError as e:
                return {"error": f"Debugger not ready: {e}", "_bp_ids": bp_ids}

            for addr_expr in trace_addresses:
                try:
                    bp_ptr = dbg.control.AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID)
                    bp = DebugBreakpoint(bp_ptr)
                    if addr_expr.startswith("0x") or addr_expr.startswith("0X"):
                        bp.SetOffset(int(addr_expr, 0))
                    else:
                        bp.SetOffsetExpression(addr_expr.encode("utf-8"))
                    bp.SetCommand(f".echo TRACE_HIT:{addr_expr}; gc".encode("utf-8"))
                    bp.AddFlags(DEBUG_BREAKPOINT_ENABLED)
                    bp_id = bp.GetId()
                    bp_ids.append((bp_id, bp_ptr, addr_expr))
                    result["trace_points"].append({"expression": addr_expr, "bp_id": bp_id})
                except DbgEngError as e:
                    result["trace_points"].append({"expression": addr_expr, "error": str(e)})

            try:
                resume_result = dbg.resume_target(max_attempts=5, verify_timeout_ms=500)
                if resume_result["status"] != "running":
                    log.warning("run_and_trace: resume may have failed: %s", resume_result)
            except DbgEngError as e:
                _cleanup_breakpoints(dbg, bp_ids)
                return {"error": f"Failed to resume: {e}", "_bp_ids": []}

            result["_bp_ids"] = bp_ids
            return result

        setup = await run_on_com_thread(_setup)
        if "error" in setup:
            setup.pop("_bp_ids", None)
            return setup

        bp_ids = setup.pop("_bp_ids", [])

        # Phase 2 (async): Run VM command
        vm_result = await vm.exec(
            command=vm_command,
            args=vm_args or [],
            cwd=vm_cwd,
            timeout=timeout,
        )
        setup["vm_output"] = vm_result

        # Phase 3 (COM): Break in, capture trace output, clean up
        def _collect():
            try:
                dbg.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE)
                dbg.control.WaitForEvent(2_000)
            except DbgEngError:
                pass

            trace_output = dbg.output_cb.get_text()
            hits = []
            for line in trace_output.split("\n"):
                line = line.strip()
                if line.startswith("TRACE_HIT:"):
                    hits.append(line[len("TRACE_HIT:"):])

            _cleanup_breakpoints(dbg, bp_ids)
            return hits

        hits = await run_on_com_thread(_collect)
        setup["trace_hits"] = hits
        setup["trace_hit_count"] = len(hits)
        return setup

    @mcp.tool()
    async def inspect_at_breakpoint(
        commands: list[str] = None,
        resume_after: bool = False,
    ) -> dict:
        """Run multiple debugger commands at a breakpoint and return all results.

        Convenience tool to batch common post-breakpoint inspection: register dumps,
        memory reads, disassembly, etc. Saves the multi-step dance of individual tool calls.

        Args:
            commands: List of debugger commands to run.
                Defaults to ["r", "k", "u @rip L5"] (registers, stack, disassembly).
            resume_after: If True, resume execution after inspection.

        Returns:
            Dict mapping each command to its output, plus optional resume status.
        """
        def _impl():
            dbg = get_debugger()
            cmds = commands if commands is not None else ["r", "k", "u @rip L5"]

            results = {}
            for cmd in cmds:
                try:
                    output = dbg.execute(cmd)
                    results[cmd] = output
                except DbgEngError as e:
                    results[cmd] = f"ERROR: {e}"

            if resume_after:
                try:
                    log.info("inspect: resuming after inspection")
                    dbg.control.SetExecutionStatus(DEBUG_STATUS_GO)
                    hr = dbg.control.WaitForEvent(1_000)
                    if hr == S_OK:
                        st = dbg.control.GetExecutionStatus()
                        dbg._state["execution_status"] = status_name(st)
                        results["_resumed"] = True
                        results["_status"] = status_name(st)
                    else:
                        dbg._state["execution_status"] = "go"
                        results["_resumed"] = True
                except DbgEngError as e:
                    results["_resumed"] = False
                    results["_resume_error"] = str(e)

            return results

        return await run_on_com_thread(_impl)

    # ─── VM proxy tools ──────────────────────────────────────────────

    @mcp.tool()
    async def vm_exec(
        command: str,
        args: list[str] = None,
        cwd: str = None,
        timeout: int = 30,
        env: dict = None,
    ) -> dict:
        """Execute a command on the VM via the VM agent.

        Proxies to the VM agent, giving the debugger agent direct VM access
        without needing a separate vm-executor delegate.

        Args:
            command: Executable path or name on the VM.
            args: Command-line arguments.
            cwd: Working directory on the VM.
            timeout: Seconds before process is killed.
            env: Extra environment variables.
        """
        vm = _session_vm_client()
        return await vm.exec(command, args or [], cwd, timeout, env=env)

    @mcp.tool()
    async def vm_read_file(path: str) -> dict:
        """Read a file from the VM via the VM agent.

        Args:
            path: Absolute Windows path on the VM.
        """
        vm = _session_vm_client()
        return await vm.read_file(path)

    @mcp.tool()
    async def vm_write_file(path: str, content: str, overwrite: bool = True) -> dict:
        """Write text content to a file on the VM via the VM agent.

        Args:
            path: Absolute Windows path on the VM.
            content: Text content to write.
            overwrite: Whether to overwrite existing file.
        """
        vm = _session_vm_client()
        return await vm.write_file(path, content, overwrite)

    @mcp.tool()
    async def vm_upload_file(local_path: str, remote_path: str,
                             overwrite: bool = False) -> dict:
        """Upload a file from the host to the VM via the VM agent.

        Args:
            local_path: Absolute path on the host machine.
            remote_path: Absolute destination path on the VM.
            overwrite: Whether to overwrite existing file.
        """
        vm = _session_vm_client()
        return await vm.upload_file(local_path, remote_path, overwrite)

    @mcp.tool()
    async def vm_status() -> dict:
        """Check if the VM is reachable via the VM agent."""
        vm = _session_vm_client()
        return await vm.status()


# ─── Helpers (module-level) ──────────────────────────────────────────

def _capture_registers(dbg) -> dict:
    """Capture key registers at current break."""
    regs = {}
    for name in [b"rax", b"rbx", b"rcx", b"rdx", b"rsi", b"rdi",
                 b"rsp", b"rbp", b"rip", b"r8", b"r9", b"r10",
                 b"r11", b"r12", b"r13", b"r14", b"r15"]:
        try:
            idx = dbg.registers.GetIndexByName(name)
            val = dbg.registers.GetValue(idx)
            regs[name.decode()] = f"0x{val.I64:016X}"
        except DbgEngError:
            pass
    return regs


def _capture_stack(dbg, max_frames: int = 10) -> list[dict]:
    """Capture stack frames."""
    dbg.output_cb.clear()
    dbg.control.Execute(f"k {max_frames}".encode("utf-8"))
    output = dbg.output_cb.get_text()
    frames = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if line and not line.startswith("Child") and not line.startswith("#"):
            frames.append(line)
    return frames


def _capture_current_instruction(dbg) -> dict:
    """Capture the current instruction at RIP."""
    result = {}
    try:
        idx = dbg.registers.GetIndexByName(b"rip")
        val = dbg.registers.GetValue(idx)
        rip = val.I64
        result["rip"] = f"0x{rip:016X}"

        try:
            name, disp = dbg.symbols.GetNameByOffset(rip)
            result["symbol"] = name + (f"+0x{disp:X}" if disp else "")
        except DbgEngError:
            pass

        dbg.output_cb.clear()
        dbg.control.Execute(f"u 0x{rip:X} L3".encode("utf-8"))
        result["disassembly"] = dbg.output_cb.get_text().strip()
    except DbgEngError as e:
        result["error"] = str(e)
    return result


def _cleanup_breakpoints(dbg, bp_ids: list):
    """Remove breakpoints by their (id, ptr, expr) tuples."""
    for bp_id, bp_ptr, _ in bp_ids:
        try:
            dbg.control.RemoveBreakpoint(bp_ptr)
            dbg.untrack_breakpoint(bp_id)
        except DbgEngError:
            pass
