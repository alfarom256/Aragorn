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
    """Get a VM client using the active session's VM agent URL if available."""
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
        setup = await run_on_com_thread(dbg.workflow_bp_setup, bp_expression)
        if "error" in setup:
            return setup

        # If target broke in immediately, skip VM command
        if setup.get("_early_break"):
            log.info("target broke immediately, capturing state")
            return await run_on_com_thread(dbg.workflow_bp_capture_early, setup)

        bp_id = setup.pop("_bp_id", None)
        setup.pop("_early_break", None)

        # Phase 2 (async): Run VM command
        log.info("running VM command: %s %s", vm_command, vm_args or [])
        vm_result = await vm.exec(
            command=vm_command,
            args=vm_args or [],
            cwd=vm_cwd,
            timeout=vm_timeout,
        )
        setup["vm_output"] = vm_result

        # Phase 3 (COM): Wait for breakpoint hit + capture state
        wait = await run_on_com_thread(
            dbg.workflow_bp_wait_capture, bp_id, bp_expression, bp_timeout_ms)
        setup.update(wait)
        return setup

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
        setup = await run_on_com_thread(dbg.workflow_trace_setup, trace_addresses)
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
        hits = await run_on_com_thread(dbg.workflow_trace_collect, bp_ids)
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
        return await run_on_com_thread(
            get_debugger().inspect_at_break,
            commands=commands, resume_after=resume_after)

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
