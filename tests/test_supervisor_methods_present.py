"""Static spec for issue #2 — every tool that previously wrapped its COM
work in a local `_impl` closure must now route through a named method on
`Debugger`. The supervisor dispatches by method name, so any closure whose
`__name__` is `_impl` triggers `AttributeError: Debugger has no method '_impl'`
when the tool is invoked under supervisor mode (the default).

Commit 5c56ff5 fixed this for the breakpoints + symbols tools by adding
`add_breakpoint`, `remove_breakpoint_by_id`, `list_all_breakpoints`,
`resolve_symbol_name`. Issue #2 reports the same bug still hits
`read_memory`, `break_in`, and others.

This test asserts that every required `Debugger` method exists. It runs in
~10ms with no VM and catches typos and missing lifts before any live test.
"""

from Aragorn.debugger import Debugger


# Every Debugger method that a supervisor-mode tool now dispatches to.
# Keep this list in sync with the tool wrappers in Aragorn/tools/*.py.
REQUIRED_METHODS = [
    # Already added in 5c56ff5 (sentinel — proves the test is well-wired)
    "add_breakpoint",
    "remove_breakpoint_by_id",
    "list_all_breakpoints",
    "resolve_symbol_name",

    # tools/memory.py
    "read_virtual_formatted",
    "write_virtual_bytes",
    "search_virtual",
    "read_physical_formatted",
    "write_physical_bytes",
    "translate_v2p",
    "read_msr_value",

    # tools/registers.py
    "read_all_registers",
    "write_register_value",

    # tools/execution.py
    "do_step_into",
    "do_step_over",
    "request_break",
    # continue_exec already routes through existing dbg.resume_target

    # tools/events.py
    "wait_for_one_event",
    "drain_events",
    "clear_event_queue",

    # tools/inspection.py
    "enumerate_modules",
    "enumerate_threads",
    "enumerate_processes",
    "switch_to_process",

    # tools/stack.py
    "get_stack_frames",

    # tools/symbols.py (resolve_symbol_name was in 5c56ff5)
    "get_field_offset_value",
    "get_type_size_value",
    "disassemble_instructions",

    # tools/breakpoints.py (the rest were in 5c56ff5)
    "configure_exception_filter",

    # tools/workflow.py
    "inspect_at_break",

    # tools/context.py
    "get_cpu_state_full",
    "disassemble_at",
    "read_qwords_resolved",
    "get_current_process_info",
    "get_current_thread_info",
    "get_full_snapshot",

    # tools/core.py + tools/workflow.py — additions found post-PR review
    "execute_batch_commands",
    "workflow_bp_setup",
    "workflow_bp_capture_early",
    "workflow_bp_wait_capture",
    "workflow_trace_setup",
    "workflow_trace_collect",
]


def test_all_required_debugger_methods_exist():
    missing = [m for m in REQUIRED_METHODS if not hasattr(Debugger, m)]
    assert not missing, (
        f"Debugger is missing {len(missing)} method(s) that supervisor-mode "
        f"tools dispatch to:\n  " + "\n  ".join(missing)
    )


if __name__ == "__main__":
    test_all_required_debugger_methods_exist()
    print(f"OK — all {len(REQUIRED_METHODS)} Debugger methods present.")
