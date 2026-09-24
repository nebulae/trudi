"""Structured work-order items and output paths with spaces (2026-09-23 run)."""
import shlex

from core.execution_log import ExecutionLog


def test_structured_reason_item_is_control_plane_and_tool_items_resolve(tmp_path):
    from tools._gates.work_order import unrun_priority_tools, unrun_from_list, _item_tool
    item = {"tool": "reason.hypothesize", "args": {"mode": "case_question"}}
    assert _item_tool(item) == "reason.hypothesize"
    assert _item_tool(str(item)) == "reason.hypothesize"
    log = ExecutionLog()
    log.configure("WI", str(tmp_path / "t.json"), save_session=False)
    log.record_dair_call("Triage", "", True, "Collect", "", "push", "",
                         directives={"priority_tools": [item, {"tool": "ez.pecmd", "args": {}}]})
    assert unrun_priority_tools(log._entries) == ["ez.pecmd"] or \
        any("pecmd" in x for x in unrun_priority_tools(log._entries))
    assert not any("{" in x for x in unrun_priority_tools(log._entries))
    assert unrun_from_list(log._entries, [item]) == []


def test_output_path_with_spaces_resolves(tmp_path):
    from tools._output_reader import _cmd_output_paths
    from tools._gates._evidence_calls import read_target_path
    d = tmp_path / "gmail.export" / "Root - Mailbox" / "IPM_SUBTREE" / "[Gmail]"
    d.mkdir(parents=True)
    f = d / "Message.txt"
    f.write_text("x")
    unquoted = f"read.output --output {f} query=nina"
    assert _cmd_output_paths(unquoted) == [str(f)]
    quoted = f"read.output --output {shlex.quote(str(f))} query=nina"
    assert _cmd_output_paths(quoted) == [str(f)]
    assert read_target_path({"cmd": quoted}).endswith("Message.txt")
    # a plain path is unchanged, and a not-yet-existing path keeps its token
    assert _cmd_output_paths("x --csv /tmp/none/out.csv") == ["/tmp/none/out.csv"]
