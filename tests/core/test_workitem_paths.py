"""Structured work-order items and output paths with spaces (2026-09-23 run)."""
import json
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


def test_present_unparseable_closes_a_comms_store(tmp_path):
    from unittest.mock import patch
    from tools._readiness import assess_readiness
    log = ExecutionLog()
    log.configure("CS", str(tmp_path / "t.json"), save_session=False)
    log.record_dair_call("Triage", "", True, "Collect", "", "push", "")
    ev = log.record_tool_call("fls -r img", True, False, 0, 0,
                              stdout_excerpt="Users/x/AppData/Roaming/Telegram Desktop/tdata")
    log.record_finding("data delivered", "SUSPECTED", "t",
                       claim={"claim_kind": "positive", "category": "delivery", "act": "delivery"})
    block = lambda: [b for b in assess_readiness(log)["blocking_issues"] if "'telegram'" in b]
    assert block()
    log.record_disposition("source", "telegram", "present_unparseable", evidence_call_ids=[ev])
    assert not block()


def test_dump_only_output_dir_uses_stdout_as_evidence(tmp_path):
    """vol -o <dir> windows.malfind --dump: the JSON result is on stdout, the
    dir holds only binary dumps — the call is citable evidence."""
    from core.evidence_packets import build_packet
    from core.finding_submission import make_request
    (tmp_path / "analysis").mkdir()
    log = ExecutionLog()
    log.configure("DMP", str(tmp_path / "analysis" / "t.json"), save_session=False)
    dumps = tmp_path / "exports" / "malfind"
    dumps.mkdir(parents=True)
    (dumps / "pid.2588.vad.0x1-0x2.dmp").write_bytes(b"MZ\x90\x00")
    cid = log.record_tool_call(f"/usr/local/bin/vol -o {dumps} -f x.mem -r json windows.malfind --dump",
                               True, False, 0, 0, stdout_excerpt='[{"PID": 2588, "Protection": "PAGE_EXECUTE_READWRITE"}]',
                               stdout_full='[{"PID": 2588, "Protection": "PAGE_EXECUTE_READWRITE"}]')
    pk = build_packet(log, make_request("PID 2588 has an RWX private region", "SUSPECTED", [cid], {},
                                        linked_call_id=cid))
    assert pk["evidence"] and "2588" in json.dumps(pk["evidence"])
