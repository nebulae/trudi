"""DAIR prescribes only tools and verification challenges the case's evidence
can feed; filtered items are recorded on the dair entry and never become
unrun work-order items or open challenges. Live-monitoring traces are never
filtered. A refused phase transition lists the phase's WHOLE unrun work order."""
import json
from unittest.mock import patch

import tools.dair as D
from core.execution_log import ExecutionLog
from tools._gates.max_pass_cap import open_challenge_issues
from tools._gates.work_order import unrun_priority_tools, unrun_from_list


def _case(tmp_path, evidence_files=("capture.pcap",)):
    case = tmp_path / "CASE"
    (case / "evidence").mkdir(parents=True)
    (case / "analysis").mkdir()
    for f in evidence_files:
        (case / "evidence" / f).write_bytes(b"")
    l = ExecutionLog()
    l.configure("EVF", str(case / "analysis" / "trace.json"), save_session=False)
    return l


def _raw(tools, challenges=(), phase="Triage", stack="stay", next_phase="", transition=False):
    return "RESULT:\n" + json.dumps({"assessment": {
        "phase_rationale": "r", "current_phase": phase, "stack_action": stack,
        "transition_recommended": transition, "next_phase": next_phase,
        "verification_challenges": list(challenges),
        "directives": {"priority_tools": list(tools)}}})


def _assess(l, raw, ctx="ctx"):
    seen = {}

    def fake_ask(system, user, max_tokens=0):
        seen["system"], seen["user"] = system, user
        return {"success": True, "raw": raw, "input_tokens": 1, "output_tokens": 1}
    with patch("core.execution_log.log", l), patch.object(D, "_ask", side_effect=fake_ask):
        r = D.dair_assess("summary", "[]", ctx)
    return r, seen


_PCAP_CHALLENGES = [
    {"claim": "Security.evtx collected and parsed", "challenge_method": "ez.evtxecmd",
     "verified": None},
    {"claim": "C2 socket to 10.0.0.9", "challenge_method": "vol.netscan, net.tcpdump_read",
     "verified": None},
    {"claim": "host 10.0.0.9 in capture", "challenge_method": "net.ngrep_search",
     "verified": None},
]


def test_pcap_case_filters_tools_challenges_and_prompt(tmp_path):
    l = _case(tmp_path)
    r, seen = _assess(l, _raw(["net.ngrep_search", "vol.pslist", "ez.pecmd",
                               "correlate.network_to_process", "live.recent_logins",
                               "strings.grep", "misc.knowns_pattern_generate"],
                              _PCAP_CHALLENGES))
    pt = r["directives"]["priority_tools"]
    assert pt == ["net.ngrep_search", "strings.grep", "misc.knowns_pattern_generate"]
    assert {f["tool"] for f in r["server_filtered_tools"]} == {
        "vol.pslist", "ez.pecmd", "correlate.network_to_process", "live.recent_logins"}
    methods = [c["challenge_method"] for c in r["verification_challenges"]]
    assert methods == ["net.tcpdump_read", "net.ngrep_search"]      # evtx dropped, vol stripped
    assert [f["challenge_method"] for f in r["server_filtered_challenges"]] == [
        "ez.evtxecmd", "vol.netscan, net.tcpdump_read"]
    # the prompt: evidence line + manifest without the absent kinds' tools
    assert "EVIDENCE AVAILABLE: pcap" in seen["user"] and "memory" in seen["user"]
    assert "vol.psscan" not in seen["system"] and "net.ngrep_search" in seen["system"]
    # recorded on the trace entry
    e = [x for x in l._entries if x.get("type") == "dair_call"][-1]
    assert e["evidence_kinds"] == ["pcap"] and e["evidence_determined"] is True
    assert len(e["server_filtered_tools"]) == 4 and len(e["server_filtered_challenges"]) == 2
    # filtered items never become unrun work or open challenges
    assert not any("pslist" in x or "pecmd" in x for x in unrun_priority_tools(l._entries))
    assert not any("evtxecmd" in x or "netscan" in x for x in open_challenge_issues(l._entries))


def test_undetermined_evidence_filters_nothing(tmp_path):
    l = ExecutionLog()
    (tmp_path / "X" / "analysis").mkdir(parents=True)
    l.configure("U", str(tmp_path / "X" / "analysis" / "trace.json"), save_session=False)
    r, seen = _assess(l, _raw(["vol.pslist", "ez.pecmd"], _PCAP_CHALLENGES[:1]))
    assert r["directives"]["priority_tools"] == ["vol.pslist", "ez.pecmd"]
    assert "server_filtered_tools" not in r and "EVIDENCE AVAILABLE" not in seen["user"]
    assert seen["system"] == D._DAIR_SYS
    assert len(r["verification_challenges"]) == 1


def test_live_monitoring_trace_is_unaffected(tmp_path):
    l = _case(tmp_path)                       # evidence dir holds only a pcap
    l.record_tool_call("monitor_start_investigation INV-001", True, False, 0, 0)
    r, seen = _assess(l, _raw(["live.processes", "vol.pslist", "velo.collect_artifact"],
                              _PCAP_CHALLENGES[:1]))
    assert r["directives"]["priority_tools"] == ["live.processes", "vol.pslist",
                                                 "velo.collect_artifact"]
    assert "server_filtered_tools" not in r and "server_filtered_challenges" not in r
    assert "EVIDENCE AVAILABLE" not in seen["user"] and seen["system"] == D._DAIR_SYS
    e = [x for x in l._entries if x.get("type") == "dair_call"][-1]
    assert e["evidence_determined"] is False


def test_stamped_kinds_clear_orders_recorded_before_the_filter(tmp_path):
    """A resumed trace: a work order / challenge recorded before the filter
    named tools the case cannot feed; once a dair entry stamps the determined
    evidence kinds, they no longer count as unrun or open."""
    l = _case(tmp_path)
    l.record_dair_call("Triage", "r", False, "", "", "stay", "",
                       verification_challenges=[{"claim": "Prefetch shows x.exe ran",
                                                 "challenge_method": "ez.pecmd",
                                                 "verified": None}],
                       directives={"priority_tools": ["ez.pecmd", "net.ngrep_search"]})
    assert any("pecmd" in x for x in unrun_priority_tools(l._entries))
    assert open_challenge_issues(l._entries)
    l.record_dair_call("Triage", "r", False, "", "", "stay", "",
                       extra={"evidence_kinds": ["pcap"], "evidence_determined": True})
    issues = unrun_priority_tools(l._entries)
    assert issues and not any("pecmd" in x for x in issues) and any("ngrep" in x for x in issues)
    assert open_challenge_issues(l._entries) == []
    assert unrun_from_list(l._entries, ["ez.pecmd", "net.ngrep_search"]) == ["net.ngrep_search"]


def test_collect_backfill_skips_tools_the_evidence_cannot_feed(tmp_path):
    l = _case(tmp_path)
    l.record_dair_call("Triage", "", True, "Collect", "", "push", "")
    l.record_finding("x present", "SUSPECTED", "t")
    r, _ = _assess(l, _raw([], phase="Collect"))
    # PCAP-only: the Windows-artifact lifecycle backfill has nothing runnable → advance
    assert r["server_override"]["kind"] != "lifecycle_backfill"
    assert not any(t.startswith(("ez.", "misc.evtx")) for t in r["directives"]["priority_tools"])


def test_refused_transition_lists_the_whole_phase_work_order(tmp_path):
    l = _case(tmp_path, ("disk.E01",))
    l.record_dair_call("Triage", "", True, "Collect", "", "push", "",
                       directives={"priority_tools": ["ez.pecmd", "ez.lecmd"]})
    l.record_dair_call("Collect", "", False, "", "", "stay", "",
                       directives={"priority_tools": ["ez.jlecmd"]})
    l.record_dair_call("Collect", "", False, "", "", "stay", "",
                       directives={"priority_tools": ["ez.sbecmd"]})
    l.record_finding("x present", "SUSPECTED", "t")
    r, seen = _assess(l, _raw(["ez.mftecmd"], phase="Collect", stack="push",
                              next_phase="Analyze", transition=True))
    assert r["server_override"]["kind"] == "work_order_incomplete"
    for t in ("pecmd", "lecmd", "jlecmd", "sbecmd"):
        assert t in r["server_override"]["detail"], t
        assert any(t in x for x in r["directives"]["priority_tools"]), t
    assert "complete list for the phase" in r["transition_rationale"]
    # the model is told what is still open before it answers
    assert "WORK ORDER STATUS (Collect)" in seen["user"] and "ez.sbecmd" in seen["user"]


def test_prompt_demands_the_complete_work_order_at_once():
    assert "Never drip-feed" in D._DAIR_SYS_BASE
    assert "EVIDENCE FIT" in D._DAIR_SYS_BASE
