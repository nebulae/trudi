"""Evidence display, coverage/disposition integrity and the Report-phase gate
(2026-09-23 run review)."""
import json
from unittest.mock import patch

import pytest

from core import iocs as I
from core.execution_log import ExecutionLog
from tests.core.test_iocs import case, _tool  # noqa: F401  (fixture)


@pytest.fixture
def log(tmp_path):
    (tmp_path / "analysis").mkdir()
    l = ExecutionLog()
    l.configure("F2", str(tmp_path / "analysis" / "trace.json"), save_session=False)
    return l


# ── coverage ──────────────────────────────────────────────────────────────────

def test_pcap_only_component_is_not_applicable_without_a_capture(case, tmp_path):
    ev = _tool(case, "setupapi read", "misc_device_install_inventory", out="VID_03EB&PID_2422")
    case.record_ioc("device", "03EB:2422", "03EB:2422", "observed", ["T1200"], [ev])
    spec = I.component_map()["Network Traffic Flow"]
    assert spec["requires"] == "pcap"
    with patch.object(I, "component_map", return_value={
            "Drive Creation": I.component_map()["Drive Creation"],
            "Process Creation": spec}):
        cov = I.coverage(case._entries, case_dir=str(tmp_path / "nocase"))
        st = {i["component"]: i["status"] for i in cov["items"] if i["component"]}
        assert st["Process Creation"] == "not_applicable"
        (tmp_path / "c" / "evidence").mkdir(parents=True)
        (tmp_path / "c" / "evidence" / "net.pcap").write_bytes(b"")
        cov = I.coverage(case._entries, case_dir=str(tmp_path / "c"))
        st = {i["component"]: i["status"] for i in cov["items"] if i["component"]}
        assert st["Process Creation"] == "open"


def test_hostname_and_domain_labels_are_tokens():
    assert "starkresearch" in I.ioc_tokens({"ioc_type": "hostname",
                                            "normalized": "starkresearch.stark.local"})
    assert "dropbox" in I.ioc_tokens({"ioc_type": "domain", "normalized": "www.dropbox.com"})
    assert "www" not in I.ioc_tokens({"ioc_type": "domain", "normalized": "www.dropbox.com"})
    assert "evil.example.org" in I.ioc_tokens({"ioc_type": "url",
                                               "normalized": "https://evil.example.org/a?b"})


def test_consolehost_history_read_covers_command_execution():
    spec = I.component_map()["Command Execution"]
    views = [(9, "strings_grep",
              "grep -i evil /mnt/c/users/x/appdata/roaming/microsoft/windows/powershell/"
              "psreadline/consolehost_history.txt", "net user evil /add", [])]
    assert I._examined_for(views, spec, {"evil"}, []) == [9]


# ── dispositions ──────────────────────────────────────────────────────────────

def test_absent_source_needs_evidence_and_new_reasons(log):
    import tools.misc as M
    from tools._gates import _dispositions as D
    log.record_dair_call("Triage", "", True, "Collect", "", "push", "")
    with patch("core.execution_log.log", log):
        r = M.record_disposition("source", "chat_messenger", "absent_from_evidence")
        assert r["success"] is False and r["missing"] == ["evidence_call_ids"]
        r = M.record_disposition("tool", "misc.chainsaw_hunt", "tool_unavailable")
        assert r.get("success") is not False
        r = M.record_disposition("challenge", "5:hive exists", "verified")
        assert r["success"] is False
        cid = log.record_tool_call("fls -r img", True, False, 0, 0, stdout_excerpt="Users/x")
        log.index().by_call_id[cid]["mcp_tool"] = "tsk_fls"
        r = M.record_disposition("source", "chat_messenger", "absent_from_evidence",
                                 evidence_call_ids=[cid])
        assert r.get("success") is not False
    assert "tool_unavailable" in D.SOURCE_WAIVER_REASONS_ALL
    assert not D.validate("source", "x", "present_unparseable")
    assert D.validate("principal", "x", "verified")


# ── Report phase is server-owned ─────────────────────────────────────────────

def test_report_tools_refuse_outside_report_phase(log):
    from tools.reasoning import reason_pre_report_check, reason_synthesize
    from tools.misc import write_final_report
    for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
        log.record_dair_call(cur, "", True, nxt, "", "push", "")
    # the model echoes Report; the recorded phase is still Analyze
    log._entries[-1]["current_phase"] = "Report"
    with patch("core.execution_log.log", log):
        r = reason_pre_report_check()
        assert r["gate"] == "report_phase_required" and r["ready_to_report"] is False
        assert reason_synthesize("f")["gate"] == "report_phase_required"
        out = str(log._path).replace("analysis/trace.json", "reports/r.md")
        assert write_final_report(out, "x")["success"] is False


# ── reformulation limit ignores reviews that produced no verdict ─────────────

def test_malformed_reviews_do_not_count_as_reformulations(log):
    from tools import reasoning as R
    log.record_dair_call("Triage", "", True, "Collect", "", "push", "")
    for _ in range(3):
        log.record_reason_call("reason_evaluate_finding", False, "", {},
                               inputs={"user_message": "FINDING:\nvanko copied the files"},
                               extra={"schema_error": True, "parse_path": R.PARSE_NONE})
    with patch("core.execution_log.log", log), \
         patch.object(R, "_ask", return_value={"success": False, "error": "down"}):
        r = R.reason_evaluate_finding("vanko copied the files", "rows")
    assert r.get("gate") != "reformulation_depth_limit"


# ── evidence display ─────────────────────────────────────────────────────────

def test_ranked_selection_prefers_rows_with_identifiers():
    from core.evidence_packets import _selection
    raw = ("".join(f"noise row {i} copied\n" for i in range(50))
           + "2016-06-30 vanko copied StarkResearch Level 5\n").encode()
    sel = _selection(raw, ["copied", "starkresearch"], {}, 4000,
                     weights={"starkresearch": 3}, row_limit=2)
    texts = [s["text"] for s in sel["spans"]]
    assert any("StarkResearch" in t for t in texts) and len(texts) == 2
    assert sel["matched_lines"] == 51 and sel["selection_complete"] is False
