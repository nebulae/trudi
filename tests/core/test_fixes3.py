"""Review-issue ID coercion, dispositions to review, and the trace replay harness."""
import json
import os
import subprocess
import sys

import pytest

from core.execution_log import ExecutionLog


@pytest.fixture
def log(tmp_path):
    (tmp_path / "analysis").mkdir()
    l = ExecutionLog()
    l.configure("F3", str(tmp_path / "analysis" / "t.json"), save_session=False)
    return l


def test_string_finding_ids_are_tracked_not_rejected(log):
    from core.review_issues import normalize_review
    fid = log.record_finding("defaultprinter added to Administrators (4732)", "LIKELY", "t")
    result = {"result_block": {"issues": [
        {"kind": "contradiction", "message": "no 4732 record exists",
         "finding_call_ids": [str(fid)], "evidence_call_ids": ["cid 999999"]}]}}
    issues, _res, rejected = normalize_review(result, log._entries)
    assert not rejected and len(issues) == 1
    assert issues[0]["finding_call_ids"] == [fid]          # coerced; unknown evidence ref dropped
    assert issues[0]["evidence_call_ids"] == []


def test_dispositions_to_review(log):
    from tools._gates._disposition_review import dispositions_to_review
    log.record_dair_call("Triage", "", True, "Collect", "", "push", "")
    usb = log.record_tool_call("read.output --output /x/registry.csv", True, False, 0, 0,
                               stdout_excerpt="VID_03EB&PID_2422 HID Keyboard and MSC installed")
    shadow = log.record_tool_call("vshadowinfo img", True, False, 0, 0,
                                  stdout_excerpt="Volume Shadow Copy store 1 copies created")
    log.record_disposition("challenge", "5:Volume Shadow Copies exist from 2016-06-29", "verified",
                           evidence_call_ids=[usb])
    log.record_disposition("challenge", "6:Volume Shadow Copies exist from 2016-06-29", "verified",
                           evidence_call_ids=[shadow])
    log.record_disposition("challenge", "7:Classified docs posted to share", "out_of_scope")
    flagged = {d["target_id"].split(":")[0] for d in dispositions_to_review(log._entries)}
    assert flagged == {"5", "7"}


def test_replay_harness_runs_on_a_saved_trace(tmp_path):
    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    l = ExecutionLog()
    l.configure("RP", str(case / "analysis" / "RP_trace.json"), save_session=False)
    l.record_dair_call("Triage", "", True, "Collect", "", "push", "",
                       directives={"priority_tools": [{"tool": "reason.hypothesize", "args": {}}]})
    l.record_disposition("challenge", "3:posted to share", "out_of_scope")
    env = dict(os.environ, PYTHONPATH=os.getcwd())
    out = subprocess.run([sys.executable, "-m", "tools.replay_check", str(case), "--json"],
                         capture_output=True, text=True, env=env, timeout=120)
    rep = json.loads(out.stdout)
    assert rep["entries"] >= 2 and rep["unrun_prescribed"] == []
    assert any(d["reason"] == "out_of_scope" for d in rep["disposition_audit"])
    assert rep["ready_to_report"] is False                # nothing recorded yet
