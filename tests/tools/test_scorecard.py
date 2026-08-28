"""tools/scorecard.py — read-only run scorecard (Phase J-4)."""
import json

from tools import scorecard as SC


def _trace(entries):
    return {"case_id": "T", "entries": entries}


def _finding(cid, tier, category, act, entities, desc, recipients=None):
    return {"call_id": cid, "type": "finding", "confidence": tier,
            "description": desc, "claim": {"category": category, "act": act,
                                           "entities": entities, "recipients": recipients or []}}


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj))
    return str(p)


def test_operational_metrics(tmp_path):
    entries = [
        {"type": "tool_call", "success": True, "cmd": "dotnet MFTECmd.dll -f $MFT", "ts": "2026-01-01T00:00:00Z"},
        {"type": "tool_call", "success": True, "cmd": "dotnet EvtxECmd.dll -f Security.evtx", "ts": "2026-01-01T00:10:00Z"},
        {"type": "tool_call", "success": True, "cmd": "<py>:misc_record_finding x", "ts": "2026-01-01T00:11:00Z"},
        {"type": "reason_call", "tool": "reason_evaluate_finding", "evidence_rounds": 1, "ts": "2026-01-01T00:12:00Z"},
        {"type": "reason_call", "tool": "reason_synthesize", "ts": "2026-01-01T00:13:00Z"},
        {"type": "dair_call", "ts": "2026-01-01T00:14:00Z"},
        {"type": "disposition", "ts": "2026-01-01T00:15:00Z"},
        {"type": "finding_refused", "gate": "tier_contract", "ts": "2026-01-01T00:16:00Z"},
        _finding(9, "CONFIRMED", "exfil", "egress", ["x"], "d", ), 
        {"type": "tool_call", "success": True, "cmd": "<py>:misc_write_final_report reports/r.md", "ts": "2026-01-01T00:30:00Z"},
    ]
    entries[8]["ts"] = "2026-01-01T00:17:00Z"
    r = SC.score(_write(tmp_path, "t.json", _trace(entries)))
    m = r["metrics"]
    assert m["minutes"] == 30.0
    assert m["evidence_calls"] == 2                       # the two real tool runs, not the <py>: ones
    assert m["control_plane"] == 5                        # 2 reason + dair + disp + refusal
    assert m["control_to_evidence"] == 2.5
    assert m["dispositions"] == 1 and m["refusals"] == 1
    assert m["findings_by_tier"]["CONFIRMED"] == 1
    assert m["reached_report"] is True
    assert r["targets"]["control_to_evidence"]["pass"] is False


def test_tier_accuracy_met_under_over_missing(tmp_path):
    findings = [
        _finding(1, "LIKELY", "device_initial_access", "account_creation",
                 ["defaultprinter", "Ducky_Storage"], "covert defaultprinter created by Ducky"),
        _finding(2, "CONFIRMED", "exfil", "egress",
                 ["Anthony Vanko", "Titan Biotech"], "Vanko engaged Titan Biotech to disseminate"),
        _finding(3, "SUSPECTED", "exfil", "egress",
                 ["temp.zip", "smallftpd.exe"], "smallftpd backdoor downloaded temp.zip"),
    ]
    gt = {"expected_findings": [
        {"id": "MET", "confidence_min": "LIKELY", "category": "device_initial_access",
         "act": "account_creation", "entities": ["defaultprinter", "Ducky_Storage"],
         "description": "covert defaultprinter account created via BadUSB Ducky"},
        {"id": "OVER", "confidence_min": "LIKELY", "category": "exfil", "act": "egress",
         "entities": ["Anthony Vanko", "Titan Biotech"],
         "description": "Vanko engaged Titan Biotech to disseminate research"},
        {"id": "UNDER", "confidence_min": "LIKELY", "category": "exfil", "act": "egress",
         "entities": ["temp.zip", "smallftpd.exe"], "description": "smallftpd downloaded temp.zip"},
        {"id": "GONE", "confidence_min": "SUSPECTED", "category": "identity", "act": "presence",
         "entities": ["SDelete", "VeraCrypt"], "description": "anti-forensic tooling present"},
    ]}
    tp = _write(tmp_path, "t.json", _trace([{"type": "tool_call", "success": True,
                "cmd": "x", "ts": "2026-01-01T00:00:00Z"}] + findings))
    gp = _write(tmp_path, "gt.json", gt)
    r = SC.score(tp, gp)
    ta = r["tier_accuracy"]
    by = {p["id"]: p["verdict"] for p in ta["pairs"]}
    assert by == {"MET": "met", "OVER": "over", "UNDER": "under", "GONE": "missing"}
    assert ta["under_tiered"] == 2 and ta["over_tiered"] == 1   # UNDER + GONE under-count
    assert ta["matched"] == 3 and ta["recall"] == 0.75
    assert r["targets"]["over_tiered"]["pass"] is False


def test_global_assignment_beats_greedy(tmp_path):
    # Two GT items whose best findings would collide under per-GT greedy: the
    # attribution GT must NOT steal the presence finding.
    findings = [
        _finding(1, "LIKELY", "identity", "attribution", ["defaultprinter", "173.73.166.249"],
                 "defaultprinter operated over RDP from 173.73.166.249"),
        _finding(2, "SUSPECTED", "identity", "presence", ["OneDrive", "research.docx"],
                 "classified docs present in OneDrive"),
    ]
    gt = {"expected_findings": [
        {"id": "RDP", "confidence_min": "LIKELY", "category": "identity", "act": "attribution",
         "entities": ["defaultprinter", "173.73.166.249"], "description": "RDP control of defaultprinter"},
        {"id": "PRESENT", "confidence_min": "SUSPECTED", "category": "identity", "act": "presence",
         "entities": ["OneDrive", "research.docx"], "description": "classified docs in OneDrive"},
    ]}
    tp = _write(tmp_path, "t.json", _trace([{"type": "tool_call", "success": True,
                "cmd": "x", "ts": "2026-01-01T00:00:00Z"}] + findings))
    r = SC.score(tp, _write(tmp_path, "gt.json", gt))
    by = {p["id"]: p["verdict"] for p in r["tier_accuracy"]["pairs"]}
    assert by == {"RDP": "met", "PRESENT": "met"}


def test_vanko_ground_truth_parses():
    import os
    p = os.path.expanduser("~/cases/vanko-Qwen3.6/ground_truth.json")
    if not os.path.exists(p):
        return
    d = json.load(open(p))
    assert d["case_id"] == "VANKO-2016"
    for f in d["expected_findings"]:
        assert f["confidence_min"] in ("CONFIRMED", "LIKELY", "SUSPECTED")
        assert f.get("category") and f.get("act")
