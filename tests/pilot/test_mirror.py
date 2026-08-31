"""trace→vera mirror (pilot/mirror.py): golden trace → expected vera rows."""
import json

import pytest

vera_db = pytest.importorskip("vera.db", reason="vera not installed")

from pilot.mirror import FTYPE_MAP, mirror_trace  # noqa: E402


GOLDEN = {
    "schema_version": 3,
    "case_id": "GOLD-1",
    "entry_count": 8,
    "entries": [
        {"type": "tool_call", "call_id": 1, "ts": "2026-08-31T10:00:00Z",
         "cmd": "hash.verify_evidence_hash /e/disk.E01",
         "stdout_excerpt": "sha256 " + "ab" * 32 + " verified",
         "success": True, "exit_code": 0},
        {"type": "tool_call", "call_id": 2, "ts": "2026-08-31T10:01:00Z",
         "cmd": "ez.mftecmd -f /m/$MFT --csv analysis/",
         "stdout_excerpt": "processed 1000 records",
         "success": True, "exit_code": 0},
        {"type": "tool_call", "call_id": 3, "ts": "2026-08-31T10:02:00Z",
         "cmd": "tsk.fls /e/disk.E01", "stdout_excerpt": "",
         "success": False, "exit_code": 1, "stderr": "bad offset"},
        {"type": "dair_call", "call_id": 4, "current_phase": "Triage",
         "next_phase": "Collect", "transition_rationale": "plan satisfied",
         "directives": {"priority_tools": ["ez.evtxecmd", "misc.readpst_extract"]}},
        {"type": "finding", "call_id": 5, "linked_call_id": 2,
         "confidence": "CONFIRMED", "source": "ez.mftecmd",
         "description": "m57plan.xlsx created 2008-07-19 on Jean's host",
         "claim_kind": "positive", "category": "exfil", "act": "egress",
         "channel": "email", "entities": ["m57plan.xlsx"],
         "input_call_ids": [1, 2]},
        {"type": "finding", "call_id": 6, "linked_call_id": 2,
         "confidence": "UNCONFIRMED", "source": "ez.recmd",
         "description": "No persistence via Run keys",
         "claim_kind": "negative", "category": "persistence",
         "act": "persistence_install"},
        {"type": "investigation_narration", "call_id": 7,
         "message": "Pivoting to the mail store next."},
        {"type": "reason_call", "call_id": 8, "verdict": "SUPPORTED"},
    ],
}


@pytest.fixture(scope="module")
def mirrored(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("mirror")
    trace = tmp / "trace.json"
    trace.write_text(json.dumps(GOLDEN))
    case_path = str(tmp / "gold.vera")
    counts = mirror_trace(str(trace), case_path, investigator="trin")
    return counts, case_path, str(trace)


class TestGoldenTrace:
    def test_counts(self, mirrored):
        counts, _, _ = mirrored
        assert counts == {"actions": 3, "findings": 2, "evidence": 1,
                          "leads": 1, "notes": 1}

    def test_rows(self, mirrored):
        _, case_path, _ = mirrored
        c = vera_db.Case(case_path)
        try:
            assert c.meta().get("name") == "GOLD-1"

            # actions carry cid markers, output, exit codes; failure noted
            actions = {a["command"]: a for a in
                       (c.get_action(i) for i in range(1, 4))}
            mft = actions["ez.mftecmd -f /m/$MFT --csv analysis/"]
            assert "[trudi:cid 2]" in mft["notes"]
            assert mft["output"] == "processed 1000 records"
            failed = actions["tsk.fls /e/disk.E01"]
            assert "FAILED" in failed["notes"] and "bad offset" in failed["notes"]

            # evidence from the verify call, sha256 extracted
            ev = c.evidence()
            assert len(ev) == 1 and ev[0]["label"] == "/e/disk.E01"
            assert ev[0]["sha256"] == "ab" * 32

            findings = c.findings()
            by_cid = {(f.get("attrs") or {}).get("trudi_call_id"): f
                      for f in findings}

            # typed positive claim: ftype from category, linked action,
            # whole claim + lineage in attrs, CONFIRMED starred
            pos = by_cid[5]
            assert pos["ftype"] == "netindicator"
            assert pos["action_id"] is not None
            assert "[trudi:cid 2]" in c.get_action(pos["action_id"])["notes"]
            assert pos["starred"] == 1
            attrs = pos["attrs"]
            assert attrs["claim_kind"] == "positive"
            assert attrs["act"] == "egress" and attrs["channel"] == "email"
            assert attrs["entities"] == ["m57plan.xlsx"]
            assert attrs["lineage"] == [1, 2]

            # negatives are notes carrying claim_kind (vera has no negative
            # ftype yet — docs/pilot.md phase 5 upstreams one)
            neg = by_cid[6]
            assert neg["ftype"] == "note"
            assert neg["attrs"]["claim_kind"] == "negative"

            # DAIR work order -> lead + items
            lead = by_cid[4]
            assert lead["ftype"] == "lead"
            items = c.lead_items(lead["id"])
            assert [i["label"] for i in items] == ["ez.evtxecmd",
                                                  "misc.readpst_extract"]

            # narration -> note; reason_call not mirrored
            assert by_cid[7]["ftype"] == "note"
            assert 8 not in by_cid
        finally:
            c.close()

    def test_idempotent(self, mirrored):
        _, case_path, trace = mirrored
        second = mirror_trace(trace, case_path, investigator="trin")
        assert all(v == 0 for v in second.values())

    def test_incremental_append(self, mirrored):
        _, case_path, trace_path = mirrored
        grown = json.loads(open(trace_path).read())
        grown["entries"].append(
            {"type": "finding", "call_id": 9, "linked_call_id": 2,
             "confidence": "LIKELY", "source": "ez.evtxecmd",
             "description": "RDP logon from 10.0.4.6",
             "claim_kind": "positive", "category": "lateral_movement",
             "act": "logon"})
        open(trace_path, "w").write(json.dumps(grown))
        counts = mirror_trace(trace_path, case_path)
        assert counts["findings"] == 1 and counts["actions"] == 0
        c = vera_db.Case(case_path)
        try:
            new = next(f for f in c.findings()
                       if (f.get("attrs") or {}).get("trudi_call_id") == 9)
            assert new["ftype"] == "lateral"
        finally:
            c.close()


class TestFtypeMap:
    def test_only_registered_ftypes(self):
        from vera import types
        registered = set(types.REGISTRY) if hasattr(types, "REGISTRY") else {
            "event", "host", "account", "malware", "netindicator", "lateral",
            "hostindicator", "filesystem", "lead", "note"}
        assert set(FTYPE_MAP.values()) <= registered

    def test_unknown_category_falls_back_to_note(self, tmp_path):
        trace = {"case_id": "X", "entries": [
            {"type": "finding", "call_id": 1, "confidence": "SUSPECTED",
             "description": "odd", "category": "someday_new_category"}]}
        p = tmp_path / "t.json"
        p.write_text(json.dumps(trace))
        mirror_trace(str(p), str(tmp_path / "x.vera"))
        c = vera_db.Case(str(tmp_path / "x.vera"))
        try:
            assert c.findings()[0]["ftype"] == "note"
        finally:
            c.close()
