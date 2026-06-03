"""Tests for the lineage_required gate (G4).

Enforces that every agent-facing record_* MCP call carries input_call_ids
(after a 5-entry genesis grace period) and that each cid is real.
"""
import pytest
from unittest.mock import patch


def _seed_log_ready_for_confirmed(tmp_path, n_pad_entries=0):
    """Build a log primed for CONFIRMED-tier finding gates to pass everything
    EXCEPT lineage_required, so we can isolate it. Optionally pads with
    additional narration entries to exit the genesis grace window."""
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("LINEAGE", str(tmp_path / "trace.json"))
    l.record_dair_call("Triage", "", False, "", "", "stay", "")
    tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
    l.record_reason_call("reason_hypothesize", True, "ok", {})
    l.record_reason_call(
        "reason_confidence_score",
        True,
        'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED", "score": 0.95}',
        {},
        inputs={"user_message": "a finding"},
    )
    l.record_reason_call(
        "reason_cite_check",
        True,
        'CITE_CHECK:\n{"verdict": "ALL_CITED"}',
        {},
        inputs={"user_message": "a finding"},
    )
    l.record_reason_call(
        "reason_evaluate_finding", True,
        "VERDICT: SUPPORTED.",
        {},
    )
    # Pad with extra entries to escape the genesis grace if requested
    for i in range(n_pad_entries):
        l.record_agent_message(f"pad {i}", input_call_ids=[tid])
    return l, tid


class TestLineageGate:
    def test_refuses_empty_after_genesis(self, tmp_path):
        """Once the trace has >= 5 entries, a record_finding call with no
        input_call_ids gets refused with gate=lineage_required."""
        from tools.misc import record_finding
        # Helper adds 6 entries (dair + tool + 4 reasons) → past genesis grace
        l, tid = _seed_log_ready_for_confirmed(tmp_path)
        assert len(l._entries) >= 6  # past genesis grace
        with patch("core.execution_log.log", l):
            r = record_finding("a finding", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid)  # NO input_call_ids
        assert r["success"] is False
        assert r["gate"] == "lineage_required"

    def test_allows_empty_in_genesis_window(self, tmp_path):
        """With < 5 entries, empty input_call_ids is OK (bootstrap grace)."""
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("GENESIS", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        # 2 entries — well within genesis grace
        assert len(l._entries) < 5
        with patch("core.execution_log.log", l):
            r = record_finding("first finding", "SUSPECTED", "vol.psscan",
                               linked_call_id=tid)  # NO input_call_ids
        # Other gates may or may not pass, but lineage_required should NOT fire
        assert r.get("gate") != "lineage_required"

    def test_refuses_unknown_cids(self, tmp_path):
        """input_call_ids containing a cid not present in the trace → refused
        with unknown_cids list."""
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("a finding", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid,
                               input_call_ids=[tid, 99999])  # 99999 doesn't exist
        assert r["success"] is False
        assert r["gate"] == "lineage_required"
        assert 99999 in r["unknown_cids"]

    def test_passes_with_valid_cids(self, tmp_path):
        """input_call_ids containing only existing cids → finding records."""
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("a finding", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid,
                               input_call_ids=[tid])
        assert r["success"] is True
        # Finding entry carries the lineage we passed
        find_entry = [e for e in l._entries if e.get("type") == "finding"][-1]
        assert find_entry["input_call_ids"] == [tid]

    def test_gate_runs_in_correct_order(self):
        """lineage_required should be in the GATES list right after
        dair_required (so DAIR-missing wins for a clearer message, but
        lineage refusal precedes the tier-specific gates that would otherwise
        confusingly run on a lineageless finding)."""
        from tools._gates import GATES
        names = [n for n, _ in GATES]
        assert names.index("lineage_required") == names.index("dair_required") + 1
