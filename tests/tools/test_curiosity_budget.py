"""Tests for the curiosity_budget gate + record_curiosity_probe.

The curiosity budget is the sanctioned address for agent-chosen exploration:
a read-only probe outside directives.priority_tools. dair_assess grants an
allowance via directives.curiosity_budget; the gate enforces it and requires a
rationale. A probe is never a finding — these tests assert it stays out of the
finding path and that budget=0 reproduces today's directive-only behavior.
"""
import pytest
from unittest.mock import patch

from tools._gates import curiosity_budget


def _log_with_budget(tmp_path, budget):
    """A configured log whose most recent dair_call granted `budget` probes."""
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("CURIOSITY", str(tmp_path / "trace.json"))
    l.record_dair_call(
        "Analyze", "", False, "", "", "stay", "",
        directives={"priority_tools": ["vol.pstree"], "curiosity_budget": budget},
    )
    return l


# ── gate unit tests ──────────────────────────────────────────────────────────

class TestCuriosityBudgetGate:
    def test_rationale_required(self, tmp_path):
        l = _log_with_budget(tmp_path, budget=2)
        failure = curiosity_budget.check(l.last_n_window(30), rationale="   ")
        assert failure is not None
        assert failure["gate"] == "curiosity_budget"
        assert "rationale" in failure["error"].lower()

    def test_zero_budget_refuses(self, tmp_path):
        """budget=0 ⇒ strict directive-only behavior (the rollback / A-B case)."""
        l = _log_with_budget(tmp_path, budget=0)
        failure = curiosity_budget.check(l.last_n_window(30), rationale="check 2nd SID bin")
        assert failure is not None
        assert failure["gate"] == "curiosity_budget"

    def test_no_dair_call_refuses(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("CURIOSITY", str(tmp_path / "trace.json"))
        failure = curiosity_budget.check(l.last_n_window(30), rationale="a hunch")
        assert failure is not None
        assert failure["gate"] == "curiosity_budget"

    def test_within_budget_allows(self, tmp_path):
        l = _log_with_budget(tmp_path, budget=2)
        assert curiosity_budget.check(l.last_n_window(30), rationale="a hunch") is None

    def test_exhaustion_after_spend(self, tmp_path):
        """Budget of 1: first probe allowed, second refused."""
        l = _log_with_budget(tmp_path, budget=1)
        assert curiosity_budget.check(l.last_n_window(30), rationale="hunch 1") is None
        l.record_curiosity_probe("hunch 1")
        failure = curiosity_budget.check(l.last_n_window(30), rationale="hunch 2")
        assert failure is not None
        assert "exhausted" in failure["error"].lower()

    def test_fresh_dair_refreshes_allowance(self, tmp_path):
        """A new dair_assess resets the spend — probes are counted only AFTER
        the most recent dair_call."""
        l = _log_with_budget(tmp_path, budget=1)
        l.record_curiosity_probe("hunch 1")
        assert curiosity_budget.check(l.last_n_window(30), rationale="hunch 2") is not None
        # next dair_assess grants a fresh budget
        l.record_dair_call(
            "Analyze", "", False, "", "", "stay", "",
            directives={"curiosity_budget": 1},
        )
        assert curiosity_budget.check(l.last_n_window(30), rationale="hunch 2") is None


# ── trace-type unit tests ────────────────────────────────────────────────────

class TestCuriosityProbeEntry:
    def test_entry_shape_and_default_lineage(self, tmp_path):
        l = _log_with_budget(tmp_path, budget=2)
        dair_cid = l._last_dair_cid
        cid = l.record_curiosity_probe("look at RM#2 recycle bin", seeded_by="H0007")
        entry = l.index().by_call_id[cid]
        assert entry["type"] == "curiosity_probe"
        assert entry["probe_rationale"] == "look at RM#2 recycle bin"
        assert entry["seeded_by"] == "H0007"
        # defaults lineage to the most recent dair_assess so it's not an orphan
        assert entry["input_call_ids"] == [dair_cid]

    def test_explicit_lineage_wins(self, tmp_path):
        l = _log_with_budget(tmp_path, budget=2)
        cid = l.record_curiosity_probe("hunch", input_call_ids=[3, 4])
        entry = l.index().by_call_id[cid]
        assert entry["input_call_ids"] == [3, 4]


# ── end-to-end through the MCP tool ──────────────────────────────────────────

class TestRecordCuriosityProbeTool:
    def test_tool_allows_and_logs(self, tmp_path):
        from tools.misc import record_curiosity_probe
        l = _log_with_budget(tmp_path, budget=2)
        with patch("core.execution_log.log", l):
            r = record_curiosity_probe("check untouched comms store", seeded_by="H0009")
        assert r["success"] is True
        entry = l.index().by_call_id[r["call_id"]]
        assert entry["type"] == "curiosity_probe"
        assert entry["seeded_by"] == "H0009"

    def test_tool_refuses_when_exhausted_and_writes_nothing(self, tmp_path):
        from tools.misc import record_curiosity_probe
        l = _log_with_budget(tmp_path, budget=1)
        with patch("core.execution_log.log", l):
            assert record_curiosity_probe("hunch 1")["success"] is True
            r = record_curiosity_probe("hunch 2")
        assert r["success"] is False
        assert r["gate"] == "curiosity_budget"
        # the refused probe left no entry behind
        probes = [e for e in l._entries if e.get("type") == "curiosity_probe"]
        assert len(probes) == 1

    def test_tool_refuses_blank_rationale(self, tmp_path):
        from tools.misc import record_curiosity_probe
        l = _log_with_budget(tmp_path, budget=2)
        with patch("core.execution_log.log", l):
            r = record_curiosity_probe("")
        assert r["success"] is False
        assert r["gate"] == "curiosity_budget"


# ── absence-mode hypothesize (the probe generator) ──────────────────────────

class TestAbsenceModeHypothesize:
    def _capture_ask(self, monkeypatch):
        import tools.reasoning as r
        seen = {}

        def fake_ask(system, user, max_tokens=2048, _tool_name="",
                     hypothesis_id="", input_call_ids=None):
            seen["system"], seen["user"] = system, user
            return {"success": True, "conclusion": "", "hypothesis_id": hypothesis_id,
                    "directives": r._EMPTY_DIRECTIVES.copy()}

        monkeypatch.setattr(r, "_ask", fake_ask)
        return r, seen

    def test_absence_mode_uses_differential_prompt(self, monkeypatch):
        r, seen = self._capture_ask(monkeypatch)
        r.reason_hypothesize("who controls the new SID?",
                             evidence="MFT, Security.evtx", mode="absence",
                             input_call_ids=[1])
        assert seen["system"] is r._HYPOTHESIZE_ABSENCE_SYS
        assert "UNRESOLVED QUESTION" in seen["user"]
        assert "ALREADY EXAMINED" in seen["user"]

    def test_presence_mode_is_default_and_unchanged(self, monkeypatch):
        r, seen = self._capture_ask(monkeypatch)
        r.reason_hypothesize("orphaned PID 5024", evidence="vol.pstree",
                             input_call_ids=[1])
        assert seen["system"] is r._HYPOTHESIZE_SYS
        assert "OBSERVATION" in seen["user"]

    def test_budget_field_in_directives_template(self):
        import tools.reasoning as r
        assert r._EMPTY_DIRECTIVES["curiosity_budget"] == 0
