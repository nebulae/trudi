"""Phase-boundary DAIR engagement gate (core/middleware.py).

Semantics (counter-free — a windowed counter is the retired DAIR_WINDOW
friction): during cold-start Triage, baseline collection is allowed but every
forensic result carries a standing start-the-ritual notice; once
reason_hypothesize is recorded, forensic results carry a finish-the-ritual
notice; once reason_plan is recorded, forensic tools BLOCK until dair_assess
engages DAIR (measured: 10/11 compliant historical runs make zero MCP forensic
calls between plan and first dair — the boundary never fires on a compliant
driver). Once engaged, DAIR directs; in Analyze/Scan with zero findings an
advisory finding_notice rides results, time-throttled.
"""
from unittest.mock import MagicMock, patch

import pytest

import core.middleware as M


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    monkeypatch.setattr(M, "_ritual", M._RitualState())
    monkeypatch.setattr(M, "DAIR_NUDGE_ENABLED", True)


def _log(phase="", entries=None):
    log = MagicMock()
    log._current_phase = phase
    log._entries = entries if entries is not None else []
    return log


_HYP = {"type": "reason_call", "tool": "reason_hypothesize"}
_PLAN = {"type": "reason_call", "tool": "reason_plan"}
_FINDING = {"type": "finding"}
_TOOLCALL = {"type": "tool_call", "cmd": "x"}


class TestColdStartTriage:
    def test_pre_ritual_baseline_carries_standing_protocol_notice(self):
        """A session that never STARTS the ritual must not sit in silent
        baseline freedom (observed live: 48 calls, no hypothesize, tcpdump
        orbit). Every forensic result carries the full ritual sequence —
        notice only, never a block, no counter."""
        with patch("core.execution_log.log", _log(entries=[_TOOLCALL] * 30)):
            for _ in range(5):
                action, msg = M._nudge_decision("net_tcpdump_read")
                assert action == "notice"
                assert "reason.hypothesize(" in msg
                assert "reason.plan(" in msg and "dair.dair_assess(" in msg

    def test_after_hypothesize_notice_names_plan_then_dair(self):
        with patch("core.execution_log.log", _log(entries=[_HYP, _TOOLCALL])):
            action, msg = M._nudge_decision("net_tcpdump_read")
        assert action == "notice"
        assert "reason.plan(" in msg and "dair.dair_assess(" in msg

    def test_after_plan_forensic_tools_block(self):
        with patch("core.execution_log.log", _log(entries=[_HYP, _PLAN])):
            action, msg = M._nudge_decision("net_tcpdump_read")
        assert action == "block"
        assert "dair.dair_assess(" in msg and "Collect" in msg

    def test_block_message_names_dair_required_gate(self):
        with patch("core.execution_log.log", _log(entries=[_PLAN])):
            _, msg = M._nudge_decision("ez_ez_mftecmd")
        assert "dair_required" in msg

    def test_dair_and_reason_tools_are_allowlisted_exits(self):
        # The way out of the block must always be open: the wiring consults the
        # allowlist BEFORE _nudge_decision, so these names never reach the gate.
        # NOTE: misc_record_finding is deliberately NOT allowlisted — it must
        # face the gates (dair_required refuses it pre-engagement with the
        # same call-dair instruction, keeping the two teachers consistent).
        for tool in ("dair_dair_assess", "reason_reason_plan",
                     "reason_reason_hypothesize", "misc_record_agent_message",
                     "misc_record_disposition", "read_read_output"):
            assert tool in M.DAIR_GATE_ALLOWLIST


class TestEngaged:
    @pytest.mark.parametrize("phase", ["Triage", "Collect", "Analyze", "Scan"])
    def test_engaged_phases_allow_regardless_of_ritual_history(self, phase):
        with patch("core.execution_log.log",
                   _log(phase=phase, entries=[_HYP, _PLAN])):
            assert M._nudge_decision("net_tcpdump_read") == ("allow", "")

    def test_trace_reset_clears_ritual_state(self):
        with patch("core.execution_log.log", _log(entries=[_HYP, _PLAN])):
            assert M._nudge_decision("t")[0] == "block"
        # new case: shorter trace, no ritual entries — the BLOCK lifts; the
        # fresh pre-ritual state carries the standing start-the-ritual notice.
        with patch("core.execution_log.log", _log(entries=[])):
            action, msg = M._nudge_decision("t")
            assert action == "notice"
            assert "reason.hypothesize(" in msg


class TestExemptions:
    @pytest.mark.parametrize("tool", ["monitor_check_alerts", "respond_list_actions",
                                      "velo_query", "live_live_processes",
                                      "misc_job_status", "misc_job_list"])
    def test_live_and_job_tools_never_gated(self, tool):
        with patch("core.execution_log.log", _log(entries=[_PLAN])):
            assert M._nudge_decision(tool) == ("allow", "")

    def test_kill_switch(self, monkeypatch):
        monkeypatch.setattr(M, "DAIR_NUDGE_ENABLED", False)
        with patch("core.execution_log.log", _log(entries=[_PLAN])):
            assert M._nudge_decision("net_tcpdump_read") == ("allow", "")

    def test_fail_open_on_log_error(self):
        broken = MagicMock()
        type(broken)._current_phase = property(lambda self: 1 / 0)
        with patch("core.execution_log.log", broken):
            assert M._nudge_decision("t") == ("allow", "")


class TestFindingNotice:
    def test_analyze_with_zero_findings_advises(self):
        with patch("core.execution_log.log", _log(phase="Analyze", entries=[])):
            msg = M._finding_nudge()
        assert "record_finding" in msg and "linked_call_id" in msg

    def test_silent_when_findings_exist(self):
        with patch("core.execution_log.log",
                   _log(phase="Analyze", entries=[_FINDING])):
            assert M._finding_nudge() == ""

    @pytest.mark.parametrize("phase", ["", "Triage", "Collect", "Report"])
    def test_silent_outside_analyze_and_scan(self, phase):
        with patch("core.execution_log.log", _log(phase=phase, entries=[])):
            assert M._finding_nudge() == ""

    def test_time_throttled(self):
        log = _log(phase="Scan", entries=[])
        with patch("core.execution_log.log", log):
            assert M._finding_nudge() != ""
            assert M._finding_nudge() == ""          # within the interval


class TestNoticeInjection:
    def test_apply_notices_adds_fields_without_clobbering(self):
        payload = {"success": True, "dair_notice": "pre-existing"}
        out = M._apply_notices(payload, [("dair_notice", "new"),
                                         ("finding_notice", "f")])
        assert out["dair_notice"] == "pre-existing"
        assert out["finding_notice"] == "f"
