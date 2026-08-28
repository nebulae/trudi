"""The DAIR gate reads DAIR's own phase state, not a tool counter. Forensics run
in any active investigation phase (Triage/Collect/Analyze/Scan); they block only
once DAIR moves to Report, where new evidence needs a DAIR-directed return to a
collection phase.
"""
import pytest
from unittest.mock import patch

from core import middleware as mw
from core.execution_log import ExecutionLog


@pytest.fixture
def log(tmp_path):
    l = ExecutionLog()
    l.configure("DAIR-GATE", str(tmp_path / "t.json"), save_session=False)
    return l


def _decide(log):
    with patch("core.execution_log.log", log):
        return mw._gate_decision()


def _dair(log, current, nxt="", action="stay"):
    log.record_dair_call(current, "", bool(nxt), nxt, "", action, "")


def _tool(log):
    log.record_tool_call("ez.mftecmd -f x", True, False, 0, 0)


class TestPhaseGate:
    def test_empty_trace_allows(self, log):
        block, reason = _decide(log)
        assert block is False and "cold start" in reason

    def test_triage_phase_allows(self, log):
        _dair(log, "Triage")
        _tool(log)
        assert _decide(log)[0] is False

    def test_collect_phase_allows_unbounded_batch(self, log):
        # The regression: a long lead-following batch must not be blocked.
        _dair(log, "Triage", nxt="Collect", action="push")
        for _ in range(40):
            _tool(log)
        block, reason = _decide(log)
        assert block is False and "Collect" in reason

    def test_analyze_and_scan_allow(self, log):
        for ph in ("Analyze", "Scan"):
            _dair(log, "Triage", nxt=ph, action="push")
            assert _decide(log)[0] is False, ph

    def test_report_phase_blocks(self, log):
        _dair(log, "Analyze", nxt="Report", action="push")
        block, reason = _decide(log)
        assert block is True and "Report" in reason and "dair_assess" in reason

    def test_report_then_return_to_collect_reopens(self, log):
        _dair(log, "Analyze", nxt="Report", action="push")
        assert _decide(log)[0] is True
        # DAIR directs a return to a collection phase (Report blocker → Collect).
        _dair(log, "Report", nxt="Collect", action="push")
        assert _decide(log)[0] is False

    def test_findings_and_narration_never_affect_the_gate(self, log):
        _dair(log, "Triage", nxt="Collect", action="push")
        for _ in range(30):
            log.record_agent_message("noise")
            log.record_finding("f", "LIKELY", "s", 1)
        assert _decide(log)[0] is False   # still Collect → allowed

    def test_fail_open_on_error(self):
        class Broken:
            @property
            def _entries(self):
                raise RuntimeError("boom")
        with patch("core.execution_log.log", Broken()):
            block, reason = mw._gate_decision()
        assert block is False and "fail-open" in reason
