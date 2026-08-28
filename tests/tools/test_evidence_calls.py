"""Shared 'evidence tool call' predicate used by the anti-workaround gates."""
from unittest.mock import MagicMock

from tools._gates import _evidence_calls as ec


def _t(cmd, cid=1, success=True):
    return {"type": "tool_call", "cmd": cmd, "call_id": cid, "success": success}


class TestPredicate:
    def test_forensic_and_read_calls_count(self):
        assert ec.is_evidence_tool_call(_t("dotnet /x/EvtxECmd.dll -f Security.evtx"))
        assert ec.is_evidence_tool_call(_t("read.read_output --output /c/exports/x.csv"))
        assert ec.is_evidence_tool_call(_t("read.read_mail -o /c/exports/mail"))
        assert ec.is_evidence_tool_call(_t("<py>:correlate_mitre_map"))
        assert ec.is_evidence_tool_call(_t("misc.chat_db_export /img/main.db"))

    def test_meta_baselines_do_not_count(self):
        for cmd in ("<py>:misc_record_finding", "<py>:misc_record_agent_message",
                    "<py>:reason_evaluate_finding", "<py>:dair_assess",
                    "<py>:accuracy_compare", "<py>:coverage_coverage_report"):
            assert not ec.is_evidence_tool_call(_t(cmd)), cmd

    def test_failed_or_empty_calls_do_not_count(self):
        assert not ec.is_evidence_tool_call(_t("dotnet /x/MFTECmd.dll", success=False))
        assert not ec.is_evidence_tool_call(_t("", success=True))
        assert not ec.is_evidence_tool_call({"type": "finding", "cmd": "x"})


class TestHelpers:
    def test_last_and_after(self):
        by_type = {"tool_call": [_t("<py>:misc_record_finding", 5),
                                 _t("ez.x", 3), _t("ez.y", 7, success=False),
                                 _t("read.read_output --output a.csv", 6)]}
        assert ec.last_evidence_call_id(by_type) == 6
        assert [e["call_id"] for e in ec.evidence_calls_after(by_type, 3)] == [6]
        assert ec.evidence_calls_after(by_type, 6) == []

    def test_tolerates_magicmock_index(self):
        assert ec.last_evidence_call_id(MagicMock()) == 0
        assert ec.evidence_calls_after(MagicMock(), 0) == []
        assert ec.last_evidence_call_id(None) == 0
