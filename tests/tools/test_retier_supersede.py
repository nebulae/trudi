"""Re-tier / supersede: a downgraded finding can be upgraded once new evidence
earns a SUPPORTED evaluate, and pre_report_check treats under-tiering as an
advisory re-confirm directive (safe direction), not a report blocker.
"""
import pytest
from unittest.mock import patch

from tools.reasoning import _is_undertier_blocker


class TestUnderTierClassifier:
    @pytest.mark.parametrize("text", [
        "F1/F2 tier misassigned to LIKELY; physical artifacts warrant CONFIRMED",
        "smallftpd execution under-classified — should be CONFIRMED",
        "F9 under-tiered given triple corroboration",
        "upgrade F3 to CONFIRMED",
    ])
    def test_upgrade_directions_are_undertier(self, text):
        assert _is_undertier_blocker(text) is True

    @pytest.mark.parametrize("text", [
        "F2 over-claims a brute-force attack; should be LIKELY",
        "downgrade F5 — no session binding",
        "tier too high, not CONFIRMED without a transfer artifact",
        "BadUSB-to-account bridge lacks a linking artifact",   # unrelated blocker
        "recipient not cross-referenced against the roster",
    ])
    def test_downgrade_and_unrelated_stay_blocking(self, text):
        assert _is_undertier_blocker(text) is False


class TestSupersedeInLog:
    def _log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("RETIER", str(tmp_path / "t.json"), save_session=False)
        return l

    def test_supersede_marks_old_and_links_new(self, tmp_path):
        l = self._log(tmp_path)
        old = l.record_finding("smallftpd executed", "LIKELY", "ez.pecmd", 5)
        new = l.record_finding("smallftpd executed (triple-corroborated)", "CONFIRMED",
                               "ez.pecmd", 5, supersedes=old)
        by = l.index().by_call_id
        assert by[old]["superseded_by"] == new
        assert by[new]["supersedes"] == old
        assert by[new]["confidence"] == "CONFIRMED"

    def test_no_supersedes_leaves_entry_clean(self, tmp_path):
        l = self._log(tmp_path)
        cid = l.record_finding("x", "LIKELY", "s", 1)
        assert "supersedes" not in l.index().by_call_id[cid]

    def test_supersede_unknown_id_is_noop_but_records(self, tmp_path):
        l = self._log(tmp_path)
        cid = l.record_finding("x", "CONFIRMED", "s", 1, supersedes=999999)
        assert l.index().by_call_id[cid]["supersedes"] == 999999   # link recorded
        # nothing to mark; no crash


class TestPreReportUnderTierAdvisory:
    """Under-tier synthesize blockers land in warnings (with a re-confirm
    directive), not blocking_issues; real blockers still block."""

    def _run(self, tmp_path, blockers):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_pre_report_check
        l = ExecutionLog()
        l.configure("PRC", str(tmp_path / "t.json"), save_session=False)
        l.record_tool_call("ez.mftecmd -f x", True, False, 0, 0)
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_hypothesize", True, "hyp", {})
        # synthesize carries the structured blockers list
        l.record_reason_call("reason_synthesize", True, "done", {}, blockers=list(blockers))
        with patch("core.execution_log.log", l):
            return reason_pre_report_check()

    def test_undertier_only_does_not_block(self, tmp_path):
        r = self._run(tmp_path, ["F1 tier misassigned to LIKELY; artifacts warrant CONFIRMED"])
        joined = " ".join(r["blocking_issues"])
        assert "warrant CONFIRMED" not in joined            # not a blocker
        assert any("UNDER-tiered" in w for w in r["warnings"])
        assert any("supersedes" in w for w in r["warnings"])  # re-confirm directive present

    def test_real_blocker_still_blocks(self, tmp_path):
        r = self._run(tmp_path, ["recipient not cross-referenced against the roster"])
        assert any("roster" in i for i in r["blocking_issues"])

    def test_mixed_splits(self, tmp_path):
        r = self._run(tmp_path, [
            "F1 under-classified — should be CONFIRMED",
            "exfil channel not ranked",
        ])
        assert any("exfil channel" in i for i in r["blocking_issues"])
        assert any("UNDER-tiered" in w for w in r["warnings"])
        assert not any("under-classified" in i for i in r["blocking_issues"])
