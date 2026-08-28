"""Attack-lifecycle coverage model (Layer 1) + pre_report advisory (Layer 2)."""
from unittest.mock import patch
from core.execution_log import ExecutionLog
from tools._gates._claims import normalize_claim, CATEGORIES, ACTS
from tools._gates._lifecycle import coverage, uncovered_phases, LIFECYCLE


def _tc(cmd):
    return {"type": "tool_call", "cmd": cmd, "success": True}


def _find(cat="", act="", kind="positive"):
    return {"type": "finding", "confidence": "SUSPECTED",
            "claim": normalize_claim(claim_kind=kind, category=cat, act=act)}


class TestVocabulary:
    def test_privilege_escalation_in_enums(self):
        assert "privilege_escalation" in CATEGORIES
        assert "privilege_escalation" in ACTS


class TestCoverageModel:
    def test_all_five_phases_present(self):
        assert set(LIFECYCLE) == {"persistence", "privilege_escalation",
                                  "lateral_movement", "execution", "exfil"}

    def test_established_by_finding(self):
        cov = coverage([_find(act="egress")])
        assert cov["exfil"]["status"] == "established"

    def test_ruled_out_by_negative(self):
        cov = coverage([_find(cat="persistence", kind="negative")])
        assert cov["persistence"]["status"] == "ruled_out"

    def test_examined_by_source_regex(self):
        cov = coverage([_tc("dotnet PECmd.dll -d /mnt/x/Windows/Prefetch")])
        assert cov["execution"]["status"] == "examined"
        assert "prefetch" in cov["execution"]["sources_examined"]

    def test_not_examined_is_the_gap(self):
        cov = coverage([_tc("dotnet EvtxECmd.dll -f Security.evtx")])   # unrelated
        assert cov["privilege_escalation"]["status"] == "not_examined"
        gaps = {p[0] for p in uncovered_phases([_tc("ls")])}
        assert "privilege_escalation" in gaps and "execution" in gaps

    def test_lateral_movement_examined_by_logon_type(self):
        cov = coverage([_tc("dotnet EvtxECmd.dll -f Security.evtx  4624 logon type 10")])
        assert cov["lateral_movement"]["status"] == "examined"

    def test_established_beats_examined(self):
        cov = coverage([_find(cat="persistence"),
                        _tc("misc.parse_scheduled_tasks /mnt/x/Windows/System32/Tasks")])
        assert cov["persistence"]["status"] == "established"

    def test_symmetric_no_bias_toward_attack(self):
        # a purely-negative trace: phases are ruled_out / examined / not_examined,
        # never falsely "established".
        cov = coverage([_find(cat="execution", kind="negative")])
        assert cov["execution"]["status"] == "ruled_out"
        assert not any(c["status"] == "established" for c in cov.values())


class TestPreReportAdvisory:
    def _log(self, tmp_path, extra_entries=()):
        l = ExecutionLog(); l.configure("LC", str(tmp_path / "t.json"), save_session=False)
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
            l.record_dair_call(cur, "", True, nxt, "", "push", "")
        l.record_reason_call("reason_plan", True, "p", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        for e in extra_entries:
            l._entries.append(e)
        return l

    def _pre(self, l):
        from tools.reasoning import reason_pre_report_check
        with patch("core.execution_log.log", l):
            return reason_pre_report_check()

    def test_warns_on_uncovered_phases_never_blocks(self, tmp_path):
        l = self._log(tmp_path)
        r = self._pre(l)
        assert any("Attack-lifecycle coverage gap" in w for w in r["warnings"])
        # advisory only — the coverage gap is NOT a blocking issue
        assert not any("lifecycle" in i.lower() for i in r["blocking_issues"])
        assert set(r["lifecycle_coverage"]) == set(LIFECYCLE)

    def test_examined_phase_not_warned(self, tmp_path):
        # examine ALL five phases -> no coverage-gap warning
        l = self._log(tmp_path, extra_entries=[
            _tc("misc.parse_scheduled_tasks /mnt/x/Windows/System32/Tasks"),
            _tc("dotnet EvtxECmd.dll Security 4672 4728"),
            _tc("dotnet EvtxECmd.dll Security 4624 logon type 3"),
            _tc("dotnet PECmd.dll -d /Prefetch"),
            _tc("strings transfers.log ftp"),
        ])
        r = self._pre(l)
        assert not any("Attack-lifecycle coverage gap" in w for w in r["warnings"])


class TestReportTable:
    def test_coverage_table_rendered_in_report(self, tmp_path):
        from tools.reasoning import reason_pre_report_check
        from tools.misc import write_final_report
        l = ExecutionLog(); l.configure("LCR", str(tmp_path / "t.json"), save_session=False)
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
            l.record_dair_call(cur, "", True, nxt, "", "push", "")
        l.record_reason_call("reason_plan", True, "p", {})
        l.record_reason_call("reason_hypothesize", True, "h", {})
        l.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        # a benign finding that answers the case question, no blocking gates
        l.record_finding("STUN.exe present", "CONFIRMED", "ez.mftecmd",
                         claim=normalize_claim(claim_kind="positive", category="other",
                                               act="presence", entities=["STUN.exe"],
                                               answers_case_question=True))
        l.record_dair_call("Analyze", "", True, "Report", "", "push", "",
                           case_question="what ran on the host?")
        with patch("core.execution_log.log", l):
            r = reason_pre_report_check()
            assert r["ready_to_report"] is True, r["blocking_issues"]
            out = str(tmp_path / "reports" / "report.md")
            import os; os.makedirs(os.path.dirname(out), exist_ok=True)
            fn = getattr(write_final_report, "fn", write_final_report)
            fn(out, "# Report\n\nFindings summary.\n")
        body = open(out).read()
        assert "## Attack-lifecycle coverage" in body
        assert "Persistence" in body and "Privilege Escalation" in body and "Exfiltration" in body
        assert "NOT examined" in body            # nothing was collected -> gaps shown
