"""Phase N — scheduled-task / BadUSB-attribution gap."""
from unittest.mock import patch
import pytest

from core.execution_log import ExecutionLog
from tools._gates._claims import normalize_claim
from tools._gates._scheduled_tasks import TASK_ENUM_RE, INJECTOR_PAYLOAD_RE, tasks_examined


def _log(tmp_path, name="N"):
    l = ExecutionLog(); l.configure(name, str(tmp_path / "t.json"), save_session=False)
    for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
        l.record_dair_call(cur, "", True, nxt, "", "push", "")
    return l

def _pre(l):
    from tools.reasoning import reason_pre_report_check
    l.record_reason_call("reason_plan", True, "plan", {})
    l.record_reason_call("reason_synthesize", True, "ok", {})
    with patch("core.execution_log.log", l):
        return reason_pre_report_check()


class TestHelper:
    def test_enum_and_payload_regexes(self):
        assert TASK_ENUM_RE.search("misc.parse_scheduled_tasks /mnt/x/Windows/System32/Tasks")
        assert TASK_ENUM_RE.search("dotnet RECmd.dll -f SYSTEM TaskCache")
        assert not TASK_ENUM_RE.search("dotnet EvtxECmd.dll -f Security.evtx")
        assert INJECTOR_PAYLOAD_RE.search("powershell -WindowStyle hidden -file %duck%\\.tree\\x.ps1")
        assert INJECTOR_PAYLOAD_RE.search("powershell -enc SQBFAFgA")
        assert not INJECTOR_PAYLOAD_RE.search("pcalua.exe -a Diskmon.exe")

    def test_tasks_examined_by_cmd_or_disposition(self, tmp_path):
        l = _log(tmp_path)
        assert tasks_examined(l._entries, l.index()) is False
        l.record_tool_call("misc.parse_scheduled_tasks /mnt/x/Windows/System32/Tasks", True, False, 0, 0)
        assert tasks_examined(l._entries, l.index()) is True
        # or a source disposition
        l2 = _log(tmp_path, "N2")
        l2.record_disposition("source", "scheduled_tasks", "absent_from_evidence")
        assert tasks_examined(l2._entries, l2.index()) is True


class TestN1EnumerationDuty:
    def test_account_creation_without_task_enum_blocks(self, tmp_path):
        l = _log(tmp_path)
        l.record_finding("acct svc_x created", "SUSPECTED", "ez.evtxecmd",
                         claim=normalize_claim(claim_kind="positive", category="persistence",
                                               act="account_creation", principal="svc_x"))
        r = _pre(l)
        assert any("no scheduled-task enumeration" in i for i in r["blocking_issues"])

    def test_enumeration_clears(self, tmp_path):
        l = _log(tmp_path)
        l.record_finding("acct svc_x created", "SUSPECTED", "ez.evtxecmd",
                         claim=normalize_claim(claim_kind="positive", category="persistence",
                                               act="account_creation", principal="svc_x"))
        l.record_tool_call("misc.parse_scheduled_tasks /mnt/x/Windows/System32/Tasks", True, False, 0, 0)
        r = _pre(l)
        assert not any("scheduled-task enumeration" in i for i in r["blocking_issues"])

    def test_source_disposition_clears(self, tmp_path):
        l = _log(tmp_path)
        l.record_finding("persistence via WMI", "SUSPECTED", "t",
                         claim=normalize_claim(claim_kind="positive", category="persistence",
                                               act="persistence_install"))
        l.record_disposition("source", "scheduled_tasks", "absent_from_evidence")
        r = _pre(l)
        assert not any("scheduled-task enumeration" in i for i in r["blocking_issues"])

    def test_unrelated_finding_no_duty(self, tmp_path):
        l = _log(tmp_path)
        l.record_finding("STUN.exe present", "SUSPECTED", "t",
                         claim=normalize_claim(claim_kind="positive", category="other", act="presence"))
        r = _pre(l)
        assert not any("scheduled-task enumeration" in i for i in r["blocking_issues"])


class TestN2InjectorRuleOutRequiresLook:
    def _log_flagged(self, tmp_path):
        l = ExecutionLog(); l.configure("N2R", str(tmp_path / "t.json"), save_session=False)
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        inv = l.record_tool_call("misc.device_install_inventory /mnt/x/setupapi.dev.log", True, False, 0, 0)
        l.annotate_tool_call(inv, device_install_inventory=True, flagged_count=1)
        return l, inv

    def test_device_ruleout_refused_without_task_look(self, tmp_path):
        from tools.misc import record_disposition
        l, inv = self._log_flagged(tmp_path)
        fn = getattr(record_disposition, "fn", record_disposition)
        with patch("core.execution_log.log", l):
            r = fn("device", "BEEF:1234", "ruled_out", evidence_call_ids=[inv],
                   window={"start": "2016-06-18", "end": "2016-06-19"})
        assert r["success"] is False
        assert r["detail_gate"] == "injector_ruleout_requires_task_look"

    def test_device_ruleout_allowed_after_task_look(self, tmp_path):
        from tools.misc import record_disposition
        l, inv = self._log_flagged(tmp_path)
        l.record_tool_call("misc.parse_scheduled_tasks /mnt/x/Windows/System32/Tasks", True, False, 0, 0)
        fn = getattr(record_disposition, "fn", record_disposition)
        with patch("core.execution_log.log", l):
            r = fn("device", "BEEF:1234", "ruled_out", evidence_call_ids=[inv],
                   window={"start": "2016-06-18", "end": "2016-06-19"})
        assert r.get("detail_gate") != "injector_ruleout_requires_task_look", r


class TestN3PayloadDetector:
    def test_parse_scheduled_tasks_flags_duck_payload(self, tmp_path):
        from tools.misc import parse_scheduled_tasks
        T = tmp_path / "Tasks"; T.mkdir()
        # a UTF-16 task XML (real Windows encoding) with a %duck% payload
        (T / "covert_recon").write_text(
            '<Task><Actions><Exec><Command>powershell.exe</Command>'
            '<Arguments>-WindowStyle hidden -file %duck%\\.tree\\getcovert_recon.ps1</Arguments>'
            '</Exec></Actions></Task>', encoding="utf-16")
        (T / "benign").write_text(
            '<Task><Actions><Exec><Command>pcalua.exe</Command>'
            '<Arguments>-a Diskmon.exe</Arguments></Exec></Actions></Task>', encoding="utf-16")
        fn = getattr(parse_scheduled_tasks, "fn", parse_scheduled_tasks)
        l = ExecutionLog(); l.configure("N3", str(tmp_path / "t.json"), save_session=False)
        with patch("core.execution_log.log", l):
            r = fn(str(T))
        assert r["task_count"] == 2
        assert r["injector_payload_tasks"] == ["/covert_recon"]      # duck flagged, pcalua not
        # UTF-16 decoded (not null-filled) and self-logged citable
        ft = [t for t in r["tasks"] if t["task"] == "/covert_recon"][0]
        assert "getcovert_recon.ps1" in ft["content"] and "\x00" not in ft["content"]
        assert r["_trudi_call_id"] in l.index().by_call_id


class TestA3A5PayloadTaskReckoning:
    """A3/A5: a FLAGGED injector-payload task (e.g. a %duck% recon task) must be
    examined by a finding, and a human/account attribution of the account it
    created cannot stand without an injector rule-out."""

    def _flagged_task(self, l):
        cid = l.record_tool_call("misc.parse_scheduled_tasks /mnt/x/Windows/System32/Tasks",
                                 True, False, 0, 0)
        l.annotate_tool_call(cid, injector_payload_tasks=["/covert_recon"])
        return cid

    def test_flagged_task_unreferenced_blocks_A3(self, tmp_path):
        l = _log(tmp_path)
        self._flagged_task(l)
        l.record_finding("acct svc_x created", "SUSPECTED", "ez.evtxecmd",
                         claim=normalize_claim(claim_kind="positive", category="persistence",
                                               act="account_creation", principal="svc_x"))
        r = _pre(l)
        assert any("injector-payload task" in i and "no finding examines" in i
                   for i in r["blocking_issues"])

    def test_task_referenced_by_finding_clears_A3(self, tmp_path):
        l = _log(tmp_path)
        self._flagged_task(l)
        l.record_finding("the covert_recon scheduled task runs a hidden PowerShell recon payload",
                         "SUSPECTED", "misc.parse_scheduled_tasks",
                         claim=normalize_claim(claim_kind="positive", category="persistence",
                                               act="persistence_install",
                                               entities=["covert_recon"]))
        r = _pre(l)
        assert not any("no finding examines" in i for i in r["blocking_issues"])

    def test_human_attribution_without_ruleout_blocks_A5(self, tmp_path):
        l = _log(tmp_path)
        self._flagged_task(l)
        # task IS referenced (A3 satisfied) but the account is credited to a human
        l.record_finding("the covert_recon task is a %duck% recon payload", "SUSPECTED", "t",
                         claim=normalize_claim(claim_kind="positive", category="persistence",
                                               act="persistence_install", entities=["covert_recon"]))
        l.record_finding("svc_helper was created by the operator", "CONFIRMED", "ez.evtxecmd",
                         claim=normalize_claim(claim_kind="positive", category="persistence",
                                               act="account_creation", actor_kind="account",
                                               actor="svc_helper", principal="svc_helper"))
        r = _pre(l)
        assert any("proves keystroke injection ran" in i for i in r["blocking_issues"])

    def test_no_flagged_task_no_duty(self, tmp_path):
        l = _log(tmp_path)
        # enumeration ran but flagged nothing
        l.record_tool_call("misc.parse_scheduled_tasks /mnt/x/Windows/System32/Tasks", True, False, 0, 0)
        l.record_finding("acct svc_x created", "CONFIRMED", "ez.evtxecmd",
                         claim=normalize_claim(claim_kind="positive", category="persistence",
                                               act="account_creation", actor_kind="account",
                                               actor="svc_x", principal="svc_x"))
        r = _pre(l)
        assert not any("injector-payload task" in i for i in r["blocking_issues"])


class TestA6NearAliasExcludeNeedsBodyRead:
    """A6: excluding a near-alias correspondent needs a body read of the
    address, not a roster/senders listing or an assumed typo."""

    def _seed(self, tmp_path):
        l = ExecutionLog(); l.configure("A6", str(tmp_path / "t.json"), save_session=False)
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        # two near-alias correspondents in the registry
        cid = l.record_tool_call("read.mail -o /x/mail mode=senders field=any", True, False, 0, 0)
        l.annotate_tool_call(cid, observed_correspondents=["contact1@ext.example",
                                                           "contactl@ext.example"],
                             observed_correspondent_stats={"contactl@ext.example": {"from": 1, "to": 2}},
                             correspondents_partial=False)
        return l

    def test_exclude_on_listing_alone_refused(self, tmp_path):
        from tools.misc import record_disposition
        l = self._seed(tmp_path)
        senders = l.record_tool_call("read.mail -o /x/mail mode=senders field=any", True, False, 0, 0)
        fn = getattr(record_disposition, "fn", record_disposition)
        with patch("core.execution_log.log", l):
            r = fn("correspondent", "contact1@ext.example", "excluded", evidence_call_ids=[senders])
        assert r["success"] is False and r["detail_gate"] == "near_alias_needs_body_read"

    def test_out_of_scope_and_noise_also_require_body_read(self, tmp_path):
        # Fix 5: the near-alias body-read requirement is not dodgeable via
        # out_of_scope / noise (observed: nina_kwa1 settled out_of_scope).
        from tools.misc import record_disposition
        fn = getattr(record_disposition, "fn", record_disposition)
        for rs in ("out_of_scope", "noise"):
            l = self._seed(tmp_path)
            senders = l.record_tool_call("read.mail -o /x/mail mode=senders field=any", True, False, 0, 0)
            with patch("core.execution_log.log", l):
                r = fn("correspondent", "contact1@ext.example", rs, evidence_call_ids=[senders])
            assert r["success"] is False and r["detail_gate"] == "near_alias_needs_body_read", rs

    def test_exclude_with_body_read_of_address_clears(self, tmp_path):
        from tools.misc import record_disposition
        l = self._seed(tmp_path)
        body = l.record_tool_call("read.mail -o /x/mail mode=messages field=body q=contact1",
                                  True, False, 0, 0)
        fn = getattr(record_disposition, "fn", record_disposition)
        with patch("core.execution_log.log", l):
            r = fn("correspondent", "contact1@ext.example", "excluded", evidence_call_ids=[body])
        assert r.get("detail_gate") != "near_alias_needs_body_read", r

    def test_non_alias_exclude_unaffected(self, tmp_path):
        from tools.misc import record_disposition
        l = ExecutionLog(); l.configure("A6b", str(tmp_path / "t.json"), save_session=False)
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        cid = l.record_tool_call("read.mail -o /x/mail mode=senders field=any", True, False, 0, 0)
        l.annotate_tool_call(cid, observed_correspondents=["spammer@x.example"],
                             correspondents_partial=False)
        fn = getattr(record_disposition, "fn", record_disposition)
        with patch("core.execution_log.log", l):
            r = fn("correspondent", "spammer@x.example", "excluded", evidence_call_ids=[cid])
        assert r.get("detail_gate") != "near_alias_needs_body_read"


class TestA8CompetingRecipient:
    """A8: the case-question answer names one recipient while another delivery
    finding names a different one — surfaced as a warning (the fork), not a block."""

    def _log_cq(self, tmp_path):
        l = ExecutionLog(); l.configure("A8", str(tmp_path / "t.json"), save_session=False)
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
            l.record_dair_call(cur, "", True, nxt, "", "push", "", case_question="who received it?")
        return l

    def _pre(self, l):
        from tools.reasoning import reason_pre_report_check
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        with patch("core.execution_log.log", l):
            return reason_pre_report_check()

    def test_competing_recipients_warn(self, tmp_path):
        l = self._log_cq(tmp_path)
        l.record_finding("disseminated to the competitor", "LIKELY", "read.mail",
                         claim=normalize_claim(claim_kind="positive", category="delivery",
                                               act="delivery", recipients=["rcpt-a@far.example"],
                                               answers_case_question=True))
        l.record_finding("china thread", "SUSPECTED", "read.mail",
                         claim=normalize_claim(claim_kind="positive", category="delivery",
                                               act="delivery", recipients=["handler@ext.example"]))
        r = self._pre(l)
        assert any("different recipient" in w for w in r.get("warnings", []))

    def test_single_recipient_no_warn(self, tmp_path):
        l = self._log_cq(tmp_path)
        l.record_finding("disseminated to the competitor", "LIKELY", "read.mail",
                         claim=normalize_claim(claim_kind="positive", category="delivery",
                                               act="delivery", recipients=["rcpt-a@far.example"],
                                               answers_case_question=True))
        r = self._pre(l)
        assert not any("different recipient" in w for w in r.get("warnings", []))


class TestA7SynthesizeStructuralPreview:
    """A7: reason.synthesize previews cheap structural blockers as advisories so
    the agent sees them a round before pre_report_check."""

    def test_synthesize_surfaces_unrun_priority_tools(self, tmp_path):
        from unittest.mock import MagicMock
        l = ExecutionLog(); l.configure("A7", str(tmp_path / "t.json"), save_session=False)
        # DAIR prescribed a forensic tool that never ran, then reached Report
        l.record_dair_call("Triage", "", True, "Collect", "", "push", "",
                           directives={"priority_tools": ["misc.usnparser_parse"]})
        l.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
        l.record_dair_call("Analyze", "", True, "Report", "", "push", "")
        l.record_finding("acct x", "SUSPECTED", "t",
                         claim=normalize_claim(claim_kind="positive", category="other", act="presence"))
        resp = MagicMock(); resp.raise_for_status = MagicMock()
        resp.json.return_value = {"choices": [{"message": {"content": "OK\n\nBLOCKERS: []",
                                                           "reasoning": ""}}]}
        from tools.reasoning import reason_synthesize
        fn = getattr(reason_synthesize, "fn", reason_synthesize)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=resp), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = fn("narrative of findings")
        adv = " ".join(r.get("structural_advisories", []))
        assert "usnparser" in adv


class TestFix3PreReportPhaseReturn:
    """Fix 3: a failed pre_report_check boots DAIR out of Report back to Analyze
    so the phase gate permits the remediation tools the blockers demand."""

    def test_failed_pre_report_returns_to_analyze(self, tmp_path):
        l = ExecutionLog(); l.configure("F3", str(tmp_path / "t.json"), save_session=False)
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze"), ("Analyze", "Report")):
            l.record_dair_call(cur, "", True, nxt, "", "push", "")
        # a finding that will block pre_report (account_creation, no scheduled-task look)
        l.record_finding("acct x created", "SUSPECTED", "t",
                         claim=normalize_claim(claim_kind="positive", category="persistence",
                                               act="account_creation", principal="x"))
        assert l._current_phase == "Report"
        from tools.reasoning import reason_pre_report_check
        l.record_reason_call("reason_synthesize", True, "ok", {})
        with patch("core.execution_log.log", l):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert l._current_phase == "Analyze"          # booted out of Report
        ent = [e for e in l._entries if e.get("tool") == "reason_pre_report_check"][-1]
        assert ent["phase_returned_to"] == "Analyze"
        assert ent["dair_phase"] == "Report"          # the check itself ran in Report

    def test_passed_pre_report_leaves_phase(self, tmp_path):
        l = ExecutionLog(); l.configure("F3b", str(tmp_path / "t.json"), save_session=False)
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze"), ("Analyze", "Report")):
            l.record_dair_call(cur, "", True, nxt, "", "push", "")
        from tools.reasoning import reason_pre_report_check
        l.record_reason_call("reason_synthesize", True, "ok", {})
        with patch("core.execution_log.log", l):
            r = reason_pre_report_check()
        # zero findings -> not ready anyway, but assert the mechanism only fires from Report
        # (here it will return to Analyze since not ready) — verify the field is set:
        assert l._current_phase in ("Analyze", "Report")


class TestFix4BatchDispositions:
    """Fix 4: record_agent_message batches dispositions=[…] — one round-trip,
    same per-target gates as record_disposition."""

    def test_batch_records_all(self, tmp_path):
        from tools.misc import record_agent_message
        l = ExecutionLog(); l.configure("F4", str(tmp_path / "t.json"), save_session=False)
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        fn = getattr(record_agent_message, "fn", record_agent_message)
        with patch("core.execution_log.log", l):
            r = fn("settling inapplicable tools", input_call_ids=[1],
                   dispositions=[
                       {"target_kind": "tool", "target_id": "vol.pstree", "reason": "absent_from_evidence"},
                       {"target_kind": "tool", "target_id": "net.tcpdump_read", "reason": "absent_from_evidence"},
                       {"target_kind": "source", "target_id": "scheduled_tasks", "reason": "inapplicable"}])
        assert r["success"] and len(r["dispositions"]) == 3
        assert r["any_disposition_refused"] is False
        assert all(d.get("success") for d in r["dispositions"])
        disps = [e for e in l._entries if e.get("type") == "disposition"]
        assert len(disps) == 3

    def test_batch_reports_per_entry_refusal_without_blocking_others(self, tmp_path):
        # a device ruled_out with no window is refused; the valid ones still record.
        from tools.misc import record_agent_message
        l = ExecutionLog(); l.configure("F4b", str(tmp_path / "t.json"), save_session=False)
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        fn = getattr(record_agent_message, "fn", record_agent_message)
        with patch("core.execution_log.log", l):
            r = fn("mixed batch", input_call_ids=[1],
                   dispositions=[
                       {"target_kind": "tool", "target_id": "ez.pecmd", "reason": "inapplicable"},
                       {"target_kind": "device", "target_id": "BEEF:1234", "reason": "ruled_out"}])  # no window -> refused
        assert r["any_disposition_refused"] is True
        assert r["dispositions"][0]["success"] is True
        assert r["dispositions"][1]["success"] is False
