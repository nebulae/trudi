"""Phase M — run-surfaced harness fixes."""
from unittest.mock import patch, MagicMock

import pytest


# ── M-1: reason.synthesize accepts a POP into Report ────────────────────────
class TestSynthesizePopIntoReport:
    def _log(self, tmp_path, dair_kw):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("M1", str(tmp_path / "t.json"), save_session=False)
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
            l.record_dair_call(cur, "", True, nxt, "", "push", "")
        l.record_dair_call(**dair_kw)
        l.record_finding("x present", "SUSPECTED", "t")
        return l

    def _synth(self, log):
        import tools.reasoning as R
        with patch("core.execution_log.log", log), \
             patch.object(R, "_ask", return_value={"success": True, "raw": "BLOCKERS: []",
                                                    "conclusion": "ok", "directives": {}}):
            return R.reason_synthesize("findings", input_call_ids=[1])

    def test_pop_into_report_is_callable(self, tmp_path):
        # current='Analyze', next='Report', action='pop', rec=True — the case
        # that used to refuse "only callable in Report phase".
        l = self._log(tmp_path, dict(current_phase="Analyze", phase_rationale="",
                                     transition_recommended=True, next_phase="Report",
                                     transition_rationale="", stack_action="pop",
                                     investigation_focus=""))
        r = self._synth(l)
        assert "only callable in Report phase" not in str(r.get("error", "")), r

    def test_push_into_report_still_callable(self, tmp_path):
        l = self._log(tmp_path, dict(current_phase="Analyze", phase_rationale="",
                                     transition_recommended=True, next_phase="Report",
                                     transition_rationale="", stack_action="push",
                                     investigation_focus=""))
        assert "only callable" not in str(self._synth(l).get("error", ""))

    def test_pop_whose_next_is_not_report_still_refused(self, tmp_path):
        l = self._log(tmp_path, dict(current_phase="Analyze", phase_rationale="",
                                     transition_recommended=True, next_phase="Collect",
                                     transition_rationale="", stack_action="pop",
                                     investigation_focus=""))
        assert "only callable in Report phase" in str(self._synth(l).get("error", ""))


# ── M-2: evaluate tolerates the record-claim kwarg set ──────────────────────
class TestEvaluateKwargTolerance:
    def test_record_claim_kwargs_accepted_and_verdict_unchanged(self, monkeypatch, tmp_path):
        import tools.reasoning as R
        from core.execution_log import ExecutionLog
        l = ExecutionLog(); l.configure("M2", str(tmp_path / "t.json"), save_session=False)
        cid = l.record_tool_call("dotnet EvtxECmd.dll -f Security.evtx", True, False, 0, 0,
                                 stdout_excerpt="4720 defaultprinter")
        ans = {"success": True, "raw": "VERDICT: SUPPORTED", "conclusion": "VERDICT: SUPPORTED",
               "directives": {}, "input_tokens": 1, "output_tokens": 1}
        fn = getattr(R.reason_evaluate_finding, "fn", R.reason_evaluate_finding)
        with patch("core.execution_log.log", l), patch.object(R, "_ask", return_value=dict(ans)):
            base = fn("acct created", "e", input_call_ids=[cid], claim_kind="positive",
                      category="persistence", act="account_creation", entities=["defaultprinter"])
            # the SAME call PLUS record_finding-only kwargs must not raise
            withx = fn("acct created", "e", input_call_ids=[cid], claim_kind="positive",
                       category="persistence", act="account_creation", entities=["defaultprinter"],
                       transfer_call_ids=[cid], session_type="interactive",
                       session_binding_call_ids=[cid], recipients=["x"], scope=["y"],
                       techniques=["T1136.001"], threat_actor="", rule_outs=[{"what": "injector", "call_ids": [cid]}],
                       resolves="confirmed", answers_case_question=True, linked_call_id=cid,
                       receipt_call_ids=[cid], artifacts=["a"])
        assert base.get("verdict") == "SUPPORTED"
        assert withx.get("verdict") == "SUPPORTED"        # extras ignored, verdict identical
        assert "unexpected" not in str(withx.get("error", "")).lower()


# ── M-3: pff_export true path + read_mail consumes the item tree ────────────
class TestPffExportPathAndReadMail:
    def _tree(self, tmp_path):
        # a minimal pffexport item tree under an output-safe exports/ dir
        # (read_mail's guard requires analysis/exports/reports).
        ex = tmp_path / "exports"; ex.mkdir(exist_ok=True)
        base = ex / "mail_x"
        d = base.with_name("mail_x.export") / "Inbox" / "Message00001"
        d.mkdir(parents=True)
        (d / "InternetHeaders.txt").write_text(
            "From: Nina <nina@qq.example>\nTo: <v@case.example>\n"
            "Subject: research paper\nDate: Sat, 18 Jun 2016 16:27:01 -0400\n")
        (d / "Message.txt").write_text("here is the sturgeon draft on the usb")
        # a second item with only Outlook headers (fallback path)
        d2 = base.with_name("mail_x.export") / "Sent" / "Message00002"
        d2.mkdir(parents=True)
        (d2 / "InternetHeaders.txt").write_text("")
        (d2 / "OutlookHeaders.txt").write_text(
            "Sender name:\tAnthony\nSender email address:\tv@case.example\n"
            "Subject:\treply\nClient submit time:\tJun 19, 2016 04:00:00 UTC\n")
        (d2 / "Recipients.txt").write_text("nina@qq.example")
        (d2 / "Message.txt").write_text("telegram is @nina")
        return str(base), str(base.with_name("mail_x.export"))

    def test_pff_export_reports_true_output_path(self, tmp_path, monkeypatch):
        import tools.misc as M
        base, exp = self._tree(tmp_path)
        monkeypatch.setattr(M, "_bin_or_warn", lambda *_: "/usr/bin/pffexport")
        monkeypatch.setattr(M, "run", lambda *a, **k: {"success": True, "cmd": " ".join(a[0])})
        fn = getattr(M.pff_export, "fn", M.pff_export)
        r = fn("x.ost", base)
        assert r["output_path"] == exp and r["layout"] == "pffexport_items"
        assert "read.mail" in r["read_hint"]

    def test_read_mail_consumes_item_tree_bodies(self, tmp_path):
        from tools.read_output import read_mail
        _, exp = self._tree(tmp_path)
        fn = getattr(read_mail, "fn", read_mail)
        r = fn(exp, query="nina@qq.example", field="any", mode="messages")
        assert r["messages_scanned"] == 2
        subs = {m["subject"] for m in r["messages"]}
        assert "research paper" in subs
        # the InternetHeaders message returns its body
        ih = [m for m in r["messages"] if m["subject"] == "research paper"][0]
        assert "sturgeon" in ih["body"]
        # the OutlookHeaders-only message resolved From/Subject via fallback
        of = [m for m in r["messages"] if m["subject"] == "reply"]
        assert of and "v@case.example" in of[0]["from"]


# ── M-4: read.output self-log records query/columns/where ──────────────
class TestReadOutputSelflogTerms:
    def test_cmd_carries_query_columns_where(self, tmp_path):
        from tools.read_output import read_output
        from core.execution_log import ExecutionLog
        l = ExecutionLog(); l.configure("M4", str(tmp_path / "t.json"), save_session=False)
        f = tmp_path / "exports" / "d.csv"; f.parent.mkdir()
        f.write_text("EventId,Name\n4720,defaultprinter\n4624,other\n")
        fn = getattr(read_output, "fn", read_output)
        with patch("core.execution_log.log", l):
            r = fn(str(f), query="4720 defaultprinter", columns="EventId,Name", where="EventId=4720")
        e = l.index().by_call_id[r["_trudi_call_id"]]
        assert "query=4720 defaultprinter" in e["cmd"]
        assert "columns=EventId,Name" in e["cmd"] and "where=EventId=4720" in e["cmd"]
        # a plain read still logs cleanly (no trailing noise)
        with patch("core.execution_log.log", l):
            r2 = fn(str(f))
        e2 = l.index().by_call_id[r2["_trudi_call_id"]]
        assert e2["cmd"].endswith("d.csv") and "query=" not in e2["cmd"]
