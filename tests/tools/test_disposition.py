"""Shared entity normalizer + typed dispositions (Phase E-04)."""
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog
from tools._gates import _entities as EN
from tools._gates import _dispositions as D


class TestEntities:
    @pytest.mark.parametrize("a,b", [
        ("J.Doe", "jdoe"), ("CORP\\jdoe", "jdoe"), ("'svc_backup'", "svc-backup"),
        ("Mr. Evil", "mrevil"), ("S-1-5-21-1-2-3-1006", "s-1-5-21-1-2-3-1006"),
        ("RID 1006", "rid1006"), ("jdoe@example.org", "jdoe"),
    ])
    def test_matches(self, a, b):
        assert EN.entity_matches(a, b)

    def test_no_match(self):
        assert not EN.entity_matches("jdoe", "asmith")
        assert not EN.entity_matches("", "asmith")

    def test_overlap(self):
        assert EN.entity_overlap(["J.Doe", "usb"], ["jdoe", "removable"]) == pytest.approx(1 / 3)
        assert EN.entity_overlap([], ["x"]) == 0.0
        assert EN.entity_overlap(["jdoe@x.org"], ["jdoe"]) == 1.0

    def test_entity_in_text(self):
        assert EN.entity_in_text("Mr. Evil", "the mr.evil account (RID 1003)")
        assert EN.entity_in_text("findme69@hotmail.example", "MSPPre=findme69@hotmail.example seen")
        assert not EN.entity_in_text("ab", "abc")   # too short to count

    def test_claim_key(self):
        assert EN.claim_key({"kind": "Positive", "category": "exfil", "act": "egress"}) == "positive|exfil|egress"
        assert EN.claim_key({}) == "||"

    def test_rewording_gate_uses_shared_normalizer(self):
        from tools._gates import refusal_rewording as rw
        assert rw._norm_entity("CORP\\J.Doe") == EN.norm_entity("jdoe")


class TestValidate:
    def test_enums(self):
        assert D.validate("principal", "x", "not_a_principal") == ""
        assert "target_kind" in D.validate("thing", "x", "noise")
        assert "reason" in D.validate("principal", "x", "bogus")
        assert "does not apply" in D.validate("source", "x", "refuted")
        assert "target_id" in D.validate("source", " ", "inapplicable")

    def test_normalize_target(self):
        assert D.normalize_target("principal", "CORP\\J.Doe") == "jdoe"
        assert D.normalize_target("tool", " ez.pecmd ") == "ez.pecmd"
        assert D.normalize_target("challenge", "217: Prefetch files exist") == "217:prefetchfilesexist"

    def test_disposition_call_text(self):
        t = D.disposition_call("principal", "MSPPre", "not_a_principal", evidence=True)
        assert "record_disposition" in t and "evidence_call_ids" in t


@pytest.fixture
def live(tmp_path):
    l = ExecutionLog()
    l.configure("DISP", str(tmp_path / "trace.json"), save_session=False)
    with patch("core.execution_log.log", l):
        yield l


class TestRecordDisposition:
    def _tool(self):
        from tools.misc import record_disposition
        return getattr(record_disposition, "fn", record_disposition)

    def test_requires_dair(self, live):
        r = self._tool()("tool", "ez.pecmd", "inapplicable")
        assert r["success"] is False and r["gate"] == "dair_required"

    def test_records_and_indexes(self, live):
        live.record_dair_call("Analyze", "", False, "", "", "stay", "")
        r = self._tool()("principal", "CORP\\MSPPre", "controller_unknown", note="parked")
        assert r["success"] and r["target_norm"] == "msppre"
        e = live._entries[-1]
        assert e["type"] == "disposition" and e["reason"] == "controller_unknown"
        assert e["input_call_ids"]     # lineage defaults to the dair call
        idx = live.index()
        assert ("principal", "msppre") in idx.dispositions
        found = D.find_disposition(idx, "principal", "msp.pre", reasons=["controller_unknown"])
        assert found and found["call_id"] == e["call_id"]
        assert D.find_disposition(idx, "principal", "msppre", reasons=["excluded"]) is None

    def test_evidence_required_reasons(self, live):
        live.record_dair_call("Analyze", "", False, "", "", "stay", "")
        r = self._tool()("principal", "MSPPre", "not_a_principal")
        assert r["success"] is False and r["missing"] == ["evidence_call_ids"]
        meta = live.record_tool_call("<py>:misc_record_agent_message", True, False, 0, 0)
        r = self._tool()("principal", "MSPPre", "not_a_principal", evidence_call_ids=[meta])
        assert r["success"] is False and "not evidence tool calls" in r["error"]
        ev = live.record_tool_call("sudo ngrep -q -I x.pcap MSPPre", True, False, 0, 0,
                                   stdout_excerpt="MSPPre=findme69@hotmail.example")
        r = self._tool()("principal", "MSPPre", "not_a_principal", evidence_call_ids=[ev])
        assert r["success"] and live._entries[-1]["evidence_call_ids"] == [ev]

    def test_invalid_enum_refused(self, live):
        live.record_dair_call("Analyze", "", False, "", "", "stay", "")
        r = self._tool()("source", "security_evtx", "refuted")
        assert r["success"] is False and r["gate"] == "typed_disposition"
        assert "does not apply" in r["error"]

    def test_window_match(self, live):
        live.record_dair_call("Analyze", "", False, "", "", "stay", "")
        ev = live.record_tool_call("misc.device_install_inventory /x", True, False, 0, 0)
        self._tool()("device", "VID_BEEF&PID_1234", "ruled_out", evidence_call_ids=[ev],
                     window={"start": "2016-06-01", "end": "2016-06-30"})
        idx = live.index()
        assert D.find_disposition(idx, "device", "vid_beef&pid_1234", reasons=["ruled_out"],
                                  window={"start": "2016-06-10", "end": "2016-06-12"})
        assert D.find_disposition(idx, "device", "vid_beef&pid_1234", reasons=["ruled_out"],
                                  window={"start": "2016-07-10", "end": "2016-07-12"}) is None

    def test_markdown_renders(self, live):
        live.record_dair_call("Analyze", "", False, "", "", "stay", "")
        self._tool()("tool", "ez.pecmd", "inapplicable", note="PECmd.dll not deployed")
        md = live.to_markdown()
        assert "DISPOSITION" in md and "ez.pecmd" in md and "inapplicable" in md


class TestSameAsAndPlaceholders:
    def test_same_as_is_principal_only_and_needs_evidence(self):
        # The honest vocabulary for "this contested identity IS the prime
        # subject" — the honest vocabulary where 'refuted' would be backwards.
        assert D.validate("principal", "Greg Schardt", "same_as") == ""
        assert "does not apply" in D.validate("source", "x", "same_as")
        assert "same_as" in D.EVIDENCE_REQUIRED

    def test_qualifiers_and_role_suffixes_fold_away(self):
        # qualifier variants (`Guest(501)`/`Guest`, `X account`/`X`) are one identity
        assert EN.norm_entity("Guest (501)") == EN.norm_entity("guest") == "guest"
        assert EN.norm_entity("defaultprinter account") == "defaultprinter"
        assert EN.norm_entity("PC User [RID 1001]") == "pcuser"
        assert EN.norm_entity("PC User") == "pcuser"          # 'User' is part of the name, not a suffix
        assert EN.norm_entity("account") == "account"           # a bare word is kept

    def test_role_words_are_not_principals(self):
        for n in ("unknown", "Unknown actor", "external actor", "N/A", "", "attacker"):
            assert EN.is_placeholder(n), n
        for n in ("Mr. Evil", "jdoe", "CORP\\svc_backup", "S-1-5-21-1-2-3-1006"):
            assert not EN.is_placeholder(n), n


class TestDispositionEvidenceRelevance:
    """K-5: evidence cited to settle a question must bear on that question's
    class and window — checked by artifact CLASS and WINDOW only, never the
    direction of the conclusion."""

    def _log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("K5", str(tmp_path / "trace.json"), save_session=False)
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        return l

    def test_device_ruled_out_requires_window(self, tmp_path):
        from unittest.mock import patch
        from tools.misc import record_disposition
        l = self._log(tmp_path)
        ev = l.record_tool_call("misc.device_install_inventory /mnt/x/setupapi.dev.log",
                                True, False, 0, 0)
        l.annotate_tool_call(ev, device_install_inventory=True)
        fn = getattr(record_disposition, "fn", record_disposition)
        with patch("core.execution_log.log", l):
            r = fn("device", "03EB:2422", "ruled_out", evidence_call_ids=[ev])
        assert r["success"] is False and "window" in r["missing"]

    def test_device_ruled_out_refuses_operation_era_evidence(self, tmp_path):
        # The Ducky was ruled out citing RDP/FTP/mail calls — how the account
        # was USED, not how it was created. Class-based refusal.
        from unittest.mock import patch
        from tools.misc import record_disposition
        l = self._log(tmp_path)
        rdp = l.record_tool_call("dotnet EvtxECmd.dll -f TerminalServices-RCM.evtx --csv /o",
                                 True, False, 0, 0)
        l.annotate_tool_call(rdp, session_artifact=True)
        ftp = l.record_tool_call("read.mail -o /case/exports/mail mode=senders field=any",
                                 True, False, 0, 0)
        fn = getattr(record_disposition, "fn", record_disposition)
        with patch("core.execution_log.log", l):
            r = fn("device", "03EB:2422", "ruled_out", evidence_call_ids=[rdp, ftp],
                   window={"start": "2016-06-18", "end": "2016-06-19"})
        assert r["success"] is False
        assert r["detail_gate"] == "disposition_evidence_relevance"
        assert "install/creation" in r["error"]

    def test_device_ruled_out_accepts_mechanism_class_evidence(self, tmp_path):
        from unittest.mock import patch
        from tools.misc import record_disposition
        l = self._log(tmp_path)
        inv = l.record_tool_call("misc.device_install_inventory /mnt/x/setupapi.dev.log",
                                 True, False, 0, 0)
        l.annotate_tool_call(inv, device_install_inventory=True)
        fn = getattr(record_disposition, "fn", record_disposition)
        with patch("core.execution_log.log", l):
            r = fn("device", "03EB:2422", "ruled_out", evidence_call_ids=[inv],
                   window={"start": "2016-06-18", "end": "2016-06-19"})
        assert r["success"] is True, r

    def test_principal_settlement_with_uncited_sessions_warns(self, tmp_path):
        from unittest.mock import patch
        from tools.reasoning import reason_pre_report_check
        l = self._log(tmp_path)
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
            l.record_dair_call(cur, "", True, nxt, "", "push", "")
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        l.record_finding("x present", "SUSPECTED", "t")
        creation = l.record_tool_call("dotnet EvtxECmd.dll -f Security.evtx --csv /o",
                                      True, False, 0, 0, stdout_excerpt="4720 svc_backup created")
        sess = l.record_tool_call("dotnet EvtxECmd.dll -f TS-RCM.evtx --csv /o", True, False, 0, 0,
                                  stdout_excerpt="1149 svc_backup 173.73.166.249")
        l.annotate_tool_call(sess, session_artifact=True, session_event_ids=[4624])
        l.record_disposition("principal", "svc_backup", "same_as", evidence_call_ids=[creation])
        with patch("core.execution_log.log", l):
            r = reason_pre_report_check()
        assert any("svcbackup" in w and "OPERATED" in w for w in r["warnings"])
        # citing the session clears the flag
        l.record_disposition("principal", "svc_backup", "same_as", evidence_call_ids=[creation, sess])
        with patch("core.execution_log.log", l):
            r2 = reason_pre_report_check()
        # the older, narrower disposition remains in the trace; the warning keys
        # on each disposition row — the new one citing the session carries none
        assert sum(1 for w in r2["warnings"] if "OPERATED" in w) <= 1
