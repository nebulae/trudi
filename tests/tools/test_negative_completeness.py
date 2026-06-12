"""Tests for the negative_completeness gate and its coverage-window instrumentation.

A negative/absence finding (UNCONFIRMED) is refused unless the trace searched the
claim category's COMPLETE source manifest AND a searched log covers the claim's
time window. Synthetic GateContexts exercise the real gate logic.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tools._gates import GateContext
from tools._gates import negative_completeness as nc


def _ctx(description, cmds=None, *, tier="UNCONFIRMED", supporting_evidence=""):
    """cmds: list of (cmd_str, coverage_window_dict_or_None) → tool_call entries."""
    tool_calls = []
    for cmd, cw in (cmds or []):
        e = {"type": "tool_call", "cmd": cmd}
        if cw is not None:
            e["coverage_window"] = cw
        tool_calls.append(e)
    by_type = {"tool_call": tool_calls}
    return GateContext(
        description=description,
        confidence=tier.capitalize(),
        tier=tier,
        source="test",
        linked_call_id=0,
        tested_hypothesis_id="",
        log=MagicMock(),
        idx=SimpleNamespace(by_call_id={}, by_type=by_type),
        window=[],
        input_call_ids=[],
        supporting_evidence=supporting_evidence,
    )


class TestNegativeCompletenessManifest:
    def test_logon_negative_only_security_refused(self):
        out = nc.check(_ctx(
            "No RDP (logon type 10) and no external network logons appear for helpsvc",
            [("dotnet EvtxECmd.dll -f Security.evtx --inc 4624,4625", None)]))
        assert out is not None
        assert out["gate"] == "negative_completeness"
        assert "TerminalServices" in out["error"]

    def test_logon_negative_with_terminalservices_passes(self):
        out = nc.check(_ctx(
            "No RDP logon for helpsvc; controller unknown",
            [("EvtxECmd -f Security.evtx", None),
             ("EvtxECmd -f Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", None)]))
        assert out is None

    def test_linux_session_tools_waive_windows_manifest(self):
        out = nc.check(_ctx(
            "No remote logon or SSH session for the svc account",
            [("last -f /var/log/wtmp", None)]))
        assert out is None

    def test_absent_from_evidence_escape(self):
        out = nc.check(_ctx(
            "No RDP logon for svc_x — TerminalServices logs not present in evidence",
            [("EvtxECmd -f Security.evtx", None)],
            supporting_evidence="TerminalServices RemoteConnectionManager channel absent from evidence"))
        assert out is None

    def test_identity_negative_incomplete_refused(self):
        out = nc.check(_ctx(
            "Operator identity is unknown — requires a subpoena",
            [("recmd -f SAM", None)]))  # SAM only; ntuser/browser/comms/roster missing
        assert out is not None and out["gate"] == "negative_completeness"

    def test_persistence_negative_incomplete_refused(self):
        out = nc.check(_ctx(
            "No persistence via Run keys was found",
            [("recmd -f SOFTWARE --bn run", None)]))  # services/tasks/startup missing
        assert out is not None

    def test_exfil_negative_incomplete_refused(self):
        out = nc.check(_ctx(
            "No exfiltration off the host could be established",
            [("lecmd -d removable", None)]))  # cloud/mail_web/srum_ftp missing
        assert out is not None

    def test_unclassified_negative_passes(self):
        # An UNCONFIRMED finding that is not an absence-claim in a gated category.
        assert nc.check(_ctx("Possibly helpsvc ran smallftpd (low confidence)",
                             [("x", None)])) is None

    def test_non_unconfirmed_tier_not_gated(self):
        assert nc.check(_ctx("No RDP logon for helpsvc", [("EvtxECmd -f Security.evtx", None)],
                             tier="LIKELY")) is None


class TestNegativeCompletenessCoverage:
    _MANIFEST_OK = [
        ("EvtxECmd -f Security.evtx", {"start": "2016-06-27 18:40:35", "end": "2018-05-13 10:08:55"}),
        ("EvtxECmd -f TerminalServices-LocalSessionManager%4Operational.evtx",
         {"start": "2016-06-27 00:00:00", "end": "2016-09-30 00:00:00"}),
    ]

    def test_claim_window_outside_coverage_refused(self):
        # Manifest complete, but both logs start 06-27 while the claim is about 06-18.
        out = nc.check(_ctx("No RDP logon for helpsvc on 2016-06-18", self._MANIFEST_OK))
        assert out is not None
        assert "outside that coverage" in out["error"].lower() or "OUTSIDE" in out["error"]

    def test_claim_window_within_coverage_passes(self):
        cmds = [
            ("EvtxECmd -f Security.evtx", {"start": "2016-06-27", "end": "2018-05-13"}),
            ("EvtxECmd -f TerminalServices-LocalSessionManager%4Operational.evtx",
             {"start": "2016-03-01", "end": "2016-09-30"}),  # covers 06-18
        ]
        assert nc.check(_ctx("No RDP logon for helpsvc on 2016-06-18", cmds)) is None

    def test_no_claim_date_skips_coverage(self):
        # Manifest complete, no parseable date → manifest-only, passes.
        assert nc.check(_ctx("No RDP logon for helpsvc; controller unknown",
                             self._MANIFEST_OK)) is None

    def test_unresolved_principal_regression(self):
        # Run-4 shape: only Security parsed (06-27→), claim 'no RDP type 10' on 06-18.
        out = nc.check(_ctx(
            "No RDP (logon type 10) for helpsvc on 2016-06-18; helpsvc is local-console only",
            [("EvtxECmd -f Security.evtx", {"start": "2016-06-27", "end": "2018-05-13"})]))
        assert out is not None and out["gate"] == "negative_completeness"
        # Manifest is checked first → fails on the missing TerminalServices source.
        assert "TerminalServices" in out["error"]


class TestEvtxCoverageCapture:
    def test_annotate_tool_call(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-COV", str(tmp_path / "t.json"))
        cid = l.record_tool_call("EvtxECmd -f Security.evtx", True, False, 0, 0)
        assert l.annotate_tool_call(cid, coverage_window={"start": "a", "end": "b"})
        entry = l.index().by_call_id[cid]
        assert entry["coverage_window"] == {"start": "a", "end": "b"}
        assert l.annotate_tool_call(999999, coverage_window={"x": 1}) is False

    def test_attach_evtx_coverage_from_csv(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.eztools import _attach_evtx_coverage
        l = ExecutionLog()
        l.configure("TEST-COV2", str(tmp_path / "t.json"))
        cid = l.record_tool_call("EvtxECmd -f Security.evtx", True, False, 0, 0)
        csv_path = tmp_path / "evtx.csv"
        csv_path.write_text(
            "RecordNumber,TimeCreated,EventId\n"
            "1,2016-06-27 18:40:35.5294095,4624\n"
            "2,2018-05-13 10:08:55.4517380,4634\n"
            "3,2016-12-01 00:00:00.0000000,4624\n")
        with patch("core.execution_log.log", l):
            _attach_evtx_coverage({"_trudi_call_id": cid}, str(tmp_path), "evtx.csv")
        cw = l.index().by_call_id[cid].get("coverage_window")
        assert cw == {"start": "2016-06-27 18:40:35.5294095", "end": "2018-05-13 10:08:55.4517380"}
