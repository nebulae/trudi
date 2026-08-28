"""Tests for the negative_completeness gate and its coverage-window instrumentation.

A negative/absence finding (UNCONFIRMED, claim_kind="negative", category in a
case-inverting manifest) is refused unless the trace searched the category's
COMPLETE source manifest AND a searched log covers the claim's declared window.
Nothing is read from the description. Synthetic GateContexts exercise the real
gate logic.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tools._gates import GateContext
from tools._gates import negative_completeness as nc
from tools._gates._claims import normalize_claim


def _ctx(description, cmds=None, *, tier="UNCONFIRMED", supporting_evidence="",
         category="logon_auth", window=None, dispositions=None, kind="negative"):
    """cmds: list of (cmd_str, coverage_window_dict_or_None) → tool_call entries.
    dispositions: list of (target_kind, target_id, reason) typed dispositions."""
    from tools._gates._dispositions import normalize_target
    tool_calls = []
    for cmd, cw in (cmds or []):
        e = {"type": "tool_call", "cmd": cmd}
        if cw is not None:
            e["coverage_window"] = cw
        tool_calls.append(e)
    disp = {}
    for i, (tk, tid, reason) in enumerate(dispositions or [], 1):
        disp.setdefault((tk, normalize_target(tk, tid)), []).append(
            {"type": "disposition", "call_id": 1000 + i, "target_kind": tk,
             "target_id": tid, "reason": reason})
    return GateContext(
        description=description,
        confidence=tier.capitalize(),
        tier=tier,
        source="test",
        linked_call_id=0,
        tested_hypothesis_id="",
        log=MagicMock(),
        idx=SimpleNamespace(by_call_id={}, by_type={"tool_call": tool_calls}, dispositions=disp),
        window=[],
        input_call_ids=[],
        supporting_evidence=supporting_evidence,
        claim=normalize_claim(claim_kind=kind, category=category, act="other", window=window),
    )


class TestNegativeCompletenessManifest:
    def test_logon_negative_only_security_refused(self):
        out = nc.check(_ctx(
            "No RDP (logon type 10) and no external network logons appear for helpsvc",
            [("dotnet EvtxECmd.dll -f Security.evtx --inc 4624,4625", None)]))
        assert out is not None
        assert out["gate"] == "negative_completeness"
        assert "TerminalServices" in out["error"] and out["missing_sources"] == ["terminalservices"]
        assert 'record_disposition(target_kind="source", target_id="terminalservices"' in out["error"]

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

    def test_typed_disposition_settles_a_missing_source(self):
        out = nc.check(_ctx(
            "No RDP logon for svc_x",
            [("EvtxECmd -f Security.evtx", None)],
            dispositions=[("source", "TerminalServices", "absent_from_evidence")]))
        assert out is None

    def test_prose_absent_from_evidence_no_longer_waives(self):
        out = nc.check(_ctx(
            "No RDP logon for svc_x — TerminalServices logs not present in evidence",
            [("EvtxECmd -f Security.evtx", None)],
            supporting_evidence="TerminalServices RemoteConnectionManager channel absent from evidence"))
        assert out is not None

    def test_identity_negative_incomplete_refused(self):
        out = nc.check(_ctx(
            "Operator identity is unknown — requires a subpoena",
            [("recmd -f SAM", None)], category="identity"))
        assert out is not None and out["gate"] == "negative_completeness"

    def test_persistence_negative_incomplete_refused(self):
        out = nc.check(_ctx(
            "No persistence via Run keys was found",
            [("recmd -f SOFTWARE --bn run", None)], category="persistence"))
        assert out is not None

    def test_exfil_negative_incomplete_refused(self):
        out = nc.check(_ctx(
            "No exfiltration off the host could be established",
            [("lecmd -d removable", None)], category="exfil"))
        assert out is not None

    def test_other_category_not_gated(self):
        # A negative in a category without a manifest is not gated here.
        assert nc.check(_ctx("Nothing of note", [("x", None)], category="other")) is None

    def test_positive_claim_not_gated(self):
        assert nc.check(_ctx("No RDP logon for helpsvc", [("x", None)], kind="positive")) is None

    def test_wording_is_not_read(self):
        # The same exfil-shaped wording with no declared negative claim passes;
        # a declared exfil negative with innocuous wording is gated.
        assert nc.check(_ctx("No exfiltration off the host could be established",
                             [("x", None)], kind="positive", category="exfil")) is None
        out = nc.check(_ctx("The material never left via the alternate route",
                            [("x", None)], category="exfil"))
        assert out is not None

    def test_non_unconfirmed_tier_not_gated(self):
        assert nc.check(_ctx("No RDP logon for helpsvc", [("EvtxECmd -f Security.evtx", None)],
                             tier="LIKELY")) is None


class TestExfilManifest:
    def test_chat_messenger_source_required(self):
        out = nc.check(_ctx(
            "No exfiltration off the host could be established",
            [("lecmd -d /Recent", None),
             ("hindsight.py -i /Dropbox", None),
             ("readpst -o /out /x.pst", None),
             ("python srum SRUDB.dat", None)], category="exfil"))
        assert out is not None
        assert "chat" in out["error"].lower() and out["missing_sources"] == ["chat_messenger"]

    def test_complete_with_chat_export_passes(self):
        out = nc.check(_ctx(
            "No exfiltration off the host could be established",
            [("lecmd -d /Recent", None),
             ("hindsight.py -i /Dropbox", None),
             ("readpst -o /out /x.pst", None),
             ("python srum SRUDB.dat", None),
             ("misc.chat_db_export /img/Users/x/Skype/main.db", None)], category="exfil"))
        assert out is None

    def test_chat_source_settled_by_disposition(self):
        out = nc.check(_ctx(
            "No exfiltration off the host could be established",
            [("lecmd -d /Recent", None), ("hindsight.py -i /Dropbox", None),
             ("readpst -o /out /x.pst", None), ("python srum SRUDB.dat", None)],
            category="exfil", dispositions=[("source", "chat_messenger", "inapplicable")]))
        assert out is None


class TestNegativeCompletenessCoverage:
    _MANIFEST_OK = [
        ("EvtxECmd -f Security.evtx", {"start": "2021-06-27 18:40:35", "end": "2023-05-13 10:08:55"}),
        ("EvtxECmd -f TerminalServices-LocalSessionManager%4Operational.evtx",
         {"start": "2021-06-27 00:00:00", "end": "2021-09-30 00:00:00"}),
    ]

    def test_claim_window_outside_coverage_refused(self):
        # Manifest complete, but both logs start 06-27 while the claim window is 06-18.
        out = nc.check(_ctx("No RDP logon for helpsvc", self._MANIFEST_OK,
                            window={"start": "2021-06-18", "end": "2021-06-18"}))
        assert out is not None
        assert "OUTSIDE" in out["error"]

    def test_claim_window_within_coverage_passes(self):
        cmds = [
            ("EvtxECmd -f Security.evtx", {"start": "2021-06-27", "end": "2023-05-13"}),
            ("EvtxECmd -f TerminalServices-LocalSessionManager%4Operational.evtx",
             {"start": "2021-03-01", "end": "2021-09-30"}),  # covers 06-18
        ]
        assert nc.check(_ctx("No RDP logon for helpsvc", cmds,
                             window={"start": "2021-06-18", "end": "2021-06-18"})) is None

    def test_date_in_prose_is_not_a_window(self):
        # Only the DECLARED window counts — a date in the wording is ignored.
        assert nc.check(_ctx("No RDP logon for helpsvc on 2021-06-18", self._MANIFEST_OK)) is None

    def test_unresolved_principal_regression(self):
        out = nc.check(_ctx(
            "No RDP (logon type 10) for helpsvc; helpsvc is local-console only",
            [("EvtxECmd -f Security.evtx", {"start": "2021-06-27", "end": "2023-05-13"})],
            window={"start": "2021-06-18", "end": "2021-06-18"}))
        assert out is not None and out["gate"] == "negative_completeness"
        # Manifest is checked first → fails on the missing TerminalServices source.
        assert "TerminalServices" in out["error"]


class TestDeviceInitialAccess:
    def test_no_inventory_refused_with_disposition_hint(self):
        out = nc.check(_ctx("No BadUSB device", [("x", None)], category="device_initial_access",
                            window={"start": "2021-06-18", "end": "2021-06-18"}))
        assert out is not None and out["missing_sources"] == ["device_inventory"]
        assert "record_disposition" in out["error"]

    def test_inventory_absent_disposition_escapes(self):
        assert nc.check(_ctx("No BadUSB device", [("x", None)], category="device_initial_access",
                             window={"start": "2021-06-18", "end": "2021-06-18"},
                             dispositions=[("source", "device_inventory", "absent_from_evidence")])) is None


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
            "1,2021-06-27 18:40:35.5294095,4624\n"
            "2,2023-05-13 10:08:55.4517380,4634\n"
            "3,2021-12-01 00:00:00.0000000,4624\n")
        with patch("core.execution_log.log", l):
            _attach_evtx_coverage({"_trudi_call_id": cid}, str(tmp_path), "evtx.csv")
        e = l.index().by_call_id[cid]
        assert e.get("coverage_window") == {"start": "2021-06-27 18:40:35.5294095",
                                            "end": "2023-05-13 10:08:55.4517380"}
        # Server-stamped session marker: the parse holds 4624/4634 rows.
        assert e.get("session_artifact") is True and e.get("session_event_ids") == [4624, 4634]

    def test_no_session_events_no_marker(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.eztools import _attach_evtx_coverage
        l = ExecutionLog()
        l.configure("TEST-COV3", str(tmp_path / "t.json"))
        cid = l.record_tool_call("EvtxECmd -f System.evtx", True, False, 0, 0)
        (tmp_path / "evtx.csv").write_text("RecordNumber,TimeCreated,EventId\n1,2021-06-27 18:40:35,7045\n")
        with patch("core.execution_log.log", l):
            _attach_evtx_coverage({"_trudi_call_id": cid}, str(tmp_path), "evtx.csv")
        assert "session_artifact" not in l.index().by_call_id[cid]
