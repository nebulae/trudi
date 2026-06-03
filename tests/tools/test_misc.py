"""Tests for tools/misc.py."""
import os
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.misc.run", return_value=run_ok) as m:
        yield m


class TestEvtxTools:
    def test_evtx_dump(self, mock_run):
        from tools.misc import evtx_dump
        evtx_dump("/mnt/wkstn01/Windows/System32/winevt/Logs/Security.evtx")
        assert mock_run.called

    def test_evtx_dump_output_path(self, mock_run, tmp_path):
        from tools.misc import evtx_dump
        from unittest.mock import MagicMock
        out = str(tmp_path / "security.xml")
        # evtx_dump with output_path redirects stdout to a file via subprocess.run directly
        mock_proc = MagicMock(returncode=0, stderr=b"")
        with patch("subprocess.run", return_value=mock_proc):
            r = evtx_dump("/logs/Security.evtx", output_path=out)
        assert r["success"] is True

    def _fake_popen(self, stdout_text: str, stderr_text: str = "",
                    returncode: int = 0):
        """Build a Popen stand-in whose stdout iterates the given text and
        whose wait/terminate are inert. Used so evtx_filter's streaming
        loop can be exercised without spawning a real subprocess."""
        import io
        from unittest.mock import MagicMock
        m = MagicMock()
        m.stdout = io.StringIO(stdout_text)
        m.stderr = io.StringIO(stderr_text)
        m.returncode = returncode
        m.terminate = MagicMock()
        m.kill = MagicMock()
        m.wait = MagicMock(return_value=returncode)
        return m

    def test_evtx_filter_streams_matches(self):
        """Happy path: stream emits 3 events with different IDs; filter keeps
        the requested one."""
        from tools.misc import evtx_filter
        xml = (
            '<?xml version="1.1" encoding="utf-8" standalone="yes" ?>\n'
            '<Events>\n'
            '<Event xmlns="ns"><System><EventID>4624</EventID></System><Data>a</Data></Event>\n'
            '\n'
            '<Event xmlns="ns"><System><EventID>4625</EventID></System><Data>b</Data></Event>\n'
            '\n'
            '<Event xmlns="ns"><System><EventID>4624</EventID></System><Data>c</Data></Event>\n'
            '</Events>\n'
        )
        with patch("subprocess.Popen", return_value=self._fake_popen(xml)):
            r = evtx_filter("/logs/Security.evtx", event_ids="4625")
        assert r["success"] is True
        assert r["events_scanned"] == 3
        assert r["matches_found"] == 1
        assert "4625" in r["events"][0]
        assert "4624" not in r["events"][0]
        assert r["cap_hit"] is False
        assert r["wall_clock_timed_out"] is False

    def test_evtx_filter_respects_max_results(self):
        """Once max_results is reached, the streamer breaks early — cap_hit
        is reported so the caller knows there may be more."""
        from tools.misc import evtx_filter
        events = "\n".join(
            f'<Event xmlns="ns"><System><EventID>4625</EventID></System><Data>{i}</Data></Event>'
            for i in range(10)
        )
        xml = f'<Events>\n{events}\n</Events>\n'
        with patch("subprocess.Popen", return_value=self._fake_popen(xml)):
            r = evtx_filter("/logs/Security.evtx", event_ids="4625",
                            max_results=3)
        assert r["matches_found"] == 3
        assert r["cap_hit"] is True

    def test_evtx_filter_rejects_empty_ids(self):
        from tools.misc import evtx_filter
        r = evtx_filter("/logs/Security.evtx", event_ids=" , ")
        assert r["success"] is False
        assert "no valid event_ids" in r["error"]

    def test_evtx_filter_handles_oversized_event(self):
        """A single Event larger than EVENT_BYTE_CAP must be dropped and the
        streamer must resync — it must NOT buffer unboundedly."""
        from tools.misc import evtx_filter
        huge = "<Data>" + ("x" * 250_000) + "</Data>"
        xml = (
            '<Events>\n'
            f'<Event xmlns="ns"><System><EventID>4625</EventID></System>{huge}</Event>\n'
            '<Event xmlns="ns"><System><EventID>4625</EventID></System><Data>ok</Data></Event>\n'
            '</Events>\n'
        )
        with patch("subprocess.Popen", return_value=self._fake_popen(xml)):
            r = evtx_filter("/logs/Security.evtx", event_ids="4625")
        assert r["oversized_events_dropped"] == 1
        assert r["matches_found"] == 1
        assert "ok" in r["events"][0]


class TestRegripper:
    def test_regripper_hive(self, mock_run):
        from tools.misc import regripper_hive
        regripper_hive("/mnt/wkstn01/Windows/System32/config/SYSTEM")
        cmd = mock_run.call_args[0][0]
        assert "rip" in " ".join(cmd) or "regripper" in " ".join(cmd)

    def test_regripper_list_plugins(self, mock_run):
        from tools.misc import regripper_list_plugins
        regripper_list_plugins()
        assert mock_run.called


class TestClamScan:
    def test_clamscan_file(self, mock_run):
        from tools.misc import clamscan_file
        clamscan_file("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "clamscan" in cmd

    def test_clamscan_directory(self, mock_run, tmp_path):
        from tools.misc import clamscan_directory
        clamscan_directory(str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert "clamscan" in cmd
        assert "-r" in cmd


class TestPdfTools:
    def test_pdfid_scan(self, mock_run):
        from tools.misc import pdfid_scan
        pdfid_scan("/evidence/malicious.pdf")
        assert mock_run.called

    def test_pdf_parser_analyze(self, mock_run):
        from tools.misc import pdf_parser_analyze
        pdf_parser_analyze("/evidence/malicious.pdf")
        assert mock_run.called

    def test_pdf_parser_with_object_id(self, mock_run):
        from tools.misc import pdf_parser_analyze
        pdf_parser_analyze("/evidence/malicious.pdf", object_id=5)
        assert mock_run.called


class TestPeTools:
    def test_pe_scanner(self, mock_run):
        from tools.misc import pe_scanner
        pe_scanner("/malware/sample.exe")
        assert mock_run.called

    def test_pe_carver(self, mock_run, tmp_path):
        from tools.misc import pe_carver
        pe_carver("/malware/blob.bin", str(tmp_path / "carved"))
        assert mock_run.called

    def test_packerid(self, mock_run):
        from tools.misc import packerid
        packerid("/malware/sample.exe")
        assert mock_run.called


class TestScheduledTasks:
    def test_parse_scheduled_tasks(self, tmp_path):
        from tools.misc import parse_scheduled_tasks
        tasks_dir = tmp_path / "Tasks"
        tasks_dir.mkdir()
        (tasks_dir / "evil_task.xml").write_text(
            '<?xml version="1.0"?><Task><Actions><Exec>'
            '<Command>powershell.exe</Command>'
            '</Exec></Actions></Task>'
        )
        r = parse_scheduled_tasks(str(tasks_dir))
        assert r["success"] is True
        assert r["task_count"] == 1

    def test_parse_scheduled_tasks_missing_dir(self):
        from tools.misc import parse_scheduled_tasks
        # os.walk on a nonexistent dir returns empty — success with 0 tasks
        r = parse_scheduled_tasks("/nonexistent/Tasks")
        assert r["task_count"] == 0


class TestUsnParser:
    def test_usnparser(self, mock_run):
        from tools.misc import usnparser_parse
        usnparser_parse("/mnt/wkstn01/$UsnJrnl")
        assert mock_run.called


class TestHindsight:
    def test_hindsight_chrome(self, mock_run, tmp_path):
        from tools.misc import hindsight_chrome
        hindsight_chrome("/mnt/wkstn01/Users/mhill/AppData/Local/Google/Chrome/User Data/Default", str(tmp_path))
        assert mock_run.called


def _seed_log_with_dair(tmp_path):
    """Helper: configure log + seed a dair_call so finding gates can be exercised."""
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("TEST", str(tmp_path / "trace.json"))
    l.record_dair_call("Triage", "", False, "", "", "stay", "")
    return l


def _seed_log_ready_for_confirmed(tmp_path, description: str = ""):
    """Seed log with dair_call + tool_call + reason_hypothesize +
    reason_confidence_score + reason_cite_check + reason_evaluate_finding
    so all gates (dair_required / confirmed_requires_supported_evaluate /
    confidence_and_citation / hypothesize_required) are satisfied for
    CONFIRMED-tier findings.

    description: if provided, the seeded reason_confidence_score and
    reason_cite_check entries carry inputs.user_message containing the
    description string so the confidence_and_citation gate's substring match
    succeeds. Pass the exact description the test will record; the helper
    normalizes it.
    """
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("TEST", str(tmp_path / "trace.json"))
    l.record_dair_call("Triage", "", False, "", "", "stay", "")
    tool_id = l.record_tool_call("vol.psscan", True, False, 0, 0)
    # hypothesize_required satisfaction (only matters when description
    # contains a keyword from _HYPOTHESIZE_KEYWORDS).
    l.record_reason_call("reason_hypothesize", True, "hypothesis OK", {})
    # confidence_and_citation satisfaction: matching user_message.
    _inputs = {"user_message": (description or "")[:200].lower()} if description else None
    l.record_reason_call(
        "reason_confidence_score",
        True,
        'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED", "score": 0.95}',
        {},
        inputs=_inputs,
    )
    l.record_reason_call(
        "reason_cite_check",
        True,
        'CITE_CHECK:\n{"verdict": "ALL_CITED"}',
        {},
        inputs=_inputs,
    )
    # confirmed_requires_supported_evaluate satisfaction.
    l.record_reason_call(
        "reason_evaluate_finding", True,
        "EVIDENCE SUPPORT: confirmed.\nVERDICT: SUPPORTED — evidence sound.",
        {},
    )
    return l, tool_id


class TestRecordFinding:
    def test_record_finding_returns_success(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "perfsvc.exe timestomped")
        with patch("core.execution_log.log", l):
            r = record_finding("PerfSvc.exe timestomped", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        assert r["confidence"] == "CONFIRMED"

    def test_record_finding_stores_linked_call_id(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "perfsvc.exe timestomped")
        with patch("core.execution_log.log", l):
            record_finding("PerfSvc.exe timestomped", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        finding_entries = [e for e in l._entries if e["type"] == "finding"]
        assert finding_entries[0]["linked_call_id"] == tid

    def test_record_finding_default_linked_call_id_zero(self, tmp_path):
        # SUSPECTED is the looser tier — no confidence_and_citation /
        # hypothesize_required checks. Documents
        # that linked_call_id defaults to 0 when omitted.
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            record_finding("test finding", "SUSPECTED", "vol.netscan", input_call_ids=[1])
        finding_entries = [e for e in l._entries if e["type"] == "finding"]
        assert finding_entries[0]["linked_call_id"] == 0


class TestRecordFindingLinkedCallIdGate:
    """confirmed_requires_linked_call_id: CONFIRMED needs a non-zero linked_call_id.
    linked_call_id_must_exist: the id must point at a real trace entry."""

    def test_confirmed_with_zero_linked_call_id_refused(self, tmp_path):
        from tools.misc import record_finding
        l, _ = _seed_log_ready_for_confirmed(tmp_path, "malicious .exe")
        with patch("core.execution_log.log", l):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=0, input_call_ids=[1])
        assert r["success"] is False
        assert "linked_call_id" in r["error"]

    def test_confirmed_with_unknown_linked_call_id_refused(self, tmp_path):
        from tools.misc import record_finding
        l, _ = _seed_log_ready_for_confirmed(tmp_path, "malicious .exe")
        with patch("core.execution_log.log", l):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=99999, input_call_ids=[1])
        assert r["success"] is False
        assert "99999" in r["error"]
        assert "not found" in r["error"]

    def test_confirmed_with_valid_linked_call_id_succeeds(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "malicious .exe")
        with patch("core.execution_log.log", l):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True

    def test_suspected_with_zero_linked_call_id_allowed(self, tmp_path):
        # confirmed_requires_linked_call_id only restricts CONFIRMED; the
        # loosest tier may omit linked_call_id.
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("possible anomaly", "SUSPECTED", "vol.netscan", linked_call_id=0, input_call_ids=[1])
        assert r["success"] is True

    def test_suspected_with_unknown_linked_call_id_refused(self, tmp_path):
        # linked_call_id_must_exist applies to any tier when linked_call_id != 0.
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("possible anomaly", "SUSPECTED", "vol.netscan", linked_call_id=42, input_call_ids=[1])
        assert r["success"] is False
        assert "42" in r["error"]


class TestRecordFindingEvaluateVerdictGate:
    """confirmed_requires_supported_evaluate: CONFIRMED refused if most recent
    reason.evaluate_finding verdict is CHALLENGED."""

    def test_confirmed_with_recent_challenged_evaluate_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call(
            "reason_evaluate_finding", True,
            "EVIDENCE SUPPORT: weak.\nVERDICT: CHALLENGED — YARA-only evidence.",
            {},
        )
        with patch("core.execution_log.log", l):
            r = record_finding("attacker tool", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert "CHALLENGED" in r["error"]
        assert r.get("evaluate_verdict") == "CHALLENGED"

    def test_confirmed_with_recent_supported_evaluate_succeeds(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "attacker tool")
        with patch("core.execution_log.log", l):
            r = record_finding("attacker tool", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True

    def test_most_recent_supported_wins_over_older_challenged(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        # hypothesize_required + confidence_and_citation satisfaction
        # (description has no keyword but CONFIRMED still needs confidence
        # + cite_check).
        _ins = {"user_message": "attacker tool"}
        l.record_reason_call("reason_hypothesize", True, "hypothesis OK", {})
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        # Older CHALLENGED followed by newer SUPPORTED — should succeed.
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: CHALLENGED", {})
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        with patch("core.execution_log.log", l):
            r = record_finding("attacker tool", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True

    def test_most_recent_challenged_refuses_even_with_older_supported(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: CHALLENGED", {})
        with patch("core.execution_log.log", l):
            r = record_finding("attacker tool", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert "CHALLENGED" in r["error"]

    def test_uncertain_verdict_blocks_confirmed(self, tmp_path):
        # VERDICT: UNCERTAIN is insufficient for CONFIRMED — it means the
        # reviewer could not confirm, not that they supported the claim.
        # The gate now requires an explicit SUPPORTED verdict.
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: UNCERTAIN", {})
        with patch("core.execution_log.log", l):
            r = record_finding("attacker tool", "CONFIRMED", "ez.mftecmd",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert r["gate"] == "confirmed_requires_supported_evaluate"
        assert "UNCERTAIN" in r["evaluate_verdict"]
        # Auto-emits self_correction just like CHALLENGED
        sc = [e for e in l._entries if e["type"] == "self_correction"]
        assert sc

    def test_challenged_refusal_auto_emits_self_correction(self, tmp_path):
        # Self-correction auto-emit: when CONFIRMED is refused due to CHALLENGED verdict,
        # a self_correction entry should be appended automatically.
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: CHALLENGED", {})
        with patch("core.execution_log.log", l):
            r = record_finding("overclaimed", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        sc = [e for e in l._entries if e["type"] == "self_correction"]
        assert len(sc) == 1
        # The gate uses a distinct trigger so it's distinguishable from the
        # auto-emit inside reason.evaluate_finding (which uses
        # "evaluate_challenged"). This one specifically captures "agent
        # attempted to push CONFIRMED through despite CHALLENGED verdict".
        assert sc[0]["trigger"] == "evaluate_challenged_gate_refused"


class TestRecordFindingDairGate:
    """Any finding (any tier) requires a recent dair_call."""

    def test_finding_without_any_dair_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_evaluate_finding", True, "ok", {})
        with patch("core.execution_log.log", l):
            r = record_finding("CONFIRMED claim", "CONFIRMED", "ez.mftecmd", input_call_ids=[1])
        assert r["success"] is False
        assert "dair_assess" in r["error"]
        assert all(e["type"] != "finding" for e in l._entries)

    def test_suspected_without_dair_also_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = record_finding("anomaly", "SUSPECTED", "vol.netscan", input_call_ids=[1])
        assert r["success"] is False
        assert "dair_assess" in r["error"]

    def test_stale_dair_beyond_30_entries_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        for _ in range(31):
            l.record_reason_call("reason_hypothesize", True, "ok", {})
        with patch("core.execution_log.log", l):
            r = record_finding("anomaly", "LIKELY", "vol.netscan", input_call_ids=[1])
        assert r["success"] is False
        assert "dair_assess" in r["error"]


class TestRecordFindingEvaluateGate:
    """CONFIRMED tier additionally requires a recent reason.evaluate_finding."""

    def test_confirmed_without_recent_evaluate_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        with patch("core.execution_log.log", l):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert "reason.evaluate_finding" in r["error"]
        assert all(e["type"] != "finding" for e in l._entries)

    def test_confirmed_with_recent_evaluate_succeeds(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "malicious .exe")
        with patch("core.execution_log.log", l):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True

    def test_suspected_with_dair_does_not_require_evaluate(self, tmp_path):
        # SUSPECTED is the loose tier — only dair_required is checked.
        from tools.misc import record_finding
        l = _seed_log_with_dair(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("anomaly observed", "SUSPECTED", "vol.netscan", input_call_ids=[1])
        assert r["success"] is True

    def test_stale_evaluate_beyond_30_entries_refused(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        # 31 dair_calls push the evaluate call out of the 30-entry window
        for _ in range(31):
            l.record_dair_call("Triage", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l):
            r = record_finding("malicious .exe", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert "reason.evaluate_finding" in r["error"]


# ── New tool wrappers ─────────────────────────────────────────────────────────

class TestPffExport:
    def test_pffexport_missing_binary_returns_error(self, tmp_path, monkeypatch):
        from tools.misc import pff_export
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        out_dir = tmp_path / "exports"
        out_dir.mkdir()
        r = pff_export("/tmp/fake.pst", str(out_dir))
        assert r["success"] is False
        assert "pffexport not installed" in r["error"]

    def test_pffexport_calls_binary_when_available(self, tmp_path, monkeypatch):
        from tools.misc import pff_export
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: "/usr/bin/pffexport")
        captured = {}
        monkeypatch.setattr("tools.misc.run", lambda cmd, **kw: captured.setdefault("cmd", cmd) or {"success": True})
        out_dir = tmp_path / "exports"
        out_dir.mkdir()
        pff_export("/tmp/x.pst", str(out_dir), mode="all")
        assert captured["cmd"][0] == "/usr/bin/pffexport"
        assert "-m" in captured["cmd"]
        assert "all" in captured["cmd"]

    def test_pffexport_refuses_evidence_output_path(self):
        from tools.misc import pff_export
        import pytest
        with pytest.raises(ValueError):
            pff_export("/tmp/x.pst", "/mnt/rd01/extract")


class TestReadpstExtract:
    def test_readpst_missing_binary(self, tmp_path, monkeypatch):
        from tools.misc import readpst_extract
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        out_dir = tmp_path / "exports"
        out_dir.mkdir()
        r = readpst_extract("/tmp/x.pst", str(out_dir))
        assert r["success"] is False

    def test_readpst_invokes_binary(self, tmp_path, monkeypatch):
        from tools.misc import readpst_extract
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: "/usr/bin/readpst")
        captured = {}
        monkeypatch.setattr("tools.misc.run", lambda cmd, **kw: captured.setdefault("cmd", cmd) or {"success": True})
        out_dir = tmp_path / "exports"
        out_dir.mkdir()
        readpst_extract("/tmp/x.pst", str(out_dir))
        assert "/usr/bin/readpst" == captured["cmd"][0]
        assert "-o" in captured["cmd"]


class TestDensityscout:
    def test_densityscout_missing_binary(self, monkeypatch):
        from tools.misc import densityscout_scan
        import os
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        # Also ensure the fallback path doesn't exist
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        r = densityscout_scan("/tmp/x.exe")
        assert r["success"] is False


class TestChainsawHunt:
    def test_chainsaw_missing_binary(self, monkeypatch):
        from tools.misc import chainsaw_hunt
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        r = chainsaw_hunt("/tmp/evtx_dir")
        assert r["success"] is False
        assert "chainsaw not installed" in r["error"]


class TestCapaAnalyze:
    def test_capa_missing_binary(self, monkeypatch):
        from tools.misc import capa_analyze
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        r = capa_analyze("/tmp/x.exe")
        assert r["success"] is False
        assert "flare-capa" in r["error"]


class TestOlevbaScan:
    def test_olevba_missing_binary(self, monkeypatch):
        from tools.misc import olevba_scan
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        r = olevba_scan("/tmp/x.docx")
        assert r["success"] is False
        assert "oletools" in r["error"]


class TestMraptorScan:
    def test_mraptor_missing_binary(self, monkeypatch):
        from tools.misc import mraptor_scan
        monkeypatch.setattr("tools.misc._bin_or_warn", lambda name: None)
        r = mraptor_scan("/tmp/x.docx")
        assert r["success"] is False


class TestBatchRun:
    def test_batch_run_empty(self):
        from tools.misc import batch_run
        r = batch_run([])
        assert r["success"] is True
        assert r["results"] == []

    def test_batch_run_runs_commands_concurrently(self, monkeypatch):
        from tools.misc import batch_run
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return {"success": True, "cmd": cmd}

        monkeypatch.setattr("tools.misc.run", fake_run)
        r = batch_run([{"cmd": ["echo", "a"]}, {"cmd": ["echo", "b"]}], max_concurrent=2)
        assert r["success"] is True
        assert len(r["results"]) == 2
        # Order preserved by index, even with concurrency
        assert r["results"][0]["cmd"] == ["echo", "a"]
        assert r["results"][1]["cmd"] == ["echo", "b"]

    def test_batch_run_rejects_invalid_cmd(self, monkeypatch):
        from tools.misc import batch_run
        # No-op fake run so the runner doesn't try real subprocess
        monkeypatch.setattr("tools.misc.run", lambda cmd, **kw: {"success": True})
        r = batch_run([{"timeout": 5}])  # missing cmd
        assert r["results"][0]["success"] is False
        assert "missing or invalid 'cmd'" in r["results"][0]["error"]


class TestRecordAgentMessageWithFindings:
    """record_agent_message accepts an optional structured findings list and
    writes each as a finding entry through the same gate as record_finding."""

    def _seed(self, tmp_path, descriptions=None):
        """Trace seeded with all checkpoints so CONFIRMED findings pass the
        gate (dair_required + confirmed_requires_supported_evaluate +
        confidence_and_citation + hypothesize_required).

        descriptions: optional list of normalized description substrings to
        seed into the user_message of confidence_score / cite_check entries
        so the confidence_and_citation per-finding substring match succeeds.
        """
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("RAM-001", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.netscan", True, False, 0, 0,
                                  stdout_excerpt="PID 7092 -> 172.16.4.10:8080")
        l.record_reason_call("reason_hypothesize", True, "hypothesis OK", {})
        # Pack every description into the user_message so a single seeded call
        # satisfies every distinct finding's substring match.
        _msg = " | ".join(d.lower() for d in (descriptions or []))
        _ins = {"user_message": _msg} if _msg else None
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        l.record_reason_call(
            "reason_evaluate_finding", True,
            "VERDICT: SUPPORTED — corroborated by multiple sources.", {},
        )
        return l, tid

    def test_without_findings_matches_legacy(self, tmp_path):
        from tools.misc import record_agent_message
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("RAM-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = record_agent_message(content="just analysis")
        assert r["success"] is True
        assert "findings" not in r
        narr = [e for e in l._entries if e["type"] == "investigation_narration"]
        assert len(narr) == 1
        assert narr[0]["content"] == "just analysis"

    def test_with_confirmed_findings_writes_atomic(self, tmp_path):
        from tools.misc import record_agent_message
        desc = "ngentask.exe (PID 7092) is CS Beacon on BASE-FILE"
        l, tid = self._seed(tmp_path, descriptions=[desc])
        with patch("core.execution_log.log", l):
            r = record_agent_message(
                content="BASE-FILE memory shows CS Beacon on ngentask.exe.",
                input_call_ids=[tid],
                findings=[
                    {"description": desc,
                     "confidence": "CONFIRMED",
                     "linked_call_id": tid,
                     "source": "vol.netscan"},
                ],
            )
        assert r["success"] is True
        assert r["any_finding_refused"] is False
        assert len(r["findings"]) == 1
        assert r["findings"][0]["success"] is True
        # Narration + 1 finding entry in the trace
        narrs = [e for e in l._entries if e["type"] == "investigation_narration"]
        finds = [e for e in l._entries if e["type"] == "finding"]
        assert len(narrs) == 1
        assert len(finds) == 1
        assert finds[0]["confidence"] == "CONFIRMED"

    def test_gate_failures_return_per_finding(self, tmp_path):
        from tools.misc import record_agent_message
        # Seed inputs covering only the valid finding's description; the
        # invalid one fails confirmed_requires_linked_call_id before
        # confidence_and_citation anyway.
        l, tid = self._seed(tmp_path, descriptions=["valid finding"])
        with patch("core.execution_log.log", l):
            r = record_agent_message(
                content="some analysis",
                input_call_ids=[tid],
                findings=[
                    # Valid CONFIRMED — inherits input_call_ids from the message
                    {"description": "valid finding", "confidence": "CONFIRMED",
                     "linked_call_id": tid, "source": "vol.netscan"},
                    # Invalid: CONFIRMED without linked_call_id → gate refuses
                    {"description": "no link", "confidence": "CONFIRMED",
                     "linked_call_id": 0, "source": "vol.netscan"},
                ],
            )
        assert r["any_finding_refused"] is True
        assert r["findings"][0]["success"] is True
        assert r["findings"][1]["success"] is False
        # Narration still written
        narrs = [e for e in l._entries if e["type"] == "investigation_narration"]
        assert len(narrs) == 1
        # Only the valid finding ended up in the trace
        finds = [e for e in l._entries if e["type"] == "finding"]
        assert len(finds) == 1

    def test_suspected_finding_no_evaluate_required(self, tmp_path):
        # SUSPECTED tier skips confirmed_requires_supported_evaluate /
        # confidence_and_citation / hypothesize_required — only dair_required.
        from tools.misc import record_agent_message
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("RAM-003", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l):
            r = record_agent_message(
                content="possible anomaly",
                findings=[
                    {"description": "weak signal", "confidence": "SUSPECTED",
                     "source": "vol.netscan"},
                ],
            )
        assert r["findings"][0]["success"] is True


# ── MCP routing enforcement ──────────────────────────────────────────────────

class TestRecordFindingMcpRoutingGate:
    """mcp_routing: findings whose linked_call_id points to a raw-bash forensic-binary
    invocation are refused. The architectural-guardrail story requires
    forensic execution to flow through the typed MCP layer, not the host shell.
    """

    def _append_bash_tool_call(self, l, cmd: str) -> int:
        """Mimic the PostToolUse hook: append a tool_call entry with
        source='claude_code_bash' directly, bypassing record_tool_call (which
        doesn't accept a `source` kwarg — that field is only set by the hook).
        """
        cid = l._next_id()
        l._entries.append({
            "call_id": cid,
            "type": "tool_call",
            "ts": "2026-05-22T07:00:00Z",
            "cmd": cmd,
            "success": True,
            "truncated": False,
            "retries": 0,
            "exit_code": 0,
            "elapsed_seconds": 0.0,
            "stderr": "",
            "source": "claude_code_bash",
        })
        return cid

    def _seed_with_bash_call(self, tmp_path, cmd: str, description: str = ""):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("MCP-ROUTE", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        cid = self._append_bash_tool_call(l, cmd)
        # confirmed_requires_supported_evaluate + confidence_and_citation +
        # hypothesize_required satisfied — only mcp_routing should refuse.
        _ins = {"user_message": description.lower()} if description else None
        l.record_reason_call("reason_hypothesize", True, "hypothesis OK", {})
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        l.record_reason_call("reason_evaluate_finding", True,
                             "VERDICT: SUPPORTED", {})
        return l, cid

    def test_bash_vol_invocation_refuses_finding(self, tmp_path):
        from tools.misc import record_finding
        desc = "p.exe is cs beacon"
        l, cid = self._seed_with_bash_call(
            tmp_path,
            cmd="/usr/local/bin/vol -f /evidence/mem.img windows.psscan",
            description=desc,
        )
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "CONFIRMED", "vol.psscan", linked_call_id=cid, input_call_ids=[1])
        assert r["success"] is False
        assert r.get("gate") == "mcp_routing"
        assert "MCP routing" in r["error"]
        assert "vol.vol_" in r.get("suggested_wrapper", "")

    def test_bash_dotnet_eztool_invocation_refuses_finding(self, tmp_path):
        from tools.misc import record_finding
        desc = "evtxecmd output anomaly"
        l, cid = self._seed_with_bash_call(
            tmp_path,
            cmd="dotnet /opt/zimmermantools/EvtxECmd/EvtxECmd.dll -f /mnt/sec.evtx",
            description=desc,
        )
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "CONFIRMED", "ez.evtxecmd", linked_call_id=cid, input_call_ids=[1])
        assert r["success"] is False
        assert r.get("gate") == "mcp_routing"
        assert "EvtxECmd" in r.get("offending_cmd_excerpt", "")
        assert "ez_evtxecmd" in r.get("suggested_wrapper", "")

    def test_bash_non_forensic_command_does_not_refuse(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("MCP-ROUTE", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        # Bash command that doesn't run a forensic binary — should not trip mcp_routing.
        cid = self._append_bash_tool_call(l, "ls /cases/srl-2018-demo/analysis")
        l.record_reason_call("reason_hypothesize", True, "OK", {})
        _ins = {"user_message": "harmless ls"}
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        with patch("core.execution_log.log", l):
            r = record_finding("harmless ls", "CONFIRMED", "vol.psscan", linked_call_id=cid, input_call_ids=[1])
        assert r["success"] is True

    def test_mcp_sourced_call_does_not_refuse(self, tmp_path):
        # An entry without source="claude_code_bash" (i.e. came through an
        # MCP wrapper) must NOT be refused even if the cmd would match.
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "perfsvc.exe timestomped")
        with patch("core.execution_log.log", l):
            r = record_finding("PerfSvc.exe timestomped", "CONFIRMED", "ez.mftecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True


# ── ATT&CK technique ID auto-validation ──────────────────────────────────────

class TestRecordFindingMitreValidateGate:
    """mitre_technique_validation: T-IDs in description are validated via
    correlate.mitre_validate."""

    def test_unknown_tid_refuses_finding(self, tmp_path):
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "process beacon t9999.999")
        with patch("core.execution_log.log", l), \
             patch("tools.correlate.mitre_validate",
                   side_effect=lambda x, **kw: {"exists": False, "technique_id": x}):
            r = record_finding("Process beacon T9999.999", "CONFIRMED",
                               "vol.netscan", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert r.get("gate") == "mitre_technique_validation"
        assert "T9999.999" in r.get("unknown_technique_ids", [])

    def test_known_tid_passes_and_records_validation(self, tmp_path):
        from tools.misc import record_finding
        desc = "wmi event subscription t1546.003"
        l, tid = _seed_log_ready_for_confirmed(tmp_path, desc)
        with patch("core.execution_log.log", l), \
             patch("tools.correlate.mitre_validate",
                   side_effect=lambda x, **kw: {
                       "exists": True, "name": "WMI Subscription",
                       "tactic": "Persistence", "technique_id": x,
                   }):
            r = record_finding("WMI Event Subscription T1546.003", "CONFIRMED",
                               "ez.evtxecmd", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        assert {"technique_id": "T1546.003",
                "name": "WMI Subscription",
                "tactic": "Persistence"} in r.get("validated_techniques", [])

    def test_no_tid_no_validation_attempted(self, tmp_path):
        # Findings without any T-ID don't invoke mitre_validate.
        from tools.misc import record_finding
        l, tid = _seed_log_ready_for_confirmed(tmp_path, "no technique here")
        with patch("core.execution_log.log", l), \
             patch("tools.correlate.mitre_validate") as mv:
            r = record_finding("No technique here", "CONFIRMED",
                               "vol.psscan", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True
        assert mv.call_count == 0


# ── confidence_score + cite_check coverage ───────────────────────────────────

class TestRecordFindingConfidenceScoreCiteCheckGate:
    """confidence_and_citation: CONFIRMED/LIKELY require a recent
    reason.confidence_score AND reason.cite_check that reference this finding."""

    def _base(self, tmp_path):
        """dair + tool + hypothesize + SUPPORTED evaluate — dair_required /
        confirmed_requires_supported_evaluate / hypothesize_required all
        satisfied but confidence_and_citation NOT yet. Tests layer the
        confidence/cite calls on top per-case."""
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("CONF-CITE", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_hypothesize", True, "OK", {})
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        return l, tid

    def test_confirmed_without_confidence_score_refused(self, tmp_path):
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        # Seed only cite_check; missing confidence_score → refuse.
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}',
                             {}, inputs={"user_message": "my finding text"})
        with patch("core.execution_log.log", l):
            r = record_finding("My finding text", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert r.get("gate") == "confidence_and_citation"
        assert r.get("missing_check") == "reason_confidence_score"

    def test_confirmed_without_cite_check_refused(self, tmp_path):
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}',
                             {}, inputs={"user_message": "my finding text"})
        with patch("core.execution_log.log", l):
            r = record_finding("My finding text", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert r.get("gate") == "confidence_and_citation"
        assert r.get("missing_check") == "reason_cite_check"

    def test_cite_check_with_uncited_claims_refused(self, tmp_path):
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        _ins = {"user_message": "my finding text"}
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "UNCITED_CLAIMS_PRESENT"}',
                             {}, inputs=_ins)
        with patch("core.execution_log.log", l):
            r = record_finding("My finding text", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert r.get("gate") == "confidence_and_citation"
        assert "UNCITED_CLAIMS_PRESENT" in r["error"]

    def test_confidence_score_lower_tier_refused(self, tmp_path):
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        _ins = {"user_message": "my finding text"}
        # Reviewer assigned SUSPECTED, agent requested CONFIRMED → refuse.
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "SUSPECTED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        with patch("core.execution_log.log", l):
            r = record_finding("My finding text", "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert r.get("gate") == "confidence_and_citation"
        assert r.get("confidence_score_tier") == "SUSPECTED"

    def test_likely_tier_also_requires_g16(self, tmp_path):
        # LIKELY is strict — confidence_and_citation fires for both CONFIRMED and LIKELY.
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_finding("My finding text", "LIKELY", "vol.psscan",
                               linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert r.get("gate") == "confidence_and_citation"

    def test_g16_anti_reuse_blocks_second_finding_with_same_description(self, tmp_path):
        # A single confidence_score+cite_check pair can satisfy ONE finding.
        # A second identical-description finding must get fresh checks.
        from tools.misc import record_finding
        l, tid = self._base(tmp_path)
        _ins = {"user_message": "duplicate finding text"}
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        with patch("core.execution_log.log", l):
            r1 = record_finding("Duplicate finding text", "CONFIRMED", "vol.psscan",
                                linked_call_id=tid, input_call_ids=[tid])
            r2 = record_finding("Duplicate finding text", "CONFIRMED", "vol.psscan",
                                linked_call_id=tid, input_call_ids=[tid])
        assert r1["success"] is True
        assert r2["success"] is False
        assert r2.get("gate") == "confidence_and_citation"


# ── hypothesize trigger ──────────────────────────────────────────────────────

class TestRecordFindingHypothesizeGate:
    """hypothesize_required: CONFIRMED/LIKELY findings mentioning process/
    service/persistence/C2/lateral-movement require a recent
    reason.hypothesize call."""

    def _base_no_hypothesize(self, tmp_path, desc: str):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("HYP-REQ", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        _ins = {"user_message": desc.lower()}
        l.record_reason_call("reason_confidence_score", True,
                             'CONFIDENCE_SCORE:\n{"tier": "CONFIRMED"}', {}, inputs=_ins)
        l.record_reason_call("reason_cite_check", True,
                             'CITE_CHECK:\n{"verdict": "ALL_CITED"}', {}, inputs=_ins)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        return l, tid

    def test_process_keyword_without_hypothesize_refused(self, tmp_path):
        from tools.misc import record_finding
        desc = "rogue process pid 7092 c2 to internal host"
        l, tid = self._base_no_hypothesize(tmp_path, desc)
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "CONFIRMED", "vol.psscan", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is False
        assert r.get("gate") == "hypothesize_required"

    def test_tested_hypothesis_id_carve_out(self, tmp_path):
        # Passing tested_hypothesis_id satisfies hypothesize_required without
        # a separate hypothesize call (proves the hypothesize→finding loop
        # completed).
        from tools.misc import record_finding
        desc = "rogue process pid 7092 c2 to internal host"
        l, tid = self._base_no_hypothesize(tmp_path, desc)
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "CONFIRMED", "vol.psscan",
                               linked_call_id=tid, tested_hypothesis_id="H0001", input_call_ids=[tid])
        assert r["success"] is True

    def test_no_keyword_no_hypothesize_required(self, tmp_path):
        # File-existence finding without trigger keywords skips hypothesize_required.
        from tools.misc import record_finding
        desc = "evidence file checksum matches reference"
        l, tid = self._base_no_hypothesize(tmp_path, desc)
        with patch("core.execution_log.log", l):
            r = record_finding(desc, "CONFIRMED", "hash.verify", linked_call_id=tid, input_call_ids=[tid])
        assert r["success"] is True


# ── export_execution_log requires pre_report_check ───────────────────────────

class TestExportRequiresPreReportCheck:
    """pre_report_check_required: misc.export_execution_log refuses unless reason.pre_report_check
    returned READY_TO_REPORT: true within the last 50 trace entries."""

    def test_missing_pre_report_check_refused(self, tmp_path, monkeypatch):
        from tools.misc import export_execution_log
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("EXPORT", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l), \
             patch("tools.misc.assert_output_safe", lambda *a, **kw: None):
            r = export_execution_log(str(tmp_path / "out"))
        assert r["success"] is False
        assert r.get("gate") == "pre_report_check_required"
        assert r.get("missing_check") == "reason_pre_report_check"

    def test_pre_report_check_not_ready_refused(self, tmp_path):
        from tools.misc import export_execution_log
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("EXPORT", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        l.record_reason_call("reason_pre_report_check", True,
                             "READY_TO_REPORT: false\nBLOCKING_ISSUES (1): ...", {})
        with patch("core.execution_log.log", l), \
             patch("tools.misc.assert_output_safe", lambda *a, **kw: None):
            r = export_execution_log(str(tmp_path / "out"))
        assert r["success"] is False
        assert r.get("gate") == "pre_report_check_required"
        assert "false" in r.get("pre_report_conclusion", "").lower()

    def test_pre_report_check_ready_passes(self, tmp_path):
        from tools.misc import export_execution_log
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("EXPORT", str(tmp_path / "trace.json"))
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        l.record_reason_call("reason_pre_report_check", True,
                             "READY_TO_REPORT: true\nBLOCKING_ISSUES (0): none", {})
        with patch("core.execution_log.log", l), \
             patch("tools.misc.assert_output_safe", lambda *a, **kw: None):
            r = export_execution_log(str(tmp_path / "out"))
        assert r["success"] is True
