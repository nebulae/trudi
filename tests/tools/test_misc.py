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

    def test_evtx_filter(self, tmp_path):
        # evtx_filter calls subprocess.run directly (not core.run)
        from tools.misc import evtx_filter
        from unittest.mock import patch, MagicMock
        xml = b"<Events><Event><EventID>4624</EventID></Event></Events>"
        mock_proc = MagicMock(returncode=0, stdout=xml, stderr=b"")
        with patch("subprocess.run", return_value=mock_proc):
            r = evtx_filter("/logs/Security.evtx", event_ids="4624")
        assert r["success"] is True


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


class TestRecordFinding:
    def test_record_finding_returns_success(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = record_finding("PerfSvc.exe timestomped", "CONFIRMED", "ez.mftecmd")
        assert r["success"] is True
        assert r["confidence"] == "CONFIRMED"

    def test_record_finding_stores_linked_call_id(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            record_finding("PerfSvc.exe timestomped", "CONFIRMED", "ez.mftecmd", linked_call_id=7)
        assert l._entries[0]["linked_call_id"] == 7

    def test_record_finding_default_linked_call_id_zero(self, tmp_path):
        from tools.misc import record_finding
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            record_finding("test finding", "LIKELY", "vol.netscan")
        assert l._entries[0]["linked_call_id"] == 0
