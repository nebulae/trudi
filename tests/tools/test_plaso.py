"""Tests for tools/plaso.py."""
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.plaso.run", return_value=run_ok) as m:
        yield m


class TestPlasoCreateTimeline:
    def test_storage_file_evidence_blocked(self):
        from tools.plaso import plaso_create_timeline
        with pytest.raises(Exception):
            plaso_create_timeline("/evidence/image.E01", "/cases/srl/evidence/timeline.plaso")

    def test_storage_file_safe(self, mock_run, tmp_path):
        from tools.plaso import plaso_create_timeline
        storage = str(tmp_path / "timeline.plaso")
        plaso_create_timeline("/evidence/image.E01", storage)
        cmd = mock_run.call_args[0][0]
        assert "log2timeline" in " ".join(cmd) or "log2timeline.py" in " ".join(cmd)
        assert storage in cmd

    def test_timezone_utc(self, mock_run, tmp_path):
        from tools.plaso import plaso_create_timeline
        storage = str(tmp_path / "timeline.plaso")
        plaso_create_timeline("/evidence/image.E01", storage, timezone="UTC")
        cmd = mock_run.call_args[0][0]
        assert "UTC" in " ".join(cmd)

    def test_targeted_timeline(self, mock_run, tmp_path):
        from tools.plaso import plaso_create_targeted
        storage = str(tmp_path / "targeted.plaso")
        plaso_create_targeted("/evidence/image.E01", storage, artifact_filters="WindowsEventLogs")
        assert mock_run.called


class TestPlasoExport:
    def test_export_csv_output_blocked(self):
        from tools.plaso import plaso_export_csv
        with pytest.raises(Exception):
            plaso_export_csv("timeline.plaso", "/cases/srl/evidence/out.csv")

    def test_export_csv_safe(self, mock_run, tmp_path):
        from tools.plaso import plaso_export_csv
        out = str(tmp_path / "timeline.csv")
        plaso_export_csv("timeline.plaso", out)
        cmd = mock_run.call_args[0][0]
        assert "psort" in " ".join(cmd) or "psort.py" in " ".join(cmd)

    def test_export_json_safe(self, mock_run, tmp_path):
        from tools.plaso import plaso_export_json
        out = str(tmp_path / "timeline.json")
        plaso_export_json("timeline.plaso", out)
        assert mock_run.called

    def test_filter_incident_window(self, mock_run, tmp_path):
        from tools.plaso import plaso_filter_incident_window
        out = str(tmp_path / "incident.csv")
        plaso_filter_incident_window("timeline.plaso", out, "2018-09-06T17:00:00", "2018-09-06T20:00:00")
        cmd = mock_run.call_args[0][0]
        assert "2018-09-06" in " ".join(cmd)


class TestPlasoInfo:
    def test_pinfo(self, mock_run):
        from tools.plaso import plaso_info
        plaso_info("timeline.plaso")
        cmd = mock_run.call_args[0][0]
        assert "pinfo" in " ".join(cmd) or "pinfo.py" in " ".join(cmd)

    def test_list_parsers(self, mock_run):
        from tools.plaso import plaso_list_parsers
        plaso_list_parsers()
        assert mock_run.called
