"""Tests for tools/carving.py."""
import os
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.carving.run", return_value=run_ok) as m:
        yield m


class TestBulkExtractor:
    def test_output_dir_evidence_blocked(self):
        from tools.carving import bulk_extractor_scan
        with pytest.raises(Exception):
            bulk_extractor_scan("/evidence/image.E01", "/cases/example/evidence/bulk")

    def test_basic_scan(self, mock_run, tmp_path):
        from tools.carving import bulk_extractor_scan
        out = str(tmp_path / "bulk")
        bulk_extractor_scan("/evidence/image.E01", out)
        cmd = mock_run.call_args[0][0]
        assert "bulk_extractor" in cmd

    def test_thread_count(self, mock_run, tmp_path):
        from tools.carving import bulk_extractor_scan
        out = str(tmp_path / "bulk")
        bulk_extractor_scan("/evidence/image.E01", out, threads=8)
        cmd = mock_run.call_args[0][0]
        assert "8" in cmd

    def test_unallocated_scan(self, mock_run, tmp_path):
        from tools.carving import bulk_extractor_unallocated
        out = str(tmp_path / "bulk_unalloc")
        bulk_extractor_unallocated("/analysis/unallocated.raw", out)
        cmd = mock_run.call_args[0][0]
        assert "bulk_extractor" in cmd


class TestForemost:
    def test_evidence_output_blocked(self):
        from tools.carving import foremost_carve
        with pytest.raises(Exception):
            foremost_carve("/evidence/image.E01", "/cases/example/evidence/foremost")

    def test_basic_carve(self, mock_run, tmp_path):
        from tools.carving import foremost_carve
        out = str(tmp_path / "foremost")
        foremost_carve("/evidence/image.E01", out)
        cmd = mock_run.call_args[0][0]
        assert "foremost" in cmd

    def test_file_types(self, mock_run, tmp_path):
        from tools.carving import foremost_carve
        out = str(tmp_path / "foremost")
        foremost_carve("/evidence/image.E01", out, file_types="jpg,pdf,docx")
        cmd = mock_run.call_args[0][0]
        assert "-t" in cmd


class TestScalpel:
    def test_evidence_output_blocked(self):
        from tools.carving import scalpel_carve
        with pytest.raises(Exception):
            scalpel_carve("/evidence/image.E01", "/cases/example/evidence/scalpel")

    def test_basic_carve(self, mock_run, tmp_path):
        from tools.carving import scalpel_carve
        out = str(tmp_path / "scalpel")
        scalpel_carve("/evidence/image.E01", out)
        cmd = mock_run.call_args[0][0]
        assert "scalpel" in cmd


class TestBulkExtractorReport:
    def test_reads_output_dir(self, tmp_path):
        from tools.carving import bulk_extractor_report
        # Create a minimal bulk_extractor output directory
        (tmp_path / "report.xml").write_text("<report/>")
        (tmp_path / "email.txt").write_text("user@example.com\n")
        r = bulk_extractor_report(str(tmp_path))
        assert r["success"] is True
        assert "output_dir" in r

    def test_missing_dir(self):
        from tools.carving import bulk_extractor_report
        r = bulk_extractor_report("/nonexistent/bulk_output")
        assert r["success"] is False
