"""Tests for tools/strings_tools.py."""
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.strings_tools.run", return_value=run_ok) as m:
        yield m


class TestStringsExtract:
    def test_strings_extract_basic(self, mock_run):
        from tools.strings_tools import strings_extract
        strings_extract("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "strings" in cmd

    def test_min_length_applied(self, mock_run):
        from tools.strings_tools import strings_extract
        strings_extract("/malware/sample.exe", min_length=10)
        cmd = mock_run.call_args[0][0]
        assert "10" in cmd

    def test_output_path_evidence_blocked(self):
        from tools.strings_tools import strings_extract
        with pytest.raises(Exception):
            strings_extract("/malware/sample.exe", output_path="/cases/srl/evidence/strings.txt")

    def test_output_path_safe(self, mock_run, tmp_path):
        from tools.strings_tools import strings_extract
        out = str(tmp_path / "strings.txt")
        strings_extract("/malware/sample.exe", output_path=out)
        assert mock_run.called


class TestStringsGrep:
    def test_grep_pattern(self, mock_run):
        from tools.strings_tools import strings_grep
        mock_run.return_value = {**mock_run.return_value, "stdout": "http://evil.com\nftp://also.evil"}
        strings_grep("/malware/sample.exe", "http")
        assert mock_run.called


class TestFileIdentify:
    def test_file_identify(self, mock_run):
        from tools.strings_tools import file_identify
        file_identify("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "file" in cmd

    def test_file_identify_directory(self, mock_run, tmp_path):
        from tools.strings_tools import file_identify_directory
        file_identify_directory(str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert "file" in cmd


class TestHexdump:
    def test_hexdump_basic(self, mock_run):
        from tools.strings_tools import hexdump
        hexdump("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "hexdump" in cmd

    def test_hexdump_length(self, mock_run):
        from tools.strings_tools import hexdump
        hexdump("/malware/sample.exe", length=512)
        cmd = mock_run.call_args[0][0]
        assert "512" in cmd or any("512" in str(a) for a in cmd)

    def test_xxd_dump(self, mock_run):
        from tools.strings_tools import xxd_dump
        xxd_dump("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "xxd" in cmd


class TestExiftool:
    def test_exiftool_metadata(self, mock_run):
        from tools.strings_tools import exiftool_metadata
        exiftool_metadata("/evidence/document.pdf")
        cmd = mock_run.call_args[0][0]
        assert "exiftool" in cmd

    def test_exiftool_batch(self, mock_run, tmp_path):
        from tools.strings_tools import exiftool_batch
        exiftool_batch(str(tmp_path))
        assert "exiftool" in mock_run.call_args[0][0]


class TestStat:
    def test_stat_file(self, mock_run):
        from tools.strings_tools import stat_file
        stat_file("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "stat" in cmd
