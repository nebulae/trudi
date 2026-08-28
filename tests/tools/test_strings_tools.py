"""Tests for tools/strings_tools.py."""
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.strings_tools.run", return_value=run_ok) as m:
        yield m


class TestStringsExtract:
    @pytest.fixture(autouse=True)
    def mock_path(self):
        with patch("tools.strings_tools.os.path.exists", return_value=True), \
             patch("core.paths.resolve_path_ci", side_effect=lambda p: (p, False)):
            yield

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
            strings_extract("/malware/sample.exe", output_path="/cases/example/evidence/strings.txt")

    def test_output_path_safe(self, mock_run, tmp_path):
        from tools.strings_tools import strings_extract
        out = str(tmp_path / "strings.txt")
        strings_extract("/malware/sample.exe", output_path=out)
        assert mock_run.called


class TestStringsGrep:
    @pytest.fixture(autouse=True)
    def mock_path(self):
        with patch("tools.strings_tools.os.path.exists", return_value=True), \
             patch("core.paths.resolve_path_ci", side_effect=lambda p: (p, False)):
            yield

    # strings_grep streams `strings` through Popen and filters line by line —
    # the executor's run()/OUTPUT_CAP is deliberately NOT in the path.
    def _popen(self, lines, returncode=0, stderr=""):
        import io
        from unittest.mock import MagicMock
        m = MagicMock()
        m.stdout = io.StringIO("\n".join(lines) + ("\n" if lines else ""))
        m.stderr = io.StringIO(stderr)
        m.returncode = returncode
        m.wait = MagicMock(return_value=returncode)
        m.kill = MagicMock()
        return m

    def test_grep_pattern(self, mock_run):
        from tools.strings_tools import strings_grep
        with patch("subprocess.Popen", return_value=self._popen(["http://evil.com", "ftp://also.evil"])), \
             patch("core.executor._log_tool"):
            r = strings_grep("/malware/sample.exe", "http")
        assert not mock_run.called
        assert r["success"] is True and r["complete"] is True and r["truncated"] is False
        assert r["match_count"] == 1 and r["matches"] == ["http://evil.com"]
        assert r["lines_scanned"] == 2

    def test_match_far_past_old_output_cap_is_found(self, mock_run):
        """Regression: the old implementation buffered all strings output
        through a 50 KB cap BEFORE filtering, so a match past the cap was
        silently lost and reported as match_count 0."""
        from tools.strings_tools import strings_grep
        filler = ["x" * 100] * 5000           # ~500 KB of non-matching strings
        with patch("subprocess.Popen", return_value=self._popen(filler + ["needle Jane Doe"])), \
             patch("core.executor._log_tool"):
            r = strings_grep("/img/disk.001", "needle")
        assert r["match_count"] == 1 and r["matches"] == ["needle Jane Doe"]
        assert r["complete"] is True and r["truncated"] is False

    def test_true_negative_is_complete_and_untruncated(self, mock_run):
        from tools.strings_tools import strings_grep
        with patch("subprocess.Popen", return_value=self._popen(["nothing", "here"])), \
             patch("core.executor._log_tool") as lt:
            r = strings_grep("/img/x.bin", "needle")
        assert r["match_count"] == 0 and r["complete"] is True and r["truncated"] is False
        assert lt.call_args[0][0]["truncated"] is False

    def test_match_cap_sets_truncated_but_counts_all(self, mock_run):
        from tools.strings_tools import strings_grep
        with patch("subprocess.Popen", return_value=self._popen([f"hit{i}" for i in range(20)])), \
             patch("core.executor._log_tool") as lt:
            r = strings_grep("/img/x.bin", "hit", max_matches=5)
        assert r["match_count"] == 20 and r["returned"] == 5 and len(r["matches"]) == 5
        assert r["truncated"] is True and r["complete"] is True and "note" in r
        assert lt.call_args[0][0]["truncated"] is True

    def test_nonzero_exit_is_incomplete(self, mock_run):
        from tools.strings_tools import strings_grep
        with patch("subprocess.Popen", return_value=self._popen(["a"], returncode=1, stderr="read error")), \
             patch("core.executor._log_tool"):
            r = strings_grep("/img/x.bin", "zzz")
        assert r["success"] is False and r["complete"] is False and r["truncated"] is True
        assert "hint" in r and "negative" in r["hint"]

    def test_invalid_regex(self, mock_run):
        from tools.strings_tools import strings_grep
        with patch("subprocess.Popen") as p:
            r = strings_grep("/img/x.bin", "(unclosed")
        assert r["success"] is False and "Invalid regex" in r["error"]
        p.assert_not_called()

    def test_spawn_failure(self, mock_run):
        from tools.strings_tools import strings_grep
        with patch("subprocess.Popen", side_effect=OSError("no strings binary")), \
             patch("core.executor._log_tool") as lt:
            r = strings_grep("/img/x.bin", "x")
        assert r["success"] is False and "spawn" in r["error"]
        lt.assert_called_once()


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
        # banner suppression so real metadata leads the stored excerpt
        assert "-q" in cmd and "--ExifToolVersion" in cmd

    def test_exiftool_batch(self, mock_run, tmp_path):
        from tools.strings_tools import exiftool_batch
        exiftool_batch(str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert "exiftool" in cmd and "-q" in cmd and "--ExifToolVersion" in cmd


class TestStat:
    def test_stat_file(self, mock_run):
        from tools.strings_tools import stat_file
        stat_file("/malware/sample.exe")
        cmd = mock_run.call_args[0][0]
        assert "stat" in cmd


class TestResolvePathCI:
    def test_missing_file_returns_error(self, tmp_path):
        from tools.strings_tools import strings_extract
        result = strings_extract(str(tmp_path / "nonexistent.exe"))
        assert result["success"] is False
        assert "not found" in result["error"]
        assert "dumpfiles" in result["hint"]

    def test_case_corrected_path_used(self, tmp_path):
        real = tmp_path / "Perfmon" / "p.exe"
        real.parent.mkdir()
        real.write_bytes(b"MZ\x00test string here!!")
        from tools.strings_tools import strings_extract
        result = strings_extract(str(tmp_path / "perfmon" / "p.exe"))
        assert result["success"] is True
        assert result["path_resolved"] is not None

    def test_stderr_in_response(self, mock_run, tmp_path):
        mock_run.return_value = {**mock_run.return_value, "success": False, "stderr": "binary error"}
        real = tmp_path / "sample.exe"
        real.write_bytes(b"data")
        from tools.strings_tools import strings_extract
        result = strings_extract(str(real))
        assert "stderr" in result


class TestFlossExtract:
    def test_floss_missing_binary(self, monkeypatch):
        from tools.strings_tools import floss_extract
        monkeypatch.setattr("tools.strings_tools.shutil.which", lambda name: None)
        r = floss_extract("/tmp/x.exe")
        assert r["success"] is False
        assert "flare-floss" in r["error"]

    def test_floss_invokes_binary(self, monkeypatch):
        from tools.strings_tools import floss_extract
        monkeypatch.setattr("tools.strings_tools.shutil.which", lambda name: "/usr/local/bin/floss")
        captured = {}
        monkeypatch.setattr("tools.strings_tools.run",
                            lambda cmd, **kw: captured.setdefault("cmd", cmd) or {"success": True})
        floss_extract("/tmp/x.exe", min_length=10)
        assert captured["cmd"][0] == "/usr/local/bin/floss"
        assert "-n" in captured["cmd"]
        assert "10" in captured["cmd"]
        assert "/tmp/x.exe" in captured["cmd"]

    def test_floss_refuses_evidence_output_path(self):
        from tools.strings_tools import floss_extract
        with pytest.raises(ValueError):
            floss_extract("/tmp/x.exe", output_path="/mnt/rd01/out.json")
