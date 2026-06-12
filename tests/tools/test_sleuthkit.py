"""Tests for tools/sleuthkit.py."""
import pytest
from unittest.mock import patch, MagicMock
import subprocess

IMG = "/mnt/ewf/ewf1"


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.sleuthkit.run", return_value=run_ok) as m:
        yield m


class TestPartitionTools:
    def test_tsk_mmls(self, mock_run):
        from tools.sleuthkit import tsk_mmls
        tsk_mmls(IMG)
        assert "mmls" in mock_run.call_args[0][0]

    def test_tsk_mmstat(self, mock_run):
        from tools.sleuthkit import tsk_mmstat
        tsk_mmstat(IMG)
        assert "mmstat" in mock_run.call_args[0][0]

    def test_tsk_mmcat(self, mock_run):
        from tools.sleuthkit import tsk_mmcat
        tsk_mmcat(IMG, 1)
        cmd = mock_run.call_args[0][0]
        assert "mmcat" in cmd
        assert "1" in cmd


class TestFilesystemTools:
    def test_tsk_fsstat(self, mock_run):
        from tools.sleuthkit import tsk_fsstat
        tsk_fsstat(IMG)
        assert "fsstat" in mock_run.call_args[0][0]

    def test_tsk_fsstat_with_offset(self, mock_run):
        from tools.sleuthkit import tsk_fsstat
        tsk_fsstat(IMG, offset_sectors=2048)
        cmd = mock_run.call_args[0][0]
        assert "-o" in cmd
        assert "2048" in cmd

    def test_tsk_fls_recursive(self, mock_run):
        from tools.sleuthkit import tsk_fls
        tsk_fls(IMG, recursive=True)
        cmd = mock_run.call_args[0][0]
        assert "fls" in cmd
        assert "-r" in cmd

    def test_tsk_fls_bodyfile(self, mock_run):
        from tools.sleuthkit import tsk_fls
        tsk_fls(IMG, bodyfile=True)
        cmd = mock_run.call_args[0][0]
        assert "-m" in cmd

    def test_tsk_fls_deleted_only(self, mock_run):
        from tools.sleuthkit import tsk_fls
        tsk_fls(IMG, deleted_only=True)
        cmd = mock_run.call_args[0][0]
        assert "-d" in cmd


class TestInodeTools:
    def test_tsk_istat(self, mock_run):
        from tools.sleuthkit import tsk_istat
        tsk_istat(IMG, 42)
        cmd = mock_run.call_args[0][0]
        assert "istat" in cmd
        assert "42" in cmd

    def test_tsk_ils_orphan(self, mock_run):
        from tools.sleuthkit import tsk_ils
        tsk_ils(IMG, orphan_only=True)
        cmd = mock_run.call_args[0][0]
        assert "-p" in cmd

    def test_tsk_ffind(self, mock_run):
        from tools.sleuthkit import tsk_ffind
        tsk_ffind(IMG, 99)
        cmd = mock_run.call_args[0][0]
        assert "ffind" in cmd
        assert "99" in cmd


class TestIcatOutputSafety:
    def test_icat_blocked_on_evidence_path(self):
        from tools.sleuthkit import tsk_icat
        with pytest.raises(ValueError, match="protected evidence"):
            tsk_icat(IMG, "42", "/cases/example/evidence/out.bin")

    def test_icat_allowed_on_safe_path(self, tmp_path):
        from tools.sleuthkit import tsk_icat
        out = str(tmp_path / "extracted.bin")
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(
                returncode=0, stdout=b"data", stderr=b""
            )
            r = tsk_icat(IMG, "42", out)
        assert r["success"] is True


class TestBlockTools:
    def test_tsk_blkcat(self, mock_run):
        from tools.sleuthkit import tsk_blkcat
        tsk_blkcat(IMG, 1024)
        cmd = mock_run.call_args[0][0]
        assert "blkcat" in cmd
        assert "1024" in cmd

    def test_tsk_blkstat(self, mock_run):
        from tools.sleuthkit import tsk_blkstat
        tsk_blkstat(IMG, 512)
        assert "blkstat" in mock_run.call_args[0][0]

    def test_tsk_blkcalc(self, mock_run):
        from tools.sleuthkit import tsk_blkcalc
        tsk_blkcalc(IMG, 512)
        assert "blkcalc" in mock_run.call_args[0][0]

    def test_tsk_blkls_output_safe(self, mock_run):
        from tools.sleuthkit import tsk_blkls
        with pytest.raises(ValueError, match="protected evidence"):
            tsk_blkls(IMG, "/cases/example/evidence/blocks.raw")

    def test_tsk_blkls_allowed(self, tmp_path, mock_run):
        from tools.sleuthkit import tsk_blkls
        out = str(tmp_path / "blocks.raw")
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            tsk_blkls(IMG, out)


class TestTimelineTools:
    def test_tsk_mactime_basic(self, mock_run):
        from tools.sleuthkit import tsk_mactime
        tsk_mactime("bodyfile.txt")
        cmd = mock_run.call_args[0][0]
        assert "mactime" in cmd
        assert "-z" in cmd
        assert "UTC" in cmd

    def test_tsk_mactime_csv(self, mock_run):
        from tools.sleuthkit import tsk_mactime
        tsk_mactime("bodyfile.txt", csv_output=True)
        assert "-d" in mock_run.call_args[0][0]

    def test_tsk_mactime_date_filter(self, mock_run):
        from tools.sleuthkit import tsk_mactime
        tsk_mactime("bodyfile.txt", start_date="2018-01-01", end_date="2018-12-31")
        cmd = mock_run.call_args[0][0]
        assert "2018-01-01" in cmd


class TestHashAndSignatureTools:
    def test_tsk_hfind(self, mock_run):
        from tools.sleuthkit import tsk_hfind
        tsk_hfind("hashdb.txt", "deadbeef")
        cmd = mock_run.call_args[0][0]
        assert "hfind" in cmd
        assert "deadbeef" in cmd

    def test_tsk_sigfind(self, mock_run):
        from tools.sleuthkit import tsk_sigfind
        tsk_sigfind(IMG, "4D5A")
        cmd = mock_run.call_args[0][0]
        assert "sigfind" in cmd
        assert "4D5A" in cmd


class TestJournalTools:
    def test_tsk_jls(self, mock_run):
        from tools.sleuthkit import tsk_jls
        tsk_jls(IMG)
        assert "jls" in mock_run.call_args[0][0]

    def test_tsk_jcat(self, mock_run):
        from tools.sleuthkit import tsk_jcat
        tsk_jcat(IMG, 5)
        cmd = mock_run.call_args[0][0]
        assert "jcat" in cmd
        assert "5" in cmd


class TestTskIndxparse:
    def test_indxparse_invokes_binary(self, mock_run):
        from tools.sleuthkit import tsk_indxparse
        tsk_indxparse("/tmp/mft.bin")
        cmd = mock_run.call_args[0][0]
        assert "INDXParse.py" in cmd[0]
        assert "/tmp/mft.bin" in cmd

    def test_indxparse_refuses_evidence_output(self):
        from tools.sleuthkit import tsk_indxparse
        with pytest.raises(ValueError):
            tsk_indxparse("/tmp/mft.bin", output_path="/mnt/rd01/dump.txt")

    def test_indxparse_writes_output(self, mock_run, tmp_path):
        from tools.sleuthkit import tsk_indxparse
        mock_run.return_value = {**mock_run.return_value, "success": True, "stdout": "indx data"}
        out_dir = tmp_path / "analysis"
        out_dir.mkdir()
        out = out_dir / "indx.txt"
        tsk_indxparse("/tmp/mft.bin", output_path=str(out))
        assert out.read_text() == "indx data"
