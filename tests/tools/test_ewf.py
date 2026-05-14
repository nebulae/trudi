"""Tests for tools/ewf.py."""
import pytest
from unittest.mock import patch, call


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.ewf.run", return_value=run_ok) as m:
        yield m


MMLS_OUTPUT = (
    "DOS Partition Table\n"
    "Offset Sector: 0\n"
    "Units are in 512-byte sectors\n"
    "\n"
    "      Slot      Start        End          Length       Description\n"
    "000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n"
    "001:  -------   0000000000   0000002047   0000002048   Unallocated\n"
    "002:  000:000   0000002048   0004194303   0004192256   NTFS (0x07)\n"
)


class TestEwfBasicTools:
    def test_ewf_info(self, mock_run):
        from tools.ewf import ewf_info
        ewf_info("/fake/image.E01")
        assert "ewfinfo" in mock_run.call_args[0][0]

    def test_ewf_verify(self, mock_run):
        from tools.ewf import ewf_verify
        ewf_verify("/fake/image.E01")
        assert "ewfverify" in mock_run.call_args[0][0]

    def test_ewf_mount(self, mock_run, tmp_path):
        from tools.ewf import ewf_mount
        ewf_mount("/fake/image.E01", str(tmp_path / "ewf"))
        assert "ewfmount" in mock_run.call_args[0][0]

    def test_ewf_umount(self, mock_run, tmp_path):
        from tools.ewf import ewf_umount
        ewf_umount(str(tmp_path / "ewf"))
        assert "umount" in mock_run.call_args[0][0]

    def test_umount_filesystem(self, mock_run, tmp_path):
        from tools.ewf import umount_filesystem
        umount_filesystem(str(tmp_path / "ntfs"))
        assert "umount" in mock_run.call_args[0][0]


class TestMountNtfs:
    def test_readonly_mounts(self, mock_run, tmp_path):
        from tools.ewf import mount_ntfs
        mount_ntfs("/mnt/ewf/ewf1", str(tmp_path / "ntfs"), offset_bytes=1048576)
        cmd = mock_run.call_args[0][0]
        assert "mount" in cmd
        assert any("ro" in x for x in cmd)

    def test_offset_in_options(self, mock_run, tmp_path):
        from tools.ewf import mount_ntfs
        mount_ntfs("/mnt/ewf/ewf1", str(tmp_path / "ntfs"), offset_bytes=2097152)
        cmd = mock_run.call_args[0][0]
        assert any("2097152" in x for x in cmd)

    def test_read_write_blocked(self):
        from tools.ewf import mount_ntfs
        r = mount_ntfs("/mnt/ewf/ewf1", "/tmp/ntfs", offset_bytes=0, read_only=False)
        assert r["success"] is False
        assert "Read-only" in r["stderr"]


class TestMountFullImage:
    def _ok(self, stdout=""):
        return {"success": True, "stdout": stdout, "stderr": "", "exit_code": 0, "truncated": False, "cmd": ""}

    def _fail(self, stderr="error"):
        return {"success": False, "stdout": "", "stderr": stderr, "exit_code": 1, "truncated": False, "cmd": ""}

    def test_success_path(self, tmp_path):
        from tools.ewf import mount_full_image
        ewf_mp = str(tmp_path / "ewf")
        fs_mp = str(tmp_path / "fs")
        side = [self._ok(), self._ok(MMLS_OUTPUT), self._ok()]
        with patch("tools.ewf.run", side_effect=side) as m:
            r = mount_full_image("/fake/image.E01", ewf_mp, fs_mp)
        assert r["success"] is True
        assert r["ntfs_offset_sectors"] == 2048
        assert r["ntfs_offset_bytes"] == 2048 * 512

    def test_ewfmount_failure_short_circuits(self, tmp_path):
        from tools.ewf import mount_full_image
        with patch("tools.ewf.run", return_value=self._fail("ewfmount: no device")):
            r = mount_full_image("/fake/image.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["success"] is False

    def test_mmls_failure_short_circuits(self, tmp_path):
        from tools.ewf import mount_full_image
        side = [self._ok(), self._fail("mmls: read error")]
        with patch("tools.ewf.run", side_effect=side):
            r = mount_full_image("/fake/image.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["success"] is False

    def test_no_ntfs_partition_detected(self, tmp_path):
        from tools.ewf import mount_full_image
        mmls_no_ntfs = "Slot  Start  End  Length  Description\n000  0  2047  2048  Linux\n"
        side = [self._ok(), self._ok(mmls_no_ntfs)]
        with patch("tools.ewf.run", side_effect=side):
            r = mount_full_image("/fake/image.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["success"] is False
        assert "NTFS" in r["stderr"]

    def test_ewf_device_path_constructed(self, tmp_path):
        from tools.ewf import mount_full_image
        ewf_mp = str(tmp_path / "ewf")
        side = [self._ok(), self._ok(MMLS_OUTPUT), self._ok()]
        with patch("tools.ewf.run", side_effect=side) as m:
            mount_full_image("/fake/image.E01", ewf_mp, str(tmp_path / "fs"))
        # Second call (mmls) should reference ewf_mp/ewf1
        mmls_cmd = m.call_args_list[1][0][0]
        assert "ewf1" in mmls_cmd[-1]
