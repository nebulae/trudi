"""Tests for tools/imaging.py."""
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.imaging.run", return_value=run_ok) as m:
        yield m


class TestVshadow:
    def test_vshadow_mount(self, mock_run, tmp_path):
        from tools.imaging import vshadow_mount
        vshadow_mount("/dev/sda1", str(tmp_path / "vss"))
        assert "vshadowmount" in mock_run.call_args[0][0]

    def test_vshadow_mount_probes_store_first(self, mock_run, tmp_path):
        from tools.imaging import vshadow_mount
        vshadow_mount("/dev/sda1", str(tmp_path / "vss"))
        first, last = mock_run.call_args_list[0][0][0], mock_run.call_args_list[-1][0][0]
        assert first[0] == "vshadowinfo"
        assert last[0] == "vshadowmount"

    def test_vshadow_mount_offset_and_allow_other(self, mock_run, tmp_path):
        """A whole-disk image needs -o <bytes>; the FUSE mount needs allow_other
        or every unprivileged follow-up (fls/fsstat/ls) gets Permission denied."""
        from tools.imaging import vshadow_mount
        r = vshadow_mount("/mnt/ewf_pc/ewf1", str(tmp_path / "vss"), offset=105906176)
        info_cmd = mock_run.call_args_list[0][0][0]
        mount_cmd = mock_run.call_args_list[-1][0][0]
        assert info_cmd[:3] == ["vshadowinfo", "-o", "105906176"]
        assert mount_cmd[:5] == ["vshadowmount", "-o", "105906176", "-X", "allow_other"]
        assert mount_cmd[-2:] == ["/mnt/ewf_pc/ewf1", str(tmp_path / "vss")]
        assert r["offset"] == 105906176 and r["allow_other"] is True

    def test_vshadow_mount_no_offset_no_allow_other(self, mock_run, tmp_path):
        from tools.imaging import vshadow_mount
        vshadow_mount("/dev/sda1", str(tmp_path / "vss"), allow_other=False)
        mount_cmd = mock_run.call_args_list[-1][0][0]
        assert "-o" not in mount_cmd and "-X" not in mount_cmd

    def test_vshadow_mount_refuses_silent_empty_mount(self, run_ok, tmp_path):
        """vshadowinfo reporting no store must FAIL the call with an offset hint —
        never leave an empty FUSE dir that looks mounted (cfreds-deepseek 2026-09-12)."""
        from tools.imaging import vshadow_mount
        no_store = {**run_ok, "stdout": "vshadowinfo 20240229\n\nNo Volume Shadow Snapshots found.\n"}
        with patch("tools.imaging.run", return_value=no_store) as m:
            r = vshadow_mount("/mnt/ewf_pc/ewf1", str(tmp_path / "vss"))
        assert r["success"] is False
        assert r["store_count"] == 0
        assert "offset=" in r["error"]
        assert all(c[0][0][0] != "vshadowmount" for c in m.call_args_list)

    def test_vshadow_mount_counts_stores(self, run_ok, tmp_path):
        from tools.imaging import vshadow_mount
        two = {**run_ok, "stdout": "Number of stores:\t2\n\nStore: 1\n\tCreation time: x\n\nStore: 2\n\tCreation time: y\n"}
        with patch("tools.imaging.run", return_value=two):
            r = vshadow_mount("/dev/sda1", str(tmp_path / "vss"))
        assert r["store_count"] == 2
        assert r["shadow_paths"] == [f"{tmp_path / 'vss'}/vss1", f"{tmp_path / 'vss'}/vss2"]

    def test_vshadow_list(self, mock_run, tmp_path):
        from tools.imaging import vshadow_list
        vshadow_list(str(tmp_path))
        assert "ls" in mock_run.call_args[0][0]

    def test_vshadow_umount(self, mock_run, tmp_path):
        from tools.imaging import vshadow_umount
        vshadow_umount(str(tmp_path / "vss"))
        assert "umount" in mock_run.call_args[0][0]


class TestBdeMout:
    def test_bde_mount_password(self, mock_run, tmp_path):
        from tools.imaging import bde_mount
        bde_mount("/evidence/bitlocker.img", str(tmp_path / "bde"), recovery_password="123456-789012")
        cmd = mock_run.call_args[0][0]
        assert "bdemount" in cmd
        assert "-r" in cmd

    def test_bde_mount_keyfile(self, mock_run, tmp_path):
        from tools.imaging import bde_mount
        bde_mount("/evidence/bitlocker.img", str(tmp_path / "bde"), recovery_key_file="/keys/key.bek")
        cmd = mock_run.call_args[0][0]
        assert "-k" in cmd

    def test_bde_info(self, mock_run):
        from tools.imaging import bde_info
        bde_info("/evidence/bitlocker.img")
        assert "bdeinfo" in mock_run.call_args[0][0]


class TestXmount:
    def test_xmount_image(self, mock_run, tmp_path):
        from tools.imaging import xmount_image
        xmount_image("/evidence/image.E01", str(tmp_path / "xmount"))
        cmd = mock_run.call_args[0][0]
        assert "xmount" in cmd
        assert "--in" in cmd
        assert "--out" in cmd

    def test_xmount_umount(self, mock_run, tmp_path):
        from tools.imaging import xmount_umount
        xmount_umount(str(tmp_path / "xmount"))
        assert "fusermount" in mock_run.call_args[0][0]


class TestPhotorec:
    def test_photorec_output_safe(self):
        from tools.imaging import photorec_carve
        with pytest.raises(Exception):
            photorec_carve("/evidence/image.E01", "/cases/example/evidence/carved")

    def test_photorec_allowed(self, mock_run, tmp_path):
        from tools.imaging import photorec_carve
        out = str(tmp_path / "carved")
        photorec_carve("/evidence/image.E01", out)
        cmd = mock_run.call_args[0][0]
        assert "photorec" in cmd

    def test_photorec_file_types(self, mock_run, tmp_path):
        from tools.imaging import photorec_carve
        out = str(tmp_path / "carved")
        photorec_carve("/evidence/image.E01", out, file_types="jpg,pdf")
        cmd = mock_run.call_args[0][0]
        assert "jpg" in " ".join(cmd)


class TestLosetup:
    def test_losetup_create(self, mock_run):
        from tools.imaging import losetup_create
        losetup_create("/evidence/image.img")
        cmd = mock_run.call_args[0][0]
        assert "losetup" in cmd
        assert "--show" in cmd

    def test_losetup_create_with_offset(self, mock_run):
        from tools.imaging import losetup_create
        losetup_create("/evidence/image.img", offset_bytes=1048576)
        cmd = mock_run.call_args[0][0]
        assert "-o" in cmd
        assert "1048576" in cmd

    def test_losetup_list(self, mock_run):
        from tools.imaging import losetup_list
        losetup_list()
        assert "losetup" in mock_run.call_args[0][0]

    def test_losetup_detach(self, mock_run):
        from tools.imaging import losetup_detach
        losetup_detach("/dev/loop0")
        cmd = mock_run.call_args[0][0]
        assert "losetup" in cmd
        assert "-d" in cmd
