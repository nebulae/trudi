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
        # ewfmount, mmls, fsstat probe of the candidate, mount
        side = [self._ok(), self._ok(MMLS_OUTPUT),
                self._ok("File System Type: NTFS\n"), self._ok()]
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
        # A real table whose only partition is not NTFS: fsstat says so, and the
        # refusal reports what was probed instead of guessing from the label.
        from tools.ewf import mount_full_image
        mmls_linux = MMLS_OUTPUT.replace("NTFS (0x07)", "Linux (0x83)")
        side = [self._ok(), self._ok(mmls_linux), self._ok("File System Type: Ext4\n")]
        with patch("tools.ewf.run", side_effect=side):
            r = mount_full_image("/fake/image.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["success"] is False
        assert "NTFS" in r["stderr"] and "Ext4" in r["stderr"]

    def test_unreadable_partition_table_is_reported(self, tmp_path):
        from tools.ewf import mount_full_image
        side = [self._ok(), self._ok("Slot  Start  End  Length  Description\n")]
        with patch("tools.ewf.run", side_effect=side):
            r = mount_full_image("/fake/image.E01", str(tmp_path / "ewf"), str(tmp_path / "fs"))
        assert r["success"] is False and "partition" in r["stderr"].lower()

    def test_ewf_device_path_constructed(self, tmp_path):
        from tools.ewf import mount_full_image
        ewf_mp = str(tmp_path / "ewf")
        side = [self._ok(), self._ok(MMLS_OUTPUT), self._ok()]
        with patch("tools.ewf.run", side_effect=side) as m:
            mount_full_image("/fake/image.E01", ewf_mp, str(tmp_path / "fs"))
        # Second call (mmls) should reference ewf_mp/ewf1
        mmls_cmd = m.call_args_list[1][0][0]
        assert "ewf1" in mmls_cmd[-1]


class TestMountOptionCompatibility:
    """Regression: ntfs-3g spells the journal-safety option `norecover`, not
    `norecovery`. The old spelling was rejected by the helper and surfaced as
    'wrong fs type, bad option, bad superblock', blocking every NTFS mount."""

    def test_options_use_correct_norecover_spelling(self, mock_run, tmp_path):
        from tools.ewf import mount_ntfs
        mount_ntfs("/mnt/ewf/ewf1", str(tmp_path / "ntfs"), offset_bytes=1048576)
        cmd = mock_run.call_args[0][0]
        assert any("norecover" in str(x) and "norecovery" not in str(x) for x in cmd), cmd

    def test_explicit_type_fallback_when_autodetect_fails(self, tmp_path):
        """On hosts with no kernel NTFS driver (WSL2), the bare `mount` fails;
        the helper must retry with `-t ntfs-3g`."""
        from tools.ewf import mount_ntfs
        ok = {"success": True, "stdout": "", "stderr": "", "exit_code": 0,
              "truncated": False, "cmd": ""}
        bad = {"success": False, "stdout": "", "stderr": "wrong fs type, bad option",
               "exit_code": 32, "truncated": False, "cmd": ""}
        with patch("tools.ewf.run", side_effect=[bad, ok]) as m, \
             patch("tools.ewf._lowntfs_available", return_value=False):
            r = mount_ntfs("/mnt/ewf/ewf1", str(tmp_path / "ntfs"), offset_bytes=345001984)
        assert r["success"] is True
        assert m.call_count == 2
        second_cmd = m.call_args_list[1][0][0]
        assert "-t" in second_cmd and "ntfs-3g" in second_cmd


class TestPartitionDetection:
    """Regression (VANKO-2016-DEEPSEEK41 run 2, 2026-09-20): a GPT table names
    no partition "NTFS", so description matching found nothing, mount_full_image
    returned "Could not detect NTFS partition", and the agent hand-derived an
    offset one sector off ("NTFS signature is missing")."""

    GPT = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
004:  000       0000002048   0000739327   0000737280   Basic data partition
007:  003       0001411072   0232294399   0230883328   Basic data partition
009:  005       0233216000   0244275199   0011059200   Basic data partition
"""

    def test_parses_gpt_rows_and_skips_meta(self):
        from tools.ewf import _mmls_partitions
        parts = _mmls_partitions(self.GPT)
        assert [p["start"] for p in parts][0] == 1411072      # largest first
        assert all(p["slot"][0].isdigit() for p in parts)     # no Meta/unallocated
        assert len(parts) == 3

    def test_sector_size_is_read_not_assumed(self):
        from tools.ewf import _mmls_sector_size
        assert _mmls_sector_size(self.GPT) == 512
        assert _mmls_sector_size(self.GPT.replace("512-byte", "4096-byte")) == 4096
        assert _mmls_sector_size("no units line") == 512

    def test_mount_full_image_probes_with_fsstat_and_mounts_that_offset(self, tmp_path):
        from tools.ewf import mount_full_image
        ok = {"success": True, "stdout": "", "stderr": "", "exit_code": 0,
              "truncated": False, "cmd": ""}
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[0] == "mmls":
                return {**ok, "stdout": self.GPT}
            if cmd[0] == "fsstat":
                # the first (largest) candidate is the Windows volume
                fs = "NTFS" if cmd[2] == "1411072" else "FAT32"
                return {**ok, "stdout": f"File System Type: {fs}\n"}
            return dict(ok)

        with patch("tools.ewf.run", side_effect=fake_run):
            r = mount_full_image("/ev/d.E01", str(tmp_path / "ewf"), str(tmp_path / "c"))
        assert r["success"] and r["ntfs_offset_sectors"] == 1411072
        assert r["ntfs_offset_bytes"] == 1411072 * 512
        assert any(c[0] == "mount" and f"offset={1411072 * 512}" in " ".join(c) for c in calls)

    def test_no_ntfs_anywhere_reports_what_was_probed(self, tmp_path):
        from tools.ewf import mount_full_image
        ok = {"success": True, "stdout": "", "stderr": "", "exit_code": 0,
              "truncated": False, "cmd": ""}

        def fake_run(cmd, **kw):
            if cmd[0] == "mmls":
                return {**ok, "stdout": self.GPT}
            if cmd[0] == "fsstat":
                return {**ok, "stdout": "File System Type: Ext4\n"}
            return dict(ok)

        with patch("tools.ewf.run", side_effect=fake_run):
            r = mount_full_image("/ev/d.E01", str(tmp_path / "ewf"), str(tmp_path / "c"))
        assert r["success"] is False
        assert "Ext4" in r["stderr"] and "1411072" in r["stderr"]
        assert len(r["partitions"]) == 3


class TestCaseInsensitiveMount:
    """Regression: ntfs-3g is case-sensitive, so Windows/AppCompat/Programs/
    Amcache.hve missed the on-disk Windows/appcompat and read as absent."""

    _ok = {"success": True, "stdout": "", "stderr": "", "exit_code": 0,
           "truncated": False, "cmd": ""}
    _bad = {"success": False, "stdout": "", "stderr": "unknown filesystem type",
            "exit_code": 32, "truncated": False, "cmd": ""}

    def test_lowntfs_ignore_case_tried_first(self, tmp_path):
        from tools.ewf import mount_ntfs
        with patch("tools.ewf.run", return_value=dict(self._ok)) as m, \
             patch("tools.ewf._lowntfs_available", return_value=True):
            r = mount_ntfs("/mnt/ewf/ewf1", str(tmp_path / "ntfs"), offset_bytes=1048576)
        assert m.call_count == 1 and r["case_insensitive"] is True
        cmd = m.call_args[0][0]
        assert cmd[:3] == ["mount", "-t", "lowntfs-3g"]
        opts = cmd[cmd.index("-o") + 1].split(",")
        assert {"ro", "loop", "norecover", "ignore_case", "offset=1048576"} <= set(opts)
        assert m.call_args[1]["needs_sudo"] is True

    def test_falls_back_to_case_sensitive_chain(self, tmp_path):
        from tools.ewf import mount_ntfs
        with patch("tools.ewf.run", side_effect=[dict(self._bad), dict(self._bad),
                                                 dict(self._ok)]) as m, \
             patch("tools.ewf._lowntfs_available", return_value=True):
            r = mount_ntfs("/mnt/ewf/ewf1", str(tmp_path / "ntfs"), offset_bytes=0)
        assert r["success"] is True and r["case_insensitive"] is False
        assert "path_case_note" in r and r["lowntfs_attempt_stderr"]
        assert m.call_args_list[2][0][0][:3] == ["mount", "-t", "ntfs-3g"]
        assert all("ro" in c[0][0][c[0][0].index("-o") + 1].split(",")
                   for c in m.call_args_list)

    def test_lowntfs_absent_uses_current_command(self, tmp_path):
        from tools.ewf import mount_ntfs
        with patch("tools.ewf.run", return_value=dict(self._ok)) as m, \
             patch("tools.ewf._lowntfs_available", return_value=False):
            mount_ntfs("/mnt/ewf/ewf1", str(tmp_path / "ntfs"), offset_bytes=0)
        assert m.call_args[0][0][:2] == ["mount", "-o"]
