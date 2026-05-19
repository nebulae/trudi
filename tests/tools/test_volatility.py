"""Tests for tools/volatility.py — verifies -s symbol path flag on every call."""
import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock


IMG = "/fake/memory.img"


def get_cmd(mock_run):
    return mock_run.call_args[0][0]


def make_mock_ctx():
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


@pytest.fixture(autouse=True)
def mock_run(run_ok):
    with patch("tools.volatility.run", return_value=run_ok) as m:
        yield m


@pytest.fixture()
def mock_run_progress(run_ok):
    """Fixture for async tools that use run_with_progress instead of run."""
    with patch("tools.volatility.run_with_progress", new_callable=AsyncMock, return_value=run_ok) as m:
        yield m


def run_async(coro):
    """Helper to run a coroutine in sync test context."""
    return asyncio.get_event_loop().run_until_complete(coro)


class TestSymbolPathFlag:
    """Critical: every vol call must pass -s <symbols_dir>."""

    def test_vol_info_has_symbol_flag(self, mock_run):
        from tools.volatility import vol_info
        vol_info(IMG)
        cmd = get_cmd(mock_run)
        assert "-s" in cmd

    def test_vol_psscan_has_symbol_flag(self, mock_run, mock_run_progress):
        from tools.volatility import vol_psscan
        run_async(vol_psscan(IMG, make_mock_ctx()))
        cmd = mock_run_progress.call_args[0][0]
        assert "-s" in cmd

    def test_symbol_path_is_not_opt_volatility3(self, mock_run, mock_run_progress):
        from tools.volatility import vol_psscan
        run_async(vol_psscan(IMG, make_mock_ctx()))
        cmd = mock_run_progress.call_args[0][0]
        s_idx = cmd.index("-s")
        sym_path = cmd[s_idx + 1]
        assert not sym_path.startswith("/opt/volatility3")


class TestVolSymbolCheck:
    def test_nonexistent_image_returns_failure(self, mock_run):
        from tools.volatility import vol_symbol_check
        r = vol_symbol_check("/nonexistent/path/image.img")
        assert r["success"] is False
        assert r["symbols_ready"] is False
        assert "not found" in r["note"].lower()
        assert mock_run.call_count == 0  # no subprocess spawned

    def test_tilde_path_nonexistent_returns_failure(self, mock_run):
        from tools.volatility import vol_symbol_check
        r = vol_symbol_check("~/nonexistent_image_xyz_abc.img")
        assert r["success"] is False
        assert "~" not in r["note"] or r["success"] is False  # expanded path in note

    def test_existing_image_returns_expanded_path(self, mock_run, tmp_path):
        from tools.volatility import vol_symbol_check
        img = tmp_path / "memory.img"
        img.write_bytes(b"\x00" * 1024)
        r = vol_symbol_check(str(img))
        assert r["success"] is True
        assert r["image"] == str(img)

    def test_existing_image_with_tilde_returns_expanded_path(self, mock_run):
        from unittest.mock import patch
        from tools.volatility import vol_symbol_check
        expanded = "/home/trin/cases/memory.img"
        with patch("tools.volatility.os.path.expanduser", return_value=expanded), \
             patch("tools.volatility.os.path.exists", return_value=True):
            r = vol_symbol_check("~/cases/memory.img")
        assert r["success"] is True
        assert r["image"] == expanded  # resolved path, not tilde path
        assert "~" not in r["image"]


class TestProcessPlugins:
    def test_vol_pslist(self, mock_run, mock_run_progress):
        from tools.volatility import vol_pslist
        run_async(vol_pslist(IMG, make_mock_ctx()))
        assert "windows.pslist" in mock_run_progress.call_args[0][0]

    def test_vol_pslist_with_pid(self, mock_run):
        # pid-filtered pslist uses sync run() — fast path, no ctx needed
        from tools.volatility import vol_pslist
        run_async(vol_pslist(IMG, make_mock_ctx(), pid=1234))
        cmd = get_cmd(mock_run)
        assert "--pid" in cmd
        assert "1234" in cmd

    def test_vol_psscan(self, mock_run, mock_run_progress):
        from tools.volatility import vol_psscan
        run_async(vol_psscan(IMG, make_mock_ctx()))
        assert "windows.psscan" in mock_run_progress.call_args[0][0]

    def test_vol_pstree(self, mock_run):
        from tools.volatility import vol_pstree
        vol_pstree(IMG)
        assert "windows.pstree" in get_cmd(mock_run)

    def test_vol_psxview(self, mock_run):
        from tools.volatility import vol_psxview
        vol_psxview(IMG)
        assert "windows.psxview" in get_cmd(mock_run)

    def test_vol_cmdline(self, mock_run):
        from tools.volatility import vol_cmdline
        vol_cmdline(IMG)
        assert "windows.cmdline" in get_cmd(mock_run)

    def test_vol_cmdline_with_pid(self, mock_run):
        from tools.volatility import vol_cmdline
        vol_cmdline(IMG, pid=888)
        assert "--pid" in get_cmd(mock_run)

    def test_vol_envars(self, mock_run):
        from tools.volatility import vol_envars
        vol_envars(IMG)
        assert "windows.envars" in get_cmd(mock_run)

    def test_vol_envars_with_pid(self, mock_run):
        from tools.volatility import vol_envars
        vol_envars(IMG, pid=42)
        cmd = get_cmd(mock_run)
        assert "--pid" in cmd
        assert "42" in cmd

    def test_vol_getsids(self, mock_run):
        from tools.volatility import vol_getsids
        vol_getsids(IMG)
        assert "windows.getsids" in get_cmd(mock_run)

    def test_vol_privileges(self, mock_run):
        from tools.volatility import vol_privileges
        vol_privileges(IMG)
        assert "windows.privileges" in get_cmd(mock_run)

    def test_vol_dlllist(self, mock_run):
        from tools.volatility import vol_dlllist
        vol_dlllist(IMG)
        assert "windows.dlllist" in get_cmd(mock_run)

    def test_vol_dlllist_with_pid(self, mock_run):
        from tools.volatility import vol_dlllist
        vol_dlllist(IMG, pid=500)
        assert "--pid" in get_cmd(mock_run)

    def test_vol_handles(self, mock_run):
        from tools.volatility import vol_handles
        vol_handles(IMG)
        assert "windows.handles" in get_cmd(mock_run)

    def test_vol_handles_with_pid_and_type(self, mock_run):
        from tools.volatility import vol_handles
        vol_handles(IMG, pid=100, object_type="File")
        cmd = get_cmd(mock_run)
        assert "--pid" in cmd
        assert "--object-type" in cmd
        assert "File" in cmd

    def test_vol_ldrmodules(self, mock_run):
        from tools.volatility import vol_ldrmodules
        vol_ldrmodules(IMG)
        assert "windows.ldrmodules" in get_cmd(mock_run)

    def test_vol_sessions(self, mock_run):
        from tools.volatility import vol_sessions
        vol_sessions(IMG)
        assert "windows.sessions" in get_cmd(mock_run)


class TestServicePlugins:
    def test_vol_svcscan(self, mock_run):
        from tools.volatility import vol_svcscan
        vol_svcscan(IMG)
        assert "windows.svcscan" in get_cmd(mock_run)

    def test_vol_svclist(self, mock_run):
        from tools.volatility import vol_svclist
        vol_svclist(IMG)
        assert "windows.svclist" in get_cmd(mock_run)

    def test_vol_svcdiff(self, mock_run):
        from tools.volatility import vol_svcdiff
        vol_svcdiff(IMG)
        assert "windows.svcdiff" in get_cmd(mock_run)


class TestNetworkPlugins:
    def test_vol_netstat(self, mock_run, mock_run_progress):
        from tools.volatility import vol_netstat
        run_async(vol_netstat(IMG, make_mock_ctx()))
        assert "windows.netstat" in mock_run_progress.call_args[0][0]

    def test_vol_netscan(self, mock_run, mock_run_progress):
        from tools.volatility import vol_netscan
        run_async(vol_netscan(IMG, make_mock_ctx()))
        assert "windows.netscan" in mock_run_progress.call_args[0][0]


class TestRegistryPlugins:
    def test_vol_hivelist(self, mock_run):
        from tools.volatility import vol_registry_hivelist
        vol_registry_hivelist(IMG)
        assert any("registry.hivelist" in x for x in get_cmd(mock_run))

    def test_vol_hivescan(self, mock_run):
        from tools.volatility import vol_registry_hivescan
        vol_registry_hivescan(IMG)
        assert any("registry.hivescan" in x for x in get_cmd(mock_run))

    def test_vol_printkey(self, mock_run):
        from tools.volatility import vol_registry_printkey
        vol_registry_printkey(IMG, key="SOFTWARE\\Microsoft\\Windows")
        cmd = get_cmd(mock_run)
        assert any("registry.printkey" in x for x in cmd)
        assert "--key" in cmd

    def test_vol_printkey_with_offset(self, mock_run):
        from tools.volatility import vol_registry_printkey
        vol_registry_printkey(IMG, key="Run", hive_offset="0xdeadbeef")
        cmd = get_cmd(mock_run)
        assert "--offset" in cmd
        assert "0xdeadbeef" in cmd

    def test_vol_userassist(self, mock_run):
        from tools.volatility import vol_userassist
        vol_userassist(IMG)
        assert any("userassist" in x for x in get_cmd(mock_run))

    def test_vol_registry_amcache(self, mock_run):
        from tools.volatility import vol_registry_amcache
        vol_registry_amcache(IMG)
        assert any("amcache" in x for x in get_cmd(mock_run))

    def test_vol_scheduled_tasks(self, mock_run):
        from tools.volatility import vol_scheduled_tasks
        vol_scheduled_tasks(IMG)
        assert any("scheduled_tasks" in x for x in get_cmd(mock_run))


class TestMalfindAndInjection:
    def test_vol_malfind_basic(self, mock_run):
        from tools.volatility import vol_malfind
        vol_malfind(IMG)
        assert "windows.malfind" in get_cmd(mock_run)

    def test_vol_malfind_with_pid(self, mock_run):
        from tools.volatility import vol_malfind
        vol_malfind(IMG, pid=1234)
        assert "--pid" in get_cmd(mock_run)

    def test_vol_malfind_with_dump(self, mock_run, tmp_path):
        from tools.volatility import vol_malfind
        out = str(tmp_path / "dumps")
        vol_malfind(IMG, dump=True, output_dir=out)
        cmd = get_cmd(mock_run)
        # -o must appear BEFORE the plugin name
        assert "-o" in cmd
        assert "--output-dir" not in cmd
        o_idx = cmd.index("-o")
        plugin_idx = cmd.index("windows.malfind")
        assert o_idx < plugin_idx
        # --dump is a plugin flag and must appear AFTER the plugin name
        assert "--dump" in cmd
        assert cmd.index("--dump") > plugin_idx

    def test_vol_malfind_evidence_output_blocked(self, mock_run):
        from tools.volatility import vol_malfind
        with pytest.raises(ValueError, match="protected evidence"):
            vol_malfind(IMG, dump=True, output_dir="/mnt/evidence/dumps")

    def test_vol_vadinfo(self, mock_run):
        from tools.volatility import vol_vadinfo
        vol_vadinfo(IMG)
        assert "windows.vadinfo" in get_cmd(mock_run)

    def test_vol_vadinfo_with_pid(self, mock_run):
        from tools.volatility import vol_vadinfo
        vol_vadinfo(IMG, pid=99)
        assert "--pid" in get_cmd(mock_run)

    def test_vol_vadwalk(self, mock_run):
        from tools.volatility import vol_vadwalk
        vol_vadwalk(IMG)
        assert "windows.vadwalk" in get_cmd(mock_run)

    def test_vol_hollowprocesses(self, mock_run):
        from tools.volatility import vol_hollowprocesses
        vol_hollowprocesses(IMG)
        assert "windows.hollowprocesses" in get_cmd(mock_run)

    def test_vol_pebmasquerade(self, mock_run):
        from tools.volatility import vol_pebmasquerade
        vol_pebmasquerade(IMG)
        assert any("pebmasquerade" in x for x in get_cmd(mock_run))

    def test_vol_suspicious_threads(self, mock_run):
        from tools.volatility import vol_suspicious_threads
        vol_suspicious_threads(IMG)
        assert "windows.suspicious_threads" in get_cmd(mock_run)

    def test_vol_vadyarascan(self, mock_run):
        from tools.volatility import vol_vadyarascan
        vol_vadyarascan(IMG, "rules/test.yar")
        cmd = get_cmd(mock_run)
        assert "windows.vadyarascan" in cmd
        assert "--yara-rules" in cmd

    def test_vol_vadyarascan_with_pid(self, mock_run):
        from tools.volatility import vol_vadyarascan
        vol_vadyarascan(IMG, "rules/test.yar", pid=777)
        assert "--pid" in get_cmd(mock_run)

    def test_vol_cmdscanner(self, mock_run):
        from tools.volatility import vol_cmdscanner
        vol_cmdscanner(IMG)
        assert "windows.cmdscan" in get_cmd(mock_run)

    def test_vol_consoles(self, mock_run):
        from tools.volatility import vol_consoles
        vol_consoles(IMG)
        assert "windows.consoles" in get_cmd(mock_run)


class TestKernelPlugins:
    def test_vol_modules(self, mock_run):
        from tools.volatility import vol_modules
        vol_modules(IMG)
        assert "windows.modules" in get_cmd(mock_run)

    def test_vol_modscan(self, mock_run):
        from tools.volatility import vol_modscan
        vol_modscan(IMG)
        assert "windows.modscan" in get_cmd(mock_run)

    def test_vol_driverscan(self, mock_run):
        from tools.volatility import vol_driverscan
        vol_driverscan(IMG)
        assert "windows.driverscan" in get_cmd(mock_run)

    def test_vol_driverirp(self, mock_run):
        from tools.volatility import vol_driverirp
        vol_driverirp(IMG)
        assert "windows.driverirp" in get_cmd(mock_run)

    def test_vol_devicetree(self, mock_run):
        from tools.volatility import vol_devicetree
        vol_devicetree(IMG)
        assert "windows.devicetree" in get_cmd(mock_run)

    def test_vol_callbacks(self, mock_run):
        from tools.volatility import vol_callbacks
        vol_callbacks(IMG)
        assert "windows.callbacks" in get_cmd(mock_run)

    def test_vol_ssdt(self, mock_run):
        from tools.volatility import vol_ssdt
        vol_ssdt(IMG)
        assert "windows.ssdt" in get_cmd(mock_run)

    def test_vol_unhooked_system_calls(self, mock_run):
        from tools.volatility import vol_unhooked_system_calls
        vol_unhooked_system_calls(IMG)
        assert "windows.unhooked_system_calls" in get_cmd(mock_run)


class TestFilesystemPlugins:
    def test_vol_filescan(self, mock_run, mock_run_progress):
        from tools.volatility import vol_filescan
        run_async(vol_filescan(IMG, make_mock_ctx()))
        assert "windows.filescan" in mock_run_progress.call_args[0][0]

    def test_vol_dumpfiles_no_output_dir(self):
        from tools.volatility import vol_dumpfiles
        r = vol_dumpfiles(IMG)
        assert r["success"] is False

    def test_vol_dumpfiles_with_output(self, mock_run, tmp_path):
        from tools.volatility import vol_dumpfiles
        vol_dumpfiles(IMG, virt_addr="0xdeadbeef", output_dir=str(tmp_path))
        cmd = get_cmd(mock_run)
        assert "windows.dumpfiles" in cmd
        assert "--virtaddr" in cmd
        assert "-o" in cmd
        assert "--output-dir" not in cmd
        assert cmd.index("-o") < cmd.index("windows.dumpfiles")

    def test_vol_dumpfiles_evidence_blocked(self):
        from tools.volatility import vol_dumpfiles
        with pytest.raises(ValueError, match="protected evidence"):
            vol_dumpfiles(IMG, output_dir="/mnt/evidence/out")

    def test_vol_dumpfiles_with_pid(self, mock_run, tmp_path):
        from tools.volatility import vol_dumpfiles
        vol_dumpfiles(IMG, pid=123, output_dir=str(tmp_path))
        assert "--pid" in get_cmd(mock_run)

    def test_vol_mftscan(self, mock_run):
        from tools.volatility import vol_mftscan
        vol_mftscan(IMG)
        assert "windows.mftscan" in get_cmd(mock_run)

    def test_vol_memmap(self, mock_run):
        from tools.volatility import vol_memmap
        vol_memmap(IMG, pid=42)
        cmd = get_cmd(mock_run)
        assert "windows.memmap" in cmd
        assert "--pid" in cmd

    def test_vol_memmap_dump(self, mock_run, tmp_path):
        from tools.volatility import vol_memmap
        vol_memmap(IMG, pid=42, dump=True, output_dir=str(tmp_path))
        cmd = get_cmd(mock_run)
        assert "--dump" in cmd
        assert "-o" in cmd
        assert "--output-dir" not in cmd
        assert cmd.index("-o") < cmd.index("windows.memmap")

    def test_vol_memmap_evidence_blocked(self):
        from tools.volatility import vol_memmap
        with pytest.raises(ValueError, match="protected evidence"):
            vol_memmap(IMG, pid=42, dump=True, output_dir="/mnt/evidence/out")


class TestExecutionArtifacts:
    def test_vol_amcache(self, mock_run):
        from tools.volatility import vol_amcache
        vol_amcache(IMG)
        assert "windows.amcache" in get_cmd(mock_run)

    def test_vol_shimcachemem(self, mock_run):
        from tools.volatility import vol_shimcachemem
        vol_shimcachemem(IMG)
        assert "windows.shimcachemem" in get_cmd(mock_run)


class TestCredentialPlugins:
    def test_vol_hashdump(self, mock_run):
        from tools.volatility import vol_hashdump
        vol_hashdump(IMG)
        assert "windows.hashdump" in get_cmd(mock_run)

    def test_vol_cachedump(self, mock_run):
        from tools.volatility import vol_cachedump
        vol_cachedump(IMG)
        assert "windows.cachedump" in get_cmd(mock_run)

    def test_vol_lsadump(self, mock_run):
        from tools.volatility import vol_lsadump
        vol_lsadump(IMG)
        assert "windows.lsadump" in get_cmd(mock_run)


class TestMiscWindowsPlugins:
    def test_vol_mutantscan(self, mock_run):
        from tools.volatility import vol_mutantscan
        vol_mutantscan(IMG)
        assert "windows.mutantscan" in get_cmd(mock_run)

    def test_vol_symlinkscan(self, mock_run):
        from tools.volatility import vol_symlinkscan
        vol_symlinkscan(IMG)
        assert "windows.symlinkscan" in get_cmd(mock_run)

    def test_vol_thrdscan(self, mock_run):
        from tools.volatility import vol_thrdscan
        vol_thrdscan(IMG)
        assert "windows.thrdscan" in get_cmd(mock_run)

    def test_vol_timeliner(self, mock_run):
        from tools.volatility import vol_timeliner
        vol_timeliner(IMG)
        assert "timeliner" in get_cmd(mock_run)

    def test_vol_timeliner_with_output(self, mock_run, tmp_path):
        from tools.volatility import vol_timeliner
        vol_timeliner(IMG, output_dir=str(tmp_path))
        cmd = get_cmd(mock_run)
        assert "-o" in cmd
        assert "--output-dir" not in cmd
        assert cmd.index("-o") < cmd.index("timeliner")

    def test_vol_timeliner_evidence_blocked(self):
        from tools.volatility import vol_timeliner
        with pytest.raises(ValueError, match="protected evidence"):
            vol_timeliner(IMG, output_dir="/mnt/evidence/timeline")

    def test_vol_yarascan(self, mock_run):
        from tools.volatility import vol_yarascan
        vol_yarascan(IMG, "rules/test.yar")
        cmd = get_cmd(mock_run)
        assert "windows.yarascan" in cmd
        assert "--yara-rules" in cmd

    def test_vol_yarascan_with_pid(self, mock_run):
        from tools.volatility import vol_yarascan
        vol_yarascan(IMG, "rules/test.yar", pid=555)
        assert "--pid" in get_cmd(mock_run)


class TestLinuxPlugins:
    def test_vol_linux_pslist(self, mock_run):
        from tools.volatility import vol_linux_pslist
        vol_linux_pslist(IMG)
        assert "linux.pslist" in get_cmd(mock_run)

    def test_vol_linux_psscan(self, mock_run):
        from tools.volatility import vol_linux_psscan
        vol_linux_psscan(IMG)
        assert "linux.psscan" in get_cmd(mock_run)

    def test_vol_linux_pstree(self, mock_run):
        from tools.volatility import vol_linux_pstree
        vol_linux_pstree(IMG)
        assert "linux.pstree" in get_cmd(mock_run)

    def test_vol_linux_netstat(self, mock_run):
        from tools.volatility import vol_linux_netstat
        vol_linux_netstat(IMG)
        assert "linux.ip" in get_cmd(mock_run)

    def test_vol_linux_lsof(self, mock_run):
        from tools.volatility import vol_linux_lsof
        vol_linux_lsof(IMG)
        assert "linux.lsof" in get_cmd(mock_run)

    def test_vol_linux_lsof_with_pid(self, mock_run):
        from tools.volatility import vol_linux_lsof
        vol_linux_lsof(IMG, pid=1)
        assert "--pid" in get_cmd(mock_run)

    def test_vol_linux_malfind(self, mock_run):
        from tools.volatility import vol_linux_malfind
        vol_linux_malfind(IMG)
        assert "linux.malfind" in get_cmd(mock_run)

    def test_vol_linux_lsmod(self, mock_run):
        from tools.volatility import vol_linux_lsmod
        vol_linux_lsmod(IMG)
        assert "linux.lsmod" in get_cmd(mock_run)

    def test_vol_linux_check_modules(self, mock_run):
        from tools.volatility import vol_linux_check_modules
        vol_linux_check_modules(IMG)
        assert "linux.check_modules" in get_cmd(mock_run)


class TestImageArg:
    def test_image_path_in_cmd(self, mock_run, mock_run_progress):
        from tools.volatility import vol_psscan
        run_async(vol_psscan("/fake/evidence.img", make_mock_ctx()))
        assert "/fake/evidence.img" in mock_run_progress.call_args[0][0]

    def test_json_renderer_flag(self, mock_run, mock_run_progress):
        from tools.volatility import vol_pslist
        run_async(vol_pslist(IMG, make_mock_ctx()))
        cmd = mock_run_progress.call_args[0][0]
        assert "-r" in cmd
        assert "json" in cmd
