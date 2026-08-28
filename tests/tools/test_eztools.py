"""Tests for tools/eztools.py — Zimmerman .NET tools."""
import pytest
from unittest.mock import patch


@pytest.fixture(autouse=True)
def mock_dotnet(run_ok):
    with patch("tools.eztools.run_dotnet", return_value=run_ok) as m:
        yield m


class TestMftEcmd:
    def test_mftecmd_basic(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_mftecmd
        ez_mftecmd("/mnt/wkstn01/$MFT", str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert "-f" in args
        assert "--csv" in args

    def test_mftecmd_output_dir(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_mftecmd
        out = str(tmp_path)
        ez_mftecmd("/mnt/$MFT", out)
        args = mock_dotnet.call_args[0][1]
        assert out in args

    def test_mftecmd_slack(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_mftecmd
        ez_mftecmd("/mnt/$MFT", str(tmp_path), include_slack=True)
        args = mock_dotnet.call_args[0][1]
        assert "--includeSlack" in args or any("slack" in a.lower() for a in args)


class TestEvtxEcmd:
    def test_evtxecmd(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_evtxecmd
        ez_evtxecmd("/mnt/wkstn01/Windows/System32/winevt/Logs/", str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert "--csv" in args

    def test_evtxecmd_event_ids_filter(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_evtxecmd
        ez_evtxecmd("/logs/", str(tmp_path), event_ids="4624,4625,4648")
        args = mock_dotnet.call_args[0][1]
        assert any("4624" in a for a in args)


class TestReCmd:
    def test_recmd_hive(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_recmd_hive
        ez_recmd_hive("/mnt/wkstn01/Windows/System32/config/SYSTEM", str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert "--csv" in args

    def test_recmd_dir(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_recmd_dir
        ez_recmd_dir("/mnt/wkstn01/Windows/System32/config/", str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert "-d" in args


class TestParserTools:
    def test_amcacheparser(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_amcacheparser
        ez_amcacheparser("/mnt/wkstn01/Windows/AppCompat/Programs/Amcache.hve", str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert "--csv" in args

    def test_appcompatcacheparser(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_appcompatcacheparser
        ez_appcompatcacheparser("/mnt/wkstn01/Windows/System32/config/SYSTEM", str(tmp_path))
        assert mock_dotnet.called

    def test_pecmd_prefetch(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_pecmd
        ez_pecmd("/mnt/wkstn01/Windows/Prefetch/", str(tmp_path))
        args = mock_dotnet.call_args[0][1]
        assert "--csv" in args

    def test_pecmd_missing_dll_returns_fallback(self, tmp_path):
        # dotnet fails AND the .dll is absent → tool_unavailable + fallback that
        # names the execution-evidence alternatives (UserAssist / Amcache / …).
        from tools.eztools import ez_pecmd
        fail = {"success": False, "stderr": "The application '…PECmd.dll' does not exist",
                "exit_code": 145, "cmd": "dotnet …PECmd.dll"}
        with patch("tools.eztools.run_dotnet", return_value=dict(fail)), \
             patch("tools.eztools.os.path.exists", return_value=False):
            r = ez_pecmd("/mnt/x/Windows/Prefetch/", str(tmp_path))
        assert r["tool_unavailable"] is True
        assert "not installed" in r["error"] and "PECmd.dll" in r["error"]
        assert "UserAssist" in r["fallback"] and "amcache" in r["fallback"].lower()

    def test_present_dll_failure_is_not_marked_unavailable(self, tmp_path):
        # A genuine runtime fault (dll present) must NOT be relabelled unavailable.
        from tools.eztools import ez_pecmd
        fail = {"success": False, "stderr": "some runtime error", "exit_code": 1}
        with patch("tools.eztools.run_dotnet", return_value=dict(fail)), \
             patch("tools.eztools.os.path.exists", return_value=True):
            r = ez_pecmd("/mnt/x/Windows/Prefetch/", str(tmp_path))
        assert "tool_unavailable" not in r and "fallback" not in r

    def test_jlecmd(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_jlecmd
        ez_jlecmd("/mnt/wkstn01/Users/mhill/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/", str(tmp_path))
        assert mock_dotnet.called

    def test_wxtcmd(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_wxtcmd
        ez_wxtcmd("/mnt/wkstn01/Users/mhill/AppData/Local/ConnectedDevicesPlatform/L.mhill/ActivitiesCache.db", str(tmp_path))
        assert mock_dotnet.called

    def test_rbcmd(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_rbcmd
        ez_rbcmd("/mnt/wkstn01/$Recycle.Bin/", str(tmp_path))
        assert mock_dotnet.called


class TestRecmdBatchPerHive:
    """H-2: `-d <Users tree>` ran to the 1800 s timeout twice; per-hive runs
    are bounded, isolated and individually citable."""

    def _users(self, tmp_path):
        u = tmp_path / "mnt" / "Users"
        for prof in ("PC User", "defaultprinter"):
            (u / prof).mkdir(parents=True)
            (u / prof / "NTUSER.DAT").write_bytes(b"regf")
            (u / prof / "ntuser.dat.LOG1").write_bytes(b"log")
            (u / prof / "AppData" / "Local" / "Microsoft" / "Windows").mkdir(parents=True)
            (u / prof / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat").write_bytes(b"regf")
        return u

    def test_enumerates_hives_and_runs_each(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_recmd_batch
        u = self._users(tmp_path)
        out = tmp_path / "analysis" / "recmd"
        r = ez_recmd_batch(str(u), "/opt/zimmermantools/RECmd/BatchExamples/DFIRBatch.reb", str(out))
        assert r["success"] and r["hives_found"] == 4 and r["hives_ok"] == 4 and mock_dotnet.call_count == 4
        cmds = [c.args[1] for c in mock_dotnet.call_args_list]
        assert all("-f" in a and "--bn" in a for a in cmds) and not any("-d" in a for a in cmds)
        assert not any(a[a.index("-f") + 1].lower().endswith(".log1") for a in cmds)

    def test_failure_isolated_and_legacy_mode(self, mock_dotnet, tmp_path, run_ok):
        from tools.eztools import ez_recmd_batch
        u = self._users(tmp_path)
        bad = dict(run_ok); bad["success"] = False; bad["stderr"] = "boom"
        mock_dotnet.side_effect = [run_ok, bad, run_ok, run_ok]
        r = ez_recmd_batch(str(u), "/b.reb", str(tmp_path / "analysis" / "o"))
        assert r["success"] and r["hives_failed"] == 1 and any(h["error"] for h in r["hives"])
        mock_dotnet.side_effect = None
        r = ez_recmd_batch(str(u), "/b.reb", str(tmp_path / "analysis" / "o2"), per_hive=False)
        assert "-d" in mock_dotnet.call_args.args[1]
