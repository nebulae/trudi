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

    def test_pecmd_platform_refusal_falls_back_to_libscca(self, tmp_path):
        """PECmd cannot decompress Win10 prefetch off Windows; libscca parses
        the same .pf into PECmd-shaped rows as a self-logged, citable call."""
        import csv
        import datetime
        import sys
        from unittest.mock import MagicMock
        from tools.eztools import ez_pecmd
        pf_dir = tmp_path / "Prefetch"
        pf_dir.mkdir()
        (pf_dir / "EVIL.EXE-1A2B3C4D.pf").write_bytes(b"MAM\x04")
        runs = [datetime.datetime(2019, 3, 20, 10, 0, 0),
                datetime.datetime(2019, 3, 19, 9, 0, 0),
                datetime.datetime(1601, 1, 1)]          # unused slot
        scca = MagicMock(executable_filename="EVIL.EXE", prefetch_hash=0x1A2B3C4D,
                         format_version=30, run_count=2, number_of_volumes=0,
                         number_of_filenames=2)
        def _run_time(i):                       # pyscca raises IOError past the end
            if i >= len(runs):
                raise IOError("invalid index")
            return runs[i]
        scca.get_last_run_time.side_effect = _run_time
        scca.get_filename.side_effect = ["\\VOLUME{x}\\EVIL.EXE", "\\VOLUME{x}\\NTDLL.DLL"].__getitem__
        fake = MagicMock()
        fake.file.return_value = scca
        refusal = {"success": True, "exit_code": 0, "stderr": "",
                   "stdout": "Non-Windows platforms not supported due to the need to load "
                             "decompression specific Windows libraries! Exiting...",
                   "cmd": "dotnet PECmd.dll"}
        out = tmp_path / "exports"
        with patch("tools.eztools.run_dotnet", return_value=dict(refusal)), \
             patch.dict(sys.modules, {"pyscca": fake}):
            r = ez_pecmd(str(pf_dir), str(out))
        assert r["success"] is True and r["parser"] == "libscca"
        assert r["pecmd_unavailable"] is True and r["files_parsed"] == 1
        assert r["_trudi_call_id"]
        with open(r["output_path"], newline="") as fh:
            row = next(csv.DictReader(fh))
        assert row["ExecutableName"] == "EVIL.EXE" and row["RunCount"] == "2"
        assert row["LastRun"].startswith("2019-03-20T10:00:00")
        assert row["PreviousRunTimes"].startswith("2019-03-19") and "1601" not in row["PreviousRunTimes"]
        assert row["FileCount"] == "2" and "NTDLL.DLL" in row["FilesLoaded"]

    def test_pecmd_success_keeps_pecmd_output(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_pecmd
        r = ez_pecmd("/mnt/x/Windows/Prefetch/", str(tmp_path))
        assert r["parser"] == "PECmd"

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


class TestSqleCmd:
    def test_no_csvf_flag(self, mock_dotnet, tmp_path):
        """SQLECmd rejects --csvf ("Unrecognized command or argument")."""
        from tools.eztools import ez_sqlecmd
        db = tmp_path / "History"            # extension-less browser DB is a file
        db.write_bytes(b"SQLite format 3\x00")
        ez_sqlecmd(str(db), str(tmp_path / "out"))
        args = mock_dotnet.call_args[0][1]
        assert "--csvf" not in args
        assert args[:2] == ["-f", str(db)] and "--csv" in args and "--maps" in args

    def test_directory_uses_d(self, mock_dotnet, tmp_path):
        from tools.eztools import ez_sqlecmd
        ez_sqlecmd(str(tmp_path), str(tmp_path / "out"))
        assert mock_dotnet.call_args[0][1][:2] == ["-d", str(tmp_path)]


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
