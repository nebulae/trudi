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
