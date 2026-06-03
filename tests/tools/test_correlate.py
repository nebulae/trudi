"""Tests for tools/correlate.py — cross-tool correlation MCP tools."""
import json
import pytest
from unittest.mock import patch
from core.execution_log import ExecutionLog


def _seed_log(tmp_path):
    l = ExecutionLog()
    l.configure("CORR-001", str(tmp_path / "trace.json"))
    l.record_dair_call("Triage", "", False, "", "", "stay", "")
    return l


class TestProcessToFile:
    def test_correlation_by_path_match(self, tmp_path):
        from tools.correlate import process_to_file
        l = _seed_log(tmp_path)
        # vol output references a path
        l.record_tool_call(
            "vol -f mem.raw windows.psscan",
            True, False, 0, 0,
            stdout_excerpt="* 5024 cmd.exe PID=5024 C:\\Windows\\Temp\\STUN.exe",
        )
        # fls output mentions the same path
        l.record_tool_call(
            "fls -r /dev/loop0",
            True, False, 0, 0,
            stdout_excerpt="r/r * 1234: C:\\Windows\\Temp\\STUN.exe",
        )
        with patch("core.execution_log.log", l):
            r = process_to_file()
        assert r["success"] is True
        assert any(c["pid"] == 5024 for c in r["correlations"])
        assert any("STUN.exe" in c["candidate_path"] for c in r["correlations"])

    def test_pid_filter(self, tmp_path):
        from tools.correlate import process_to_file
        l = _seed_log(tmp_path)
        l.record_tool_call("vol psscan", True, False, 0, 0,
                           stdout_excerpt="5024 cmd.exe C:\\Windows\\foo.exe\n8000 svchost C:\\Windows\\bar.exe")
        l.record_tool_call("fls", True, False, 0, 0,
                           stdout_excerpt="r/r * 1: C:\\Windows\\foo.exe\nr/r * 2: C:\\Windows\\bar.exe")
        with patch("core.execution_log.log", l):
            r = process_to_file(pid=5024)
        pids_seen = {c["pid"] for c in r["correlations"]}
        assert pids_seen <= {5024}

    def test_no_match_returns_empty_correlations(self, tmp_path):
        from tools.correlate import process_to_file
        l = _seed_log(tmp_path)
        with patch("core.execution_log.log", l):
            r = process_to_file()
        assert r["success"] is True
        assert r["correlations"] == []


class TestNetworkToProcess:
    def test_correlation_basic(self, tmp_path):
        from tools.correlate import network_to_process
        l = _seed_log(tmp_path)
        l.record_tool_call(
            "vol windows.netscan", True, False, 0, 0,
            stdout_excerpt="TCP 192.168.1.10:443 -> 1.2.3.4:8443 ESTABLISHED 5024 cmd.exe",
        )
        l.record_tool_call(
            "vol windows.pslist", True, False, 0, 0,
            stdout_excerpt="* 5024 cmd.exe",
        )
        with patch("core.execution_log.log", l):
            r = network_to_process()
        assert r["success"] is True
        assert any(c["pid"] == 5024 for c in r["connections"])

    def test_ip_filter(self, tmp_path):
        from tools.correlate import network_to_process
        l = _seed_log(tmp_path)
        l.record_tool_call(
            "vol netscan", True, False, 0, 0,
            stdout_excerpt="TCP 10.0.0.1:80 5024 cmd.exe\nTCP 8.8.8.8:53 7000 svchost.exe",
        )
        l.record_tool_call("vol pslist", True, False, 0, 0,
                           stdout_excerpt="5024 cmd.exe\n7000 svchost.exe")
        with patch("core.execution_log.log", l):
            r = network_to_process(ip="10.0.0.1")
        assert all("10.0.0.1" in " ".join(c["ips"]) for c in r["connections"])


class TestMitreMap:
    def test_keyword_match_ranks_techniques(self, tmp_path):
        from tools.correlate import mitre_map
        l = _seed_log(tmp_path)
        with patch("core.execution_log.log", l):
            r = mitre_map("attacker extracted NTDS.dit via ntdsutil with Domain Admin rights")
        assert r["success"] is True
        tids = [c["technique_id"] for c in r["candidates"]]
        assert "T1003.003" in tids  # NTDS

    def test_no_match_returns_empty_candidates(self, tmp_path):
        from tools.correlate import mitre_map
        l = _seed_log(tmp_path)
        with patch("core.execution_log.log", l):
            r = mitre_map("xyzzy plover frob notarealthreat")
        assert r["success"] is True
        assert r["candidates"] == []

    def test_table_missing_returns_error(self, tmp_path):
        from tools.correlate import mitre_map
        nonexistent = str(tmp_path / "no_such_file.json")
        with patch("core.execution_log.log", _seed_log(tmp_path)):
            r = mitre_map("anything", table_path=nonexistent)
        assert r["success"] is False


class TestMitreValidate:
    def test_existing_technique(self, tmp_path):
        from tools.correlate import mitre_validate
        with patch("core.execution_log.log", _seed_log(tmp_path)):
            r = mitre_validate("T1003.003")
        assert r["success"] is True
        assert r["exists"] is True
        assert "NTDS" in r["name"]

    def test_nonexistent_technique(self, tmp_path):
        from tools.correlate import mitre_validate
        with patch("core.execution_log.log", _seed_log(tmp_path)):
            r = mitre_validate("T9999.999")
        assert r["exists"] is False

    def test_validate_with_custom_table(self, tmp_path):
        from tools.correlate import mitre_validate
        path = tmp_path / "custom_mitre.json"
        path.write_text(json.dumps({"techniques": {"T0001": {"name": "Test"}}}))
        with patch("core.execution_log.log", _seed_log(tmp_path)):
            r = mitre_validate("T0001", table_path=str(path))
        assert r["exists"] is True
        assert r["name"] == "Test"
