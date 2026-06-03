"""Tests for tools/live.py and core/ssh.py.

Mocks `core.ssh.ssh_run` so no actual SSH is invoked. Verifies that each
live tool:
  - constructs the expected argv (correct binary, correct flags)
  - returns the standard executor result dict
  - rejects malformed inputs at the boundary
"""
import json
import os
import pytest
from unittest.mock import patch, MagicMock


# Standard SSH-runner mock result (mirrors what core.ssh.ssh_run returns)
@pytest.fixture
def ssh_ok():
    return {
        "success": True,
        "stdout": "sample output\n",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "cmd": "ssh trudi@host:22 -- mock",
        "retries": 0,
        "elapsed_seconds": 0.1,
        "progress_lines": [],
        "host": "test-endpoint",
        "source": "ssh_runner",
        "_trudi_call_id": 7,
    }


@pytest.fixture(autouse=True)
def mock_ssh(ssh_ok):
    """Auto-mock ssh_run for every test so no real SSH ever runs."""
    with patch("tools.live.ssh_run", return_value=ssh_ok) as m:
        yield m


HOST = "test-endpoint"


class TestLiveHosts:
    def test_list_configured(self):
        from tools.live import live_hosts
        with patch("tools.live.list_configured_hosts", return_value=["a", "b"]):
            r = live_hosts()
        assert r["success"] is True
        assert r["hosts"] == ["a", "b"]
        assert r["count"] == 2

    def test_empty_when_unconfigured(self):
        from tools.live import live_hosts
        with patch("tools.live.list_configured_hosts", return_value=[]):
            r = live_hosts()
        assert r["count"] == 0


class TestLiveProcesses:
    def test_calls_ps_with_expected_argv(self, mock_ssh):
        from tools.live import live_processes
        live_processes(HOST)
        args, _ = mock_ssh.call_args
        assert args[0] == HOST
        assert args[1][0] == "ps"
        assert "pid,ppid,user,etimes,start,cmd" in args[1]
        assert "--no-headers" in args[1]


class TestLiveProcessDetails:
    def test_pid_embedded_in_remote_script(self, mock_ssh):
        from tools.live import live_process_details
        live_process_details(HOST, 5024)
        args, _ = mock_ssh.call_args
        assert args[0] == HOST
        argv = args[1]
        assert argv[0] == "sh"
        assert argv[1] == "-c"
        assert "/proc/5024/" in argv[2]


class TestLiveNetworkConnections:
    def test_runs_ss_tnlpa(self, mock_ssh):
        from tools.live import live_network_connections
        live_network_connections(HOST)
        argv = mock_ssh.call_args[0][1]
        assert argv == ["ss", "-tnlpa"]


class TestLiveReadFile:
    def test_max_bytes_enforced(self, mock_ssh):
        from tools.live import live_read_file
        live_read_file(HOST, "/etc/hostname", max_bytes=512)
        argv = mock_ssh.call_args[0][1]
        assert argv == ["head", "-c", "512", "/etc/hostname"]

    def test_rejects_oversized_max_bytes(self, mock_ssh):
        from tools.live import live_read_file
        r = live_read_file(HOST, "/tmp/x", max_bytes=10_000_000)
        assert r["success"] is False
        assert "max_bytes" in r["error"]
        mock_ssh.assert_not_called()

    def test_rejects_zero_max_bytes(self, mock_ssh):
        from tools.live import live_read_file
        r = live_read_file(HOST, "/tmp/x", max_bytes=0)
        assert r["success"] is False
        mock_ssh.assert_not_called()


class TestLiveRecentLogins:
    def test_rejects_invalid_hours(self, mock_ssh):
        from tools.live import live_recent_logins
        assert live_recent_logins(HOST, hours=0)["success"] is False
        assert live_recent_logins(HOST, hours=10_000)["success"] is False
        mock_ssh.assert_not_called()

    def test_includes_hours_in_journalctl_query(self, mock_ssh):
        from tools.live import live_recent_logins
        live_recent_logins(HOST, hours=48)
        script = mock_ssh.call_args[0][1][2]
        assert "48 hours ago" in script
        assert "journalctl" in script
        assert "lastlog" in script


class TestLiveServices:
    def test_systemctl_list_units(self, mock_ssh):
        from tools.live import live_services
        live_services(HOST)
        argv = mock_ssh.call_args[0][1]
        assert argv[0] == "systemctl"
        assert "list-units" in argv
        assert "--type=service" in argv


class TestLiveEventLogTail:
    def test_unit_and_lines_passed(self, mock_ssh):
        from tools.live import live_event_log_tail
        live_event_log_tail(HOST, unit="sshd.service", lines=100)
        argv = mock_ssh.call_args[0][1]
        assert "journalctl" in argv
        assert "-u" in argv
        assert "sshd.service" in argv
        assert "100" in argv

    def test_rejects_invalid_lines(self, mock_ssh):
        from tools.live import live_event_log_tail
        assert live_event_log_tail(HOST, "x", lines=0)["success"] is False
        assert live_event_log_tail(HOST, "x", lines=10_000)["success"] is False
        mock_ssh.assert_not_called()


class TestLiveYaraScan:
    def test_yara_recursive(self, mock_ssh):
        from tools.live import live_yara_scan
        live_yara_scan(HOST, rules_path="/tmp/r.yar", target_dir="/var/tmp")
        argv = mock_ssh.call_args[0][1]
        assert argv == ["yara", "-r", "-s", "/tmp/r.yar", "/var/tmp"]


# ── Direct tests of core.ssh argv safety ─────────────────────────────────────

class TestSSHRunnerSafety:
    def test_rejects_string_cmd_argv(self, tmp_path, monkeypatch):
        """The defining safety property: cmd_argv MUST be list[str]. Strings
        are rejected to prevent remote-shell injection. This is the load-
        bearing constraint of the whole architecture."""
        from core.ssh import ssh_run
        hosts = {"h": {"user": "u", "host": "1.2.3.4", "identity": "~/.ssh/id"}}
        cfg = tmp_path / "hosts.json"
        cfg.write_text(json.dumps(hosts))
        monkeypatch.setattr("core.ssh.LIVE_HOSTS_CONFIG", str(cfg))
        # Pass a STRING instead of a list — should be refused without ever
        # invoking subprocess
        with patch("core.ssh.subprocess.run") as mock_run:
            r = ssh_run("h", "ps; rm -rf /")  # type: ignore[arg-type]
            mock_run.assert_not_called()
        assert r["success"] is False
        assert "list" in r["stderr"].lower()

    def test_rejects_empty_argv(self, tmp_path, monkeypatch):
        from core.ssh import ssh_run
        hosts = {"h": {"user": "u", "host": "1.2.3.4", "identity": "~/.ssh/id"}}
        cfg = tmp_path / "hosts.json"
        cfg.write_text(json.dumps(hosts))
        monkeypatch.setattr("core.ssh.LIVE_HOSTS_CONFIG", str(cfg))
        r = ssh_run("h", [])
        assert r["success"] is False

    def test_unknown_host_returns_error(self, tmp_path, monkeypatch):
        from core.ssh import ssh_run
        cfg = tmp_path / "hosts.json"
        cfg.write_text(json.dumps({"other": {"user": "u", "host": "x", "identity": "~/.ssh/id"}}))
        monkeypatch.setattr("core.ssh.LIVE_HOSTS_CONFIG", str(cfg))
        r = ssh_run("missing", ["ps"])
        assert r["success"] is False
        assert "missing" in r["stderr"]

    def test_argv_with_shell_metacharacters_passed_literally(self, tmp_path, monkeypatch):
        """Operand like '; rm -rf /' must be shlex-quoted before being sent
        over SSH. We verify by checking the constructed argv string never
        contains an unquoted semicolon between operands."""
        from core.ssh import ssh_run, _build_ssh_argv, _resolve_host
        cfg = tmp_path / "hosts.json"
        cfg.write_text(json.dumps({"h": {"user": "u", "host": "x", "identity": "~/.ssh/id"}}))
        monkeypatch.setattr("core.ssh.LIVE_HOSTS_CONFIG", str(cfg))
        argv = _build_ssh_argv(_resolve_host("h"), ["ls", "; rm -rf /"])
        # The dangerous operand should be quoted inside the argv list — joined
        # form must NOT have a bare semicolon followed by a destructive command
        joined = " ".join(argv)
        # quoted form should contain the literal characters wrapped in single quotes
        assert "'; rm -rf /'" in joined
        # The shell-interpreted form is what SSH passes, but ssh joins with
        # spaces — since shlex.quote wraps in single-quotes, the ; cannot
        # escape and split the remote command.

    def test_uses_batchmode_and_strict_host_key(self, tmp_path, monkeypatch):
        from core.ssh import _build_ssh_argv, _resolve_host
        cfg = tmp_path / "hosts.json"
        cfg.write_text(json.dumps({"h": {"user": "u", "host": "x", "identity": "~/.ssh/id"}}))
        monkeypatch.setattr("core.ssh.LIVE_HOSTS_CONFIG", str(cfg))
        argv = _build_ssh_argv(_resolve_host("h"), ["ps"])
        assert "BatchMode=yes" in argv
        assert "StrictHostKeyChecking=accept-new" in argv
