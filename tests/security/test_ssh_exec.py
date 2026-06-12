"""Tests for the write-capable SSH execution path (core/ssh_exec.py).

The auto-protect feature's safety rests on this module: structured validated
argv (no shell interpolation of evidence), and an in-runner live-monitoring
scope gate so writable SSH cannot run off-scope.
"""
import subprocess
import types

import pytest

from core import ssh_exec
from response import gates as gates_mod


# ── Validators / injection rejection ──────────────────────────────────────────

class TestValidators:
    @pytest.mark.parametrize("bad", ["4242; rm -rf /", "$(whoami)", "1|2", "-1", "0",
                                     "4194304", "abc", ""])
    def test_pid_rejects_bad(self, bad):
        with pytest.raises(ssh_exec.ParamValidationError):
            ssh_exec._v_pid(bad)

    def test_pid_accepts_int(self):
        assert ssh_exec._v_pid(4242) == "4242"
        assert ssh_exec._v_pid("77") == "77"

    @pytest.mark.parametrize("bad", ["1.2.3.999", "$(whoami)", "10.0.0", "10.0.0.5;ls",
                                     "::1", "999.1.1.1"])
    def test_ipv4_rejects_bad(self, bad):
        with pytest.raises(ssh_exec.ParamValidationError):
            ssh_exec._v_ipv4(bad)

    def test_ipv4_accepts(self):
        assert ssh_exec._v_ipv4("203.0.113.10") == "203.0.113.10"

    @pytest.mark.parametrize("bad", ["0", "65536", "8080; reboot", "http"])
    def test_port_rejects_bad(self, bad):
        with pytest.raises(ssh_exec.ParamValidationError):
            ssh_exec._v_port(bad)

    @pytest.mark.parametrize("bad", ["/etc/passwd", "relative/path", "/tmp/../etc/x",
                                     "/tmp/a b", "/tmp/x;rm", "/tmp/$(x)"])
    def test_quarantine_path_rejects_bad(self, bad):
        with pytest.raises(ssh_exec.ParamValidationError):
            ssh_exec._v_path_quarantine(bad)

    def test_quarantine_path_accepts_allowlisted(self):
        assert ssh_exec._v_path_quarantine("/tmp/evil") == "/tmp/evil"
        assert ssh_exec._v_path_quarantine("/home/victim/.x/bot") == "/home/victim/.x/bot"

    def test_cron_path_allowlist(self):
        assert ssh_exec._v_path_cron("/etc/cron.d/evil") == "/etc/cron.d/evil"
        with pytest.raises(ssh_exec.ParamValidationError):
            ssh_exec._v_path_cron("/etc/passwd")

    def test_unit_validation(self):
        assert ssh_exec._v_unit("evil.service") == "evil.service"
        with pytest.raises(ssh_exec.ParamValidationError):
            ssh_exec._v_unit("evil.service;reboot")


# ── argv builders mirror the Respond.* artifacts ──────────────────────────────

class TestBuildArgv:
    def test_pause_and_kill(self):
        assert ssh_exec.build_argv("pause_pid", {"pid": 4242}) == ["/bin/kill", "-STOP", "4242"]
        assert ssh_exec.build_argv("kill_pid", {"pid": 4242}) == ["/bin/kill", "-9", "4242"]

    def test_block_egress_argv(self):
        argv = ssh_exec.build_argv("block_egress_to_endpoint",
                                   {"remote_ip": "203.0.113.10", "remote_port": 8080})
        assert argv == ["/sbin/iptables", "-I", "OUTPUT", "-d", "203.0.113.10", "-p", "tcp",
                        "--dport", "8080", "-m", "comment", "--comment", "TRUDI_RESPOND",
                        "-j", "REJECT"]

    def test_unblock_is_delete(self):
        argv = ssh_exec.build_argv("unblock_egress",
                                   {"remote_ip": "203.0.113.10", "remote_port": 8080})
        assert argv[1] == "-D"

    def test_quarantine_wraps_sh_with_validated_path(self):
        argv = ssh_exec.build_argv("quarantine_image", {"image_path": "/tmp/evil"})
        assert argv[0:2] == ["/bin/sh", "-c"]
        assert "/tmp/evil" in argv[2]

    def test_injection_blocked_via_build_argv(self):
        with pytest.raises(ssh_exec.ParamValidationError):
            ssh_exec.build_argv("pause_pid", {"pid": "4242; rm -rf /"})

    def test_unknown_template(self):
        with pytest.raises(ssh_exec.ParamValidationError):
            ssh_exec.build_argv("definitely_not_a_template", {})

    def test_missing_required_key(self):
        with pytest.raises(ssh_exec.ParamValidationError):
            ssh_exec.build_argv("pause_pid", {})

    def test_revert_template_map(self):
        assert ssh_exec.revert_template_for("pause_pid") == "resume_pid"
        assert ssh_exec.revert_template_for("block_egress_to_endpoint") == "unblock_egress"
        assert ssh_exec.revert_template_for("kill_pid") is None


# ── ssh_run_write: in-runner scope gate + schema ──────────────────────────────

def _baseline_case(tmp_path, monkeypatch):
    monkeypatch.setattr(gates_mod, "CASES_ROOT", tmp_path)
    case_id = "DEMO-TEST"
    bl = tmp_path / case_id / "monitoring" / "baselines"
    bl.mkdir(parents=True)
    (bl / "C.x.json").write_text("{}")
    return case_id


class TestSshRunWriteScope:
    def test_refuses_off_scope_without_subprocess(self, tmp_path, monkeypatch):
        # No baselines dir → live_monitoring_scope refuses, and we must NOT shell out.
        monkeypatch.setattr(gates_mod, "CASES_ROOT", tmp_path)

        def _boom(*a, **k):
            raise AssertionError("subprocess.run must not be called off-scope")
        monkeypatch.setattr(ssh_exec.subprocess, "run", _boom)

        r = ssh_exec.ssh_run_write("NO-SUCH", "trudi-victim", "pause_pid", {"pid": 4242})
        assert r["success"] is False
        assert "scope" in r["stderr"].lower() or "baseline" in r["stderr"].lower()

    def test_validation_refused_before_subprocess(self, tmp_path, monkeypatch):
        case_id = _baseline_case(tmp_path, monkeypatch)

        def _boom(*a, **k):
            raise AssertionError("subprocess.run must not run on bad params")
        monkeypatch.setattr(ssh_exec.subprocess, "run", _boom)

        r = ssh_exec.ssh_run_write(case_id, "trudi-victim", "pause_pid",
                                   {"pid": "4242; rm -rf /"})
        assert r["success"] is False
        assert "validation" in r["stderr"].lower()

    def test_result_schema_mirrors_ssh_run(self, tmp_path, monkeypatch):
        case_id = _baseline_case(tmp_path, monkeypatch)
        monkeypatch.setattr(ssh_exec, "_resolve_host",
                            lambda h: {"user": "u", "host": "h", "port": 22,
                                       "identity": "/secret/idkey"})
        logged = {}
        monkeypatch.setattr(ssh_exec, "_log_ssh_tool",
                            lambda result: logged.setdefault("called", True))

        def _fake_run(argv, capture_output, timeout):
            return types.SimpleNamespace(returncode=0, stdout=b"ok\n", stderr=b"")
        monkeypatch.setattr(ssh_exec.subprocess, "run", _fake_run)

        r = ssh_exec.ssh_run_write(case_id, "trudi-victim", "pause_pid", {"pid": 4242})
        for key in ("success", "stdout", "stderr", "exit_code", "elapsed_seconds",
                    "truncated", "cmd", "host", "source"):
            assert key in r
        assert r["source"] == "ssh_writer"
        assert r["success"] is True
        assert logged.get("called") is True
        # identity path is never leaked into the recorded command
        assert "/secret/idkey" not in r["cmd"]
