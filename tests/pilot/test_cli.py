"""The trudi umbrella CLI (pilot/cli.py): mode dispatch and resolution rules."""
import os

import pytest

from pilot import cli


class TestCaseDirResolution:
    def test_explicit_case_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TRUDI_INVOKE_DIR", "/elsewhere")
        assert cli.resolve_case_dir(str(tmp_path)) == str(tmp_path)

    def test_invoke_dir_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TRUDI_INVOKE_DIR", str(tmp_path))
        assert cli.resolve_case_dir(None) == str(tmp_path)

    def test_cwd_fallback(self, tmp_path, monkeypatch):
        monkeypatch.delenv("TRUDI_INVOKE_DIR", raising=False)
        monkeypatch.chdir(tmp_path)
        assert cli.resolve_case_dir(None) == str(tmp_path)

    def test_missing_dir_exits(self, monkeypatch):
        monkeypatch.delenv("TRUDI_INVOKE_DIR", raising=False)
        with pytest.raises(SystemExit):
            cli.check_case_dir("/no/such/dir")

    def test_unprepared_dir_warns_but_proceeds(self, tmp_path, capsys):
        cli.check_case_dir(str(tmp_path))
        assert "no case CLAUDE.md" in capsys.readouterr().err


class TestAgentClientResolution:
    def test_explicit_flag(self, monkeypatch):
        monkeypatch.delenv("TRUDI_AGENT_CLIENT", raising=False)
        assert cli.resolve_agent_client("opencode") == "opencode"

    def test_env_default(self, monkeypatch):
        monkeypatch.setenv("TRUDI_AGENT_CLIENT", "claude")
        assert cli.resolve_agent_client(None) == "claude"

    def test_unknown_client_exits(self, monkeypatch):
        with pytest.raises(SystemExit):
            cli.resolve_agent_client("copilot")

    def test_path_detection_order(self, monkeypatch):
        monkeypatch.delenv("TRUDI_AGENT_CLIENT", raising=False)
        monkeypatch.setattr(cli.shutil, "which",
                            lambda c: "/bin/x" if c == "opencode" else None)
        assert cli.resolve_agent_client(None) == "opencode"

    def test_nothing_on_path_exits(self, monkeypatch):
        monkeypatch.delenv("TRUDI_AGENT_CLIENT", raising=False)
        monkeypatch.setattr(cli.shutil, "which", lambda c: None)
        with pytest.raises(SystemExit):
            cli.resolve_agent_client(None)


class TestClientArgv:
    def test_agent_mode_launches_bare(self):
        assert cli.client_argv("claude", "agent") == ["claude"]
        assert cli.client_argv("opencode", "agent") == ["opencode"]

    def test_pilot_claude_appends_profile_file(self):
        argv = cli.client_argv("claude", "pilot")
        assert argv == ["claude", "--append-system-prompt-file",
                        cli.PILOT_PROFILE]
        assert os.path.exists(cli.PILOT_PROFILE)  # the profile ships

    def test_pilot_opencode_selects_agent(self):
        assert cli.client_argv("opencode", "pilot") == \
            ["opencode", "--agent", "trudi-pilot"]


class TestDispatch:
    def _case(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("**Case ID:** T-1\n")
        (tmp_path / "evidence").mkdir()
        return tmp_path

    def test_pilot_mode_execs_claude_with_profile(self, tmp_path, monkeypatch):
        case = self._case(tmp_path)
        calls = {}
        monkeypatch.setattr(cli.shutil, "which", lambda c: f"/bin/{c}")
        monkeypatch.setattr(cli.os, "chdir", lambda d: calls.setdefault("cd", d))
        monkeypatch.setattr(cli.os, "execv",
                            lambda b, argv: calls.setdefault("exec", (b, argv)))
        cli.main(["--mode", "pilot", "--case", str(case), "--client", "claude"])
        assert calls["cd"] == str(case)
        assert calls["exec"] == ("/bin/claude", [
            "claude", "--append-system-prompt-file", cli.PILOT_PROFILE])

    def test_agent_mode_execs_client_bare(self, tmp_path, monkeypatch):
        case = self._case(tmp_path)
        calls = {}
        monkeypatch.setattr(cli.shutil, "which",
                            lambda c: f"/bin/{c}" if c == "opencode" else None)
        monkeypatch.setattr(cli.os, "chdir", lambda d: calls.setdefault("cd", d))
        monkeypatch.setattr(cli.os, "execv",
                            lambda b, argv: calls.setdefault("exec", (b, argv)))
        cli.main(["--mode", "agent", "--case", str(case)])
        assert calls["exec"] == ("/bin/opencode", ["opencode"])

    def test_mirror_spawns_follow_before_exec(self, tmp_path, monkeypatch):
        case = self._case(tmp_path)
        calls = {}
        monkeypatch.setattr(cli.shutil, "which", lambda c: f"/bin/{c}")
        monkeypatch.setattr(cli.os, "chdir", lambda d: None)
        monkeypatch.setattr(cli.os, "execv",
                            lambda b, argv: calls.setdefault("exec", (b, argv)))

        class FakeProc:
            pid = 4242

        def fake_popen(argv, **kw):
            calls["popen"] = (argv, kw)
            return FakeProc()
        monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)
        cli.main(["--mode", "pilot", "--case", str(case),
                  "--client", "opencode", "--mirror"])
        argv, kw = calls["popen"]
        assert argv[1:4] == ["-m", "pilot.mirror",
                             os.path.join(str(case), "analysis", "T-1_trace.json")]
        assert argv[4].endswith("T-1.vera") and argv[5] == "--follow"
        assert kw["start_new_session"] is True
        assert "exec" in calls  # mirror never blocks the launch

    def test_mode_is_required(self):
        with pytest.raises(SystemExit):
            cli.main(["--case", "/tmp"])
