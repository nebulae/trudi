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


class TestDispatch:
    def test_agent_mode_execs_client_in_case_dir(self, tmp_path, monkeypatch):
        (tmp_path / "CLAUDE.md").write_text("# case")
        calls = {}
        monkeypatch.setattr(cli.shutil, "which",
                            lambda c: f"/bin/{c}" if c == "claude" else None)
        monkeypatch.setattr(cli.os, "chdir", lambda d: calls.setdefault("cd", d))
        monkeypatch.setattr(cli.os, "execv",
                            lambda b, argv: calls.setdefault("exec", (b, argv)))
        cli.main(["--mode", "agent", "--case", str(tmp_path)])
        assert calls["cd"] == str(tmp_path)
        assert calls["exec"] == ("/bin/claude", ["claude"])

    def test_pilot_mode_runs_repl_in_case_dir(self, tmp_path, monkeypatch):
        (tmp_path / "CLAUDE.md").write_text("# case")
        calls = {}
        monkeypatch.setattr(cli.os, "chdir", lambda d: calls.setdefault("cd", d))

        async def fake_run(stdio=False):
            calls["repl"] = stdio
        import pilot.spike
        monkeypatch.setattr(pilot.spike, "run", fake_run)
        assert cli.main(["--mode", "pilot", "--case", str(tmp_path), "--stdio"]) == 0
        assert calls["cd"] == str(tmp_path)
        assert calls["repl"] is True
        assert os.environ["TRUDI_CASE_DIR"] == str(tmp_path)

    def test_mode_is_required(self):
        with pytest.raises(SystemExit):
            cli.main(["--case", "/tmp"])
