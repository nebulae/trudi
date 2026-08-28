"""OpenCode registration + self-heal (opencode/register_opencode.py)."""
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MOD = REPO / "opencode" / "register_opencode.py"


def _mod():
    spec = importlib.util.spec_from_file_location("register_opencode", MOD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_fresh_config_registers_mcp_and_permissions(tmp_path):
    m = _mod()
    cfg = tmp_path / "opencode.json"
    msgs = m.register(cfg, REPO, "/venv/bin/python3")
    d = json.loads(cfg.read_text())
    assert d["mcp"]["trudi-sift"] == {
        "type": "local",
        "command": ["/venv/bin/python3", str(REPO / "server.py")],
        "enabled": True,
        "environment": {"TRUDI_SLIM_TOOL_DESCRIPTIONS": "1"},
    }
    assert d["permission"]["trudi-sift*"] == "allow"
    bash = d["permission"]["bash"]
    # catch-all first (order matters — last match wins in OpenCode)
    assert list(bash)[0] == "*" and bash["*"] == "allow"
    # ban list derived from the Claude Code deny list: bare + with-args forms
    assert bash["vol"] == "deny" and bash["vol *"] == "deny"
    assert bash["log2timeline.py *"] == "deny"
    assert bash["dotnet *"] == "deny"
    assert any("Registered mcp.trudi-sift" in x for x in msgs)


def test_ban_list_matches_claude_deny_list(tmp_path):
    m = _mod()
    claude_deny = json.loads(
        (REPO / "case-template" / ".claude" / "settings.json").read_text()
    )["permissions"]["deny"]
    cfg = tmp_path / "opencode.json"
    m.register(cfg, REPO, "/venv/bin/python3")
    bash = json.loads(cfg.read_text())["permission"]["bash"]
    # every Bash(x:*) entry produced both deny forms — nothing dropped
    for entry in claude_deny:
        name = entry[len("Bash("):-len(":*)")]
        assert bash.get(name) == "deny", name
        assert bash.get(f"{name} *") == "deny", name
    assert len(bash) == 1 + 2 * len(claude_deny)


def test_stale_mcp_command_healed(tmp_path):
    m = _mod()
    cfg = tmp_path / "opencode.json"
    cfg.write_text(json.dumps({"mcp": {"trudi-sift": {
        "type": "local", "command": ["/old/python3", "/old/server.py"],
        "enabled": True}}}))
    msgs = m.register(cfg, REPO, "/venv/bin/python3")
    d = json.loads(cfg.read_text())
    assert d["mcp"]["trudi-sift"]["command"] == [
        "/venv/bin/python3", str(REPO / "server.py")]
    assert any("re-pointed" in x for x in msgs)


def test_unrelated_user_keys_preserved(tmp_path):
    m = _mod()
    cfg = tmp_path / "opencode.json"
    cfg.write_text(json.dumps({
        "model": "ollama/qwen3",
        "mcp": {"other-server": {"type": "remote", "url": "http://x"}},
        "permission": {"bash": {"*": "allow", "git push": "ask"}},
    }))
    m.register(cfg, REPO, "/venv/bin/python3")
    d = json.loads(cfg.read_text())
    assert d["model"] == "ollama/qwen3"
    assert d["mcp"]["other-server"]["url"] == "http://x"
    assert d["permission"]["bash"]["git push"] == "ask"
    assert d["permission"]["bash"]["vol *"] == "deny"


def test_register_idempotent(tmp_path):
    m = _mod()
    cfg = tmp_path / "opencode.json"
    m.register(cfg, REPO, "/venv/bin/python3")
    before = cfg.read_text()
    msgs = m.register(cfg, REPO, "/venv/bin/python3")
    assert cfg.read_text() == before
    assert msgs == ["  opencode.json already registered — nothing to do"]


def test_link_assets_symlinks_commands_and_plugin(tmp_path):
    m = _mod()
    m.link_assets(tmp_path, REPO)
    cmds = sorted(p.name for p in (tmp_path / "command").iterdir())
    assert "trudi-clear-case.md" in cmds
    assert all(not n.endswith(".bak") for n in cmds)
    for p in (tmp_path / "command").iterdir():
        assert p.is_symlink() and p.resolve().is_relative_to(REPO)
    plug = tmp_path / "plugin" / "trudi.js"
    assert plug.is_symlink()
    assert plug.resolve() == (REPO / "opencode" / "plugin" / "trudi.js").resolve()
    # idempotent
    msgs = m.link_assets(tmp_path, REPO)
    assert msgs == ["  commands + plugin already linked — nothing to do"]


def test_agents_md_installed_with_backup(tmp_path):
    m = _mod()
    msgs = m.install_agents_md(tmp_path, REPO)
    dest = tmp_path / "AGENTS.md"
    assert dest.read_text() == (REPO / "claude" / "CLAUDE.md").read_text()
    assert any("installed TRUDI orchestrator" in x for x in msgs)
    # unchanged → no-op
    assert m.install_agents_md(tmp_path, REPO) == [
        "  AGENTS.md already current — nothing to do"]
    # user-modified → backed up, then replaced
    dest.write_text("user edits")
    msgs = m.install_agents_md(tmp_path, REPO)
    baks = list(tmp_path.glob("AGENTS.md.*.bak"))
    assert len(baks) == 1 and baks[0].read_text() == "user edits"
    assert dest.read_text() == (REPO / "claude" / "CLAUDE.md").read_text()
