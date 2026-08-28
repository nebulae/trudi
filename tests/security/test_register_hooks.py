"""Hook registration + self-heal (claude/hooks/_register_hooks.py)."""
import importlib.util
import json
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[2] / "claude" / "hooks"


def _mod():
    spec = importlib.util.spec_from_file_location("_register_hooks", HOOKS / "_register_hooks.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_fresh_settings_gets_matcher(tmp_path):
    m = _mod()
    sp = tmp_path / ".claude" / "settings.json"
    msgs = m.register(sp, "/repo/claude/hooks")
    d = json.loads(sp.read_text())
    pre = d["hooks"]["PreToolUse"]
    assert pre[0]["matcher"] == "Bash|Write|Edit|MultiEdit|NotebookEdit"
    assert pre[0]["hooks"][0]["command"] == "python3 /repo/claude/hooks/guard_pretooluse.py"
    assert "matcher" not in d["hooks"]["PostToolUse"][0]
    assert any("Registered PreToolUse" in x for x in msgs)


def test_stale_registration_healed(tmp_path):
    m = _mod()
    sp = tmp_path / "settings.json"
    sp.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command",
                                       "command": "python3 /old/hooks/guard_pretooluse.py"}]}]}}))
    msgs = m.register(sp, "/repo/claude/hooks")
    d = json.loads(sp.read_text())
    pre = d["hooks"]["PreToolUse"]
    assert len(pre) == 1
    assert pre[0]["matcher"] == "Bash|Write|Edit|MultiEdit|NotebookEdit"
    assert pre[0]["hooks"][0]["command"].endswith("/repo/claude/hooks/guard_pretooluse.py")
    assert any("matcher set" in x for x in msgs) and any("re-pointed" in x for x in msgs)


def test_idempotent(tmp_path):
    m = _mod()
    sp = tmp_path / "settings.json"
    m.register(sp, "/repo/claude/hooks")
    before = sp.read_text()
    msgs = m.register(sp, "/repo/claude/hooks")
    assert sp.read_text() == before
    assert msgs == ["  hooks already registered — nothing to do"]


def test_other_settings_preserved(tmp_path):
    m = _mod()
    sp = tmp_path / "settings.json"
    sp.write_text(json.dumps({"permissions": {"allow": ["Bash(ls)"]}, "hooks": {}}))
    m.register(sp, "/repo/claude/hooks")
    d = json.loads(sp.read_text())
    assert d["permissions"] == {"allow": ["Bash(ls)"]}
    assert set(d["hooks"]) == {"PreToolUse", "PostToolUse", "Stop", "UserPromptSubmit"}
