"""Contract tests: the payloads the OpenCode adapter (opencode/plugin/trudi.js)
constructs are accepted by the Python hooks — same guard decisions, same trace
entries — so the JS layer can stay a logic-free shape mapper.

Each payload here is built EXACTLY as trudi.js builds it (tool-name map,
filePath→file_path, no transcript_path). If a hook's contract changes, these
fail before the adapter breaks in the field.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
HOOKS = REPO / "claude" / "hooks"
PLUGIN = REPO / "opencode" / "plugin" / "trudi.js"


def _run(script, payload, home):
    env = dict(os.environ, HOME=str(home))
    env.pop("TRUDI_GUARD_DISABLE", None)
    p = subprocess.run([sys.executable, str(HOOKS / script)],
                       input=json.dumps(payload), capture_output=True,
                       text=True, env=env, timeout=30)
    assert p.returncode == 0, p.stderr
    return p.stdout


def _decision(out):
    if not out.strip():
        return None
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"]


@pytest.fixture
def owner_env(tmp_path):
    home = tmp_path / "home"
    case_dir = home / "cases" / "case-x"
    trace = case_dir / "analysis" / "T_trace.json"
    trace.parent.mkdir(parents=True)
    trace.write_text('{"entries": []}')
    cache = home / ".cache" / "trudi"
    cache.mkdir(parents=True)
    (cache / "session.json").write_text(
        json.dumps({"case_id": "T", "path": str(trace)}))
    return {"home": home, "case_dir": case_dir, "trace": trace}


def _adapter_payload(oc_tool, args, env, event="PreToolUse", sid="OC-SESSION-1"):
    """Mirror trudi.js: TOOL_MAP + mapArgs, cwd = project directory."""
    tool_map = {"bash": "Bash", "edit": "Edit", "write": "Write",
                "read": "Read", "grep": "Grep", "glob": "Glob", "patch": "Edit"}
    if oc_tool == "bash":
        tool_input = {"command": args.get("command", "")}
    else:
        tool_input = dict(args)
        if "filePath" in tool_input:
            tool_input["file_path"] = tool_input.pop("filePath")
    return {"hook_event_name": event, "session_id": sid,
            "cwd": str(env["case_dir"]), "tool_name": tool_map[oc_tool],
            "tool_input": tool_input}


class TestGuardAcceptsAdapterPayloads:
    def test_forensic_binary_denied(self, owner_env):
        # The guard matches vol as /usr/local/bin/vol or vol.py (a bare "vol"
        # is left to the OpenCode permission deny map, which blocks it earlier).
        p = _adapter_payload(
            "bash", {"command": "/usr/local/bin/vol -f mem.raw windows.pslist"},
            owner_env)
        out = _run("guard_pretooluse.py", p, owner_env["home"])
        assert _decision(out) == "deny"

    def test_produced_output_read_denied(self, owner_env):
        p = _adapter_payload("bash", {"command": "cat reports/final.md"}, owner_env)
        out = _run("guard_pretooluse.py", p, owner_env["home"])
        assert _decision(out) == "deny"

    def test_write_into_reports_denied_with_opencode_filepath(self, owner_env):
        # OpenCode's write tool uses filePath — the adapter renames to file_path.
        p = _adapter_payload(
            "write",
            {"filePath": str(owner_env["case_dir"] / "reports" / "x.md"),
             "content": "draft"},
            owner_env)
        out = _run("guard_pretooluse.py", p, owner_env["home"])
        assert _decision(out) == "deny"

    def test_benign_command_allowed(self, owner_env):
        p = _adapter_payload("bash", {"command": "ls -la evidence/"}, owner_env)
        out = _run("guard_pretooluse.py", p, owner_env["home"])
        assert _decision(out) is None

    def test_non_owner_session_fails_open(self, owner_env, tmp_path):
        # cwd outside the case dir → not the beacon owner → no decision.
        p = _adapter_payload("bash", {"command": "cat reports/final.md"}, owner_env)
        p["cwd"] = str(tmp_path)
        out = _run("guard_pretooluse.py", p, owner_env["home"])
        assert _decision(out) is None


class TestNarrationAcceptsTranscriptless:
    def test_tool_call_logged_without_transcript(self, owner_env):
        # trudi.js sends PostToolUse with no transcript_path — the tool_call
        # must still land in the trace (narration scan silently skipped).
        p = _adapter_payload("bash", {"command": "ls evidence/"}, owner_env,
                             event="PostToolUse")
        p["tool_response"] = {"output": "nitroba.pcap"}
        _run("log_narration.py", p, owner_env["home"])
        entries = json.loads(owner_env["trace"].read_text())["entries"]
        assert any(e.get("type") == "tool_call" and
                   e.get("cmd", "").startswith("ls evidence/") for e in entries)

    def test_missing_transcript_path_still_logs(self, owner_env):
        p = _adapter_payload("bash", {"command": "file evidence/nitroba.pcap"},
                             owner_env, event="PostToolUse")
        p["transcript_path"] = str(owner_env["home"] / "nonexistent.jsonl")
        p["tool_response"] = {"output": "pcap capture file"}
        _run("log_narration.py", p, owner_env["home"])
        entries = json.loads(owner_env["trace"].read_text())["entries"]
        assert any(e.get("type") == "tool_call" for e in entries)


class TestUserMessageAcceptsAdapterPayload:
    def test_prompt_logged(self, owner_env):
        p = {"hook_event_name": "UserPromptSubmit", "session_id": "OC-SESSION-1",
             "cwd": str(owner_env["case_dir"]), "prompt": "approve ACT-2"}
        _run("log_user_message.py", p, owner_env["home"])
        entries = json.loads(owner_env["trace"].read_text())["entries"]
        assert any(e.get("type") == "user_message" and
                   "approve ACT-2" in json.dumps(e) for e in entries)


class TestAdapterSourceInvariants:
    """Static checks that trudi.js and this test file share one contract."""

    def test_tool_map_in_sync(self):
        src = PLUGIN.read_text()
        for oc, cc in [("bash", "Bash"), ("edit", "Edit"), ("write", "Write"),
                       ("read", "Read"), ("grep", "Grep"), ("glob", "Glob"),
                       ("patch", "Edit")]:
            assert f'{oc}: "{cc}"' in src, f"TOOL_MAP missing {oc}→{cc}"

    def test_adapter_maps_filepath_and_blocks_on_deny(self):
        src = PLUGIN.read_text()
        assert "file_path" in src and "filePath" in src
        assert "permissionDecision" in src and "throw" in src
        # fail-open posture: spawn errors resolve, never reject
        assert 'resolve("")' in src

    def test_adapter_targets_existing_hooks(self):
        src = PLUGIN.read_text()
        for script in ("guard_pretooluse.py", "log_narration.py",
                       "log_user_message.py", "forensic_audit.py"):
            assert script in src
            assert (HOOKS / script).exists()
