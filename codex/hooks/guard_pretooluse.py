#!/usr/bin/env python3
"""Codex PreToolUse hook: TRUDI's execution-time evidence guard for Codex sessions.

Same deny rules as claude/hooks/guard_pretooluse.py — bash reads of produced
output, forensic binaries outside the MCP wrappers, raw writes into the case's
reports/ exports/ analysis/ or the operator's memory — adapted to the Codex
hook payload (developers.openai.com/codex/hooks):

- shell calls arrive as tool_name "Bash" with the command in tool_input.command
  (a string; an argv list is joined);
- file edits arrive as tool_name "apply_patch" (matcher aliases Edit/Write) with
  the patch text in tool_input.command — every "*** Add File:", "*** Update
  File:", "*** Delete File:" and "*** Move to:" target is judged as a file write.

A refusal is the shared hookSpecificOutput.permissionDecision="deny" shape,
which Codex honours for PreToolUse. Only the Codex session that owns the TRUDI
trace beacon is guarded (the same ownership rule as the Claude guard and the
Codex UserPromptSubmit hook); --cache-dir names the cache holding session.json
and session_owner.json, --case-dir the case this hook was installed for.
Fail-open everywhere: any error exits 0 with no output. Emergency off:
TRUDI_GUARD_DISABLE=1.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
_GUARDED_TOOLS = ("Bash", "apply_patch", "Edit", "Write")
_PATCH_TARGET_RE = re.compile(
    r"^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+?)\s*$", re.M)


def _claude_guard():
    """Load claude/hooks/guard_pretooluse.py under a distinct module name (this
    file shares its basename, so a plain import would resolve to itself)."""
    path = REPO / "claude/hooks/guard_pretooluse.py"
    spec = importlib.util.spec_from_file_location("trudi_claude_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _command_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(str(part) for part in value)
    return ""


def patch_targets(patch: str) -> list[str]:
    """File paths an apply_patch body creates, updates, deletes or moves to."""
    return _PATCH_TARGET_RE.findall(patch or "")


def decide(payload: dict, case_dir: Path, cache_dir: Path) -> str | None:
    """Refusal reason for this Codex tool call, or None when it may run."""
    if payload.get("hook_event_name") not in (None, "PreToolUse"):
        return None
    tool = payload.get("tool_name")
    if tool not in _GUARDED_TOOLS:
        return None
    if os.environ.get("TRUDI_GUARD_DISABLE") == "1":
        return None

    sys.path.insert(0, str(REPO / "claude/hooks"))
    from _session_owner import resolve_owner  # noqa: E402
    trace_path, _reason = resolve_owner(
        payload, claim=False,
        session_file=cache_dir / "session.json",
        owner_file=cache_dir / "session_owner.json")
    if trace_path is None:
        return None  # not the investigation session — never interfere
    trace = Path(trace_path).resolve()
    try:
        trace.relative_to(case_dir.resolve() / "analysis")
    except ValueError:
        return None  # the beacon belongs to a different case than this install
    case_root = trace.parent.parent

    guard = _claude_guard()
    tool_input = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or str(case_root)
    if tool == "Bash":
        command = _command_text(tool_input.get("command"))
        return guard.decide("Bash", {"command": command}, cwd, case_root)
    for target in patch_targets(_command_text(tool_input.get("command"))):
        reason = guard.decide("Write", {"file_path": target}, cwd, case_root)
        if reason:
            return reason
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path,
                        default=Path(os.environ.get("TRUDI_CACHE_DIR")
                                     or "~/.cache/trudi").expanduser())
    args = parser.parse_args()
    try:
        payload = json.load(sys.stdin)
        reason = decide(payload, args.case_dir, args.cache_dir)
    except Exception:
        return  # fail open: a broken guard must never stall the investigation
    if reason:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }}))


if __name__ == "__main__":
    main()
