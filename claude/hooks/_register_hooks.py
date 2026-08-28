#!/usr/bin/env python3
"""Register (and self-heal) the TRUDI Claude Code hooks in settings.json.

Stdlib only — called by install.sh and unit-tested directly. Each event maps to
(script, matcher). The PreToolUse guard must match Write/Edit/MultiEdit as well
as Bash, or the reports/ write rule sits inert; a stale registration (wrong
command path, missing/old matcher) is rewritten in place.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HOOK_EVENTS: dict[str, tuple[str, str | None]] = {
    "PreToolUse":       ("guard_pretooluse.py", "Bash|Write|Edit|MultiEdit|NotebookEdit"),
    "PostToolUse":      ("log_narration.py", None),
    "Stop":             ("forensic_audit.py", None),
    "UserPromptSubmit": ("log_user_message.py", None),
}


def register(settings_path: Path, hooks_src: str) -> list[str]:
    """Merge the hook registrations into `settings_path`. Returns log lines."""
    settings_path = Path(settings_path)
    if settings_path.exists():
        settings = json.loads(settings_path.read_text() or "{}")
    else:
        settings = {}
    settings.setdefault("hooks", {})
    msgs, changed = [], False
    for event, (script, matcher) in HOOK_EVENTS.items():
        desired = f"python3 {hooks_src}/{script}"
        existing = settings["hooks"].setdefault(event, [])
        matched = False
        for h in existing:
            for entry in h.get("hooks", []):
                cmd = entry.get("command", "")
                if not cmd.endswith(script):
                    continue
                matched = True
                if cmd != desired:
                    entry["command"] = desired
                    msgs.append(f"  {event} hook ({script}) re-pointed to repo path")
                    changed = True
                if matcher and h.get("matcher") != matcher:
                    h["matcher"] = matcher
                    msgs.append(f"  {event} hook ({script}) matcher set to {matcher!r}")
                    changed = True
                if not matcher and "matcher" in h:
                    del h["matcher"]
                    changed = True
        if not matched:
            reg = {"hooks": [{"type": "command", "command": desired}]}
            if matcher:
                reg = {"matcher": matcher, **reg}
            existing.append(reg)
            msgs.append(f"  Registered {event} hook ({script})")
            changed = True
    if changed:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(settings, indent=2))
    elif not msgs:
        msgs.append("  hooks already registered — nothing to do")
    return msgs


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    hooks_src = argv[0] if argv else str(Path(__file__).resolve().parent)
    settings = Path(argv[1]) if len(argv) > 1 else Path.home() / ".claude" / "settings.json"
    for m in register(settings, hooks_src):
        print(m)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
