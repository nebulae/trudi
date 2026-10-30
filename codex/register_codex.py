#!/usr/bin/env python3
"""Install the portable live-monitoring skills and input hook for one case.

Preserves unrelated configuration and does not trust hooks on the user's behalf.
MCP registration remains independent: codex mcp add trudi-sift -- PYTHON server.py.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex
import sys

REPO = Path(__file__).resolve().parent.parent


def register(case_dir: Path, python: str, *, repo: Path = REPO,
             cache_dir: Path | None = None) -> list[str]:
    case_dir, repo = case_dir.resolve(), repo.resolve()
    if not (case_dir / 'CLAUDE.md').is_file():
        raise ValueError(f'Not a TRUDI case: {case_dir}')
    cache_dir = (cache_dir or Path('~/.cache/trudi').expanduser()).resolve()
    dest = case_dir / '.agents/skills'
    dest.mkdir(parents=True, exist_ok=True)
    messages = []
    for src in sorted((repo / 'codex/skills').iterdir()):
        if not (src / 'SKILL.md').is_file():
            continue
        link = dest / src.name
        if link.is_symlink() and link.resolve() == src:
            continue
        if link.exists() or link.is_symlink():
            backup = case_dir / '.agents/backups' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') / src.name
            backup.parent.mkdir(parents=True, exist_ok=True)
            link.rename(backup)
        link.symlink_to(src, target_is_directory=True)
        messages.append(f'Installed ${src.name}')
    codex_dir = case_dir / '.codex'
    codex_dir.mkdir(exist_ok=True)
    config = codex_dir / 'config.toml'
    if not config.exists():
        config.write_text('# TRUDI case hooks are defined in hooks.json.\n')
    hooks_path = codex_dir / 'hooks.json'
    document = json.loads(hooks_path.read_text()) if hooks_path.exists() else {}
    before = json.dumps(document, sort_keys=True)
    hooks = document.setdefault('hooks', {})
    for event, script, group_fields, label in HOOKS:
        command = shlex.join([python, str(repo / script),
                              '--case-dir', str(case_dir), '--cache-dir', str(cache_dir)])
        handler = {'type': 'command', 'command': command, 'timeout': 15}
        if event == 'PreToolUse':
            handler['statusMessage'] = 'TRUDI evidence guard'
        # Remove this adapter's old registration, preserving all other handlers.
        kept = []
        for group in hooks.get(event, []):
            others = [h for h in group.get('hooks', []) if script not in h.get('command', '')]
            if others:
                kept.append({**group, 'hooks': others})
        groups = kept + [{**group_fields, 'hooks': [handler]}]
        if json.dumps(groups, sort_keys=True) != json.dumps(hooks.get(event), sort_keys=True):
            messages.append(f'Registered the Codex {label}')
        hooks[event] = groups
    if json.dumps(document, sort_keys=True) != before:
        hooks_path.write_text(json.dumps(document, indent=2) + '\n')
    return messages or ['Codex skills and hooks already installed']


# (event, script under the repo, extra group fields, human label). The PreToolUse
# guard matches Codex's shell tool (Bash) and its file editor (apply_patch, whose
# matcher aliases are Edit/Write) — the two paths that can read produced output
# or write into the case's tool-only directories outside MCP.
HOOKS = (
    ('UserPromptSubmit', 'codex/hooks/log_user_message.py', {}, 'UserPromptSubmit trace hook'),
    ('PreToolUse', 'codex/hooks/guard_pretooluse.py', {'matcher': 'Bash|apply_patch'},
     'PreToolUse evidence guard'),
)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-dir', type=Path, required=True)
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--cache-dir', type=Path)
    args = parser.parse_args()
    for message in register(args.case_dir, args.python, cache_dir=args.cache_dir):
        print(message)
    print('Restart/resume Codex in the case directory; review and trust both TRUDI hooks with /hooks.')
