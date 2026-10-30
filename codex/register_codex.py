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
    groups = document.setdefault('hooks', {}).setdefault('UserPromptSubmit', [])
    command = shlex.join([python, str(repo / 'codex/hooks/log_user_message.py'),
                          '--case-dir', str(case_dir), '--cache-dir', str(cache_dir)])
    handler = {'type': 'command', 'command': command, 'timeout': 15}
    # Remove this adapter's old registration, preserving all other handlers.
    kept = []
    for group in groups:
        others = [h for h in group.get('hooks', [])
                  if 'codex/hooks/log_user_message.py' not in h.get('command', '')]
        if others:
            kept.append({**group, 'hooks': others})
    document['hooks']['UserPromptSubmit'] = kept + [{'hooks': [handler]}]
    if json.dumps(document, sort_keys=True) != before:
        hooks_path.write_text(json.dumps(document, indent=2) + '\n')
        messages.append('Registered the Codex UserPromptSubmit trace hook')
    return messages or ['Codex skills and input hook already installed']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-dir', type=Path, required=True)
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--cache-dir', type=Path)
    args = parser.parse_args()
    for message in register(args.case_dir, args.python, cache_dir=args.cache_dir):
        print(message)
    print('Restart/resume Codex in the case directory; review and trust the input hook with /hooks.')
