#!/usr/bin/env python3
"""Record Codex UserPromptSubmit input through TRUDI's shared trace lock.

Installed as a trusted Codex command hook, never called by the investigator
to manufacture approvals. Only the operator's answer is retained from an
asynchronous question reply; the agent-authored question is not user consent.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

REPO = Path(__file__).resolve().parents[2]


def operator_text(prompt: str) -> str:
    opening = '<send_user_message_question_reply>'
    closing = '</send_user_message_question_reply>'
    if not prompt.lstrip().startswith(opening):
        return prompt
    stripped = prompt.strip()
    if not stripped.endswith(closing):
        raise ValueError('Malformed Codex question reply; no approval recorded')
    replies = json.loads(stripped[len(opening):-len(closing)])
    if not isinstance(replies, list):
        raise ValueError('Expected a list of Codex question replies')
    return '\n'.join(item['answer'] for item in replies
                     if isinstance(item, dict) and isinstance(item.get('answer'), str))


def record_prompt(payload: dict, case_dir: Path, cache_dir: Path) -> str:
    if payload.get('hook_event_name') != 'UserPromptSubmit':
        return 'ignored_event'
    if not all(isinstance(payload.get(key), str) and payload[key]
               for key in ('session_id', 'turn_id', 'cwd', 'prompt')):
        raise ValueError('Codex hook is missing session_id, turn_id, cwd, or prompt')
    case_dir = case_dir.resolve()
    try:
        Path(payload['cwd']).resolve().relative_to(case_dir)
    except ValueError:
        return 'outside_case'
    content = operator_text(payload['prompt'])
    if not content.strip():
        return 'empty_prompt'
    # Set before importing core: hooks and this case's MCP server must share
    # exactly the same lock and call-id counter.
    os.environ['TRUDI_CACHE_DIR'] = str(cache_dir)
    sys.path.insert(0, str(REPO))
    sys.path.insert(0, str(REPO / 'claude/hooks'))
    from core.execution_log import _hook_flock, _next_shared_call_id
    from _session_owner import resolve_trace_path, resolve_owner

    with _hook_flock():
        session_file = cache_dir / 'session.json'
        trace_path = resolve_trace_path(session_file)
        if not trace_path:
            return 'no_active_trace'
        # Check the install's case before claiming the machine-wide beacon.
        try:
            Path(trace_path).resolve().relative_to(case_dir / 'analysis')
        except ValueError:
            return 'different_case'
        trace_path, reason = resolve_owner(payload, claim=True,
                                          session_file=session_file,
                                          owner_file=cache_dir / 'session_owner.json')
        if trace_path is None:
            return reason
        trace = json.loads(Path(trace_path).read_text())
        entries = trace.get('entries', [])
        identity = json.dumps([payload['session_id'], payload['turn_id'], payload['prompt']])
        source_uuid = 'codex:' + hashlib.sha256(identity.encode()).hexdigest()
        if any(e.get('_source_uuid') == source_uuid for e in entries):
            return 'duplicate'
        entries.append({
            'call_id': _next_shared_call_id(trace_path),
            'type': 'user_message', 'role': 'user', 'source': 'codex_user_prompt',
            'ts': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'content': content, '_source_uuid': source_uuid,
            '_source_session_id': payload['session_id'],
            '_source_turn_id': payload['turn_id'],
        })
        trace['entries'] = entries
        trace['entry_count'] = len(entries)
        fd, name = tempfile.mkstemp(prefix='.codex-prompt-', dir=Path(trace_path).parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(trace, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, trace_path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    return 'recorded'


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-dir', type=Path, required=True)
    parser.add_argument('--cache-dir', type=Path,
                        default=Path(os.environ.get('TRUDI_CACHE_DIR') or '~/.cache/trudi').expanduser())
    args = parser.parse_args()
    try:
        result = record_prompt(json.load(sys.stdin), args.case_dir, args.cache_dir)
        if result in ('no_active_trace', 'different_case', 'not_owner'):
            print(json.dumps({'hookSpecificOutput': {
                'hookEventName': 'UserPromptSubmit',
                'additionalContext': f'TRUDI did not record this input ({result}). Initialize/resume the correct case trace before requesting a fresh action approval. Never fabricate a user_message.',
            }}))
    except (OSError, ValueError, TypeError) as exc:
        # Do not quietly lose approval inputs and let the investigator claim
        # an approval succeeded. Codex displays the failure before continuing.
        print(f'TRUDI could not record Codex operator input: {exc}', file=sys.stderr)
        raise SystemExit(2)


if __name__ == '__main__':
    main()
