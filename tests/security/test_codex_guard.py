"""Codex PreToolUse adapter of the TRUDI execution-time evidence guard.

Codex reports shell calls as tool_name "Bash" (tool_input.command) and file
edits as "apply_patch" (the patch text in tool_input.command). The adapter
must refuse the same things the Claude Code guard refuses, only for the
session that owns the trace beacon, and stay silent for everything else.
"""
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
GUARD = REPO / 'codex/hooks/guard_pretooluse.py'
PROMPT_HOOK = REPO / 'codex/hooks/log_user_message.py'


@pytest.fixture
def case(tmp_path):
    root = tmp_path / 'cases' / 'case-x'
    trace = root / 'analysis/case-x_trace.json'
    trace.parent.mkdir(parents=True)
    trace.write_text(json.dumps({'case_id': 'case-x', 'entry_count': 0, 'entries': []}))
    (root / 'CLAUDE.md').write_text('# Case: case-x\n')
    (root / 'reports').mkdir()
    (root / 'exports').mkdir()
    cache = tmp_path / 'private-cache'
    cache.mkdir()
    (cache / 'session.json').write_text(json.dumps({'case_id': 'case-x', 'path': str(trace)}))
    return SimpleNamespace(root=root, trace=trace, cache=cache)


def run(script, case, payload, case_dir=None):
    return subprocess.run([sys.executable, str(script), '--case-dir', str(case_dir or case.root),
                           '--cache-dir', str(case.cache)],
                          input=json.dumps(payload), capture_output=True, text=True, timeout=30)


def claim(case, session_id='codex-session'):
    """The owning session is the one whose UserPromptSubmit hook fired first."""
    result = run(PROMPT_HOOK, case, {'hook_event_name': 'UserPromptSubmit', 'session_id': session_id,
                                     'turn_id': 'turn-1', 'cwd': str(case.root), 'prompt': 'start'})
    assert result.returncode == 0, result.stderr


def pre_tool_use(case, tool_name, command, session_id='codex-session', cwd=None):
    return {'hook_event_name': 'PreToolUse', 'session_id': session_id, 'turn_id': 'turn-2',
            'cwd': str(cwd or case.root), 'tool_name': tool_name,
            'tool_input': {'command': command}, 'permission_mode': 'default'}


def decision(result):
    assert result.returncode == 0, result.stderr
    if not result.stdout.strip():
        return None
    return json.loads(result.stdout)['hookSpecificOutput']


@pytest.mark.parametrize('command', [
    'cat analysis/.tool_output/12.txt',
    'python3 -c "import csv" exports/mail/roster.csv',
    ['jq', '.entries', 'analysis/case-x_trace.json'],
])
def test_bash_read_of_produced_output_is_denied(case, command):
    claim(case)
    verdict = decision(run(GUARD, case, pre_tool_use(case, 'Bash', command)))
    assert verdict['hookEventName'] == 'PreToolUse'
    assert verdict['permissionDecision'] == 'deny'
    assert 'read.output' in verdict['permissionDecisionReason']


def test_forensic_binary_outside_mcp_is_denied(case):
    claim(case)
    verdict = decision(run(GUARD, case, pre_tool_use(case, 'Bash', '/usr/local/bin/vol -f evidence/mem.raw windows.pslist')))
    assert verdict['permissionDecision'] == 'deny'
    assert 'mcp_routing' in verdict['permissionDecisionReason']


def test_bash_write_into_reports_is_denied(case):
    claim(case)
    verdict = decision(run(GUARD, case, pre_tool_use(case, 'Bash', 'echo done > reports/final.md')))
    assert verdict['permissionDecision'] == 'deny'
    assert 'write_final_report' in verdict['permissionDecisionReason']


@pytest.mark.parametrize('tool_name', ['apply_patch', 'Write', 'Edit'])
def test_apply_patch_into_tool_only_dirs_is_denied(case, tool_name):
    claim(case)
    patch = ('*** Begin Patch\n*** Add File: notes.md\n+scratch\n'
             '*** Add File: reports/case-x_investigation_report.md\n+# Report\n*** End Patch\n')
    verdict = decision(run(GUARD, case, pre_tool_use(case, tool_name, patch)))
    assert verdict['permissionDecision'] == 'deny'
    assert 'write_final_report' in verdict['permissionDecisionReason']


def test_apply_patch_update_under_exports_is_denied(case):
    claim(case)
    patch = '*** Begin Patch\n*** Update File: exports/mail/roster.csv\n@@\n-a\n+b\n*** End Patch\n'
    verdict = decision(run(GUARD, case, pre_tool_use(case, 'apply_patch', patch)))
    assert verdict['permissionDecision'] == 'deny'


@pytest.mark.parametrize('tool_name,command', [
    ('Bash', 'ls analysis'),
    ('Bash', 'git status'),
    ('apply_patch', '*** Begin Patch\n*** Add File: notes.md\n+scratch\n*** End Patch\n'),
    ('update_plan', 'anything'),
])
def test_ordinary_calls_are_allowed(case, tool_name, command):
    claim(case)
    assert decision(run(GUARD, case, pre_tool_use(case, tool_name, command))) is None


def test_sessions_that_do_not_own_the_trace_are_not_guarded(case):
    claim(case, session_id='owner-session')
    other = pre_tool_use(case, 'Bash', 'cat analysis/.tool_output/12.txt', session_id='other-session')
    assert decision(run(GUARD, case, other)) is None


def test_session_outside_the_case_dir_is_not_guarded(case, tmp_path):
    claim(case)
    elsewhere = pre_tool_use(case, 'Bash', 'cat analysis/.tool_output/12.txt', cwd=tmp_path)
    assert decision(run(GUARD, case, elsewhere)) is None


def test_install_for_another_case_stays_silent(case, tmp_path):
    claim(case)
    other_case = tmp_path / 'cases' / 'case-y'
    other_case.mkdir()
    assert decision(run(GUARD, case, pre_tool_use(case, 'Bash', 'cat analysis/x.csv'), case_dir=other_case)) is None


def test_malformed_payload_fails_open(case):
    result = subprocess.run([sys.executable, str(GUARD), '--case-dir', str(case.root),
                             '--cache-dir', str(case.cache)],
                            input='not json', capture_output=True, text=True, timeout=30)
    assert result.returncode == 0
    assert result.stdout == ''
