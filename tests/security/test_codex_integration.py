"""Codex operator-input provenance and case-local workflow installation."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
HOOK = REPO / 'codex/hooks/log_user_message.py'


@pytest.fixture
def case(tmp_path):
    root = tmp_path / 'cases' / 'case-x'
    trace = root / 'analysis/case-x_INV-003_trace.json'
    trace.parent.mkdir(parents=True)
    trace.write_text(json.dumps({'case_id': 'case-x', 'entry_count': 1,
                                'entries': [{'call_id': 41, 'type': 'agent_message', 'content': 'existing evidence'}]}))
    (root / 'CLAUDE.md').write_text('# Case: case-x\n')
    suggestion = root / 'monitoring/response/suggestions/ACT-16.json'
    suggestion.parent.mkdir(parents=True)
    suggestion.write_text('{}')
    cache = tmp_path / 'private-cache'
    cache.mkdir()
    (cache / 'session.json').write_text(json.dumps({'case_id': 'case-x', 'path': str(trace)}))
    return SimpleNamespace(root=root, trace=trace, cache=cache)


def payload(case, prompt='approve ACT-16', **changes):
    return {'hook_event_name': 'UserPromptSubmit', 'session_id': 'codex-session',
            'turn_id': 'turn-1', 'cwd': str(case.root), 'prompt': prompt, **changes}


def run_hook(case, value):
    return subprocess.run([sys.executable, str(HOOK), '--case-dir', str(case.root),
                           '--cache-dir', str(case.cache)],
                          input=json.dumps(value), capture_output=True, text=True, timeout=15)


def entries(case):
    return json.loads(case.trace.read_text())['entries']


def approval_gate(case, monkeypatch):
    from core import execution_log
    from response import gates
    monkeypatch.setattr(gates, 'CASES_ROOT', case.root.parent)
    monkeypatch.setattr(execution_log, 'log', SimpleNamespace(
        _path=str(case.trace), last_n_window=lambda n: []))
    return gates.check_operator_text('case-x', 'ACT-16', 'approve ACT-16')


def test_real_prompt_satisfies_existing_gate_without_gate_changes(case, monkeypatch):
    assert approval_gate(case, monkeypatch)['gate'] == 'operator_text_required'
    result = run_hook(case, payload(case))
    assert result.returncode == 0, result.stderr
    assert approval_gate(case, monkeypatch) is None
    entry = entries(case)[-1]
    assert entry['source'] == 'codex_user_prompt'
    assert entry['role'] == 'user'
    assert entry['call_id'] == 42
    assert entries(case)[0]['content'] == 'existing evidence'


def test_retry_deduplicates_but_later_identical_prompt_is_retained(case):
    value = payload(case)
    for _ in range(2):
        assert run_hook(case, value).returncode == 0
    assert len(entries(case)) == 2
    assert run_hook(case, payload(case, turn_id='turn-2')).returncode == 0
    assert [e['call_id'] for e in entries(case)] == [41, 42, 43]


@pytest.mark.parametrize('answer,approved', [('Approve ACT-16', True), ('Skip ACT-16', False), ('No', False)])
def test_only_human_answer_can_authorize_async_question(case, monkeypatch, answer, approved):
    prompt = '<send_user_message_question_reply>\n' + json.dumps([
        {'question': 'Approve ACT-16: kill the RDP client?', 'answer': answer}
    ]) + '\n</send_user_message_question_reply>'
    result = run_hook(case, payload(case, prompt))
    assert result.returncode == 0, result.stderr
    assert entries(case)[-1]['content'] == answer
    assert (approval_gate(case, monkeypatch) is None) is approved


def test_malformed_question_reply_is_not_recorded(case):
    result = run_hook(case, payload(case, '<send_user_message_question_reply>approve ACT-16'))
    assert result.returncode == 2
    assert len(entries(case)) == 1


@pytest.mark.parametrize('change', [
    {'hook_event_name': 'PostToolUse'},
    {'cwd': '/some/other/project'},
])
def test_other_events_and_workspaces_cannot_write(case, change):
    assert run_hook(case, payload(case, **change)).returncode == 0
    assert len(entries(case)) == 1


def test_active_other_case_is_not_claimed(case, tmp_path):
    other = tmp_path / 'other/analysis/other_trace.json'
    other.parent.mkdir(parents=True)
    other.write_text('{"entries": []}')
    (case.cache / 'session.json').write_text(json.dumps({'path': str(other)}))
    result = run_hook(case, payload(case))
    assert result.returncode == 0
    assert 'different_case' in result.stdout
    assert not (case.cache / 'session_owner.json').exists()
    assert json.loads(other.read_text())['entries'] == []


def test_another_live_session_cannot_approve_into_owned_trace(case):
    assert run_hook(case, payload(case, 'read the case')).returncode == 0
    result = run_hook(case, payload(case, session_id='unrelated-session'))
    assert result.returncode == 0
    assert 'not_owner' in result.stdout
    assert len(entries(case)) == 2
    assert entries(case)[-1]['content'] == 'read the case'


def test_parallel_hook_events_share_monotonic_ids_without_lost_evidence(case):
    command = [sys.executable, str(HOOK), '--case-dir', str(case.root), '--cache-dir', str(case.cache)]
    jobs = []
    for n in range(6):
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        proc.stdin.write(json.dumps(payload(case, f'operator message {n}', turn_id=f'turn-{n}')))
        proc.stdin.close()
        jobs.append(proc)
    for proc in jobs:
        assert proc.wait(timeout=15) == 0, proc.stderr.read()
    assert sorted(e['call_id'] for e in entries(case)) == list(range(41, 48))
    assert len({e['_source_uuid'] for e in entries(case)[1:]}) == 6


def registrar():
    spec = importlib.util.spec_from_file_location('trudi_register_codex', REPO / 'codex/register_codex.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_registration_preserves_config_hooks_and_is_idempotent(case):
    folder = case.root / '.codex'
    folder.mkdir()
    config = folder / 'config.toml'
    config.write_text('model = "existing-model"\n')
    hooks = folder / 'hooks.json'
    hooks.write_text(json.dumps({'hooks': {'Stop': [{'hooks': [{'type': 'command', 'command': 'my-existing-hook'}]}]}}))
    module = registrar()
    module.register(case.root, sys.executable, cache_dir=case.cache)
    before = hooks.read_text()
    assert config.read_text() == 'model = "existing-model"\n'
    assert json.loads(before)['hooks']['Stop'][0]['hooks'][0]['command'] == 'my-existing-hook'
    assert (case.root / '.agents/skills/trudi-watch-alerts/SKILL.md').is_file()
    reference = case.root / '.agents/skills/trudi-check-alerts/references/workflow.md'
    assert reference.resolve() == REPO / 'claude/commands/trudi-check-alerts.md'
    assert module.register(case.root, sys.executable, cache_dir=case.cache) == ['Codex skills and input hook already installed']
    assert hooks.read_text() == before


def test_replaced_skill_is_backed_up(case):
    old = case.root / '.agents/skills/trudi-watch-alerts'
    old.mkdir(parents=True)
    (old / 'SKILL.md').write_text('existing customization')
    registrar().register(case.root, sys.executable, cache_dir=case.cache)
    backups = list((case.root / '.agents/backups').glob('*/trudi-watch-alerts/SKILL.md'))
    assert len(backups) == 1
    assert backups[0].read_text() == 'existing customization'
