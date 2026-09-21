"""Real detached subprocess tests, isolated from all investigation state."""
import json
from pathlib import Path
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from core import jobs
from core.execution_log import log, ExecutionLog
from core.phase_routing import pending_work
from core.evidence_packets import build_packet, PacketError


def start(tmp_path, script, **kw):
    output = tmp_path / 'exports' / kw.pop('name', 'out')
    output.mkdir(parents=True, exist_ok=True)
    return jobs.start_job([sys.executable, '-c', script, str(output)],
        'test.parse', kw.pop('timeout', 10), str(output), inline_wait=kw.pop('inline_wait', 0), **kw)


def collect(job_id, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = jobs.job_status(job_id)
        if result.get('status') not in ('running', 'orphaned'):
            return result
        time.sleep(.05)
    raise AssertionError(jobs.read_state(job_id))


def test_collect_preserves_identity_and_is_exactly_once(tmp_path):
    r = start(tmp_path, 'print("observation")')
    out = collect(r['job_id'])
    assert out['success'], out
    entry = log.index().by_call_id[out['_trudi_call_id']]
    assert entry['mcp_tool'] == 'test.parse' and entry['run_id'] == log._run_id
    assert 'observation' in entry['stdout_excerpt']
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(jobs.job_status, [r['job_id']] * 2))
    assert all(x['_trudi_call_id'] == out['_trudi_call_id'] for x in results)
    assert len([e for e in log._entries if e.get('job_completion')]) == 1
    assert not pending_work(log)


def test_inline_fast_path_returns_complete_result(tmp_path):
    out = start(tmp_path, 'print("quick")', inline_wait=10)
    assert out['status'] == 'finished' and out['success'], out
    assert out['_trudi_call_id']


def test_partial_csv_is_validated_citable_and_scope_remains_open(tmp_path):
    script = 'import pathlib,sys,time; p=pathlib.Path(sys.argv[1])/"rows.csv"; p.write_text(\'name,value\\nobservation,1\\n"broken\'); time.sleep(10)'
    r = start(tmp_path, script, timeout=1)
    out = collect(r['job_id'])
    assert not out['success'] and out['result_status'] == 'partial', out
    cid = out['_trudi_call_id']
    entry = log.index().by_call_id[cid]
    files = entry['output_manifest']['files']
    assert len(files) == 1 and 'broken' not in Path(files[0]['path']).read_text()
    packet = build_packet(log, {'description': 'observation', 'input_call_ids': [cid]})
    assert packet['evidence'] and not packet['evidence'][0]['retained_output_complete']
    assert pending_work(log)[0]['status'] == 'incomplete'
    from tools.read_output import read_output
    from tools._output_reader import entry_text_sources
    read = read_output(files[0]['path'])
    read_entry = log.index().by_call_id[read['_trudi_call_id']]
    assert read_entry['scope_complete'] is False
    assert all(not s.complete for s in entry_text_sources(read_entry))
    assert read_output(files[0]['derived_from'])['success'] is False


def test_changed_output_after_completion_is_not_rehashed_as_original(tmp_path):
    r = start(tmp_path, 'import pathlib,sys; (pathlib.Path(sys.argv[1])/"rows.txt").write_text("original\\n")')
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        state = jobs.read_state(r['job_id'])
        if state['status'] in jobs.TERMINAL and not jobs.writers_alive(state):
            break
        time.sleep(.05)
    Path(state['output_manifest']['files'][0]['path']).write_text('changed\n')
    out = jobs.job_status(r['job_id'])
    assert not out['success'] and out['verification_errors'], out
    with pytest.raises(PacketError):
        build_packet(log, {'description': 'changed', 'input_call_ids': [out['_trudi_call_id']]})


def test_same_case_same_path_new_run_cannot_collect_old_job(tmp_path):
    r = start(tmp_path, 'print("old run")')
    original = log._run_id
    try:
        log._run_id = 'replacement-run'
        assert jobs.job_status(r['job_id'])['status'] == 'foreign'
    finally:
        log._run_id = original
    assert collect(r['job_id'])['success']


def test_restart_reuses_ownership_and_collection(tmp_path):
    r = start(tmp_path, 'print("restart")')
    restored = ExecutionLog()
    restored.configure(log._case_id, log._path, save_session=False)
    with patch('core.execution_log.log', restored):
        result = collect(r['job_id'])
    assert result['success']
    assert restored._run_id == log._run_id


def test_trace_commit_before_state_commit_recovers_without_duplicate(tmp_path):
    r = start(tmp_path, 'print("commit")')
    out = collect(r['job_id'])
    state = jobs.read_state(r['job_id'])
    state.update(collected=False, call_id=None)
    jobs.write_state(state)
    again = jobs.job_status(r['job_id'])
    assert again['_trudi_call_id'] == out['_trudi_call_id']
    assert len([e for e in log._entries if e.get('job_completion')]) == 1


def test_reset_refuses_live_writer_even_with_force_and_cancel_only_one(tmp_path):
    r1 = start(tmp_path, 'import time; time.sleep(5)', name='one')
    r2 = start(tmp_path, 'import time; time.sleep(5)', name='two')
    @jobs.reset_guard
    def reset(case_dir, force=False):
        return {'success': True}
    assert not reset(str(tmp_path), force=True)['success']
    from tools.trudi_reset import reset as cli_reset
    from tools.misc import clear_case_run
    assert cli_reset(str(tmp_path), force=True)['gate'] == 'running_jobs'
    assert clear_case_run(str(tmp_path))['gate'] == 'running_jobs'
    # Let handlers initialize before signalling; cancellation during startup is
    # separately retained as an orphan, never claimed as settled.
    time.sleep(.6)
    result = jobs.job_cancel(r1['job_id'], 'Requested scope no longer required')
    assert result.get('obligation_settled') is False, result
    assert not result.get('scope_complete')
    assert any(w['job_id'] == r2['job_id'] and w['status'] == 'running' for w in pending_work(log))
    settled = jobs.dispose_job(r1['job_id'], 'out_of_scope', 'Scope withdrawn', [result['_trudi_call_id']])
    assert settled['success'], settled
    assert all(w['job_id'] != r1['job_id'] for w in pending_work(log))
    assert collect(r2['job_id'])['success']


def test_conflict_and_concurrency_refusals(tmp_path):
    first = start(tmp_path, 'import time; time.sleep(2)')
    same = start(tmp_path, 'import time; time.sleep(2)')
    assert same['job_id'] == first['job_id']
    conflict = start(tmp_path, 'print("different")')
    assert conflict['status'] == 'capacity_refused'
    with patch.object(jobs, 'MAX_JOBS', 1):
        assert start(tmp_path, 'print("other")', name='other')['status'] == 'capacity_refused'
    assert collect(first['job_id'])['success']


def test_unknown_and_legacy_jobs_are_not_adopted(tmp_path):
    assert jobs.job_status('unknown')['status'] == 'unknown'
    with jobs.registry_lock():
        jobs.write_state({'job_id': 'legacy', 'status': 'finished', 'collected': False})
    assert jobs.job_status('legacy')['status'] == 'foreign'
    assert jobs.list_jobs()['jobs'][0]['foreign']


def test_orphan_cancellation_only_validates_retained_output(tmp_path):
    r = start(tmp_path, 'print("finished once")')
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        state = jobs.read_state(r['job_id'])
        if state['status'] in jobs.TERMINAL and not jobs.writers_alive(state):
            break
        time.sleep(.05)
    state.update(status='running', collected=False, call_id=None)
    # Simulate a dead worker before publication, with no committed result.
    jobs.write_state(state)
    assert jobs.job_status(r['job_id'])['status'] == 'orphaned'
    recovered = jobs.job_cancel(r['job_id'], 'Finalize interrupted worker')
    assert recovered['status'] == 'finished' and not recovered['scope_complete'], recovered
    assert recovered['result_status'] == 'cancelled'


def test_worker_preserves_original_working_directory(tmp_path, monkeypatch):
    case = tmp_path / 'working-case'
    case.mkdir()
    (case / 'relative.txt').write_text('relative observation')
    monkeypatch.chdir(case)
    out = start(tmp_path, 'from pathlib import Path; print(Path("relative.txt").read_text())', inline_wait=10)
    assert out['success'] and 'relative observation' in out['stdout'], out


def test_yara_capped_scan_preserves_validated_records(tmp_path):
    import pytest
    pytest.importorskip('yara')
    inputs = tmp_path / 'input'
    inputs.mkdir()
    for name in ('one', 'two'):
        (inputs / name).write_text('synthetic marker')
    rules = tmp_path / 'test.yar'
    rules.write_text('rule synthetic { strings: $x = "marker" condition: $x }')
    result = jobs.start_job([], 'yara_scan_directory', 0, '', inline_wait=0,
        adapter='tools.yara_tools:yara_scan_directory', arguments={
            'directory': str(inputs), 'rules_path': str(rules), 'max_files': 1})
    out = collect(result['job_id'])
    assert out['success'] and out['result_status'] == 'partial' and not out['scope_complete'], out
    entry = log.index().by_call_id[out['_trudi_call_id']]
    assert entry['output_manifest']['files'][0]['row_count'] == 1
    assert build_packet(log, {'description': 'marker', 'input_call_ids': [out['_trudi_call_id']]})['evidence']
    assert pending_work(log)
