import os
from pathlib import Path
from unittest.mock import patch

from core import jobs
from core.execution_log import log, ExecutionLog


def test_directory_policy_uses_resolved_input_and_preserves_signature(tmp_path, monkeypatch):
    from tools.eztools import ez_pecmd
    import inspect
    monkeypatch.setenv('TRUDI_BACKGROUND_JOBS', '1')
    folder = tmp_path / 'prefetch'
    folder.mkdir()
    file = folder / 'one.pf'
    file.touch()
    with patch('core.jobs.start_job', return_value={'job_id': 'selected'}) as start, \
         patch('tools.eztools._ez', return_value={'success': True}) as execute:
        assert ez_pecmd(str(folder), str(tmp_path / 'out'))['job_id'] == 'selected'
        assert start.call_args.kwargs['adapter'] == 'tools.eztools:ez_pecmd'
        ez_pecmd(str(file), str(tmp_path / 'out'))
        assert execute.call_count == 1 and start.call_count == 1
    assert 'prefetch_path' in inspect.signature(ez_pecmd).parameters


def test_worker_executes_wrapper_finalizer_and_records_metadata(tmp_path, monkeypatch):
    from core.job_worker import main
    import core.execution_log as E
    from tools import eztools
    output = tmp_path / 'exports'
    output.mkdir()
    with patch('core.jobs.subprocess.Popen') as popen:
        popen.return_value.pid = 99999999
        result = jobs.start_job([], 'ez_evtxecmd', 0, str(output), inline_wait=0,
            adapter='tools.eztools:ez_evtxecmd', arguments={
                'evtx_path': str(tmp_path / 'events'), 'output_dir': str(output), 'output_file': 'events.csv'})
    def run_dll(dll, args, **kw):
        (output / 'events.csv').write_text('TimeCreated,EventId\n2025-01-01T00:00:00,4624\n')
        cid = E.log.record_tool_call('parse event logs', True, False, 0, 0)
        return {'success': True, '_trudi_call_id': cid, 'cmd': 'parse event logs', 'exit_code': 0}
    monkeypatch.setenv('TRUDI_JOB_WORKER', '1')
    monkeypatch.setenv('TRUDI_JOBS_DIR', jobs.JOBS_DIR)
    worker_log = ExecutionLog()
    with patch.object(E, 'log', worker_log), patch.object(E, '_SESSION_FILE', E._SESSION_FILE), \
         patch.object(E, '_CALL_ID_COUNTER_FILE', E._CALL_ID_COUNTER_FILE), \
         patch.object(E, '_TRACE_LOCK_FILE', E._TRACE_LOCK_FILE), \
         patch('signal.signal'), patch.object(eztools, 'run_dotnet', side_effect=run_dll):
        main(result['job_id'])
    state = jobs.read_state(result['job_id'])
    assert state['status'] == 'complete'
    assert state['result']['coverage_window']['start'].startswith('2025-01-01')
    assert state['result']['session_artifact']
    assert state['output_manifest']['files'][0]['sha256']
    out = jobs.job_status(result['job_id'])
    assert out['success']
    assert log.index().by_call_id[out['_trudi_call_id']]['session_artifact']


def test_partial_csv_drops_unterminated_unquoted_record(tmp_path):
    from core.job_outputs import finalize
    path = tmp_path / 'records.csv'
    path.write_text('name,value\ngood,1\ncut,par')
    result = finalize([str(path)], {}, complete=False, job_id='test')
    data = Path(result['files'][0]['path']).read_text()
    assert 'good,1' in data and 'cut,par' not in data


def test_large_job_response_has_versioned_lossless_route():
    from core.review_delivery import wire_size
    result = {'success': True, 'status': 'finished', 'job_id': 'test', 'cached': False,
              'validated_outputs': [{'path': '漢字' * 1000}] * 30}
    view = jobs.client_result(result)
    assert wire_size(view) < 8192
    assert view['details']['tool'] == 'misc.job_status'
    assert view['state_version'] == jobs.client_result({**result, 'cached': True})['state_version']


def test_complete_wrapper_cannot_admit_corrupt_csv_or_archive(tmp_path):
    from core.job_outputs import finalize
    path = tmp_path / 'records.csv'
    path.write_text('name,value\ngood,1\n"cut')
    archive = tmp_path / 'bad.zip'
    archive.write_bytes(b'PK unreadable')
    result = finalize([str(path), str(archive)], {}, complete=True, job_id='synthetic')
    assert len(result['files']) == 1
    assert not result['files'][0]['complete']
    assert 'good,1' in Path(result['files'][0]['path']).read_text()
    assert any(f['path'] == str(archive) for f in result['rejected_files'])


def test_gc_retains_uncollected_and_outputs(tmp_path):
    import time
    now = time.time()
    with jobs.registry_lock():
        for jid, collected in [('old', True), ('pending', False)]:
            directory = Path(jobs.JOBS_DIR) / (jid + '.d')
            directory.mkdir()
            (directory / 'worker_trace.json').write_text('{}')
            jobs.write_state({'schema_version': 2, 'job_id': jid, 'run_id': 'old-run',
                'status': 'complete', 'collected': collected, 'completed': now - 40 * 86400})
    evidence = tmp_path / 'retained.txt'
    evidence.write_text('forensic output')
    assert jobs.gc_collected(now) == ['old']
    assert jobs.read_state('pending') and evidence.exists()


def test_polling_never_runs_slow_fallback_and_completion_waits_for_it(tmp_path, monkeypatch):
    import threading
    import core.execution_log as E
    from core.job_worker import main
    from tools import eztools
    output = tmp_path / 'exports'
    output.mkdir()
    with patch('core.jobs.subprocess.Popen') as popen:
        popen.return_value.pid = 99999999
        start = jobs.start_job([], 'ez_pecmd', 0, str(output), inline_wait=0,
            adapter='tools.eztools:ez_pecmd', arguments={
                'prefetch_path': str(tmp_path / 'prefetch'), 'output_dir': str(output), 'output_file': 'records.csv'})
    entered, release = threading.Event(), threading.Event()
    def fallback(*args):
        entered.set()
        assert release.wait(10)
        (output / 'records.csv').write_text('ExecutableName,RunCount\nPROGRAM.EXE,1\n')
        cid = E.log.record_tool_call('pyscca parse', True, False, 0, 0)
        return {'success': True, 'parser': 'libscca', '_trudi_call_id': cid}
    monkeypatch.setenv('TRUDI_JOB_WORKER', '1')
    monkeypatch.setenv('TRUDI_JOBS_DIR', jobs.JOBS_DIR)
    worker_log = ExecutionLog()
    with patch.object(E, 'log', worker_log), patch.object(E, '_SESSION_FILE', E._SESSION_FILE), \
         patch.object(E, '_CALL_ID_COUNTER_FILE', E._CALL_ID_COUNTER_FILE), \
         patch.object(E, '_TRACE_LOCK_FILE', E._TRACE_LOCK_FILE), patch('signal.signal'), \
         patch.object(eztools, '_ez', return_value={'success': False, 'tool_unavailable': True}), \
         patch.object(eztools, '_prefetch_libscca', side_effect=fallback) as parse:
        worker = threading.Thread(target=main, args=(start['job_id'],))
        worker.start()
        try:
            assert entered.wait(10)
            with patch.object(E, 'log', log):
                assert jobs.job_status(start['job_id'])['status'] != 'finished'
            assert parse.call_count == 1
            assert jobs.read_state(start['job_id'])['status'] == 'running'
        finally:
            release.set()
            worker.join(10)
    result = jobs.job_status(start['job_id'])
    assert result['success'] and result['parser'] == 'libscca', result
    assert result['validated_outputs']
