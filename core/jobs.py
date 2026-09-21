"""Durable jobs bound to an investigation run, with idempotent collection."""
from __future__ import annotations
from contextlib import contextmanager
from functools import wraps
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

JOBS_DIR = os.path.expanduser('~/.cache/trudi/jobs')
INLINE_WAIT = float(os.environ.get('TRUDI_JOB_INLINE_WAIT', '15'))
MAX_JOBS = int(os.environ.get('TRUDI_MAX_JOBS', '2'))
TERMINAL = {'complete', 'partial', 'failed', 'cancelled'}


def _job_path(job_id):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', job_id):
        raise ValueError('Invalid job_id')
    return os.path.join(JOBS_DIR, job_id + '.json')


def read_state(job_id):
    with open(_job_path(job_id)) as stream:
        return json.load(stream)


def write_state(state):
    path = _job_path(state['job_id'])
    temp = path + f'.{os.getpid()}.tmp'
    with open(temp, 'w') as stream:
        json.dump(state, stream, default=str)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    fd = os.open(JOBS_DIR, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def registry_lock(name='registry'):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', name):
        raise ValueError('Invalid registry key')
    os.makedirs(JOBS_DIR, exist_ok=True)
    with open(os.path.join(JOBS_DIR, name + '.lock'), 'a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def states():
    records = []
    for path in sorted(Path(JOBS_DIR).glob('*.json')):
        try:
            records.append(json.loads(path.read_text()))
        except (OSError, ValueError):
            continue
    return records


def gc_collected(now=None):
    """Bounded registry cleanup; trace records and forensic outputs are retained."""
    import shutil
    cutoff = (time.time() if now is None else now) - 30 * 86400
    root = Path(JOBS_DIR).resolve()
    removed = []
    with registry_lock():
        for state in states():
            if len(removed) >= 32:
                break
            if (state.get('schema_version') != 2 or not state.get('run_id')
                    or not state.get('collected') or state.get('status') not in TERMINAL
                    or state.get('completed', float('inf')) >= cutoff or writers_alive(state)):
                continue
            jid = state.get('job_id', '')
            with registry_lock(jid):
                directory = root / (jid + '.d')
                # Never delete paths supplied by legacy or foreign state files.
                if directory.is_dir() and not directory.is_symlink():
                    shutil.rmtree(directory)
                Path(_job_path(jid)).unlink(missing_ok=True)
                removed.append(jid)
    return removed


def process_identity(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
    except OSError:
        return None


def writers_alive(state):
    """Check the detached process group, including children after worker exit."""
    pid = state.get('pid')
    if not isinstance(pid, int):
        if state.get('launcher_pid'):
            return process_identity(state['launcher_pid']) == state.get('launcher_start')
        return state.get('status') == 'starting'
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():
            continue
        try:
            fields = (item / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == pid and fields[0] != 'Z':
                return True
        except (OSError, ValueError, IndexError):
            continue
    return False


def _roots(arguments, output_dir=''):
    values = [output_dir] if output_dir else []
    for key, value in arguments.items():
        if key in ('output_dir', 'output_path', 'output_csv', 'output_json', 'storage_file') and isinstance(value, str) and value:
            values.append(value)
    # pffexport appends this suffix to its destination.
    if output_dir:
        values.append(output_dir + '.export')
    return sorted({os.path.realpath(os.path.expanduser(v)) for v in values})


def _overlap(a, b):
    return any(x == y or x.startswith(y + os.sep) or y.startswith(x + os.sep) for x in a for y in b if x and y)


def reset_guard(fn):
    @wraps(fn)
    def wrapped(case_dir, *args, **kwargs):
        case = os.path.realpath(os.path.expanduser(case_dir))
        # Lock order is registry -> trace, the same order as job start.
        with registry_lock():
            from core.operations import running as running_operations
            operations = running_operations(case_dir=case)
            if operations:
                return {'success': False, 'gate': 'running_operations',
                        'operation_ids': [s['operation_id'] for s in operations],
                        'error': 'In-process writers are still running; inspect misc.operation_status before resetting.'}
            running = [s['job_id'] for s in states() if
                       (s.get('case_dir') == case or _overlap(s.get('output_roots', [s.get('output_dir', '')]), [case]))
                       and writers_alive(s)]
            if running:
                return {'success': False, 'gate': 'running_jobs', 'job_ids': running,
                        'error': 'Cancel these workers and collect their results before resetting. --force cannot bypass active writers.'}
            return fn(case_dir, *args, **kwargs)
    return wrapped


def start_job(cmd, tool, timeout, output_dir, needs_sudo=False, *, inline_wait=None,
              adapter=None, arguments=None):
    from core.execution_log import log, current_mcp_tool, current_mcp_arguments
    from core.paths import assert_output_safe
    from core.phase_routing import work_state, append_event, request_identity, source_versions, normalized, execution_policy
    log._auto_recover()
    log._require_configured('start background job')
    gc_collected()
    arguments = dict(arguments or current_mcp_arguments.get() or {})
    if not arguments:
        import shlex
        arguments = {'command': shlex.join(cmd), 'output_dir': output_dir}
    roots = _roots(arguments, output_dir)
    for root in roots:
        assert_output_safe(root)
    origin = current_mcp_tool.get() or tool
    identity = hashlib.sha256(json.dumps([log._run_id, origin, arguments, cmd, roots,
        source_versions(arguments), execution_policy(origin)], sort_keys=True, default=str).encode()).hexdigest()
    with registry_lock():
        existing = states()
        unsettled = [s for s in existing if (not s.get('collected') and s.get('run_id') == log._run_id)
                     or writers_alive(s)]
        same = next((s for s in unsettled if s.get('identity') == identity), None)
        if same:
            return {'success': True, 'status': 'running' if writers_alive(same) else 'awaiting_collection',
                    'job_id': same['job_id'], 'request_id': same.get('request_id'), 'reused': True}
        previous = next((s for s in reversed(existing) if s.get('identity') == identity
                         and s.get('collected') and s.get('status') == 'complete'), None)
        if previous:
            from core.job_outputs import verify_manifest
            if not verify_manifest(previous.get('output_manifest') or {'files': []}):
                return client_result(job_status(previous['job_id']))
        conflict = [s['job_id'] for s in unsettled if _overlap(roots, s.get('output_roots', []))]
        live = [s['job_id'] for s in existing if writers_alive(s)]
        if conflict or len(live) >= MAX_JOBS:
            return {'success': False, 'status': 'capacity_refused', 'job_ids': conflict or live,
                    'error': 'Output destination is reserved or the concurrent job limit is reached'}
        job_id = re.sub('[^A-Za-z0-9_-]', '_', tool) + '-' + os.urandom(6).hex()
        directory = str(Path(JOBS_DIR) / (job_id + '.d'))
        os.makedirs(directory)
        with log.transaction():
            rid = request_identity(log, origin, arguments)
            work = work_state(log).get(rid)
            if not work or work.get('status') != 'running':
                work = append_event(log, 'phase_work', request_id=rid, tool=normalized(origin),
                    arguments=arguments, source_versions=source_versions(arguments),
                    required_phase=log._current_phase, scope=log._case_id, status='running',
                    owner_pid=os.getpid(), owner_start=process_identity(os.getpid()))
            fields = {k: v for k, v in work.items() if k not in ('call_id', 'type', 'ts', 'dair_phase', 'dair_depth')}
            append_event(log, 'phase_work', **{**fields, 'job_id': job_id, 'status': 'running'})
        trace = os.path.realpath(log._path)
        records_path = ''
        if adapter == 'tools.yara_tools:yara_scan_directory':
            records_path = str(Path(trace).parent / '.job-results' / (job_id + '.jsonl'))
            roots.append(records_path)
        state = {'schema_version': 2, 'job_id': job_id, 'identity': identity,
            'case_id': log._case_id, 'run_id': log._run_id, 'trace_path': trace,
            'case_dir': str(Path(trace).parent.parent) if Path(trace).parent.name == 'analysis' else str(Path(trace).parent),
            'phase': log._current_phase, 'tool': origin, 'arguments': arguments,
            'scope': work.get('scope', log._case_id), 'source_versions': source_versions(arguments),
            'input_call_ids': sorted({c for c in (log._last_dair_cid, work.get('trigger_call_id')) if c}),
            'request_id': rid, 'cmd': cmd, 'adapter': adapter, 'timeout': timeout,
            'output_dir': output_dir, 'output_roots': roots, 'needs_sudo': needs_sudo,
            'directory': directory, 'started': time.time(), 'status': 'starting',
            'working_directory': os.getcwd(), 'records_path': records_path,
            'launcher_pid': os.getpid(), 'launcher_start': process_identity(os.getpid()),
            'collected': False, 'call_id': None}
        write_state(state)
        env = worker_environment(state)
        try:
            proc = subprocess.Popen([sys.executable, '-m', 'core.job_worker', job_id],
                cwd=state['working_directory'], env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
            state.update(pid=proc.pid, process_start=process_identity(proc.pid), status='running')
        except OSError as exc:
            state.update(status='failed', error=str(exc), result={'success': False, 'error': str(exc)})
        write_state(state)
    wait = INLINE_WAIT if inline_wait is None else inline_wait
    deadline = time.monotonic() + max(0, wait)
    while time.monotonic() < deadline:
        current = read_state(job_id)
        if current['status'] in TERMINAL and not writers_alive(current):
            return client_result(job_status(job_id))
        time.sleep(min(.05, max(0, deadline - time.monotonic())))
    return {'success': True, 'status': 'running', 'job_id': job_id, 'request_id': rid,
            'output_dir': output_dir, 'hint': 'Continue other work; poll misc.job_status between useful steps.'}


def _owned(state, log):
    return bool(state.get('run_id') and state.get('run_id') == log._run_id and
                state.get('trace_path') == os.path.realpath(log._path or ''))


def worker_environment(state):
    root = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ, TRUDI_JOB_WORKER='1', TRUDI_JOBS_DIR=JOBS_DIR,
               TRUDI_JOB_RECORDS=state.get('records_path', ''))
    env['PYTHONPATH'] = root + (os.pathsep + env['PYTHONPATH'] if env.get('PYTHONPATH') else '')
    return env


def job_status(job_id):
    from core.execution_log import log
    from core.phase_routing import finish, work_state
    from core.job_outputs import verify_manifest
    log._auto_recover()
    try:
        with registry_lock(job_id):
            state = read_state(job_id)
            if not _owned(state, log):
                return {'success': False, 'status': 'foreign', 'job_id': job_id,
                        'error': 'Job belongs to another or unverifiable investigation run; nothing collected'}
            if state['status'] not in TERMINAL or writers_alive(state):
                return {'success': True, 'status': 'running' if writers_alive(state) else 'orphaned',
                        'job_id': job_id, 'elapsed_seconds': round(time.time() - state['started'], 1),
                        'request_id': state['request_id'], 'output_dir': state['output_dir'],
                        'next_action': 'poll_between_other_work' if writers_alive(state) else 'misc.job_cancel to finalize retained partial output without re-executing'}
            with log.transaction():
                prior = next((e for e in log._entries if e.get('job_id') == job_id and
                              e.get('type') == 'tool_call' and e.get('job_completion')), None)
                if prior:
                    result = dict(prior['job_result'])
                    errors = verify_manifest(prior.get('output_manifest') or {'files': []}, hashes=False)
                    if errors:
                        result.update(success=False, result_status='failed', scope_complete=False,
                                      error='Output changed after worker completion', verification_errors=errors,
                                      validated_outputs=[])
                else:
                    result = dict(state.get('result') or {'success': False, 'error': state.get('error')})
                    manifest = state.get('output_manifest') or {'files': []}
                    result['validated_outputs'] = [{k: item[k] for k in ('path', 'byte_size', 'row_count', 'complete') if k in item}
                                                   for item in manifest.get('files', [])]
                    errors = verify_manifest(manifest)
                    if errors:
                        result.update(success=False, result_status='failed', scope_complete=False,
                                      error='Output changed after worker completion', verification_errors=errors,
                                      validated_outputs=[])
                        manifest = {'files': [], 'rejected_files': errors}
                    from core.execution_log import current_mcp_tool
                    token = current_mcp_tool.set(state['tool'])
                    result.update(job_id=job_id, request_id=state['request_id'], status='finished',
                                  result_status=result.get('result_status', state['status']))
                    metadata = {k: v for k, v in result.items() if k in (
                        'coverage_window', 'session_artifact', 'scope_complete', 'result_status', 'parser',
                        'parse_failures', 'files_seen', 'files_parsed', 'source_hashes', 'reproduction')}
                    metadata.update(job_id=job_id, job_completion=True, run_id=state['run_id'],
                        job_result=result, originating_phase=state['phase'], mcp_arguments=state['arguments'],
                        dair_phase=state['phase'])
                    try:
                        cid = log.record_tool_call(str(result.get('cmd') or state['cmd'] or state['tool']),
                            result.get('success', False), result.get('truncated', False), result.get('retries', 0),
                            result.get('exit_code', -1), stderr=result.get('stderr', result.get('error', '')),
                            elapsed_seconds=result.get('elapsed_seconds', time.time() - state['started']),
                            timed_out=result.get('timed_out', False), input_call_ids=state['input_call_ids'],
                            stdout_excerpt=state.get('stdout_full', result.get('stdout', ''))[:600],
                            stdout_full=state.get('stdout_full', result.get('stdout', '')),
                            output_path=result.get('output_path') or state['output_dir'], output_manifest=manifest,
                            extra=metadata)
                    finally:
                        current_mcp_tool.reset(token)
                    result.update(_trudi_call_id=cid, job_id=job_id, request_id=state['request_id'],
                                  status='finished', result_status=result.get('result_status', state['status']))
                work = work_state(log).get(state['request_id'])
                if work and work['status'] not in ('completed', 'dispositioned'):
                    from core.evidence_admission import scope_complete
                    finish(log, work, result, status='completed' if scope_complete(result) else 'incomplete')
                state.update(collected=True, call_id=result['_trudi_call_id'])
                write_state(state)
                return {**result, 'cached': prior is not None}
    except (OSError, ValueError) as exc:
        return {'success': False, 'status': 'unknown', 'job_id': job_id, 'error': str(exc)}


def list_jobs():
    from core.execution_log import log
    rows = [{k: s.get(k) for k in ('job_id', 'tool', 'run_id', 'case_id', 'status', 'collected', 'request_id', 'output_dir')}
            | {'foreign': not _owned(s, log), 'writers_alive': writers_alive(s)} for s in states()]
    from core.job_adapters import guidance
    return {'success': True, 'jobs': rows, 'count': len(rows), 'adapter_policies': guidance(),
            'inline_wait_seconds': INLINE_WAIT, 'max_concurrent_jobs': MAX_JOBS}


def recover_legacy(job_id, reason):
    """Archive registry metadata only, retaining every result/output for recovery."""
    if not reason or not reason.strip():
        return {'success': False, 'error': 'A recovery reason is required'}
    with registry_lock():
        try:
            state = read_state(job_id)
        except (ValueError, OSError) as exc:
            return {'success': False, 'error': str(exc)}
        if state.get('schema_version') == 2 or state.get('run_id'):
            return {'success': False, 'error': 'Use collection/cancellation for owned jobs'}
        pid = state.get('pid')
        if writers_alive(state) or (isinstance(pid, int) and process_identity(pid) is not None):
            return {'success': False, 'error': 'A possible owner or child is alive; ownership must be reconciled first'}
        if not isinstance(pid, int) and not (state.get('collected') and state.get('status') in ('finished', 'complete', 'completed')):
            return {'success': False, 'error': 'Legacy ownership is unverifiable; metadata and outputs retained for manual recovery'}
        archive = Path(JOBS_DIR) / 'recovery'
        archive.mkdir(exist_ok=True)
        state['recovery'] = {'reason': reason, 'archived_at': time.time(),
                             'ownership': 'not_attached_to_any_run', 'outputs_preserved': True}
        target = archive / (job_id + '.json')
        if target.exists():
            return {'success': False, 'error': 'Recovery archive already exists'}
        target.write_text(json.dumps(state, default=str))
        Path(_job_path(job_id)).unlink()
        return {'success': True, 'status': 'archived_for_recovery', 'archive': str(target),
                'uncollected_results_preserved': not state.get('collected'), 'outputs_preserved': True}


def client_result(result):
    from core.review_delivery import wire_size, MAX_WIRE_BYTES
    from core.readiness import digest
    if wire_size(result) <= MAX_WIRE_BYTES - 256:
        return result
    view = {k: result[k] for k in ('success', 'status', 'result_status', 'scope_complete',
            'job_id', 'request_id', '_trudi_call_id', 'elapsed_seconds', 'timed_out', 'cached') if k in result}
    stable = {k: v for k, v in result.items() if k != 'cached'}
    view.update(details_required=True, state_version=digest(stable),
                details={'tool': 'misc.job_status', 'arguments': {'job_id': result['job_id'], 'state_version': digest(stable)},
                         'sections': sorted(stable)})
    if result.get('error'):
        view['error'] = str(result['error'])[:600]
    return view


def dispose_job(job_id, reason, note, evidence_call_ids):
    from core.execution_log import log
    from core.phase_routing import work_state, append_event
    try:
        with registry_lock(job_id), log.transaction():
            state = read_state(job_id)
            if not _owned(state, log) or not state.get('collected') or writers_alive(state):
                return {'success': False, 'gate': 'job_disposition',
                        'error': 'Job must belong to this run, have stopped, and have a collected result'}
            if not note.strip() or state.get('call_id') not in (evidence_call_ids or []):
                return {'success': False, 'gate': 'job_disposition',
                        'error': 'Explain the unmet scope and cite this job’s collected call_id'}
            work = work_state(log).get(state['request_id'])
            if not work:
                return {'success': False, 'error': 'Job work obligation is unavailable'}
            cid = log.record_disposition('job', job_id, reason, note=note, evidence_call_ids=evidence_call_ids)
            fields = {k: v for k, v in work.items() if k not in ('call_id', 'type', 'ts', 'dair_phase', 'dair_depth')}
            append_event(log, 'phase_work', **{**fields, 'status': 'dispositioned', 'disposition_call_id': cid})
            return {'success': True, '_trudi_call_id': cid, 'job_id': job_id,
                    'request_id': state['request_id'], 'status': 'dispositioned'}
    except (ValueError, OSError) as exc:
        return {'success': False, 'error': str(exc)}


def job_cancel(job_id, reason):
    from core.execution_log import log
    if not isinstance(reason, str) or not reason.strip():
        return {'success': False, 'error': 'A cancellation reason is required'}
    try:
        with registry_lock(), registry_lock(job_id):
            state = read_state(job_id)
            if not _owned(state, log):
                return {'success': False, 'status': 'foreign', 'job_id': job_id}
            Path(state['directory'], 'cancel.request').write_text(reason)
            recovery_started = False
            if not writers_alive(state) and state['status'] not in TERMINAL:
                # Explicit cancellation may finalize an orphan, but polling
                # never executes work. Recovery only validates retained output.
                before = Path(state['directory'], 'before.json')
                if not before.exists():
                    state.update(status='failed', result={'success': False, 'scope_complete': False,
                        'result_status': 'failed', 'error': 'Worker stopped before its ownership snapshot; output requires separate validation'})
                    write_state(state)
                else:
                    env = dict(worker_environment(state), TRUDI_JOB_RECOVER='1')
                    proc = subprocess.Popen([sys.executable, '-m', 'core.job_worker', job_id],
                        cwd=state.get('working_directory', str(Path(__file__).resolve().parents[1])), env=env,
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        start_new_session=True)
                    state.update(pid=proc.pid, process_start=process_identity(proc.pid), status='finalizing')
                    write_state(state)
                    # The previous worker's ready marker must not cause us to
                    # signal this recovery worker before it installs a handler.
                    recovery_started = True
            if not recovery_started and writers_alive(state) and Path(state['directory'], 'handler.ready').exists():
                if state.get('process_start') and process_identity(state['pid']) not in (None, state['process_start']):
                    return {'success': False, 'status': 'unknown', 'error': 'Worker PID identity changed'}
                if state.get('needs_sudo'):
                    subprocess.run(['sudo', '-n', 'kill', '-TERM', '--', '-' + str(state['pid'])], timeout=10, check=True)
                else:
                    os.killpg(state['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            state = read_state(job_id)
            if not writers_alive(state):
                result = job_status(job_id)
                return {**result, 'cancel_reason': reason, 'obligation_settled': False}
            time.sleep(.05)
        return {'success': False, 'status': 'cancelling', 'job_id': job_id,
                'error': 'Workers have not stopped; scope obligation and reset guard remain active'}
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {'success': False, 'status': 'cancel_failed', 'error': str(exc), 'job_id': job_id}
