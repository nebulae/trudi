"""Ownership of in-process writers that can outlive a client watchdog."""
from contextvars import ContextVar, copy_context
import inspect
import json
import os
from pathlib import Path
import threading
import time
import uuid
from core.readiness import digest

operation_run = ContextVar('operation_run', default=None)
_lock = threading.RLock()
_active = {}


def root():
    from core.jobs import JOBS_DIR
    path = Path(JOBS_DIR) / 'operations'
    path.mkdir(parents=True, exist_ok=True)
    return path


def persist(state):
    path = root() / (state['operation_id'] + '.json')
    temp = path.with_suffix('.tmp-' + uuid.uuid4().hex)
    temp.write_text(json.dumps(state, default=str))
    os.replace(temp, path)


def running(case_dir=None, run_id=None):
    from core.phase_routing import process_identity
    result = []
    for path in root().glob('*.json'):
        try:
            state = json.loads(path.read_text())
            if state['status'] != 'running' or (run_id and state.get('run_id') != run_id):
                continue
            if case_dir and not os.path.realpath(state['trace_path']).startswith(os.path.realpath(case_dir) + os.sep):
                continue
            if process_identity(state['pid']) == state['process_start']:
                result.append(state)
        except (OSError, ValueError, KeyError):
            continue
    return result


def check_owner(log):
    expected = operation_run.get()
    if expected and expected != log._run_id:
        raise RuntimeError('Operation belongs to a previous investigation run; stale write refused')


def pending(state, seconds):
    return {'success': False, 'status': 'running', 'timed_out': True,
            'waited_seconds': seconds, 'operation_id': state['operation_id'],
            'tool': state['tool'], 'run_id': state['run_id'],
            'next_action': 'misc.operation_status',
            'error': 'Client wait expired; the operation is still running. Do not duplicate it.'}


def execute(fn, label, seconds, args, kwargs):
    from core.execution_log import log
    from core.phase_routing import source_versions, process_identity
    bound = inspect.signature(fn).bind(*args, **kwargs)
    bound.apply_defaults()
    key = digest([log._run_id, label, bound.arguments, source_versions(bound.arguments)])
    from core.jobs import registry_lock
    with _lock, registry_lock():
        old = _active.get(key)
        if old:
            thread, box, state = old
            if thread.is_alive():
                return pending(state, seconds)
            _active.pop(key, None)
            if state.get('detached'):
                if box.get('error'):
                    raise box['error']
                return box['result']
        remote = next((s for s in running(run_id=log._run_id) if s.get('request_key') == key), None)
        if remote:
            return pending(remote, seconds)
        state = {'operation_id': 'OP-' + uuid.uuid4().hex, 'request_key': key,
                 'run_id': log._run_id, 'trace_path': log._path or '', 'tool': label,
                 'pid': os.getpid(), 'process_start': process_identity(os.getpid()),
                 'status': 'running', 'started': time.time()}
        box = {}
        context = copy_context()
        def body():
            token = operation_run.set(state['run_id'])
            try:
                box['result'] = fn(*args, **kwargs)
                check_owner(log)
                state.update(status='complete', result=box['result'])
            except BaseException as exc:
                box['error'] = exc
                state.update(status='failed', error=str(exc))
            finally:
                with _lock:
                    state['finished'] = time.time()
                    persist(state)
                operation_run.reset(token)
        thread = threading.Thread(target=lambda: context.run(body), daemon=True, name='trudi-timeout:' + label)
        _active[key] = (thread, box, state)
        persist(state)
        thread.start()
    thread.join(seconds)
    with _lock:
        if thread.is_alive():
            state['detached'] = True
            persist(state)
            return pending(state, seconds)
        _active.pop(key, None)
    if box.get('error'):
        raise box['error']
    return box.get('result')


def status(operation_id, log):
    if not isinstance(operation_id, str) or not operation_id.startswith('OP-') or not operation_id[3:].isalnum():
        return {'success': False, 'error': 'Invalid operation_id'}
    try:
        state = json.loads((root() / (operation_id + '.json')).read_text())
    except (OSError, ValueError):
        return {'success': False, 'error': 'Unknown operation_id'}
    if state['run_id'] != log._run_id:
        return {'success': False, 'error': 'Operation belongs to another run'}
    if state['status'] == 'running':
        if not any(s['operation_id'] == operation_id for s in running(run_id=log._run_id)):
            return {'success': False, 'status': 'interrupted', 'operation_id': operation_id,
                    'next_action': 'resume_checkpoint', 'error': 'Owner stopped; resume the saved review checkpoint'}
        return pending(state, 0)
    return {'success': state['status'] == 'complete', 'status': state['status'],
            'operation_id': operation_id, 'result': state.get('result'), 'error': state.get('error')}
