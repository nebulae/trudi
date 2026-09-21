"""Detached worker; owns wrapper execution, fallback, validation and finalization."""
import importlib
import json
import os
from pathlib import Path
import signal
import sys
import time


class Cancelled(BaseException):
    pass


def main(job_id):
    from core import jobs
    from core.job_outputs import snapshot, finalize
    jobs.JOBS_DIR = os.environ.get('TRUDI_JOBS_DIR', jobs.JOBS_DIR)
    # Start cannot publish its PID after the worker has already completed.
    with jobs.registry_lock():
        state = jobs.read_state(job_id)
        try:
            owner = json.loads(Path(state['trace_path']).read_text()).get('run_id')
        except (OSError, ValueError):
            owner = None
        if owner != state.get('run_id'):
            state.update(status='failed', result={'success': False, 'scope_complete': False,
                'result_status': 'failed', 'error': 'Investigation run changed before worker execution'})
            jobs.write_state(state)
            return
        state.update(pid=os.getpid(), process_start=jobs.process_identity(os.getpid()), status='running')
        jobs.write_state(state)
    directory = Path(state['directory'])
    from core import execution_log as E
    E._SESSION_FILE = str(directory / 'session.json')
    E._CALL_ID_COUNTER_FILE = str(directory / 'counter.json')
    E._TRACE_LOCK_FILE = str(directory / 'hook.lock')
    E.log.configure(state['case_id'], str(directory / 'worker_trace.json'), save_session=False)
    E.log._current_phase = state['phase']
    token = E.current_mcp_tool.set(state['tool'])
    arg_token = E.current_mcp_arguments.set(state['arguments'])
    recovering = os.environ.get('TRUDI_JOB_RECOVER') == '1'
    before = (json.loads(Path(directory, 'before.json').read_text()) if recovering else
              snapshot(state['output_roots']))
    if not recovering:
        Path(directory, 'before.json').write_text(json.dumps(before))
    cancelled = False
    finalizing = False
    def stop(signum, frame):
        nonlocal cancelled
        if not cancelled:
            cancelled = True
            if not finalizing:
                raise Cancelled()
    signal.signal(signal.SIGTERM, stop)
    Path(directory, 'handler.ready').touch()
    result = {}
    try:
        if recovering or Path(directory, 'cancel.request').exists():
            raise Cancelled()
        if state.get('adapter'):
            from core.job_adapters import ADAPTERS
            if state['adapter'] not in ADAPTERS:
                raise ValueError('Unregistered worker adapter')
            module, name = state['adapter'].split(':')
            fn = getattr(importlib.import_module(module), name)
            result = fn(**state['arguments'])
        else:
            from core.executor import run
            result = run(state['cmd'], timeout=state['timeout'], output_dir=state['output_dir'] or None,
                         needs_sudo=state['needs_sudo'])
    except Cancelled:
        result = {'success': False, 'exit_code': -15, 'stderr': 'Cancelled by request', 'cancelled': True}
    except BaseException as exc:
        result = {'success': False, 'exit_code': -1, 'stderr': f'{type(exc).__name__}: {exc}'}
    finally:
        E.current_mcp_tool.reset(token)
        E.current_mcp_arguments.reset(arg_token)
    try:
        finalizing = True
        state['status'] = 'finalizing'
        jobs.write_state(state)
        entries = [e for e in E.log._entries if e.get('type') == 'tool_call']
        final = entries[-1] if entries else {}
        for key in ('coverage_window', 'session_artifact', 'scope_complete', 'parser', 'cmd'):
            if key in final:
                result.setdefault(key, final[key])
        cancelled = cancelled or Path(directory, 'cancel.request').exists()
        complete = bool(result.get('success') and not cancelled and not result.get('timed_out')
                        and not result.get('capped') and not result.get('parse_failures')
                        and not result.get('hives_failed') and not result.get('errors')
                        and result.get('scope_complete') is not False)
        manifest = finalize(state['output_roots'], before, complete=complete, job_id=job_id)
        cancelled = cancelled or Path(directory, 'cancel.request').exists()
        if manifest['rejected_files'] or cancelled:
            complete = False
        status = 'cancelled' if cancelled else 'complete' if complete else 'partial' if manifest['files'] else 'failed'
        result.update(scope_complete=complete, result_status=status,
                      elapsed_seconds=round(time.time() - state['started'], 3))
        if cancelled:
            result['success'] = False
        # Python adapters can produce multiple command records. Preserve their
        # recipes and metadata together; private worker IDs are not case IDs.
        result['reproduction'] = {'tool': state['tool'], 'arguments': state['arguments'],
            'adapter': state.get('adapter'), 'python_version': sys.version.split()[0],
            'steps': [{k: e[k] for k in ('cmd', 'success', 'exit_code', 'coverage_window', 'parser') if k in e} for e in entries]}
        from core.job_outputs import sha256
        result['reproduction']['finalizer_sha256'] = sha256(str(Path(__file__).with_name('job_outputs.py')))
        if state.get('adapter'):
            module = importlib.import_module(state['adapter'].split(':')[0])
            result['reproduction']['adapter_sha256'] = sha256(module.__file__)
        versions = {}
        for name in ('pyscca', 'yara', 'plaso', 'pyevtx', 'pypff'):
            module = sys.modules.get(name)
            if module is None:
                continue
            version = getattr(module, '__version__', None)
            if version is None and callable(getattr(module, 'get_version', None)):
                try:
                    version = module.get_version()
                except Exception:
                    pass
            versions[name] = str(version) if version is not None else 'not_reported'
        result['reproduction']['parser_versions'] = versions
        result['reproduction']['version_limitation'] = 'External binary versions are available only when emitted by the tool; adapter and finalizer code hashes are exact.'
        stdout = final.get('stdout_excerpt', '')
        if final.get('stdout_path'):
            stdout = Path(final['stdout_path']).read_text(errors='replace')
        if not entries:
            # Pure Python adapters have no subprocess record. Retain the actual
            # structured result, not an empty synthetic invocation log.
            stdout = json.dumps(result, default=str)
        result.pop('_trudi_call_id', None)
        for item in result.get('hives', []):
            item.pop('_trudi_call_id', None)
        state.update(status=status, result=result, output_manifest=manifest,
                     stdout_full=stdout, completed=time.time())
        jobs.write_state(state)
    except BaseException as exc:
        state.update(status='failed', result={'success': False, 'scope_complete': False,
                     'error': 'Worker finalization failed: ' + str(exc), 'result_status': 'failed'})
        jobs.write_state(state)


if __name__ == '__main__':
    main(sys.argv[1])
