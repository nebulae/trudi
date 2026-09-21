"""Durable evidence exchanges for one finding, across retries and reconnects."""
from copy import deepcopy
import fcntl
import json
from pathlib import Path
import time

from core import synthesis_session as S
from core.evidence_packets import packet_current
from core.evidence_requests import normalize_requests
from core.readiness import digest

KIND = 'finding_review_progress'


def advance(log, system, user, packet, ids):
    key = 'FR-' + digest([log._run_id, packet['packet_id']])[:24]
    with open(Path(log._path).parent / ('.' + key + '.lock'), 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'success': False, 'status': 'in_progress', 'review_pending': True,
                    'review_session_id': key, 'next_action': 'review_already_running'}
        return _advance(log, key, system, user, packet, ids)


def _advance(log, key, system, user, packet, ids):
    from tools import reasoning as R
    session = S.latest(log, KIND, key) or {'session_id': key, 'run_id': log._run_id,
        'tasks': [{'task_id': key, 'provider_calls': 0, 'status': 'pending', 'cache': {},
                   'pending': [], 'coverage': [], 'access_failures': {}}]}
    task = session['tasks'][0]
    if task.get('result') and task['status'] == 'complete':
        return {**deepcopy(task['result']), 'cached': True, 'review_session_id': key}
    if task['status'] == 'blocked' and not task.get('retryable'):
        return {**deepcopy(task['result']), 'cached': True, 'review_session_id': key}
    def save():
        S.checkpoint(log, session, KIND)
    started, before, rounds = time.monotonic(), task['provider_calls'], 0
    result = {}
    task['status'] = 'pending'
    while task['provider_calls'] - before < S.SLICE_CALL_LIMIT and time.monotonic() - started < R._REASON_WATCHDOG - 10:
        if not packet_current(log, packet):
            return {'success': False, 'status': 'access_failure', 'error': 'Evidence changed; refresh the packet'}
        if task['pending']:
            if rounds >= R.COMPAT_EVIDENCE_ROUNDS:
                break
            requests = task['pending'][:R.COMPAT_EVIDENCE_MAX_REQUESTS]
            records = []
            for request in requests:
                rid = S.request_key(packet, request)
                cached = task['cache'].get(rid)
                if cached:
                    record = cached['record']
                    task['cache_hits'] = task.get('cache_hits', 0) + 1
                else:
                    block, recs = R._resolve_evidence_requests([request], ids,
                        R.COMPAT_EVIDENCE_ROUND_CHARS // max(1, len(requests)), packet)
                    record = recs[0]
                    record['request_id'] = rid
                    if record['status'] == 'ok' and record.get('searched'):
                        task['cache'][rid] = {'record': record, 'block': block}
                    else:
                        task['access_failures'][rid] = {**record, 'access_message': block}
                if rid in task['cache']:
                    task['access_failures'].pop(rid, None)
                    task['access_failures'].pop(request.get('replaces_request_id'), None)
                records.append(record)
            fetch_id = log.record_reason_evidence_fetch(task.get('last_call_id', 0), records, input_call_ids=ids)
            for rec in records:
                if rec['request_id'] in task['cache']:
                    task['cache'][rec['request_id']].setdefault('fetch_call_id', fetch_id)
            task['pending'] = task['pending'][len(requests):]
            rounds += 1
            task['fetch_rounds'] = task.get('fetch_rounds', 0) + 1
            save()
        continued = user + (f'\nEVIDENCE_REQUEST RESULTS (round {rounds}/{R.COMPAT_EVIDENCE_ROUNDS} of this slice):\n' if rounds else '') + S._context(task) + '\nUNRESOLVED ACCESS REQUESTS:\n' + json.dumps(task['access_failures'])
        continued += ('\nReview is resumable. Request at most four deciding sources now. '
                      'Use replaces_request_id to repair a refused selector. Do not issue a verdict '
                      'while requests remain unfinished. Return classification_consistency: '
                      '{matches:true|false, reason:"explanation", suggested_fields:{}} comparing '
                      'the typed claim with the actual prose. Generic other is valid when accurate; '
                      'solicitation is not a completed transfer. Never silently reclassify.')
        result = R._ask(system, continued, max_tokens=R.MAX_TOKENS_EVALUATE,
            _tool_name='reason_evaluate_finding', input_call_ids=ids, want_raw=True,
            evidence_packet=packet, single_round=True, review_progress=task, progress_hook=save)
        task['last_call_id'] = result.get('_trudi_call_id', 0)
        for key_usage in ('input_tokens', 'output_tokens'):
            task[key_usage] = task.get(key_usage, 0) + int(result.get(key_usage) or 0)
        if not result.get('success'):
            task.update(status='blocked', retryable=bool(result.get('retryable')), result=deepcopy(result))
            break
        try:
            requests = normalize_requests((result.get('result_block') or {}).get('evidence_request')
                                           or result.get('evidence_requests') or [])
        except ValueError as exc:
            result.update(success=False, status='access_failure', error=str(exc))
            task.update(status='blocked', retryable=False, result=deepcopy(result))
            break
        if requests:
            task['pending'].extend(r for r in requests if r not in task['pending'])
            log.update_reason_call(task['last_call_id'], review_pending=True)
            save()
            continue
        if task['pending'] or task['access_failures']:
            result.update(success=False, status='access_failure', review_pending=True,
                          error='Required evidence requests remain unresolved; repair the named selectors',
                          unresolved_requests=task['access_failures'])
            task.update(status='blocked', retryable=False, result=deepcopy(result))
            break
        result['evidence_fetches'] = [c['record'] for c in task['cache'].values()]
        task.update(status='complete', result=deepcopy(result))
        log.update_reason_call(task['last_call_id'], review_pending=False,
                               evidence_requests=result['evidence_fetches'], review_session_id=key)
        break
    if task['status'] == 'pending':
        result = {'success': False, 'status': 'in_progress', 'review_pending': True,
                  '_trudi_call_id': task.get('last_call_id'), 'next_action': 'resume_same_finding',
                  'error': 'Review checkpoint saved; continue the same finding without revising it'}
    result.update(review_session_id=key, provider_calls=task['provider_calls'],
                  evidence_rounds=task.get('fetch_rounds', 0),
                  cumulative_input_tokens=task.get('input_tokens', 0), cumulative_output_tokens=task.get('output_tokens', 0),
                  pending_requests=len(task['pending']), cached_fetches=task.get('cache_hits', 0))
    if task.get('last_call_id') and not result.get('success'):
        result.setdefault('_trudi_call_id', task['last_call_id'])
        log.update_reason_call(task['last_call_id'], success=False, review_pending=True,
                               access_failures=list(task['access_failures'].values()))
    if task['status'] in ('complete', 'blocked'):
        task['result'] = deepcopy(result)
    save()
    return result
