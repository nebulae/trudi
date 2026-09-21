"""Durable, bounded independent review over a versioned evidence index.

Progress is data in the trace, not approval. A model response is accepted only
after its required requests and evidence coverage have been checked.
"""
from copy import deepcopy
import itertools
import json
import os
import time

from core.readiness import digest
from core.evidence_packets import PacketError, packet_current
from core.evidence_display import prompt_packet, displayed_text, MAX_CONTEXT_CHARS
from core.synthesis_evidence import build_synthesis_index, task_packet

TASK_CALL_LIMIT = int(os.environ.get('TRUDI_SYNTHESIS_TASK_CALLS', '24'))
SLICE_CALL_LIMIT = 6
BASE_PROMPT_LIMIT = MAX_CONTEXT_CHARS - 40000

TASK_SYSTEM = """You independently review a bounded evidence task. The TASK and its
coverage contract define your responsibility. Finding review checks that finding's
material assertions against its authorized sources; comparison checks consistency
between the supplied findings. Do not conduct a new investigation or require an
unrelated source merely to strengthen an already supported claim. Typed claims
and prose must agree. Conservative confidence is not a blocker. Source column
names are authoritative: a missing requested column is a selector problem, not
proof that an event or timestamp is absent. Request deciding evidence before
issuing a factual objection. While requesting evidence return issues:[] and
resolutions:[]; provisional thoughts are not instructions to the investigator.
Return one RESULT JSON object using the supplied schema, without a long essay.
"""

INSTRUCTION = """
This is a resumable independent synthesis task. The recorded findings are
authoritative as CLAIMS, never as proof. Review their complete descriptions,
entities, time windows and evidence. A comparison task must check consistency
BETWEEN its findings, even when individual findings passed earlier review.
Pull deciding evidence with evidence_request (at most four requests per response).
Each request names call_id, query, exact path when supplied, and finding_call_id.
Use a replacement request with replaces_request_id to repair a refused request.
Do not repeat a successful unchanged query. Saved receipts identify observations
already examined; request them again if their displayed text is needed now.
RESULT must include issues:[], resolutions:[], evidence_request:[], and
coverage:[{finding_call_id:123, complete:true, request_ids:["ER-..."],
assertions_reviewed:["the actual factual assertions checked"]}].
Coverage is complete only after ALL material assertions in that finding have
been examined. Reading one irrelevant row is not review of the finding.
For a scoped negative, a complete zero-match search may be cited; partial scans
cannot prove absence. No fetch means no factual approval. Factual issues must
include evidence_quotes:[{call_id:123,path:null,quote:"exact displayed text"}]
or absence_request_ids naming complete zero-match searches.
If more evidence is needed, request it; unfinished review is not a verdict.
Comparison tasks run only after every individual finding has been reviewed.
For these, compare the actual claims and return comparison_complete:true and
compared_finding_ids:[...] covering EVERY supplied finding. You may reuse that
completed factual review; fetch when needed to decide an objection. Do not
repeat individual factual approval merely to establish logical consistency.
"""


def latest(log, kind='synthesis_progress', session_id=None):
    entry = next((e for e in reversed(log._entries) if e.get('type') == kind
                  and (session_id is None or e['session'].get('session_id') == session_id)), None)
    if not entry:
        return None
    session = deepcopy(entry['session'])
    by_id = log.index().by_call_id
    for task in session['tasks']:
        for rid, value in list(task['cache'].items()):
            if 'record' in value:
                continue
            record = next((r for r in by_id.get(value['fetch_call_id'], {}).get('requests', [])
                           if r.get('request_id') == rid), None)
            if record is None:
                raise PacketError('Persisted review receipt is missing; repair the trace', 'missing_receipt')
            block = json.dumps({k: record.get(k) for k in ('call_id', 'query', 'status', 'sources', 'matched_rows')})
            block += '\n' + '\n'.join(displayed_text(s) for s in record.get('source_selections', []))
            task['cache'][rid] = {**value, 'record': deepcopy(record), 'block': block}
    return session


def checkpoint(log, session, kind='synthesis_progress'):
    from core.phase_routing import append_event
    saved = deepcopy(session)
    for task in saved['tasks']:
        task['cache'] = {rid: {k: c[k] for k in ('fetch_call_id', 'read_key') if k in c} if c.get('fetch_call_id') else c
                         for rid, c in task['cache'].items()}
    with log.transaction():
        append_event(log, kind, session=saved)


def tasks_for(index):
    """Individual dependency keys and exhaustive block-pair comparisons."""
    findings = sorted(index['findings'], key=lambda f: f['call_id'])
    tasks = []
    def add(kind, ids):
        packet = task_packet(index, ids)
        key = 'T-' + digest([kind, packet['packet_id']])[:24]
        tasks.append({'task_id': key, 'kind': kind, 'finding_ids': ids,
                      'status': 'pending', 'provider_calls': 0, 'cache': {},
                      'pending': [], 'coverage': [], 'reason_call_ids': []})
    for finding in findings:
        add('finding', [finding['call_id']])
    if findings:
        ids = [f['call_id'] for f in findings]
        if len(json.dumps(prompt_packet(task_packet(index, ids)))) <= BASE_PROMPT_LIMIT - 12000:
            add('comparison', ids)
        else:
            # Half-sized blocks allow any pair to fit. No relationship heuristic
            # may discard a pair merely because its entity names differ.
            blocks, current = [], []
            for fid in ids:
                candidate = current + [fid]
                if current and len(json.dumps(prompt_packet(task_packet(index, candidate)))) > (BASE_PROMPT_LIMIT - 12000) // 2:
                    blocks.append(current)
                    current = []
                current.append(fid)
            if current:
                blocks.append(current)
            for block in blocks:
                add('comparison', block)
            for a, b in itertools.combinations(blocks, 2):
                add('comparison', a + b)
    return tasks


def prepare(log, index, requested=''):
    previous = latest(log)
    run_id = getattr(log, '_run_id', None)
    if requested and (not previous or previous['session_id'] != requested or previous['run_id'] != run_id):
        raise PacketError('Unknown or foreign review_session_id', 'invalid_session')
    old = {t['task_id']: t for t in (previous or {}).get('tasks', [])} if previous and previous['run_id'] == run_id else {}
    definitions = tasks_for(index)
    from core.review_issues import review_state
    for issue in review_state(log._entries):
        if issue['status'] != 'open' or issue['kind'] == 'advisory':
            continue
        ids = sorted(set(issue.get('finding_call_ids') or []) & {f['call_id'] for f in index['findings']})
        if not ids:
            ids = [f['call_id'] for f in index['findings']]
        packet = task_packet(index, ids)
        key = 'A-' + digest([issue['issue_id'], packet['packet_id']])[:24]
        definitions.append({'task_id': key, 'kind': 'adjudication', 'finding_ids': ids,
                            'issue_ids': [issue['issue_id']], 'status': 'pending',
                            'provider_calls': 0, 'cache': {}, 'pending': [], 'coverage': [], 'reason_call_ids': []})
    tasks = [deepcopy(old.get(t['task_id'], t)) for t in definitions]
    reused = sum(t['status'] == 'complete' for t in tasks)
    retired_usage = deepcopy((previous or {}).get('retired_usage', {}))
    active_ids = {t['task_id'] for t in definitions}
    for key in ('provider_calls', 'input_tokens', 'output_tokens'):
        retired_usage[key] = retired_usage.get(key, 0) + sum(t.get(key, 0) for tid, t in old.items() if tid not in active_ids)
    for task in tasks:
        if task['status'] == 'blocked' and (task.get('retryable') or task.get('budget_exhausted')) and task['provider_calls'] < TASK_CALL_LIMIT:
            task['status'] = 'pending'
            task.pop('budget_exhausted', None)
    session = {'session_id': (previous['session_id'] if old else 'RS-' + digest([run_id, index['packet_id']])[:24]),
               'run_id': run_id, 'index_id': index['packet_id'], 'tasks': tasks,
               'status': 'in_progress', 'policy': index['policy'],
               'extra_ids': index.get('extra_ids', []),
               'retired_usage': retired_usage, 'reused_review_tasks': reused,
               'elapsed_seconds': (previous or {}).get('elapsed_seconds', 0),
               'last_response': (previous or {}).get('last_response', {})}
    return session


def request_key(packet, request):
    # No reason_call_id: the same versioned read is reusable after a restart.
    return 'ER-' + digest([packet['policy'], packet['file_versions'],
        packet['entry_identities'].get(str(request.get('call_id'))),
        {k: v for k, v in request.items() if k not in ('request_id', 'replaces_request_id')}])[:24]


def shared_read_key(packet, request):
    sources = [s for s in packet['evidence'] if s['call_id'] == request['call_id']
               and (not request.get('path') or request['path'] == s['path'])]
    return digest([packet['policy'], packet['entry_identities'].get(str(request['call_id'])),
        [(s['source_id'], s['path']) for s in sources],
        {k: v for k, v in request.items() if k not in ('request_id', 'replaces_request_id', 'finding_call_id')}])


def reusable_read(session, packet, request, key):
    finding = next((f for f in packet['finding_sources']
                    if f['finding_call_id'] == request.get('finding_call_id')), None)
    if not finding:
        return None
    allowed = {(s['call_id'], s['path']) for s in finding['sources']}
    for task in session['tasks']:
        for cached in task['cache'].values():
            record = cached['record']
            if cached.get('read_key') == key and record.get('sources') and all(
                    (record['call_id'], s.get('path')) in allowed for s in record['sources']):
                return deepcopy(cached)
    return None


def complete_zero(rec):
    return (rec.get('status') == 'ok' and rec.get('searched') and rec.get('scan_complete')
            and rec.get('source_complete') and not rec.get('missing_columns')
            and not rec.get('columns_ignored') and rec.get('matched_rows') == 0)


def validate_coverage(task, result, packet):
    rb = result.get('result_block') or {}
    comparison = task['kind'] == 'comparison' and rb.get('comparison_complete') is True
    if comparison and set(rb.get('compared_finding_ids') or []) != set(task['finding_ids']):
        raise ValueError('Consistency review must compare every supplied finding')
    coverage = rb.get('coverage')
    if comparison:
        coverage = []
    if not isinstance(coverage, list):
        raise ValueError('Return explicit coverage for every finding; no fetch cannot approve')
    completed = {}
    for item in coverage:
        if not isinstance(item, dict) or item.get('finding_call_id') not in task['finding_ids']:
            raise ValueError('Coverage must reference this task’s findings')
        if item.get('complete') is not True:
            continue
        refs = item.get('request_ids') or []
        assertions = item.get('assertions_reviewed')
        if not isinstance(assertions, list) or not assertions or not all(isinstance(s, str) and s.strip() for s in assertions):
            raise ValueError('Coverage must state which material assertions were examined')
        finding = next(f for f in packet['finding_sources'] if f['finding_call_id'] == item['finding_call_id'])
        allowed = {(s['call_id'], s.get('path')) for s in finding['sources']}
        valid = []
        for rid in refs:
            cached = task['cache'].get(rid)
            if not cached:
                raise ValueError('Coverage references an unknown evidence receipt')
            rec = cached['record']
            if not any((rec['call_id'], s.get('path')) in allowed for s in rec.get('sources', [])):
                raise ValueError('Coverage uses another finding’s source')
            if rec.get('status') != 'ok' or not rec.get('searched'):
                raise ValueError('A refused request cannot establish coverage')
            rows = [displayed_text(s) for s in rec.get('source_selections', [])]
            if not rows and not complete_zero(rec):
                raise ValueError('Coverage needs displayed rows or a complete zero-match search')
            valid.append(rid)
        if not valid:
            raise ValueError('No fetch cannot approve factual review')
        definition = next(f for f in packet['findings'] if f['call_id'] == item['finding_call_id'])
        if not any(task['cache'][r]['record'].get('source_selections') for r in valid):
            challenged = any(item['finding_call_id'] in i.get('finding_call_ids', []) and
                             i.get('kind') in ('unsupported_claim', 'contradiction', 'evidence_gap')
                             for i in rb.get('issues', []))
            if (definition.get('claim') or {}).get('kind') != 'negative' and not challenged:
                raise ValueError('A zero-match search cannot approve a positive claim')
        completed[item['finding_call_id']] = item
    if not comparison and set(completed) != set(task['finding_ids']):
        raise ValueError('Required factual review remains unfinished; request the deciding evidence')
    for issue in rb.get('issues', []):
        if issue.get('kind') not in ('contradiction', 'unsupported_claim'):
            continue
        quotes = issue.get('evidence_quotes') or []
        absence = issue.get('absence_request_ids') or []
        if not quotes and not absence:
            raise ValueError('A factual issue needs displayed evidence or a complete absence search')
        for proof in quotes:
            if not isinstance(proof.get('quote'), str) or not proof['quote'].strip() or not any(
                    proof.get('call_id') == c['record']['call_id'] and
                    proof.get('path') == span.get('path') and proof['quote'] in displayed_text(span)
                    for c in task['cache'].values() for span in c['record'].get('source_selections', [])):
                raise ValueError('Issue quote was not displayed')
        if any(not complete_zero(task['cache'].get(r, {}).get('record', {})) for r in absence):
            raise ValueError('Issue absence search is incomplete')
    return list(completed.values())


def _context(task):
    inventory = [{'request_id': rid, 'call_id': c['record']['call_id'],
                  'finding_call_id': c['record'].get('finding_call_id'),
                  'query': c['record']['query'], 'matched_rows': c['record'].get('matched_rows'),
                  'complete': c['record'].get('scan_complete') and c['record'].get('source_complete')}
                 for rid, c in task['cache'].items()]
    rows, size = [], 0
    for rid, cached in reversed(list(task['cache'].items())):
        block = '\n' + rid + '\n' + cached['block']
        if size + len(block) <= 28000:
            rows.append(block)
            size += len(block)
    return '\nSAVED REQUEST RECEIPTS:\n' + json.dumps(inventory) + '\nDISPLAYED EVIDENCE:\n' + ''.join(reversed(rows))


def advance(log, extra_ids=(), requested='', context=''):
    import fcntl
    from pathlib import Path
    lock_path = Path(log._path).parent / ('.synthesis-' + str(log._run_id) + '.lock')
    with open(lock_path, 'a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'success': True, 'status': 'in_progress', 'approved': False,
                    'next_action': 'review_already_running',
                    'review_session_id': (latest(log) or {}).get('session_id')}
        return _advance(log, extra_ids, requested, context)


def _advance(log, extra_ids=(), requested='', context=''):
    from tools import reasoning as R
    from core.review_issues import normalize_review, review_state
    extra_ids = sorted(set(extra_ids) | set((latest(log) or {}).get('extra_ids', [])))
    index = build_synthesis_index(log, extra_ids)
    if not index['findings']:
        raise PacketError('No recorded findings to synthesize; record the investigation conclusions first', 'no_findings')
    session = prepare(log, index, requested)
    already_complete = bool(session['tasks']) and all(t['status'] == 'complete' for t in session['tasks'])
    started = time.monotonic()
    calls_at_start = sum(t['provider_calls'] for t in session['tasks'])
    checkpoint(log, session)
    last_cid = 0
    for task in session['tasks']:
        if task['status'] == 'complete':
            continue
        packet = task_packet(index, task['finding_ids'])
        ids = sorted({s['call_id'] for s in packet['evidence']})
        if task['status'] == 'blocked':
            break
        fetch_rounds = 0
        while task['status'] != 'complete':
            if (sum(t['provider_calls'] for t in session['tasks']) - calls_at_start >= SLICE_CALL_LIMIT
                    or time.monotonic() - started >= R._REASON_WATCHDOG - 10):
                break
            if not packet_current(log, packet):
                task.update(status='blocked', error='Evidence changed during review; refresh the session')
                break
            if task['pending']:
                if fetch_rounds >= R.COMPAT_EVIDENCE_ROUNDS:
                    break
                requests = task['pending'][:R.COMPAT_EVIDENCE_MAX_REQUESTS]
                records = []
                for request in requests:
                    rid = request_key(packet, request)
                    if rid not in task['cache']:
                        read_key = shared_read_key(packet, request)
                        cached = reusable_read(session, packet, request, read_key)
                        if cached:
                            block, rec = cached['block'], cached['record']
                            rec['finding_call_id'] = request.get('finding_call_id')
                            rec['reused_fetch_call_id'] = cached.get('fetch_call_id')
                            task['cache_hits'] = task.get('cache_hits', 0) + 1
                        else:
                            block, recs = R._resolve_evidence_requests([request], ids,
                                R.COMPAT_EVIDENCE_ROUND_CHARS // max(1, len(requests)), packet)
                            rec = recs[0]
                        rec['request_id'] = rid
                        if rec['status'] == 'ok' and rec.get('searched'):
                            rec.pop('permitted_sources', None)
                            task['cache'][rid] = {'record': rec, 'block': block, 'read_key': read_key}
                        else:
                            task.setdefault('access_failures', {})[rid] = rec
                        records.append(rec)
                    else:
                        records.append(task['cache'][rid]['record'])
                        task['cache_hits'] = task.get('cache_hits', 0) + 1
                    if request.get('replaces_request_id') and rid in task['cache']:
                        task.setdefault('access_failures', {}).pop(request['replaces_request_id'], None)
                    if rid in task['cache']:
                        task.setdefault('access_failures', {}).pop(rid, None)
                task['pending'] = task['pending'][len(requests):]
                fetch_id = log.record_reason_evidence_fetch(task.get('last_call_id', 0), records, input_call_ids=ids)
                if not fetch_id:
                    raise PacketError('Could not persist evidence receipts', 'trace_write_failure')
                for rec in records:
                    if rec['request_id'] in task['cache']:
                        task['cache'][rec['request_id']].setdefault('fetch_call_id', fetch_id)
                if all(r.get('searched') is not True for r in records) and not task.get('free_refusal_used'):
                    task['free_refusal_used'] = True
                else:
                    fetch_rounds += 1
                checkpoint(log, session)
            user = 'TASK: ' + task['kind'] + '\n' + INSTRUCTION + _context(task)
            if context:
                user += '\nINVESTIGATOR CONTEXT (non-authoritative):\n' + context[:8000]
                if len(context) > 8000:
                    user += '\n[Context excerpt; recorded findings above remain authoritative.]'
            user += '\nUNRESOLVED REQUESTS:\n' + json.dumps(task.get('access_failures', {}))
            user += '\nREMAINING REQUESTS:\n' + json.dumps(task['pending'])
            issues_now = [i for i in review_state(log._entries) if i['status'] == 'open'
                          and (not i.get('finding_call_ids') or set(i['finding_call_ids']) & set(task['finding_ids']))]
            if issues_now:
                user += '\nOPEN ISSUES (omission never resolves an issue):\n' + json.dumps(issues_now)
            if task.get('repair'):
                user += '\nFORMAT/COVERAGE REPAIR: ' + task['repair']
            task_system = TASK_SYSTEM + R._result_suffix('reason_synthesize')
            if len(task_system) + len(user) + len(json.dumps(prompt_packet(packet))) + 3000 > MAX_CONTEXT_CHARS:
                task.update(status='blocked', error='Review task exceeds the prompt budget; use narrower evidence selectors')
                break
            result = R._ask(task_system, user, max_tokens=R.MAX_TOKENS_SYNTHESIZE,
                _tool_name='reason_synthesize', input_call_ids=ids, evidence_packet=packet,
                single_round=True, review_progress=task,
                progress_hook=lambda: checkpoint(log, session))
            last_cid = result.get('_trudi_call_id', 0)
            task['last_call_id'] = last_cid
            if last_cid:
                task['reason_call_ids'].append(last_cid)
                log.update_reason_call(last_cid, synthesis_status='in_progress', review_session_id=session['session_id'])
            task['input_tokens'] = task.get('input_tokens', 0) + int(result.get('input_tokens') or 0)
            task['output_tokens'] = task.get('output_tokens', 0) + int(result.get('output_tokens') or 0)
            blockers, tiers = R._split_tier_blockers(result.get('blockers') or [])
            result['blockers'] = blockers
            if tiers:
                result['under_tiered'] = list(result.get('under_tiered') or []) + tiers
                result['tier_blockers_demoted'] = tiers
                if isinstance(result.get('result_block'), dict) and 'blockers' in result['result_block']:
                    result['result_block']['blockers'] = blockers
            task['provisional_response'] = {k: result[k] for k in ('blockers', 'directives', 'under_tiered',
                'advisories', 'tier_blockers_demoted') if k in result}
            if not result.get('success'):
                task.update(status='blocked', error=result.get('error', 'Independent review failed'),
                            retryable=bool(result.get('retryable')),
                            budget_exhausted=task['provider_calls'] >= TASK_CALL_LIMIT)
                checkpoint(log, session)
                break
            requests = (result.get('result_block') or {}).get('evidence_request') or result.get('evidence_requests') or []
            if requests:
                from core.evidence_requests import normalize_requests
                try:
                    requests = normalize_requests(requests)
                    task['pending'].extend(r for r in requests if r not in task['pending'])
                except ValueError as exc:
                    task.update(status='blocked', error=str(exc))
                checkpoint(log, session)
                if task['status'] == 'blocked':
                    break
                continue
            try:
                if not packet_current(log, packet):
                    raise ValueError('Evidence changed during the model call; refresh this review')
                if task['pending'] or task.get('access_failures'):
                    raise ValueError('Required evidence requests remain unfinished')
                coverage = validate_coverage(task, result, packet)
                result['evidence_fetches'] = [c['record'] for c in task['cache'].values()]
                issues, resolutions = normalize_review(result, log._entries, packet)
                if task.get('issue_ids') and not set(task['issue_ids']) <= {r['issue_id'] for r in resolutions}:
                    raise ValueError('Explicitly adjudicate the named open issues with evidence or request the missing work')
                task.update(status='complete', coverage=coverage, issues=issues, resolutions=resolutions)
                log.update_reason_call(last_cid, review_issues=issues, issue_resolutions=resolutions,
                                       evidence_requests=result['evidence_fetches'])
            except ValueError as exc:
                if task.get('coverage_repair_used'):
                    task.update(status='blocked', error=str(exc))
                else:
                    task.update(coverage_repair_used=True, repair=str(exc))
            checkpoint(log, session)
            if task['status'] == 'blocked':
                break
        if task['status'] != 'complete':
            break
    tasks = session['tasks']
    if build_synthesis_index(log, extra_ids)['packet_id'] != index['packet_id']:
        session['status'] = 'in_progress'
        checkpoint(log, session)
        return {'success': True, 'status': 'in_progress', 'approved': False,
                'review_session_id': session['session_id'], 'next_action': 'resume_against_changed_snapshot'}
    open_issues = [i for i in review_state(log._entries) if i['status'] == 'open' and i['kind'] != 'advisory']
    done = bool(tasks) and all(t['status'] == 'complete' for t in tasks)
    blocked = [t for t in tasks if t['status'] == 'blocked']
    session['status'] = 'blocked' if blocked or open_issues else 'complete' if done else 'in_progress'
    session['elapsed_seconds'] = (latest(log) or {}).get('elapsed_seconds', 0) + time.monotonic() - started
    checkpoint(log, session)
    if not last_cid:
        last_cid = next((t.get('last_call_id') for t in reversed(tasks) if t.get('last_call_id')), 0)
    payload = {'blockers': [i['message'] for i in open_issues], 'directives': {}, 'success': session['status'] != 'blocked', 'status': session['status'],
        'synthesis_status': session['status'], 'review_session_id': session['session_id'],
        '_trudi_call_id': last_cid, 'approved': session['status'] == 'complete',
        'coverage': {'completed_tasks': sum(t['status'] == 'complete' for t in tasks),
                     'total_tasks': len(tasks), 'findings': len(index['findings'])},
        'provider_calls': session['retired_usage'].get('provider_calls', 0) + sum(t['provider_calls'] for t in tasks),
        'input_tokens': session['retired_usage'].get('input_tokens', 0) + sum(t.get('input_tokens', 0) for t in tasks),
        'output_tokens': session['retired_usage'].get('output_tokens', 0) + sum(t.get('output_tokens', 0) for t in tasks),
        'elapsed_seconds': session['elapsed_seconds'],
        'reused_review_tasks': session['reused_review_tasks'],
        'cached_fetches': sum(t.get('cache_hits', 0) for t in tasks),
        'maximum_prompt_characters': max((t.get('maximum_prompt_characters', 0) for t in tasks), default=0),
        'cached': already_complete,
        'errors': [t.get('error') for t in blocked], 'review_issues': open_issues,
        'budget_blockers': [{'task_id': t['task_id'], 'provider_calls': t['provider_calls'],
                            'limit': TASK_CALL_LIMIT, 'kind': 'review_budget_exhausted'}
                           for t in blocked if t['provider_calls'] >= TASK_CALL_LIMIT],
        'next_action': 'write_report' if session['status'] == 'complete' else
            'repair_named_blocker' if session['status'] == 'blocked' else 'resume_reason.synthesize',
        'next_arguments': {'findings': '', 'review_session_id': session['session_id'],
                           'input_call_ids': [last_cid or index['findings'][0]['call_id']]}}
    if last_cid:
        log.update_reason_call(last_cid, synthesis_status=session['status'], control_result=payload)
    from core.phase_routing import route_issues
    handoff = route_issues(log, open_issues, last_cid)
    if handoff:
        payload['follow_up'] = handoff
    return payload


def readiness_error(log):
    session = latest(log)
    if not session:
        return ''  # preserve legacy trace readability
    if session['status'] != 'complete':
        return 'Synthesis review is ' + session['status'] + '; resume or repair ' + session['session_id']
    try:
        index = build_synthesis_index(log, session.get('extra_ids', []))
        if [t['task_id'] for t in tasks_for(index)] != [t['task_id'] for t in session['tasks'] if t['kind'] != 'adjudication']:
            return 'Synthesis evidence/claims changed; resume the current review session'
    except (PacketError, OSError) as exc:
        return 'Synthesis evidence unavailable: ' + str(exc)
    return ''
