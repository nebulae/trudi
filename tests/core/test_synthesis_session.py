from copy import deepcopy
from unittest.mock import patch
import pytest

from core.execution_log import log, ExecutionLog
from core.synthesis_evidence import build_synthesis_index
from core import synthesis_session as S
from core.evidence_display import prompt_packet


def setup_findings(count=1, sources=1):
    ids = []
    for i in range(count):
        cids = [log.record_tool_call('parse artifact', True, False, 0, 0,
                    stdout_full=f'observation {i} {j}', stdout_excerpt=f'observation {i} {j}')
                for j in range(sources)]
        fid = log.record_finding(f'observation {i}', 'CONFIRMED', input_call_ids=cids)
        ids.append(fid)
    return ids


def reviewer(system, user, **kw):
    task, packet = kw['review_progress'], kw['evidence_packet']
    task['provider_calls'] += 1
    kw['progress_hook']()
    seen = {c['record']['call_id'] for c in task['cache'].values()}
    missing = [s for s in packet['evidence'] if s['call_id'] not in seen]
    rb = {'issues': [], 'resolutions': []}
    if missing:
        rb['evidence_request'] = [{'call_id': s['call_id'], 'query': 'observation', 'path': s['path'],
            'finding_call_id': next(f['finding_call_id'] for f in packet['finding_sources']
                                   if any(x['call_id'] == s['call_id'] for x in f['sources']))}
                                  for s in missing[:4]]
    else:
        rb['coverage'] = [{'finding_call_id': f['finding_call_id'], 'complete': True,
            'assertions_reviewed': ['observation'], 'request_ids': [rid for rid, c in task['cache'].items()
                if any(s['call_id'] == c['record']['call_id'] for s in f['sources'])]}
                         for f in packet['finding_sources']]
    cid = log.record_reason_call('reason_synthesize', True, 'Review', {}, extra={'result_block': rb})
    return {'success': True, '_trudi_call_id': cid, 'result_block': rb,
            'evidence_requests': rb.get('evidence_request', [])}


def test_thirteen_sources_resume_across_restart_without_repeating_fetches():
    from tools import reasoning as R
    setup_findings(sources=13)
    with patch('tools.reasoning._ask', side_effect=reviewer), \
         patch.object(R, '_resolve_evidence_requests', wraps=R._resolve_evidence_requests) as fetch:
        first = S.advance(log)
        assert first['status'] == 'in_progress'
        checkpoint = S.latest(log)
        assert len(checkpoint['tasks'][0]['cache']) == 12
        restored = ExecutionLog()
        restored.configure(log._case_id, log._path, save_session=False)
        assert restored._run_id == log._run_id
        assert S.latest(restored) == checkpoint
        for _ in range(8):
            result = S.advance(log, requested=first['review_session_id'])
            if result['status'] != 'in_progress':
                break
    assert result['approved'], result
    assert fetch.call_count == 13  # comparison receipts reuse the same versioned reads
    assert result['cached_fetches'] == 13
    assert all(len(t['cache']) == 13 for t in S.latest(log)['tasks'])
    assert S.readiness_error(log) == ''


def test_zero_fetch_cannot_approve_and_unchanged_retry_does_not_refill():
    setup_findings()
    def no_fetch(system, user, **kw):
        kw['review_progress']['provider_calls'] += 1
        return {'success': True, 'result_block': {'issues': [], 'coverage': []}}
    with patch('tools.reasoning._ask', side_effect=no_fetch) as ask:
        assert S.advance(log)['status'] == 'blocked'
        count = ask.call_count
        assert S.advance(log)['status'] == 'blocked'
        assert ask.call_count == count == 2


def test_one_finding_change_preserves_other_task_progress():
    ids = setup_findings(count=3)
    index = build_synthesis_index(log)
    session = S.prepare(log, index)
    for task in session['tasks']:
        task.update(status='complete', provider_calls=2)
    S.checkpoint(log, session)
    log.index().by_call_id[ids[0]]['description'] = 'changed assertion'
    current = S.prepare(log, build_synthesis_index(log))
    assert current['tasks'][0]['status'] == 'pending'
    assert all(t['status'] == 'complete' for t in current['tasks'][1:3])
    assert current['tasks'][-1]['status'] == 'pending'


@pytest.mark.parametrize('count', [10, 30, 100])
def test_index_has_no_rows_and_scales_to_one_hundred_findings(count):
    import json
    setup_findings(count=count)
    index = build_synthesis_index(log)
    assert len(index['finding_sources']) == count
    assert all(not s['selections'] for s in index['evidence'])
    tasks = S.tasks_for(index)
    assert len([t for t in tasks if t['kind'] == 'finding']) == count
    assert all(len(json.dumps(prompt_packet(S.task_packet(index, t['finding_ids'])))) < 96000 for t in tasks)


def test_comparison_blocks_cover_every_pair_of_actual_claims():
    import itertools
    setup_findings(count=5)
    index = build_synthesis_index(log)
    for f in index['findings']:
        f['description'] += ' contradictory assertion' * 15
    with patch.object(S, 'BASE_PROMPT_LIMIT', 15000):
        tasks = S.tasks_for(index)
    compared = set()
    for task in tasks:
        if task['kind'] == 'comparison':
            compared.update(itertools.combinations(task['finding_ids'], 2))
            assert all(f['description'] for f in prompt_packet(S.task_packet(index, task['finding_ids']))['findings'])
    assert compared == set(itertools.combinations([f['call_id'] for f in index['findings']], 2))


def test_complete_zero_search_is_not_a_refused_or_partial_search():
    assert S.complete_zero({'status': 'ok', 'searched': True, 'scan_complete': True,
                            'source_complete': True, 'matched_rows': 0})
    assert not S.complete_zero({'status': 'out_of_scope', 'matched_rows': 0})
    assert not S.complete_zero({'status': 'ok', 'searched': True, 'scan_complete': True,
                                'source_complete': False, 'matched_rows': 0})


def test_changed_source_invalidates_only_its_review(tmp_path):
    ids = []
    paths = []
    for n in range(2):
        path = tmp_path / f'output{n}.txt'
        path.write_text('observation\n')
        cid = log.record_tool_call('parse records', True, False, 0, 0, output_path=str(path))
        ids.append(log.record_finding('observation', 'LIKELY', input_call_ids=[cid]))
        paths.append(path)
    index = build_synthesis_index(log)
    old = S.prepare(log, index)
    for task in old['tasks']:
        task['status'] = 'complete'
    S.checkpoint(log, old)
    paths[0].write_text('changed observation\n')
    new = S.prepare(log, build_synthesis_index(log))
    assert new['tasks'][0]['status'] == 'pending'
    assert new['tasks'][1]['status'] == 'complete'
    assert new['tasks'][2]['status'] == 'pending'


def test_completed_claims_are_compared_without_repeating_factual_review():
    setup_findings(count=2)
    def model(system, user, **kw):
        task = kw['review_progress']
        if task['kind'] == 'comparison':
            task['provider_calls'] += 1
            assert not task['cache']
            cid = log.record_reason_call('reason_synthesize', True, 'consistent', {})
            return {'success': True, '_trudi_call_id': cid, 'result_block': {
                'issues': [], 'comparison_complete': True, 'compared_finding_ids': task['finding_ids']}}
        return reviewer(system, user, **kw)
    with patch('tools.reasoning._ask', side_effect=model):
        result = S.advance(log)
    assert result['approved'], result
    assert result['provider_calls'] == 5  # two fetch/review pairs, one comparison


def test_overlap_suggestions_retain_missing_relationship_candidates():
    from core.citation_candidates import suggest_sources
    cited = log.record_tool_call('read account inventory', True, False, 0, 0,
                                stdout_full='svc_alpha exists', stdout_excerpt='svc_alpha exists')
    other = log.record_tool_call('read delivery records', True, False, 0, 0,
                                stdout_full='svc_alpha delivered payload', stdout_excerpt='svc_alpha delivered payload')
    result = suggest_sources(log, "'svc_alpha'", [cited])
    assert other in [c['call_id'] for c in result['uncited_sources']]


def test_real_protocol_resumes_fetches_and_reports_current_coverage():
    import json
    from tools import reasoning as R
    from tests.tools.test_compat_thinking import _resp
    fid = setup_findings()[0]
    source = build_synthesis_index(log)['evidence'][0]
    prompts = []
    def post(url, **kwargs):
        prompts.append(sum(len(m['content']) for m in kwargs['json']['messages']))
        session = S.latest(log)
        task = next(t for t in session['tasks'] if t['status'] != 'complete')
        if task['kind'] == 'comparison':
            rb = {'issues': [], 'comparison_complete': True, 'compared_finding_ids': [fid]}
        elif not task['cache']:
            rb = {'issues': [], 'evidence_request': [{'call_id': source['call_id'],
                  'path': source['path'], 'finding_call_id': fid, 'query': 'observation'}]}
        else:
            rb = {'issues': [], 'coverage': [{'finding_call_id': fid, 'complete': True,
                  'assertions_reviewed': ['observation'], 'request_ids': list(task['cache'])}]}
        return _resp('RESULT:\n' + json.dumps(rb))
    with patch.object(R, 'REASON_BACKEND', 'openai-compat'), \
         patch.object(R, 'REASON_URL', 'http://synthetic.test'), \
         patch.object(R, 'REASON_MODEL', 'synthetic'), \
         patch.object(R, 'COMPAT_THINKING_BUDGET', 0), patch('httpx.post', side_effect=post) as http:
        result = S.advance(log)
        assert result['approved'], result
        assert result['provider_calls'] == 3
        assert S.advance(log)['reused_review_tasks'] == 2
        assert http.call_count == 3
        assert not S.readiness_error(log)
    assert max(prompts) < 96000
    assert S.readiness_error(log)  # restoring the configured backend changes policy


def test_provider_retry_counts_toward_persisted_budget():
    from tools import reasoning as R
    from tests.tools.test_compat_thinking import _exhausted, _resp
    task = {'provider_calls': 23}
    checkpoints = []
    with patch.object(R, 'REASON_BACKEND', 'openai-compat'), \
         patch.object(R, 'REASON_URL', 'http://synthetic.test'), \
         patch.object(R, 'REASON_MODEL', 'synthetic'), \
         patch.object(R, 'COMPAT_THINKING_BUDGET', 8192), \
         patch.object(R, 'COMPAT_MAX_TOKENS_CEILING', 32768), \
         patch('httpx.post', side_effect=[_exhausted(), _resp('RESULT: {"issues": []}')]) as http:
        for _ in range(2):
            result = R._ask('Review', 'Claim', _tool_name='reason_synthesize', single_round=True,
                review_progress=task, progress_hook=lambda: checkpoints.append(task['provider_calls']))
            assert not result['success'] and 'budget exhausted' in result['error']
        assert http.call_count == 1
    assert task['provider_calls'] == 24 and checkpoints == [24]


def test_existing_review_issue_is_adjudicated_without_restarting_findings():
    from core.review_issues import review_state
    fid = setup_findings()[0]
    with patch('tools.reasoning._ask', side_effect=reviewer):
        assert S.advance(log)['approved']
    source = build_synthesis_index(log)['evidence'][0]
    log.record_reason_call('reason_synthesize', True, 'old objection', {}, extra={
        'review_issues': [{'issue_id': 'R-synthetic', 'kind': 'unsupported_claim',
                         'message': 'observation is absent', 'finding_call_ids': [fid],
                         'evidence_call_ids': [source['call_id']]}]})
    def adjudicate(system, user, **kw):
        assert kw['review_progress']['kind'] == 'adjudication'
        result = reviewer(system, user, **kw)
        if result['result_block'].get('coverage'):
            result['result_block']['resolutions'] = [{
                'issue_id': 'R-synthetic', 'basis': 'reviewer_error',
                'reason': 'The displayed source contains the observation',
                'incorrect_premise': 'observation is absent', 'call_ids': [source['call_id']],
                'evidence_quotes': [{'call_id': source['call_id'], 'path': source['path'],
                                     'quote': 'observation 0 0'}]}]
        return result
    with patch('tools.reasoning._ask', side_effect=adjudicate):
        result = S.advance(log)
    assert result['approved'], result
    assert result['reused_review_tasks'] == 2
    assert review_state(log._entries)[0]['status'] == 'resolved'
    assert not S.readiness_error(log)


def test_conflicting_findings_in_different_blocks_cannot_approve():
    ids = setup_findings(count=3)
    first, last = ids[0], ids[-1]
    log.index().by_call_id[first]['description'] = 'Account exported the records. ' * 12
    log.index().by_call_id[last]['description'] = 'Account did not export the records. ' * 12
    log._flush()
    def compare(system, user, **kw):
        result = reviewer(system, user, **kw)
        task = kw['review_progress']
        if (task['kind'] == 'comparison' and {first, last} <= set(task['finding_ids'])
                and result['result_block'].get('coverage')):
            definitions = kw['evidence_packet']['findings']
            assert any('did not export' in f['description'] for f in definitions)
            assert any('Account exported' in f['description'] for f in definitions)
            record = next(iter(task['cache'].values()))['record']
            from core.evidence_display import displayed_text
            span = record['source_selections'][0]
            result['result_block']['issues'] = [{'kind': 'contradiction',
                'message': 'These findings describe opposite outcomes for the same account.',
                'finding_call_ids': [first, last], 'evidence_call_ids': [record['call_id']],
                'evidence_quotes': [{'call_id': record['call_id'], 'path': span.get('path'),
                                     'quote': displayed_text(span)}]}]
        return result
    with patch.object(S, 'BASE_PROMPT_LIMIT', 15000), patch('tools.reasoning._ask', side_effect=compare):
        for _ in range(10):
            result = S.advance(log)
            if result['status'] != 'in_progress':
                break
    assert result['status'] == 'blocked' and not result['approved'], result
    assert any(set(i['finding_call_ids']) == {first, last} for i in result['review_issues'])
    assert S.readiness_error(log)


def test_zero_match_receipt_approves_only_a_scoped_negative():
    from tools import reasoning as R
    fid = setup_findings()[0]
    log.index().by_call_id[fid]['claim'] = {'kind': 'negative', 'scope': 'this retained source'}
    index = build_synthesis_index(log)
    packet = S.task_packet(index, [fid])
    source = packet['evidence'][0]
    _, records = R._resolve_evidence_requests([{'call_id': source['call_id'], 'path': source['path'],
        'finding_call_id': fid, 'query': 'definitely_no_matching_record'}], [source['call_id']], 2000, packet)
    task = S.tasks_for(index)[0]
    task['cache']['zero'] = {'record': records[0], 'block': ''}
    result = {'result_block': {'issues': [], 'coverage': [{'finding_call_id': fid,
        'complete': True, 'request_ids': ['zero'], 'assertions_reviewed': ['No matching records in this source']}]}}
    assert S.validate_coverage(task, result, packet)
    packet['findings'][0]['claim']['kind'] = 'observation'
    with pytest.raises(ValueError, match='positive claim'):
        S.validate_coverage(task, result, packet)
    packet['findings'][0]['claim']['kind'] = 'negative'
    records[0]['source_complete'] = False
    with pytest.raises(ValueError, match='complete zero-match'):
        S.validate_coverage(task, result, packet)


def test_transient_provider_failure_and_explicit_budget_increase_retain_progress():
    import httpx
    from tools import reasoning as R
    setup_findings()
    with patch.object(R, 'REASON_BACKEND', 'openai-compat'), \
         patch.object(R, 'REASON_URL', 'http://synthetic.test'), \
         patch.object(R, 'REASON_MODEL', 'synthetic'), \
         patch('httpx.post', side_effect=httpx.ConnectError('temporary connection failure')):
        assert S.advance(log)['status'] == 'blocked'
        index = build_synthesis_index(log)
        resumed = S.prepare(log, index)
        assert resumed['tasks'][0]['status'] == 'pending'
        assert resumed['tasks'][0]['provider_calls'] == 1
        task = resumed['tasks'][0]
        task.update(status='blocked', retryable=False, budget_exhausted=True, provider_calls=24)
        S.checkpoint(log, resumed)
        assert S.prepare(log, index)['tasks'][0]['status'] == 'blocked'
        with patch.object(S, 'TASK_CALL_LIMIT', 25):
            increased = S.prepare(log, index)['tasks'][0]
            assert increased['status'] == 'pending' and increased['provider_calls'] == 24
