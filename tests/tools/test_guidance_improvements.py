"""Case-neutral regressions for bounded guidance and independent review."""
import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import pytest
from core.execution_log import ExecutionLog
from core.control_response import control_response, detail_page, size, MAX_BYTES
from core.review_issues import normalize_review, review_state
from core.synthesis_evidence import build_synthesis_packet


@pytest.fixture
def case(tmp_path):
    log = ExecutionLog()
    log.configure('GENERIC', str(tmp_path / 'trace.json'), save_session=False)
    return log


def evidence(log, path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return log.record_tool_call(f'read.read_output {path}', True, False, 0, 0,
                                output_path=str(path), stdout_full=text, stdout_excerpt=text)


def test_large_guidance_lossless_unicode_paging_and_stale_rejection():
    raw = {'ready_to_report': False, 'blocking_issues': ['Important \\"\n🙂' * 9000],
           'registry_inventory': {'subjects': ['subject'] * 5000}, 'warnings': []}
    summary = control_response(raw, 'reason.readiness_status')
    assert size(summary) <= MAX_BYTES and summary['required_count'] == 1
    assert summary['next_actions'][0]['arguments']['section'] == 'blocking_issues'
    chunks, offset = [], 0
    while offset is not None:
        page = detail_page(raw, 'blocking_issues', offset, 4096, summary['state_version'])
        assert size(page) <= MAX_BYTES and page['success']
        chunks.append(page['json_chunk'])
        offset = page['next_offset']
    assert json.loads(''.join(chunks)) == raw['blocking_issues']
    assert not detail_page({**raw, 'ready_to_report': True}, 'blocking_issues',
                           state_version=summary['state_version'])['success']


def test_readiness_details_and_persisted_review_do_not_call_model(case):
    from tools.reasoning import reason_readiness_status, reason_pre_report_check, reason_review_details
    raw = {'ready_for_synthesis': False, 'ready_to_report': False,
           'blocking_issues': ['exact obligation ' * 700], 'warnings': []}
    with patch('core.execution_log.log', case), patch('tools._readiness.assess_readiness', return_value=raw), \
         patch('tools.reasoning._ask') as model:
        result = reason_readiness_status()
        assert result['details_required']
        page = reason_readiness_status(section='blocking_issues', state_version=result['state_version'])
        assert page['success']
        pre = reason_pre_report_check()
        page = reason_review_details(pre['_trudi_call_id'], 'blocking_issues', state_version=pre['state_version'])
        assert page['success'] and size(page) <= MAX_BYTES
        model.assert_not_called()


def test_synthesis_prerequisites_prevent_model_spend(case):
    from tools.reasoning import reason_synthesize
    case.record_dair_call('Report', '', False, '', '', 'stay', '')
    with patch('core.execution_log.log', case), patch('tools.reasoning._ask') as model:
        result = reason_synthesize('Claimed completion')
        assert result['gate'] == 'synthesis_prerequisites'
        model.assert_not_called()


@pytest.mark.parametrize('kind', ['documents', 'network', 'mobile'])
def test_synthesis_covers_more_than_twelve_sources_and_preserves_subjects(case, tmp_path, kind):
    for n in range(14):
        cid = evidence(case, tmp_path / kind / f'subject-{n}' / 'records.txt', f'Observation token{n}\n')
        case.record_finding(f'Observation token{n}', 'SUSPECTED', linked_call_id=cid,
                            claim={'kind': 'positive', 'principal': f'subject-{n}'})
    with patch('core.execution_log.log', case):
        packet = build_synthesis_packet(case)
    assert len(packet['finding_sources']) == 14
    assert len({e['call_id'] for e in packet['evidence']}) == 14
    assert all(f['principal'] in f['sources'][0]['path'] for f in packet['finding_sources'])
    assert 'token13' in json.dumps(packet)


def test_repeated_physical_source_has_shared_rows_not_independent_corroboration(case, tmp_path):
    source = tmp_path / 'records.txt'
    a = evidence(case, source, 'Relevant observation\n')
    b = evidence(case, source, 'Relevant observation\n')
    case.record_finding('Relevant observation', 'SUSPECTED', linked_call_id=a)
    case.record_finding('Relevant observation with qualification', 'SUSPECTED', linked_call_id=b)
    with patch('core.execution_log.log', case):
        packet = build_synthesis_packet(case)
    assert len(packet['finding_sources']) == 2
    spans = [span for e in packet['evidence'] for sel in e['selections'] for span in sel['spans']]
    assert len(spans) == 1
    assert any(sel['shared_spans'] for e in packet['evidence'] for sel in e['selections'])


def test_wrong_subject_fetch_is_scope_mismatch_not_absence(case, tmp_path):
    from tools.reasoning import _resolve_evidence_requests
    a = evidence(case, tmp_path / 'alpha' / 'records.txt', 'target observed\n')
    b = evidence(case, tmp_path / 'beta' / 'records.txt', 'unrelated\n')
    fid = case.record_finding('target observed', 'SUSPECTED', linked_call_id=a)
    case.record_finding('unrelated', 'SUSPECTED', linked_call_id=b)
    with patch('core.execution_log.log', case):
        packet = build_synthesis_packet(case)
        text, records = _resolve_evidence_requests(
            [{'call_id': b, 'finding_call_id': fid, 'query': 'target'}], [a, b], 2000, packet)
    assert records[0]['status'] == 'scope_mismatch' and not records[0]['source_complete']
    assert 'No absence inference' in text


def correction_fixture(case, tmp_path):
    path = tmp_path / 'observations.txt'
    cid = evidence(case, path, 'Identifier Alpha appears in this record.\n')
    fid = case.record_finding('Identifier Alpha appears in this record.', 'SUSPECTED', linked_call_id=cid)
    issues, _ = normalize_review({'result_block': {'issues': [{
        'kind': 'unsupported_claim', 'message': 'Identifier Alpha is absent from the record',
        'finding_call_ids': [fid], 'evidence_call_ids': [cid]}]}}, case._entries)
    case.record_reason_call('reason_synthesize', True, 'objection', {}, extra={'review_issues': issues})
    with patch('core.execution_log.log', case):
        packet = build_synthesis_packet(case)
    reviewer = case.record_reason_call('reason_synthesize', True, 'correction', {})
    result = {'_trudi_call_id': reviewer, 'result_block': {'issues': [], 'resolutions': [{
        'issue_id': issues[0]['issue_id'], 'basis': 'reviewer_error',
        'reason': 'The observed row disproves the absence premise; operator identity remains unknown.',
        'incorrect_premise': issues[0]['message'], 'call_ids': [cid],
        'evidence_quotes': [{'call_id': cid, 'path': str(path), 'quote': 'Identifier Alpha appears'}]}]}}
    return packet, result, path


def test_old_evidence_can_correct_reviewer_and_changed_source_reopens(case, tmp_path):
    packet, result, path = correction_fixture(case, tmp_path)
    _, resolutions = normalize_review(result, case._entries, packet)
    case.update_reason_call(result['_trudi_call_id'], issue_resolutions=resolutions)
    assert review_state(case._entries)[0]['status'] == 'resolved'
    path.write_text('Changed source')
    assert review_state(case._entries)[0]['status'] == 'open'


@pytest.mark.parametrize('failure', ['invented_quote', 'wrong_path', 'no_review', 'changed_source'])
def test_reviewer_error_cannot_bypass_evidence_checks(case, tmp_path, failure):
    packet, result, path = correction_fixture(case, tmp_path)
    proof = result['result_block']['resolutions'][0]['evidence_quotes'][0]
    if failure == 'invented_quote': proof['quote'] = 'Unobserved claim'
    if failure == 'wrong_path': proof['path'] = str(tmp_path / 'other.txt')
    if failure == 'no_review': result['_trudi_call_id'] = 0
    if failure == 'changed_source': path.write_text('different')
    with pytest.raises(ValueError):
        normalize_review(result, case._entries, packet)


def test_reviewer_correction_can_use_rows_pulled_after_initial_packet(case, tmp_path):
    from tools.reasoning import _resolve_evidence_requests
    packet, result, path = correction_fixture(case, tmp_path)
    cid = result['result_block']['resolutions'][0]['call_ids'][0]
    # Force the deciding row into a later bounded fetch rather than the push.
    for source in packet['evidence']:
        for selection in source['selections']:
            selection['spans'] = []
            selection['shown_lines'] = 0
    with patch('core.execution_log.log', case):
        _, receipts = _resolve_evidence_requests(
            [{'call_id': cid, 'query': 'Alpha', 'path': str(path)}], [cid], 2000, packet)
    result['evidence_fetches'] = receipts
    _, resolutions = normalize_review(result, case._entries, packet)
    assert resolutions[0]['status'] == 'resolved'


@pytest.mark.parametrize('scope', ['documents', 'network', 'mobile'])
def test_synthesis_smoke_uses_real_review_pipeline_and_caches(case, tmp_path, scope):
    from tools import reasoning as R
    from tests.tools.test_reasoning import _http_resp
    case.record_reason_call('reason_plan', True, 'Investigate the question', {})
    case.record_dair_call('Triage', '', True, 'Collect', '', 'push', '')
    case.record_dair_call('Collect', '', True, 'Analyze', '', 'push', '')
    cid = evidence(case, tmp_path / scope / 'records.txt', 'Alpha observation\n')
    fid = case.record_finding('Alpha observation', 'SUSPECTED', linked_call_id=cid)
    case.record_dair_call('Analyze', '', True, 'Report', '', 'push', '')
    def respond(*args, **kwargs):
        from core.synthesis_session import latest
        task = next(t for t in latest(case)['tasks'] if t['status'] != 'complete')
        if task['kind'] == 'comparison':
            result = {'issues': [], 'comparison_complete': True, 'compared_finding_ids': [fid]}
        elif not task['cache']:
            result = {'evidence_request': [{'call_id': cid, 'finding_call_id': fid,
                       'query': 'Alpha', 'path': str(tmp_path / scope / 'records.txt')}]}
        else:
            result = {'issues': [], 'coverage': [{'finding_call_id': fid, 'complete': True,
                'assertions_reviewed': ['Alpha observation'], 'request_ids': list(task['cache'])}]}
        return _http_resp('RESULT: ' + json.dumps(result))
    with patch('core.execution_log.log', case), patch.object(R, 'REASON_BACKEND', 'openai-compat'), \
         patch.object(R, 'REASON_URL', 'http://localhost:8000'), \
         patch.object(R, 'REASON_MODEL', 'synthetic'), \
         patch('httpx.post', side_effect=respond) as backend:
        first = R.reason_synthesize('Alpha observation', input_call_ids=[cid])
        assert first['success'], first
        second = R.reason_synthesize('unchanged', input_call_ids=[cid])
        assert second['cached'] and backend.call_count == 3
        prompt = backend.call_args.kwargs['json']['messages'][1]['content']
        assert 'finding_sources' in prompt and str(tmp_path / scope / 'records.txt') in prompt
    saved = case.index().by_call_id[first['_trudi_call_id']]
    assert saved['synthesis_evidence_packet']['finding_sources']


def test_long_batch_restart_and_concurrent_probe_spending(case):
    from tools.misc import record_curiosity_probe
    case.record_dair_call('Analyze', '', False, '', '', 'stay', '', directives={'curiosity_budget': 1})
    for n in range(40): case.record_agent_message(f'Bookkeeping {n}')
    case.configure('GENERIC', case._path, save_session=False)
    with patch('core.execution_log.log', case), ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(record_curiosity_probe, ['hunch A', 'hunch B']))
    assert sum(r['success'] for r in results) == 1
    assert len(case.index().by_type['curiosity_probe']) == 1


def test_absence_candidates_are_optional_and_empty_means_no_invented_work(case):
    import tools.reasoning as R
    for candidates in ([], ['read.output']):
        cid = case.record_reason_call('reason_hypothesize', True, '', {})
        response = {'success': True, '_trudi_call_id': cid, 'conclusion': 'Check the available records.',
                    'directives': {'priority_tools': candidates}}
        with patch('core.execution_log.log', case), patch.object(R, '_ask', return_value=response):
            result = R.reason_hypothesize('What remains unresolved?', mode='absence')
        assert result['directives']['priority_tools'] == []
        assert result['directives']['exploratory_suggestions'] == candidates
        assert case.index().by_call_id[cid]['directives'] == result['directives']


class TestReviewDetailsCallIdResolution:
    """Regression (VANKO run 3): the agent holds the `<py>:` wrapper tool_call
    id the middleware writes, not the reason_call id underneath. Five of six
    calls were refused with a bare 'call_id must name a saved reason result'."""

    def _log(self, tmp_path):
        from core.execution_log import ExecutionLog
        log = ExecutionLog()
        log.configure('DETAILS', str(tmp_path / 'trace.json'), save_session=False)
        return log

    def test_linked_wrapper_resolves_to_its_own_reason_call(self, tmp_path):
        from unittest.mock import patch
        from core.middleware import _trace_success_baseline
        from tools.reasoning import _resolve_reason_entry
        log = self._log(tmp_path)
        rid = log.record_reason_call('reason_evaluate_finding', True, 'VERDICT: SUPPORTED', {})
        before = len(log._entries)
        with patch('core.execution_log.log', log):
            wid = _trace_success_baseline('reason_evaluate_finding', 0.1, before,
                                          {'success': True, '_trudi_call_id': rid})
        entry, resolved = _resolve_reason_entry(log, wid)
        assert entry is not None and resolved == rid

    def test_failed_wrapper_cannot_borrow_a_neighbouring_review(self, tmp_path):
        """Peer-review reproduction: two successful reviews then a wrapper whose
        own call failed before any review existed. Nearest-preceding matching
        returned the second review with success=true for that request."""
        from tools.reasoning import _resolve_reason_entry, _reason_entry_error
        log = self._log(tmp_path)
        first = log.record_reason_call('reason_evaluate_finding', True, 'claim A', {})
        second = log.record_reason_call('reason_evaluate_finding', True, 'claim B', {})
        wid = log.record_tool_call('<py>:reason_evaluate_finding', False, False, 0, 1,
                                   stderr='ValidationError')
        log._entries[-1]['mcp_tool'] = 'reason_evaluate_finding'
        entry, _ = _resolve_reason_entry(log, wid)
        assert entry is None, 'an unlinked wrapper must not resolve to another claim'
        err = _reason_entry_error(log, wid)
        assert err['success'] is False and set(err['valid_call_ids']) >= {first, second}

    def test_interleaved_same_tool_calls_resolve_to_their_own_reviews(self, tmp_path):
        from unittest.mock import patch
        from core.middleware import _trace_success_baseline
        from tools.reasoning import _resolve_reason_entry
        log = self._log(tmp_path)
        a = log.record_reason_call('reason_evaluate_finding', True, 'claim A', {})
        b = log.record_reason_call('reason_evaluate_finding', True, 'claim B', {})
        with patch('core.execution_log.log', log):
            wa = _trace_success_baseline('reason_evaluate_finding', 0.1, len(log._entries),
                                         {'success': True, '_trudi_call_id': a})
            wb = _trace_success_baseline('reason_evaluate_finding', 0.1, len(log._entries),
                                         {'success': True, '_trudi_call_id': b})
        assert _resolve_reason_entry(log, wa)[1] == a
        assert _resolve_reason_entry(log, wb)[1] == b

    def test_reason_call_id_passes_through(self, tmp_path):
        from tools.reasoning import _resolve_reason_entry
        log = self._log(tmp_path)
        rid = log.record_reason_call('reason_synthesize', True, 'ok', {})
        entry, resolved = _resolve_reason_entry(log, rid)
        assert entry is not None and resolved == rid

    def test_unrelated_id_error_names_type_and_valid_ids(self, tmp_path):
        from tools.reasoning import _resolve_reason_entry, _reason_entry_error
        log = self._log(tmp_path)
        rid = log.record_reason_call('reason_synthesize', True, 'ok', {})
        other = log.record_tool_call('sudo fls -o 1411072 /ev/img.E01', True, False, 0, 0)
        entry, _ = _resolve_reason_entry(log, other)
        assert entry is None
        err = _reason_entry_error(log, other)
        assert err['success'] is False
        assert 'tool_call' in err['error'] and str(rid) in err['error']
        assert rid in err['valid_call_ids']

    def test_readiness_id_is_routed_to_its_own_pager(self, tmp_path):
        from tools.reasoning import _reason_entry_error
        log = self._log(tmp_path)
        log.record_reason_call('reason_synthesize', True, 'ok', {})
        rid = log.record_tool_call('<py>:reason_readiness_status', True, False, 0, 0)
        log._entries[-1]['mcp_tool'] = 'reason_readiness_status'
        err = _reason_entry_error(log, rid)
        assert 'reason.readiness_status(section=' in err['error']
