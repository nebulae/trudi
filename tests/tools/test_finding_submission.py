"""Submission preserves review/gates while eliminating manual orchestration."""
import json
import threading
from unittest.mock import patch
import pytest
from core.execution_log import ExecutionLog
from core.evidence_packets import build_packet, PacketError, packet_current
from core.finding_submission import make_request
from tools.misc import submit_finding


@pytest.fixture
def case(tmp_path):
    log = ExecutionLog()
    log.configure('SUBMIT', str(tmp_path / 'trace.json'), save_session=False)
    log.record_dair_call('Analyze', 'review', False, '', '', 'stay', 'facts')
    cid = log.record_tool_call('read.output --path /tmp/source.csv', True, False, 0, 0,
                               stdout_full='Observed alpha record\nObserved beta record\n',
                               stdout_excerpt='Observed alpha record\nObserved beta record\n')
    with patch('core.execution_log.log', log):
        yield log, cid


def request(cid, **kw):
    return make_request('Observed alpha record', 'SUSPECTED', [cid], {},
                        linked_call_id=cid, **kw)


def fake_review(log, verdict='SUPPORTED', callback=None):
    def ask(system, user, **kw):
        if callback:
            callback()
        cid = log.record_reason_call('reason_evaluate_finding', True, f'VERDICT: {verdict}', {},
                                    input_call_ids=kw.get('input_call_ids'))
        return {'success': True, '_trudi_call_id': cid, 'conclusion': f'VERDICT: {verdict}',
                'result_block': {'verdict': verdict}}
    return ask


def submit(cid, key='alpha', **kw):
    return submit_finding('Observed alpha record', 'SUSPECTED', [cid], key, {},
                          linked_call_id=cid, **kw)


def test_packet_contains_exact_hashed_bytes_and_scope(case):
    log, cid = case
    packet = build_packet(log, request(cid))
    item = packet['evidence'][0]
    assert item['output_sha256'] and item['retained_output_complete']
    assert 'not the entire original evidence' in item['search_scope']
    span = item['selections'][0]['spans'][0]
    assert span['start_byte'] == 0 and span['text'] == 'Observed alpha record\n'
    assert packet_current(log, packet)


@pytest.mark.parametrize('bad_id', [0, -1, 99999, True])
def test_bad_reference_rejected_before_model(case, bad_id):
    with patch('tools.reasoning._ask') as ask:
        result = submit_finding('x', 'SUSPECTED', [bad_id], 'bad', {})
    assert not result['success'] and result['status'] == 'invalid'
    ask.assert_not_called()


def test_submit_records_once_and_survives_restart(case):
    log, cid = case
    with patch('tools.reasoning._ask', side_effect=fake_review(log)) as ask:
        first = submit(cid)
        assert first['success'], first
        log.configure('SUBMIT', log._path, save_session=False)
        second = submit(cid)
    assert second['cached'] and first['_trudi_call_id'] == second['_trudi_call_id']
    assert ask.call_count == 1
    assert len(log.index().by_type['finding']) == 1
    assert log.index().by_type['finding'][0]['evidence_packet_id'].startswith('EP-')


def test_key_cannot_be_reused_for_changed_claim(case):
    log, cid = case
    with patch('tools.reasoning._ask', side_effect=fake_review(log)):
        assert submit(cid)['success']
    result = submit_finding('Different claim', 'SUSPECTED', [cid], 'alpha', {}, linked_call_id=cid)
    assert result['status'] == 'invalid'


@pytest.mark.parametrize('verdict,status', [('CONTRADICTED', 'contradicted'), ('UNVERIFIABLE', 'needs-evidence')])
def test_review_never_silently_downgrades(case, verdict, status):
    log, cid = case
    with patch('tools.reasoning._ask', side_effect=fake_review(log, verdict)):
        result = submit(cid)
    assert result['status'] == status and not result['success']
    assert not log.index().by_type.get('finding')


def test_preflight_aggregates_without_model_or_refusal_side_effects(case):
    log, cid = case
    with patch('tools.reasoning._ask') as ask, patch.dict('os.environ', {'TRUDI_REQUIRE_TYPED_CLAIMS': '1'}):
        result = submit_finding('Observed alpha record', 'CONFIRMED', [cid], 'invalid-typed', {})
    assert result['status'] == 'needs-evidence'
    assert len(result['issues']) >= 2
    assert not log.index().by_type.get('finding_refused')
    ask.assert_not_called()


def test_changed_output_during_review_does_not_commit(case, tmp_path):
    log, cid = case
    output = tmp_path / 'rows.txt'
    output.write_text('Observed alpha record\n')
    log.annotate_tool_call(cid, output_path=str(output))
    with patch('tools.reasoning._ask', side_effect=fake_review(log, callback=lambda: output.write_text('changed'))):
        result = submit(cid)
    assert result['status'] == 'retryable-review-failure'
    assert not log.index().by_type.get('finding')


def test_review_does_not_hold_trace_lock_and_concurrent_key_coalesces(case):
    log, cid = case
    def during():
        results = []
        worker = threading.Thread(target=lambda: results.append(submit(cid)))
        worker.start(); worker.join(3)
        assert not worker.is_alive(), 'model work held the trace writer lock'
        assert results[0]['status'] == 'retryable-review-failure'
    with patch('tools.reasoning._ask', side_effect=fake_review(log, callback=during)) as ask:
        result = submit(cid)
    assert result['success'] and ask.call_count == 1


def test_missing_output_invocation_is_not_primary_evidence(case, tmp_path):
    log, cid = case
    log.annotate_tool_call(cid, output_path=str(tmp_path / 'missing.csv'))
    with pytest.raises(PacketError, match='invocation'):
        build_packet(log, request(cid))


def test_agent_authored_source_rejected(case, tmp_path):
    log, cid = case
    path = tmp_path / 'analysis' / 'fabricated.txt'
    path.parent.mkdir(); path.write_text('Observed alpha record')
    author = log.record_tool_call(f'Write {path}', True, False, 0, 0)
    log.annotate_tool_call(author, source='claude_code_write')
    log.annotate_tool_call(cid, output_path=str(path))
    with pytest.raises(PacketError, match='agent-authored'):
        build_packet(log, request(cid))


def test_packet_case_and_selected_range_are_cache_identity(case):
    log, cid = case
    a = build_packet(log, request(cid), [{'call_id': cid, 'start_byte': 0, 'end_byte': 21}])
    b = build_packet(log, request(cid), [{'call_id': cid, 'start_byte': 21}])
    assert a['packet_id'] != b['packet_id']
    log._case_id = 'OTHER'
    assert not packet_current(log, a)


def test_confirmed_submission_uses_actual_exact_receipt(case):
    log, cid = case
    claim = {'claim_kind': 'positive', 'category': 'other', 'act': 'other'}
    extra = log.record_tool_call('ez.evtxecmd Security.evtx', True, False, 0, 0,
                                  stdout_full='Observed alpha record', stdout_excerpt='Observed alpha record')
    with patch('tools.reasoning._ask', side_effect=fake_review(log)):
        result = submit_finding('Observed alpha record', 'CONFIRMED', [cid, extra], 'confirmed', claim,
                                linked_call_id=cid)
    assert result['success'], result
    finding = log.index().by_call_id[result['_trudi_call_id']]
    assert finding['confidence'] == 'CONFIRMED'
    assert log.index().by_call_id[finding['gated_by_evaluate_call_id']]['review_receipt']


def test_large_internal_review_remains_complete_through_transactional_submission(case):
    from core.review_delivery import client_review, wire_size, MAX_WIRE_BYTES
    log, cid = case
    base = fake_review(log)
    def large(*args, **kwargs):
        result = base(*args, **kwargs)
        result['inputs'] = {'user_message': 'observed data ' * 20000}
        result['conclusion'] += '\n' + 'detailed reasoning ' * 10000
        return result
    captured = []
    from core import finding_submission as S
    matches = S.receipt_matches
    def check(ctx, review):
        captured.append(review)
        return matches(ctx, review)
    with patch('tools.reasoning._ask', side_effect=large), patch.object(S, 'receipt_matches', side_effect=check):
        result = submit(cid)
    assert result['success'] and captured
    saved = captured[0]
    assert len(saved['conclusion']) > 100000 and saved['review_receipt']['binding']
    envelope = client_review(log, {**saved, '_trudi_call_id': saved['call_id']})
    assert envelope['review_receipt'] == saved['review_receipt']
    assert wire_size(envelope) <= MAX_WIRE_BYTES


def test_legacy_record_cannot_borrow_nearby_receipt_for_different_description(case):
    from tools.misc import record_finding
    import tools.reasoning as R
    log, cid = case
    claim = {'claim_kind': 'positive', 'category': 'other', 'act': 'other'}
    with patch.object(R, '_ask', side_effect=fake_review(log)):
        review = R.reason_evaluate_finding('Observed alpha record', 'Observed alpha record',
                                           input_call_ids=[cid], linked_call_id=cid, **claim)
    assert review['success'] and review['review_receipt']
    changed = record_finding('Observed alpha record AND beta caused compromise', 'LIKELY',
                             linked_call_id=cid, input_call_ids=[cid],
                             supporting_evidence='Observed alpha record AND beta caused compromise', **claim)
    assert not changed['success'] and changed.get('detail_gate') == 'review_receipt'
    original = record_finding('Observed alpha record', 'LIKELY', linked_call_id=cid,
                              input_call_ids=[cid], supporting_evidence='Observed alpha record', **claim)
    assert original['success'], original


def test_review_cache_survives_final_gate_refusal(case):
    log, cid = case
    with patch('tools.reasoning._ask', side_effect=fake_review(log)) as ask:
        with patch('tools.misc.record_finding', return_value={'success': False, 'gate': 'test', 'error': 'temporary'}):
            first = submit(cid)
        assert first['status'] == 'needs-evidence'
        second = submit(cid)
    assert second['success'], second
    assert ask.call_count == 1


def test_commit_survives_lost_response(case):
    from core import finding_submission as S
    log, cid = case
    event = S._event
    def fail_after_commit(log, key, request_hash, status, **extra):
        if status == 'recorded':
            raise RuntimeError('response transport failed')
        return event(log, key, request_hash, status, **extra)
    with patch('tools.reasoning._ask', side_effect=fake_review(log)) as ask:
        with patch.object(S, '_event', side_effect=fail_after_commit):
            first = submit(cid)
        assert not first['success']
        second = submit(cid)
    assert second['success'] and second['cached'] and ask.call_count == 1
    assert len(log.index().by_type['finding']) == 1


def test_concurrent_revision_rechecked_at_commit(case):
    log, cid = case
    parent = log.record_finding('Old alpha claim', 'SUSPECTED')
    def compete():
        log.record_finding('Concurrent alpha correction', 'SUSPECTED', supersedes=parent)
    with patch('tools.reasoning._ask', side_effect=fake_review(log, callback=compete)):
        result = submit(cid, supersedes=parent)
    assert not result['success']
    assert len(log.index().active_findings) == 1
    assert log.index().active_findings[0]['description'] == 'Concurrent alpha correction'


def test_unrelated_narration_during_review_does_not_restart(case):
    log, cid = case
    with patch('tools.reasoning._ask', side_effect=fake_review(log, callback=lambda: log.record_agent_message('planning'))) as ask:
        result = submit(cid)
    assert result['success'], result
    assert ask.call_count == 1


def test_hash_tool_retains_typed_result_for_packet(case, tmp_path):
    from tools.hashing import hash_file
    log, _ = case
    path = tmp_path / 'sample.bin'
    path.write_bytes(b'forensic sample')
    result = hash_file(str(path))
    cid = result['_trudi_call_id']
    assert log.index().by_call_id[cid]['hash_result']['sha256'] == result['sha256']
    r = make_request('SHA256 ' + result['sha256'], 'SUSPECTED', [cid], {})
    packet = build_packet(log, r)
    assert result['sha256'] in packet['evidence'][0]['selections'][0]['spans'][0]['text']


def test_csv_selection_retains_header_multiline_record_and_exact_byte_span(case, tmp_path):
    log, cid = case
    path = tmp_path / 'rows.csv'
    raw = b'name,detail\nalpha,"first line\nsecond line"\nbeta,other\n'
    path.write_bytes(raw)
    log.annotate_tool_call(cid, output_path=str(path))
    req = make_request('Alpha record', 'SUSPECTED', [cid], {}, linked_call_id=cid)
    packet = build_packet(log, req)
    sel = packet['evidence'][0]['selections'][0]
    assert sel['columns'] == ['name', 'detail'] and sel['scanned_rows'] == 2
    span = sel['spans'][0]
    assert raw[span['start_byte']:span['end_byte']].decode() == span['text']
    assert 'second line' in span['text']


def test_backend_failure_releases_key_for_retry(case):
    log, cid = case
    with patch('tools.reasoning._ask', side_effect=RuntimeError('backend unavailable')):
        failed = submit(cid)
    assert failed['status'] == 'retryable-review-failure'
    assert not log.index().by_type.get('finding')
    with patch('tools.reasoning._ask', side_effect=fake_review(log)):
        assert submit(cid)['success']


def test_identical_submission_new_transport_key_reuses_committed_finding(case):
    log, cid = case
    with patch('tools.reasoning._ask', side_effect=fake_review(log)) as ask:
        assert submit(cid)['success']
        assert submit(cid, key='different-key')['success']
    assert ask.call_count == 1
    findings = log.index().by_type['finding']
    assert len(findings) == 1


def test_legacy_receipt_binds_window_even_when_description_unchanged(case):
    from tools.misc import record_finding
    import tools.reasoning as R
    log, cid = case
    claim = {'claim_kind': 'positive', 'category': 'other', 'act': 'other'}
    with patch.object(R, '_ask', side_effect=fake_review(log)):
        review = R.reason_evaluate_finding('Observed alpha record', 'Observed alpha record',
                                           input_call_ids=[cid], linked_call_id=cid, **claim)
    assert review['success']
    result = record_finding('Observed alpha record', 'LIKELY', input_call_ids=[cid],
                             linked_call_id=cid, supporting_evidence='Observed alpha record',
                             window={'start': '2026-01-01'}, **claim)
    assert not result['success'] and result.get('detail_gate') == 'review_receipt'


@pytest.mark.parametrize('rules', [[{'what': 'alternative', 'call_ids': [True]}],
                                   [{'what': 'alternative', 'call_ids': ['2']}], 'invalid'])
def test_rule_out_ids_are_not_silently_coerced(case, rules):
    _, cid = case
    with patch('tools.reasoning._ask') as ask:
        result = submit_finding('Observed alpha record', 'SUSPECTED', [cid], 'bad-rules',
                                 {'rule_outs': rules}, linked_call_id=cid)
    assert result['status'] == 'invalid'
    ask.assert_not_called()


def test_changed_hash_source_cannot_be_attached_to_old_digest(case, tmp_path):
    import hashlib
    from tools.hashing import _record_hash_result, _cache_key
    log, _ = case
    path = tmp_path / 'hash-source'
    path.write_bytes(b'original')
    key = _cache_key(path.stat(), str(path))
    result = {'success': True, 'file': str(path), 'size_bytes': 8,
              **{algo: getattr(hashlib, algo)(b'original').hexdigest() for algo in ('md5', 'sha1', 'sha256')}}
    path.write_bytes(b'replaced')
    count = len(log._entries)
    assert not _record_hash_result(result, key)['success']
    assert len(log._entries) == count


def test_followup_fetch_uses_only_versioned_packet_sources(case, tmp_path):
    from tools.reasoning import _resolve_evidence_requests
    log, cid = case
    artifact = tmp_path / 'artifact.csv'
    artifact.write_text('name\nAlpha\n')
    sidecar = tmp_path / 'invocation.txt'
    sidecar.write_text('SECRET banner only\n')
    log.annotate_tool_call(cid, output_path=str(artifact), stdout_path=str(sidecar))
    packet = build_packet(log, request(cid))
    with patch('tools._output_reader.sibling_match_counts') as siblings:
        text, records = _resolve_evidence_requests(
            [{'call_id': cid, 'query': 'SECRET', 'columns': []}], [cid], 4000,
            evidence_packet=packet)
    assert records[0]['rows_returned'] == 0
    assert 'SECRET banner only' not in text
    siblings.assert_not_called()
    text, records = _resolve_evidence_requests(
        [{'call_id': cid, 'query': 'Alpha', 'columns': []}], [cid], 4000,
        evidence_packet=packet)
    assert records[0]['rows_returned'] == 1 and 'Alpha' in text


# Regression (VANKO-2016-DEEPSEEK41): every refusal after a CHALLENGED or failed
# review read "Review does not match the exact current claim", so the agent kept
# rewording instead of collecting evidence or dropping to SUSPECTED.
@pytest.mark.parametrize('verdict', ['CHALLENGED', 'CONTRADICTED', 'UNVERIFIABLE'])
def test_non_supported_review_is_reported_as_its_verdict(case, verdict):
    from tools.misc import record_finding
    import tools.reasoning as R
    log, cid = case
    claim = {'claim_kind': 'positive', 'category': 'other', 'act': 'other'}
    with patch.object(R, '_ask', side_effect=fake_review(log, verdict=verdict)):
        R.reason_evaluate_finding('Observed alpha record', 'Observed alpha record',
                                  input_call_ids=[cid], linked_call_id=cid, **claim)
    r = record_finding('Observed alpha record', 'LIKELY', linked_call_id=cid,
                       input_call_ids=[cid], supporting_evidence='Observed alpha record', **claim)
    assert not r['success']
    # stored verdicts are normalized (CONTRADICTED→CHALLENGED, UNVERIFIABLE→UNCERTAIN)
    names = {verdict, {'CONTRADICTED': 'CHALLENGED', 'UNVERIFIABLE': 'UNCERTAIN'}.get(verdict, verdict)}
    assert any(n in r['error'] for n in names) and 'SUSPECTED' in r['error']
    assert 'does not match' not in r['error']


def test_receipt_mismatch_names_the_differing_field(case):
    from tools.misc import record_finding
    import tools.reasoning as R
    log, cid = case
    claim = {'claim_kind': 'positive', 'category': 'other', 'act': 'other'}
    with patch.object(R, '_ask', side_effect=fake_review(log)):
        R.reason_evaluate_finding('Observed alpha record', 'Observed alpha record',
                                  input_call_ids=[cid], linked_call_id=cid, **claim)
    r = record_finding('Observed alpha record', 'LIKELY', linked_call_id=cid, input_call_ids=[cid],
                       supporting_evidence='Observed alpha record', techniques=['T1048'], **claim)
    assert not r['success'] and r.get('detail_gate') == 'review_receipt'
    assert 'claim.techniques' in r['error']
