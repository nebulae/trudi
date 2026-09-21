"""Review delivery, access failures, selection and suggestions across evidence types."""
import asyncio
import json
from unittest.mock import patch

import pytest

from core.evidence_packets import build_packet, file_version, PacketError, _selection
from core.execution_log import log
from core.review_delivery import client_review, wire_size, MAX_WIRE_BYTES
from core.output_manifest import Invocation, read_manifest
from core.citation_candidates import suggest_sources
from tools._output_reader import entry_text_sources
import tools.reasoning as R


def evidence(text='rare observation', **kw):
    return log.record_tool_call('inspect retained records', True, False, 0, 0,
                                stdout_excerpt=text, stdout_full=text, **kw)


def review(**kw):
    cid = log.record_reason_call('reason_evaluate_finding', True, 'SUPPORTED', {},
                                extra={'review_pending': False})
    return {'success': True, '_trudi_call_id': cid, 'verdict': 'SUPPORTED', **kw}


def test_large_review_delivers_id_receipt_and_lossless_unicode_details():
    body = review(inputs={'user_message': 'evidence ' * 40000},
                  unverifiable=['漢字\\"😀' * 5000], review_receipt={'binding': 'exact'})
    out = client_review(log, body)
    assert wire_size(out) <= MAX_WIRE_BYTES
    assert out['review_receipt'] == body['review_receipt']
    assert 'inputs' not in out and out['review_call_id'] == body['_trudi_call_id']
    chunks, offset = [], 0
    while offset is not None:
        page = R.reason_review_details(out['review_call_id'], 'unverifiable', offset,
                                       state_version=out['state_version'])
        assert wire_size(page) <= MAX_WIRE_BYTES
        chunks.append(page['json_chunk'])
        offset = page['next_offset']
    assert json.loads(''.join(chunks)) == body['unverifiable']
    assert len(body['inputs']['user_message']) == 360000  # internal object is intact


def test_validation_refusal_gets_own_id_and_never_borrows_review():
    previous = review()
    wrapper = evidence('validation wrapper')
    out = client_review(log, {'success': False, 'error': 'bad arguments', '_trudi_call_id': wrapper})
    assert out['review_call_id'] not in (previous['_trudi_call_id'], wrapper)
    assert log.index().by_call_id[wrapper]['reason_call_id'] == out['review_call_id']


def test_real_mcp_review_response_is_bounded_after_enrichment():
    from fastmcp import FastMCP, Client
    from core.middleware import NarrationMiddleware
    server = FastMCP('review-delivery')
    server.add_middleware(NarrationMiddleware())
    @server.tool()
    async def reason_evaluate_finding() -> dict:
        return review(inputs={'user_message': '漢字' * 50000},
                      conclusion='large rationale ' * 5000, review_receipt={'binding': 'exact'})
    async def scenario():
        async with Client(server) as client:
            result = await client.call_tool('reason_evaluate_finding', {})
            assert result.data['review_call_id']
            assert result.data['review_receipt']['binding'] == 'exact'
            assert wire_size(result.data) <= MAX_WIRE_BYTES
            assert json.loads(result.content[0].text) == result.data
            from mcp.types import CallToolResult
            envelope = CallToolResult(content=result.content, structuredContent=result.data)
            assert len(envelope.model_dump_json(by_alias=True).encode()) <= MAX_WIRE_BYTES
    asyncio.run(scenario())


def test_failed_required_request_cannot_be_discarded_by_supported_prose():
    cid = evidence()
    initial = review(evidence_requests=[{'call_id': cid + 1000, 'query': 'rare'}])
    result = R._evidence_round_trip(initial, lambda *_: {'success': True, 'verdict': 'SUPPORTED'},
                                     'review', 'reason_evaluate_finding', [cid])
    assert not result['success'] and result['status'] == 'access_failure'
    assert not result['verdict'] and not result['review_receipt']
    assert not any(e.get('type') == 'self_correction' for e in log._entries)
    log.configure(log._case_id, log._path, save_session=False)
    saved = log.index().by_call_id[initial['_trudi_call_id']]
    assert saved['access_failures'] and not saved['success']


def test_one_explicit_repair_settles_refusal_without_poisoning_verdict():
    cid = evidence()
    initial = review(evidence_requests=[{'call_id': cid + 1000, 'query': 'rare'}])
    prompts = []
    def answer(prompt, _):
        prompts.append(prompt)
        if len(prompts) == 1:
            pending = log.index().by_call_id[initial['_trudi_call_id']]['access_failures']
            return {'success': True, 'evidence_requests': [{'call_id': cid, 'query': 'rare',
                    'replaces_request_id': pending[0]['request_id']}]}
        return {'success': True, 'verdict': 'SUPPORTED'}
    result = R._evidence_round_trip(initial, answer, 'review', 'reason_evaluate_finding', [cid])
    assert result['success'] and result['verdict'] == 'SUPPORTED'
    assert result['evidence_rounds'] == 1 and result['evidence_repair_rounds'] == 1
    assert not log.index().by_call_id[initial['_trudi_call_id']]['access_failures']


def test_second_all_refused_batch_does_not_call_model_again():
    cid = evidence()
    initial = review(evidence_requests=[{'call_id': 999, 'query': 'rare'}])
    with patch.object(R, '_resolve_evidence_requests', wraps=R._resolve_evidence_requests) as resolver:
        calls = []
        def answer(*_):
            calls.append(1)
            return {'success': True, 'evidence_requests': [{'call_id': 998, 'query': 'rare'}]}
        result = R._evidence_round_trip(initial, answer, 'review', 'reason_evaluate_finding', [cid])
    assert not result['success'] and len(calls) == 1 and resolver.call_count == 2


def test_mixed_batch_does_not_repeat_successful_read():
    cid = evidence()
    requests = [{'call_id': cid, 'query': 'rare'}, {'call_id': 999, 'query': 'rare'}]
    initial = review(evidence_requests=requests)
    calls = []
    def answer(*_):
        calls.append(1)
        if len(calls) == 1:
            failed = log.index().by_call_id[initial['_trudi_call_id']]['access_failures'][0]
            return {'success': True, 'evidence_requests': [{**requests[0], 'replaces_request_id': failed['request_id']}]}
        return {'success': True, 'verdict': 'SUPPORTED'}
    result = R._evidence_round_trip(initial, answer, 'review', 'reason_evaluate_finding', [cid])
    assert result['success']
    assert sum(f['call_id'] == cid for f in result['evidence_fetches']) == 1


@pytest.mark.parametrize('mapping', [None, {}, [{'finding_call_id': 1}], [None]])
def test_malformed_synthesis_packet_never_falls_back_to_unscoped_search(mapping):
    cid = evidence()
    packet = {'purpose': 'cross_finding_review', 'finding_sources': mapping, 'evidence': []}
    _, records = R._resolve_evidence_requests([{'call_id': cid, 'query': 'rare'}], [cid], 4000, packet)
    assert records[0]['status'] == 'invalid_packet' and not records[0]['searched']


def test_completed_empty_search_differs_from_refusal():
    cid = evidence()
    _, records = R._resolve_evidence_requests([{'call_id': cid, 'query': 'missing'}], [cid], 4000)
    assert records[0]['status'] == 'ok' and records[0]['searched']
    assert records[0]['scan_complete'] and records[0]['matched_rows'] == 0


def test_manifest_does_not_acquire_later_siblings_and_detects_overwrite(tmp_path):
    own = tmp_path / 'own.csv'
    inv = Invocation([str(own)])
    inv.acquire()
    try:
        own.write_text('name\nrare\n')
        manifest = inv.finish(True)
    finally:
        inv.release()
    cid = evidence(output_manifest=manifest)
    (tmp_path / 'later.csv').write_text('unrelated')
    entry = log.index().by_call_id[cid]
    assert [s.path for s in entry_text_sources(entry) if s.kind == 'file'] == [str(own)]
    own.write_text('replaced')
    with pytest.raises(PacketError, match='changed since'):
        build_packet(log, {'description': 'rare', 'input_call_ids': [cid]})


def test_unchanged_existing_file_is_not_a_new_produced_output(tmp_path):
    path = tmp_path / 'old.csv'
    path.write_text('old')
    inv = Invocation([str(path)])
    inv.acquire()
    try:
        result = inv.finish(True)
    finally:
        inv.release()
    assert not result['files'] and result['unavailable_targets'] == [str(path)]


def test_concurrent_producers_in_shared_directory_have_distinct_manifests(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from types import SimpleNamespace
    from core.executor import run
    barrier = Barrier(2)
    def execute(cmd, **_):
        barrier.wait(timeout=3)
        (tmp_path / cmd[-1]).write_text('name\nobserved\n')
        return SimpleNamespace(returncode=0, stdout=b'done', stderr=b'')
    with patch('core.executor.subprocess.run', side_effect=execute), \
         patch('core.executor.assert_output_safe'), ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda name: run(['extract', '--csv', str(tmp_path), '--csvf', name]),
                                ['left.csv', 'right.csv']))
    for name, result in zip(['left.csv', 'right.csv'], results):
        entry = log.index().by_call_id[result['_trudi_call_id']]
        files = entry['output_manifest']['files']
        assert [f['path'] for f in files] == [str(tmp_path / name)]
        assert files[0]['producer_call_id'] == entry['call_id']


def test_same_output_target_is_serialized_before_capture(tmp_path):
    from threading import Event, Thread
    path = str(tmp_path / 'shared.csv')
    first, second = Invocation([path]), Invocation([path])
    acquired = Event()
    first.acquire()
    def acquire_second():
        second.acquire()
        acquired.set()
        second.release()
    thread = Thread(target=acquire_second)
    thread.start()
    try:
        assert not acquired.wait(0.05)
    finally:
        first.release()
    thread.join(3)
    assert acquired.is_set() and not thread.is_alive()


def test_executor_keeps_original_stdout_length_when_retention_is_capped():
    from core.executor import _log_tool
    result = {'cmd': 'inspect', 'success': True, 'truncated': True, 'retries': 0,
              'exit_code': 0, 'stderr': '', 'stdout': 'prefix', '_stdout_full': 'prefix', '_stdout_chars': 5000}
    _log_tool(result)
    entry = log.index().by_call_id[result['_trudi_call_id']]
    assert entry['stdout_chars'] == 5000 and entry['stdout_partial']
    assert not entry_text_sources(entry)[0].complete


def test_replaced_stdout_sidecar_is_not_fresh_evidence():
    from pathlib import Path
    cid = evidence('retained observation\n' * 100)
    entry = log.index().by_call_id[cid]
    Path(entry['stdout_path']).write_text('substituted evidence')
    with pytest.raises(PacketError, match='changed since'):
        build_packet(log, {'description': 'observation', 'input_call_ids': [cid]})


def test_client_stdout_truncation_does_not_make_fully_retained_data_partial(tmp_path):
    cid = log.record_tool_call('inspect', True, True, 0, 0, stdout_excerpt='observed',
                              stdout_full='observed data\n' * 100)
    packet = build_packet(log, {'description': 'observed data', 'input_call_ids': [cid]})
    assert packet['evidence'][0]['retained_output_complete']
    path = tmp_path / 'artifact.csv'
    path.write_text('field\nobserved data\n')
    log.annotate_tool_call(cid, output_path=str(path), stdout_partial=True)
    packet = build_packet(log, {'description': 'observed data', 'input_call_ids': [cid]})
    assert packet['evidence'][0]['retained_output_complete']


def test_targeted_late_read_retained_and_shared_physical_rows_not_repeated(tmp_path):
    path = tmp_path / 'rows.csv'
    path.write_text('year,name,detail\n' + '2016,noise,' + 'x' * 1200 + '\n' +
                    ''.join(f'2016,noise{i},filler\n' for i in range(100)) + '2016,needle,deciding\n')
    early = evidence(output_path=str(path))
    late = evidence(output_manifest=read_manifest(str(path), file_version(path), {'query': 'needle'}))
    other = evidence('needle independent source')
    packet = build_packet(log, {'description': '2016 needle record', 'input_call_ids': [early, late, other]})
    sources = {s['call_id']: s for s in packet['evidence']}
    assert 'deciding' in json.dumps(sources[late]['selections'])
    assert sources[other]['selections'][0]['spans']
    all_spans = [sp for s in packet['evidence'] if s['path'] == str(path)
                 for sel in s['selections'] for sp in sel['spans']]
    assert sum('deciding' in s['text'] for s in all_spans) == 1
    assert sources[early]['selections'][0]['shared_spans']


def test_rare_terms_beat_chronological_year_matches():
    raw = ('year,name\n' + '2016,noise\n' * 100 + '2016,needle\n').encode()
    selection = _selection(raw, ['2016', 'needle'], {}, 1000, 'source.csv')
    assert 'needle' in selection['spans'][0]['text']
    for span in selection['spans']:
        assert raw[span['start_byte']:span['end_byte']].decode() == span['text']


def test_candidate_search_finds_inline_stdout_but_not_reviewer_or_authored_text():
    cited = evidence('known observation')
    actual = evidence('protocol.ini ServiceUser=service_account')
    log.record_reason_call('reason_evaluate_finding', True, 'protocol.ini ServiceUser', {})
    authored = evidence('protocol.ini ServiceUser fabricated')
    log.annotate_tool_call(authored, source='claude_code_write')
    result = suggest_sources(log, 'protocol.ini ServiceUser', [cited])
    assert [c['call_id'] for c in result['uncited_sources']] == [actual]
    assert result['uncited_sources'][0]['kind'] == 'stdout_excerpt'
    assert result['uncited_sources'][0]['advisory_only']
    assert result['candidate_search']['scan_complete']


def test_capped_empty_candidate_scan_does_not_direct_collection():
    evidence('noise')
    with patch('core.citation_candidates.MAX_BYTES', 0):
        result = suggest_sources(log, 'needle')
    assert not result['uncited_sources'] and not result['candidate_search']['scan_complete']
    assert 'does not require collection' in result['candidate_search']['guidance']


def test_self_correction_candidates_are_separate_from_evidence_citations():
    from tools.misc import record_self_correction
    original = evidence('known observation')
    candidate = evidence('protocol.ini ServiceUser=service_account')
    result = record_self_correction('hypothesis_refuted', 'protocol.ini ServiceUser',
        'narrowed observation', evidence='original observation only', input_call_ids=[original])
    entry = log.index().by_call_id[result['_trudi_call_id']]
    assert candidate in entry['candidate_source_ids']
    assert entry['input_call_ids'] == [original]
    assert entry['evidence'] == 'original observation only'
