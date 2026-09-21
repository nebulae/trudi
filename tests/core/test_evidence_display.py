"""Displayed CSV proof is distinct from retained source bytes."""
import csv
import io
import json
from unittest.mock import patch

import pytest

from core.evidence_display import (display_span, displayed_text, prompt_packet,
                                   scan_review_rows, FIELD_CHARS)
from core.evidence_packets import build_packet, file_version, PacketError
from core.output_manifest import read_manifest
from core.execution_log import log
from core.review_issues import normalize_review, review_state
from core.synthesis_evidence import build_synthesis_packet
from tools.reasoning import _resolve_evidence_requests


def make_source(tmp_path, suffix='.csv', projection=None):
    path = tmp_path / ('observations' + suffix)
    delim = '\t' if suffix == '.tsv' else ','
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter=delim, lineterminator='\r\n')
    writer.writerow(['Identifier', 'Detail', 'Empty', 'Hidden'])
    writer.writerow(['Alpha', 'first, "quoted"\nsecond line ' + 'x' * 450 + 'CLIPPED_SUFFIX', '', 'HIDDEN_VALUE'])
    raw = stream.getvalue().encode()
    path.write_bytes(raw)
    cid = log.record_tool_call('inspect output', True, False, 0, 0,
        output_manifest=read_manifest(str(path), file_version(path),
                                      {'query': 'Alpha', 'columns': projection or []}))
    return path, cid, raw


@pytest.mark.parametrize('suffix', ['.csv', '.tsv', '.txt'])
def test_packet_display_preserves_bytes_multiline_fields_and_projection(tmp_path, suffix):
    path, cid, raw = make_source(tmp_path, suffix, ['Identifier', 'Detail', 'Empty'])
    packet = build_packet(log, {'description': 'Alpha', 'input_call_ids': [cid]})
    span = packet['evidence'][0]['selections'][0]['spans'][0]
    assert raw[span['start_byte']:span['end_byte']].decode() == span['text']
    shown = displayed_text(span)
    assert 'Identifier: Alpha' in shown and 'Detail: first, "quoted"\n  second line' in shown
    assert 'Empty:' not in shown and 'HIDDEN_VALUE' not in shown and 'CLIPPED_SUFFIX' not in shown
    assert '[field truncated]' in shown
    wire = json.dumps(prompt_packet(packet))
    assert 'HIDDEN_VALUE' not in wire and 'CLIPPED_SUFFIX' not in wire
    assert 'HIDDEN_VALUE' in span['text'] and span['row_number'] == 1


def test_fetch_and_packet_share_renderer_and_fetch_retains_canonical_bytes(tmp_path):
    projection = ['Identifier', 'Detail']
    path, cid, raw = make_source(tmp_path, projection=projection)
    packet = build_packet(log, {'description': 'Alpha', 'input_call_ids': [cid]})
    span = packet['evidence'][0]['selections'][0]['spans'][0]
    body, records = _resolve_evidence_requests(
        [{'call_id': cid, 'query': 'Alpha', 'columns': projection}], [cid], 4000, packet)
    fetched = records[0]['source_selections'][0]
    assert raw[fetched['start_byte']:fetched['end_byte']].decode() == fetched['text']
    assert displayed_text(fetched) == displayed_text(span)
    assert 'HIDDEN_VALUE' not in body and 'CLIPPED_SUFFIX' not in body
    assert displayed_text(span) in body and fetched['row_number'] == 1
    rid = log.record_reason_call('reason_synthesize', True, 'review', {})
    fetch_id = log.record_reason_evidence_fetch(rid, records)
    assert log.index().by_call_id[fetch_id]['requests'][0]['source_selections'][0]['display']


def correction(tmp_path):
    path, cid, _ = make_source(tmp_path, projection=['Identifier', 'Detail'])
    fid = log.record_finding('Alpha observed', 'SUSPECTED', linked_call_id=cid)
    issues, _ = normalize_review({'result_block': {'issues': [{
        'kind': 'unsupported_claim', 'message': 'Alpha is absent',
        'finding_call_ids': [fid], 'evidence_call_ids': [cid]}]}}, log._entries)
    log.record_reason_call('reason_synthesize', True, 'objection', {}, extra={'review_issues': issues})
    packet = build_synthesis_packet(log)
    reviewer = log.record_reason_call('reason_synthesize', True, 'correction', {})
    proof = {'call_id': cid, 'path': str(path), 'quote': 'Identifier: Alpha'}
    result = {'_trudi_call_id': reviewer, 'result_block': {'issues': [], 'resolutions': [{
        'issue_id': issues[0]['issue_id'], 'basis': 'reviewer_error',
        'reason': 'The displayed record establishes presence.', 'incorrect_premise': 'Alpha is absent',
        'call_ids': [cid], 'evidence_quotes': [proof]}]}}
    return packet, result, proof, path


def test_rendered_quote_resolves_objection_and_renderer_change_reopens_it(tmp_path):
    packet, result, proof, path = correction(tmp_path)
    _, resolutions = normalize_review(result, log._entries, packet)
    log.update_reason_call(result['_trudi_call_id'], issue_resolutions=resolutions)
    assert review_state(log._entries)[0]['status'] == 'resolved'
    with patch('core.evidence_display.VERSION', 999):
        assert review_state(log._entries)[0]['status'] == 'open'


@pytest.mark.parametrize('failure', ['hidden_column', 'clipped_suffix', 'raw_syntax', 'renderer', 'source', 'tampered_display'])
def test_unshown_or_stale_text_cannot_resolve_objection(tmp_path, failure):
    packet, result, proof, path = correction(tmp_path)
    if failure == 'hidden_column': proof['quote'] = 'HIDDEN_VALUE'
    if failure == 'clipped_suffix': proof['quote'] = 'CLIPPED_SUFFIX'
    if failure == 'raw_syntax': proof['quote'] = 'Alpha,"first'
    if failure == 'source': path.write_text('changed')
    if failure == 'tampered_display':
        packet['evidence'][0]['selections'][0]['spans'][0]['display']['displayed_text'] += ' invented'
    with patch('core.evidence_display.VERSION', 999 if failure == 'renderer' else 1):
        with pytest.raises(ValueError):
            normalize_review(result, log._entries, packet)


def test_fetched_projection_cannot_expose_hidden_raw_for_proof(tmp_path):
    packet, result, proof, path = correction(tmp_path)
    for source in packet['evidence']:
        for selection in source['selections']:
            selection['spans'] = []
    _, result['evidence_fetches'] = _resolve_evidence_requests([
        {'call_id': proof['call_id'], 'query': 'Alpha', 'columns': ['Identifier']}],
        [proof['call_id']], 4000, packet)
    assert normalize_review(result, log._entries, packet)[1][0]['status'] == 'resolved'
    proof['quote'] = 'HIDDEN_VALUE'
    with pytest.raises(ValueError, match='not shown'):
        normalize_review(result, log._entries, packet)


def test_bad_header_falls_back_to_labelled_raw_and_non_tabular_json_survives(tmp_path):
    path = tmp_path / 'broken.csv'
    path.write_text('Name,Name\nAlpha,Beta\n')
    fetched = scan_review_rows(str(path), ['alpha'], 1000)
    assert fetched.shown_rows == 1 and '[raw fallback:' in fetched.body
    assert fetched.source_selections[0]['text'] == 'Alpha,Beta\n'
    path = tmp_path / 'normal.txt'
    text = '{"name":"Alpha","hash":"0123"}\n'
    path.write_text(text)
    fetched = scan_review_rows(str(path), ['alpha'], 1000)
    assert displayed_text(fetched.source_selections[0]) == text


def test_display_budgets_do_not_clip_rows_silently_or_invent_absence(tmp_path):
    path, cid, raw = make_source(tmp_path)
    fetched = scan_review_rows(str(path), ['alpha'], 70)
    assert fetched.matched_rows == 1 and fetched.shown_rows == 0
    assert len(fetched.body) <= 70 and fetched.truncation_reason == 'budget'
    with patch('core.evidence_display.MAX_CONTEXT_CHARS', 10), patch('tools.reasoning._ask_claude') as backend:
        from tools.reasoning import _ask
        packet = build_packet(log, {'description': 'Alpha', 'input_call_ids': [cid]})
        result = _ask('system', 'review', evidence_packet=packet)
    assert not result['success'] and result['status'] == 'access_failure'
    backend.assert_not_called()


def test_targeted_where_keeps_physical_row_number(tmp_path):
    path = tmp_path / 'table.csv'
    path.write_text('ID,Value\nfirst,one\nsecond,two\n')
    cid = log.record_tool_call('read output', True, False, 0, 0,
        output_manifest=read_manifest(str(path), file_version(path), {'where': 'ID=second'}))
    packet = build_packet(log, {'description': 'second', 'input_call_ids': [cid]})
    assert packet['evidence'][0]['selections'][0]['spans'][0]['row_number'] == 2


def test_projection_keeps_requested_order_and_raw_prose_remains_bounded(tmp_path):
    span = {'text': 'alpha,beta\n', 'start_byte': 0, 'end_byte': 11, 'row_number': 1}
    receipt = display_span(span, ['First', 'Second'], ['second', 'FIRST'])
    assert receipt['displayed_text'] == 'Second: beta\nFirst: alpha'
    path = tmp_path / 'prose.txt'
    text = 'Alpha ' + 'x' * 4000 + 'HIDDEN_END\n'
    path.write_text(text)
    result = scan_review_rows(str(path), ['alpha'], 2000)
    assert result.shown_rows == 1 and len(result.body) <= 2000
    assert 'HIDDEN_END' not in result.body and result.source_selections[0]['text'] == text


def test_non_tabular_comma_prose_does_not_lose_first_line(tmp_path):
    path = tmp_path / 'prose.txt'
    path.write_text('Alpha is present, according to records\nAdditional unrelated prose\n')
    result = scan_review_rows(str(path), ['alpha'], 2000)
    assert result.shown_rows == 1 and 'Alpha is present' in result.body


def test_inline_csv_fetch_uses_labels_and_retains_unprojected_raw_separately():
    text = 'Identifier,Hidden\nAlpha,HIDDEN_VALUE\n'
    cid = log.record_tool_call('inspect records', True, False, 0, 0, stdout_excerpt=text, stdout_full=text)
    block, records = _resolve_evidence_requests([
        {'call_id': cid, 'query': 'Alpha', 'columns': ['Identifier']}], [cid], 2000)
    assert 'Identifier: Alpha' in block and 'HIDDEN_VALUE' not in block
    saved = records[0]['source_selections'][0]
    assert saved['path'] is None and 'HIDDEN_VALUE' in saved['text']
    assert displayed_text(saved) == 'Identifier: Alpha'


def test_bom_and_spaced_headers_render_identically_in_packet_and_fetch(tmp_path):
    path = tmp_path / 'spaced.csv'
    path.write_bytes(b'\xef\xbb\xbfIdentifier, Detail \r\nAlpha,value\r\n')
    cid = log.record_tool_call('inspect output', True, False, 0, 0, output_path=str(path))
    packet = build_packet(log, {'description': 'Alpha', 'input_call_ids': [cid]})
    span = packet['evidence'][0]['selections'][0]['spans'][0]
    fetched = scan_review_rows(str(path), ['alpha'], 2000).source_selections[0]
    assert displayed_text(span) == displayed_text(fetched) == 'Identifier: Alpha\nDetail: value'
