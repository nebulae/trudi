#!/usr/bin/env python3
"""Read-only trace replay for review delivery/selection, without model calls.

Writes aggregate measurements to --output. Does not rewrite the trace, create
review receipts for use by an investigation, or claim a new factual evaluation.
"""
import argparse
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.execution_log import ExecutionLog
from core.evidence_packets import build_packet, PacketError
from core.evidence_display import display_span, prompt_packet, MAX_CONTEXT_CHARS
from core.review_delivery import client_review, wire_size, MAX_WIRE_BYTES
from core.citation_candidates import suggest_sources
from tools.reasoning import _resolve_evidence_requests


class ReplayLog(ExecutionLog):
    @contextmanager
    def transaction(self):
        yield

    def _flush(self):
        pass

    def _next_id(self):
        raise RuntimeError('Replay cannot create investigation events')


def counts(packet):
    rows = {}
    for source in packet.get('evidence', []):
        cid = str(source['call_id'])
        item = rows.setdefault(cid, {'shown': 0, 'shared': 0})
        item['shown'] += sum(len(s['spans']) for s in source['selections'])
        item['shared'] += sum(len(s.get('shared_spans', [])) for s in source['selections'])
    return rows


def replay(trace_path, client_results=None):
    raw = trace_path.read_bytes()
    original_hash = hashlib.sha256(raw).hexdigest()
    trace = json.loads(raw)
    entries = trace['entries']
    bodies = {}
    if client_results:
        for path in client_results.glob('mcp-*-reason_evaluate_finding-*.txt'):
            body = json.loads(path.read_text())
            bodies[body.get('_trudi_call_id')] = (body, path.stat().st_size)
    measurements = []
    for review in entries:
        if review.get('tool') != 'reason_evaluate_finding' or not review.get('evidence_packet'):
            continue
        cid = review['call_id']
        log = ReplayLog()
        log._case_id, log._path = trace['case_id'], str(trace_path)
        log._entries = deepcopy([e for e in entries if e.get('call_id', 0) <= cid])
        body, cached_bytes = bodies.get(cid, ({**review, '_trudi_call_id': cid}, None))
        envelope = client_review(log, body)
        old = review['evidence_packet']
        # The saved selections can still exercise presentation when original
        # output files have been retired. This does not renew their provenance.
        displayed = deepcopy(old)
        for source in displayed.get('evidence', []):
            selector = source.get('provenance', {}).get('targeted_read') or {}
            projection = selector.get('columns') or []
            if isinstance(projection, str):
                projection = [c.strip() for c in projection.split(',') if c.strip()]
            delimiter = '\t' if str(source.get('path') or '').endswith('.tsv') else ','
            for selection in source['selections']:
                for span in selection['spans']:
                    span['display'] = display_span(span, selection.get('columns', []), projection, delimiter)
        displayed_chars = len(json.dumps(prompt_packet(displayed)))
        measure = {'review_call_id': cid, 'original_cached_response_bytes': cached_bytes,
                   'new_initial_wire_bytes': wire_size(envelope),
                   'within_wire_budget': wire_size(envelope) <= MAX_WIRE_BYTES,
                   'old_packet_characters': len(json.dumps(old)), 'old_rows_by_call': counts(old),
                   'saved_selection_display_characters': displayed_chars,
                   'saved_selection_display_within_budget': displayed_chars <= MAX_CONTEXT_CHARS}
        with patch('core.execution_log.log', log):
            try:
                new = build_packet(log, old['request'], old.get('selectors'))
                measure.update(new_packet_characters=len(json.dumps(new)), new_rows_by_call=counts(new))
            except PacketError as exc:
                measure['packet_error'] = str(exc)
            suggestions = suggest_sources(log, old['request']['description'], review.get('input_call_ids'),
                                          old['request'].get('claim'))
            measure['candidate_source_ids'] = [s['call_id'] for s in suggestions['uncited_sources']]
            measure['candidate_search'] = {k: v for k, v in suggestions['candidate_search'].items() if k != 'guidance'}
            replayed = []
            for fetch in entries:
                if fetch.get('type') != 'reason_evidence_fetch' or fetch.get('reason_call_id') != cid:
                    continue
                for request in fetch.get('requests', []):
                    if request.get('status') != 'scope_mismatch':
                        continue
                    # Old receipts omitted the erroneous finding_call_id. Test
                    # the irrelevant synthesis field explicitly, without
                    # pretending it is the exact original wire request.
                    rq = {k: request[k] for k in ('call_id', 'query', 'columns') if k in request}
                    rq['finding_call_id'] = -1
                    _, records = _resolve_evidence_requests([rq], review.get('input_call_ids'), 4000, old)
                    replayed.append({'call_id': rq['call_id'], 'new_status': records[0]['status'],
                                     'searched': records[0]['searched'], 'rows': records[0]['rows_returned']})
            measure['scope_refusal_replays'] = replayed
        measurements.append(measure)
    assert hashlib.sha256(trace_path.read_bytes()).hexdigest() == original_hash
    return {'trace_sha256': original_hash, 'entry_count': len(entries), 'review_count': len(measurements),
            'method': 'Offline delivery, selection and candidate-search replay over retained outputs. '
                      'Historical ownership is not reconstructed. No new model calls or factual verdicts. '
                      'Does not measure end-to-end time or report accuracy.',
            'measurements': measurements}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', required=True, type=Path)
    parser.add_argument('--client-results', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = replay(args.trace, args.client_results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'reviews': report['review_count'], 'output': str(args.output),
                      'all_initial_responses_bounded': all(m['within_wire_budget'] for m in report['measurements'])}))
