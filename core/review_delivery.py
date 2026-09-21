"""A bounded client view of a complete, saved independent review."""
from copy import deepcopy
import json

from core.readiness import digest

REVIEW_TOOLS = {'reason_evaluate_finding', 'reason_confidence_score', 'reason_cite_check'}
MAX_WIRE_BYTES = 8192


def wire_size(body):
    # Account for MCP's text and structured copies, JSON escaping and envelope.
    text = json.dumps(body, ensure_ascii=True, separators=(',', ':'))
    return len(json.dumps({'content': [{'type': 'text', 'text': text}],
                           'structuredContent': body, 'isError': False},
                          ensure_ascii=True, separators=(',', ':')).encode())


def client_review(log, body, tool_name='reason_evaluate_finding'):
    cid = body.get('_trudi_call_id')
    with log.transaction():
        entry = log.index().by_call_id.get(cid, {})
        if entry.get('type') != 'reason_call':
            # Validation refusals also need a real retrievable ID. Follow only
            # an explicit wrapper link; never borrow a neighbouring review.
            wrapper = entry if entry.get('type') == 'tool_call' else {}
            linked = log.index().by_call_id.get(wrapper.get('reason_call_id'), {})
            if linked.get('type') == 'reason_call':
                cid, entry = linked['call_id'], linked
            else:
                cid = log.record_reason_call(tool_name, bool(body.get('success')), body.get('conclusion', ''), {},
                    error=body.get('error', ''), extra={'review_pending': False})
                entry = log.index().by_call_id[cid]
                if wrapper:
                    log.annotate_tool_call(wrapper['call_id'], reason_call_id=cid)
            body = {**body, '_trudi_call_id': cid}
        saved = deepcopy({**entry, **body})
        saved.pop('control_result', None)
        log.update_reason_call(cid, control_result=saved)
    args = {'call_id': cid, 'state_version': digest(saved)}
    result = {k: saved[k] for k in ('success', 'verdict', 'fact_verdict', 'status',
              'review_pending', 'review_receipt', 'cached', 'review_session_id', 'next_action',
              'provider_calls', 'pending_requests', 'classification_consistency') if k in saved}
    result.update(review_call_id=cid, _trudi_call_id=cid,
                  control_schema_version=1, state_version=args['state_version'],
                  details_required=True,
                  details={'tool': 'reason.review_details', 'arguments': args})
    sections = [k for k in ('access_failures', 'unverifiable', 'contradictions',
                           'discriminators_missing', 'uncited_sources', 'error', 'conclusion')
                if saved.get(k)]
    result['section_counts'] = {k: len(saved[k]) if isinstance(saved[k], (list, dict)) else 1
                                for k in sections}
    result['next_actions'] = [{'kind': 'read_saved_review', 'tool': 'reason.review_details',
                              'arguments': {**args, 'section': sections[0], 'offset': 0}}] if sections else []
    # No excerpts masquerading as complete guidance. Include complete fields only.
    for key in ('tier', 'score', 'deterministic', 'tier_path', 'downgrade_reasons',
                'error', 'conclusion', 'unverifiable', 'discriminators_missing',
                'uncited_sources', 'candidate_search', 'phase_transition'):
        if key in saved and wire_size({**result, key: saved[key]}) <= MAX_WIRE_BYTES - 256:
            result[key] = saved[key]
    return result
