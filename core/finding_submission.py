"""One-finding orchestration. Model work never holds the trace writer lock."""
import contextvars
import inspect
import json
import time
import uuid
from core.evidence_packets import (PacketError, build_packet, case_identity, cited_ids,
                                   packet_current, packet_evidence_text, request_identity)
from core.readiness import digest

# Internal context, not an agent-controlled MCP parameter. Legacy entry points
# and the submission service use exactly the same reviewer and final gate path.
review_packet = contextvars.ContextVar('finding_review_packet', default=None)
submission_commit = contextvars.ContextVar('finding_submission_commit', default=None)
LEASE_SECONDS = 3600


def material_binding(description, claim, ids, supersedes=0):
    return digest([description.strip(), claim, sorted(set(ids)), supersedes])


def packet_binding(packet):
    r = packet['request']
    return material_binding(r['description'], r['claim'],
                            [e['call_id'] for e in packet['evidence']], r.get('supersedes', 0))


def receipt_matches(ctx, review):
    if review.get('success') is not True or review.get('review_pending'):
        return False
    packet, receipt = review.get('evidence_packet'), review.get('review_receipt')
    if not packet or not receipt or review.get('verdict') != 'SUPPORTED':
        return False
    ids = cited_ids({'input_call_ids': ctx.input_call_ids, 'linked_call_id': ctx.linked_call_id,
                     'claim': ctx.claim})
    # Context/review call IDs may appear in legacy lineage, but cannot stand in
    # for evidence IDs in the exact binding.
    ids = [cid for cid in ids if (ctx.idx.by_call_id.get(cid) or {}).get('type') == 'tool_call']
    binding = material_binding(ctx.description, ctx.claim, ids, getattr(ctx, 'supersedes', 0))
    return binding == receipt.get('binding') and packet_current(ctx.log, packet)


def make_request(description, confidence, input_call_ids, claim, source='', linked_call_id=0,
                 tested_hypothesis_id='', supersedes=0, case_context=''):
    from tools._gates._claims import normalize_claim
    if not isinstance(description, str) or not description.strip():
        raise PacketError('A nonempty finding description is required')
    if not isinstance(confidence, str) or confidence.upper() not in {'CONFIRMED', 'LIKELY', 'SUSPECTED', 'UNCONFIRMED'}:
        raise PacketError('Invalid confidence tier')
    if not isinstance(claim, dict):
        raise PacketError('claim must contain the typed record_finding fields')
    claim = dict(claim)
    if 'kind' in claim:
        claim['claim_kind'] = claim.pop('kind')
    allowed = set(inspect.signature(normalize_claim).parameters)
    unknown = set(claim) - allowed
    if unknown:
        raise PacketError(f'Unknown claim fields: {sorted(unknown)}')
    for key in ('transfer_call_ids', 'receipt_call_ids', 'session_binding_call_ids'):
        if key in claim and (not isinstance(claim[key], list) or
                            any(type(c) is not int or c <= 0 for c in claim[key])):
            raise PacketError(f'{key} must be positive integer call IDs')
    if 'rule_outs' in claim:
        rules = claim['rule_outs']
        if (not isinstance(rules, list) or any(
                not isinstance(rule, dict) or not isinstance(rule.get('call_ids', []), list)
                or any(type(cid) is not int or cid <= 0 for cid in rule.get('call_ids', []))
                for rule in rules)):
            raise PacketError('rule_outs must contain positive integer call IDs')
    if type(supersedes) is not int or supersedes < 0:
        raise PacketError('supersedes must be an integer finding call ID')
    if not isinstance(input_call_ids, list) or any(type(c) is not int or c <= 0 for c in input_call_ids):
        raise PacketError('input_call_ids must be positive integer call IDs')
    if type(linked_call_id) is not int or linked_call_id < 0:
        raise PacketError('linked_call_id must be a positive integer call ID or zero')
    request = {'description': description.strip(), 'confidence': confidence.upper(),
               'input_call_ids': sorted(set(input_call_ids)), 'claim': normalize_claim(**claim),
               'source': source, 'linked_call_id': linked_call_id,
               'tested_hypothesis_id': tested_hypothesis_id, 'supersedes': supersedes,
               'case_context': case_context}
    cited_ids(request)
    return request


def claim_kwargs(claim):
    from tools._gates._claims import normalize_claim
    return {k: claim.get('kind' if k == 'claim_kind' else k)
            for k in inspect.signature(normalize_claim).parameters}


def gate_context(log, request, supporting):
    from tools._gates import GateContext
    return GateContext(description=request['description'], confidence=request['confidence'],
                       tier=request['confidence'], source=request['source'],
                       linked_call_id=request['linked_call_id'],
                       tested_hypothesis_id=request['tested_hypothesis_id'],
                       log=log, idx=log.index(), window=log.last_n_window(30),
                       input_call_ids=cited_ids(request), supporting_evidence=supporting,
                       claim=request['claim'])


def preflight(log, request, supporting=None):
    """Aggregate side-effect-free prerequisites; no review gate is fabricated."""
    from core.findings import validate_revision
    from tools._gates import (mcp_routing, agent_authored_source, dair_required,
                             lineage_required, tier_contract, contracts)
    from tools._gates import (typed_claims, refusal_rewording, confirmed_requires_linked_call_id,
                             linked_call_id_must_exist, confidence_and_citation,
                             hypothesize_required, mitre_technique_validation)
    try:
        validate_revision(log._entries, request['supersedes'], request['claim'])
    except ValueError as exc:
        return [{'gate': 'finding_revision', 'error': str(exc)}]
    ctx = gate_context(log, request, supporting or '')
    failures = []
    for check in (typed_claims.check, mcp_routing.check, agent_authored_source.check,
                  dair_required.check, lineage_required.check,
                  confirmed_requires_linked_call_id.check, linked_call_id_must_exist.check,
                  mitre_technique_validation.check, hypothesize_required.check, refusal_rewording.check):
        result = check(ctx)
        if result:
            failures.append(result)
    if any(f.get('gate') in {'typed_claims', 'linked_call_id_must_exist', 'lineage_required'} for f in failures):
        return failures
    checks = [tier_contract.check, contracts.completeness, contracts.attribution, contracts.transfer]
    if supporting is not None:
        checks.insert(0, confidence_and_citation.check)
    for check in checks:
        result = check(ctx)
        if result:
            if result.get('gate') == 'confidence_and_citation':
                result = {**result, 'error': (
                    'The packet selection does not support every concrete value in the claim. '
                    'Use selectors to include the deciding rows, cite a narrower traced read, '
                    f"or correct the claim. Missing: {result.get('uncited_claims', [])}")}
            failures.append(result)
    return failures


def _event(log, key, request_hash, status, **extra):
    from core.execution_log import _utcnow
    cid = log._next_id()
    log._append_entry({'type': 'finding_submission', 'call_id': cid, 'ts': _utcnow(),
                       'idempotency_key': key, 'request_hash': request_hash,
                       'status': status, **extra})
    return cid


def _existing(log, key, request_hash):
    rows = [e for e in log._entries if e.get('submission_key') == key or
            (e.get('type') == 'finding_submission' and e.get('idempotency_key') == key)]
    if any(e.get('submission_request_hash', e.get('request_hash')) != request_hash for e in rows):
        raise PacketError('Idempotency key was already used for a different request')
    finding = next((e for e in rows if e.get('type') == 'finding'), None)
    if finding:
        from core.findings import active_findings
        return {'success': True, 'status': 'recorded', 'cached': True,
                '_trudi_call_id': finding['call_id'], 'finding_id': finding['finding_id'],
                'revision': finding['revision'],
                'currently_active': any(e['call_id'] == finding['call_id'] for e in active_findings(log._entries))}
    if rows and rows[-1].get('status') == 'reviewing' and rows[-1].get('lease_until', 0) > time.time():
        return {'success': False, 'status': 'retryable-review-failure', 'retryable': True,
                'error': 'This submission is already being reviewed; retry the same key later'}
    return None


def _failure(status, error, **extra):
    return {'success': False, 'status': status, 'error': error,
            'retryable': status == 'retryable-review-failure', **extra}


def submit(log, request, key, selectors=None):
    if not isinstance(key, str) or not key.strip() or len(key) > 200:
        return _failure('invalid', 'Provide a nonempty idempotency_key of at most 200 characters')
    request_hash = request_identity([request, selectors or []])
    owner = uuid.uuid4().hex
    configured = case_identity(log)
    try:
        with log.transaction():
            if not log._path:
                raise PacketError('Start the case execution log before submission')
            previous = _existing(log, key, request_hash)
            if previous:
                return previous
            identical = next((e for e in log._entries if e.get('type') == 'finding'
                              and e.get('submission_request_hash') == request_hash), None)
            if identical:
                # A new transport key must not spend a receipt again or create
                # another copy of the identical already-recorded conclusion.
                return _existing(log, identical['submission_key'], request_hash)
            known = log.index().by_call_id
            if any(cid not in known for cid in cited_ids(request)):
                raise PacketError('Unknown/future evidence call IDs in this case')
            failures = preflight(log, request)
            if failures:
                _event(log, key, request_hash, 'needs-evidence', error='Deterministic prerequisites')
                return _failure('needs-evidence', 'Resolve deterministic prerequisites before review',
                                issues=failures, next_actions=[f.get('error', '') for f in failures])
            # Freeze inputs without holding the writer lock during file IO/model work.
            from copy import deepcopy
            snapshot = deepcopy(log._entries)
        from types import SimpleNamespace
        packet = build_packet(SimpleNamespace(_entries=snapshot, _case_id=log._case_id, _path=log._path),
                              request, selectors)
        supporting = packet_evidence_text(packet)
        with log.transaction():
            if case_identity(log) != configured or not packet_current(log, packet):
                raise PacketError('Evidence changed during preflight; retry', 'retryable-review-failure')
            previous = _existing(log, key, request_hash)
            if previous:
                return previous
            failures = preflight(log, request, supporting)
            if failures:
                _event(log, key, request_hash, 'needs-evidence', error='Deterministic prerequisites')
                return _failure('needs-evidence', 'Resolve deterministic prerequisites before review',
                                issues=failures, next_actions=[f.get('error', '') for f in failures])
            _event(log, key, request_hash, 'reviewing', owner=owner,
                   lease_until=time.time() + LEASE_SECONDS, packet_id=packet['packet_id'])
        from tools import reasoning as R
        # Cache only finalized reviews. They are scoped by case, exact proposition,
        # selected bytes, source version and reviewer/policy identity.
        cached = next((e for e in reversed(log._entries)
                       if e.get('tool') == 'reason_evaluate_finding'
                       and (e.get('review_receipt') or {}).get('binding') == packet_binding(packet)), None)
        spent = {e.get('gated_by_evaluate_call_id') for e in log._entries if e.get('type') == 'finding'}
        if (cached and cached.get('success') is True and not cached.get('review_pending')
                and cached['call_id'] not in spent
                and cached['review_receipt'].get('packet_id') == packet['packet_id']):
            result = {**cached, '_trudi_call_id': cached['call_id'], 'cached': True}
        else:
            token = review_packet.set(packet)
            try:
                # One orchestration owner: use the same evaluator body without
                # spawning another watchdog thread that would lose case context.
                args = claim_kwargs(request['claim'])
                result = inspect.unwrap(R.reason_evaluate_finding)(
                    finding=request['description'], supporting_evidence=supporting,
                    case_context=request['case_context'], input_call_ids=cited_ids(request),
                    intended_tier=request['confidence'], linked_call_id=request['linked_call_id'],
                    supersedes=request['supersedes'], **args)
            finally:
                review_packet.reset(token)
        with log.transaction():
            if case_identity(log) != configured:
                return _failure('retryable-review-failure', 'Active case changed; no finding committed')
            # Successful commit is sufficient for a retry even if response/logging
            # after that commit was interrupted.
            prior = next((e for e in log._entries if e.get('type') == 'finding' and
                          e.get('submission_key') == key), None)
            if prior:
                return _existing(log, key, request_hash)
            latest = next((e for e in reversed(log._entries) if e.get('type') == 'finding_submission'
                           and e.get('idempotency_key') == key), {})
            if latest.get('owner') != owner:
                return _failure('retryable-review-failure', 'Submission lease was replaced; retry the same key')
            if not packet_current(log, packet):
                outcome = _failure('retryable-review-failure', 'Reviewed evidence changed; retry with current evidence')
            elif not result.get('success'):
                outcome = _failure(result['status'] if result.get('status') in ('in_progress', 'access_failure', 'classification_mismatch', 'review_budget_exhausted') else
                                   'retryable-review-failure', result.get('error', 'Review did not complete'),
                                   next_action=result.get('next_action'), review_session_id=result.get('review_session_id'))
            elif result.get('verdict') != 'SUPPORTED':
                status = 'contradicted' if result.get('verdict') == 'CHALLENGED' else 'needs-evidence'
                outcome = _failure(status, result.get('conclusion') or 'Reviewer needs more evidence',
                                   review_call_id=result.get('_trudi_call_id'),
                                   next_actions=result.get('discriminators_missing') or result.get('directives'))
            else:
                from tools.misc import record_finding
                token = submission_commit.set({'submission_key': key, 'submission_request_hash': request_hash,
                                               'evidence_packet_id': packet['packet_id'],
                                               'review_call_id': result.get('_trudi_call_id'),
                                               'packet': packet})
                try:
                    outcome = record_finding(
                        description=request['description'], confidence=request['confidence'],
                        source=request['source'], linked_call_id=request['linked_call_id'],
                        tested_hypothesis_id=request['tested_hypothesis_id'],
                        input_call_ids=cited_ids(request), supporting_evidence=supporting,
                        supersedes=request['supersedes'], **claim_kwargs(request['claim']))
                finally:
                    submission_commit.reset(token)
                outcome['status'] = 'recorded' if outcome.get('success') else 'needs-evidence'
            if not outcome.get('success') and result.get('_trudi_call_id'):
                from core.review_delivery import client_review
                saved = client_review(log, result)
                outcome.update(review_call_id=saved['review_call_id'], details=saved['details'],
                               uncited_sources=result.get('uncited_sources', []),
                               candidate_search=result.get('candidate_search', {}))
            _event(log, key, request_hash, outcome['status'], owner=owner,
                   review_call_id=result.get('_trudi_call_id'), error=outcome.get('error'))
            return outcome
    except Exception as exc:
        status = exc.status if isinstance(exc, PacketError) else 'retryable-review-failure'
        if case_identity(log) == configured:
            with log.transaction():
                latest = next((e for e in reversed(log._entries) if e.get('type') == 'finding_submission'
                               and e.get('idempotency_key') == key), {})
                if latest.get('owner') == owner:
                    _event(log, key, request_hash, status, owner=owner, error=str(exc))
        return _failure(status, str(exc))
