"""Durable synthesis issues. New review rounds cannot erase unresolved objections."""
from core.findings import active_findings
from core.readiness import digest

KINDS = {'contradiction', 'unsupported_claim', 'evidence_gap', 'evidence_unavailable',
         'review_failure', 'advisory'}


def review_state(entries):
    issues = {}
    for e in entries:
        if e.get('tool') != 'reason_synthesize' or e.get('success') is False:
            continue
        for it in e.get('review_issues') or []:
            old = issues.get(it['issue_id'])
            if old is None or old['status'] != 'open':
                issues[it['issue_id']] = {**it, 'status': 'open', 'raised_call_id': e.get('call_id')}
            else:
                # A re-raise of an open issue restates it; the original raise
                # still dates what counts as fresh resolving evidence.
                old['message'] = it['message']
                old['evidence_call_ids'] = it.get('evidence_call_ids', [])
        for r in e.get('issue_resolutions') or []:
            if r.get('issue_id') in issues:
                issues[r['issue_id']].update(status=r['status'], resolution=r)
    active = {e['call_id'] for e in active_findings(entries)}
    all_findings = {e['call_id'] for e in entries if e.get('type') == 'finding'}
    for it in issues.values():
        refs = set(it.get('finding_call_ids') or [])
        if it['status'] == 'open' and refs and refs <= all_findings and not refs & active:
            it.update(status='obsolete', resolution={'basis': 'retired_revisions'})
    return list(issues.values())


def issue_id_for(kind, finding_call_ids, message) -> str:
    """Stable identity: a reworded re-raise against the same findings is the
    same issue, not a second open one. Issues naming no finding fall back to
    their message."""
    fids = sorted(set(finding_call_ids or []))
    key = {'kind': kind, 'finding_call_ids': fids} if fids else {'kind': kind, 'message': message}
    return 'R-' + digest(key)[:16]


def completed_rounds(entries) -> int:
    """Synthesis rounds whose review was recorded (issues + resolutions stored)."""
    return sum(1 for e in entries if e.get('tool') == 'reason_synthesize'
               and e.get('success') is not False and 'review_issues' in e)


def normalize_review(result, entries):
    """Validate reviewer issues and resolutions ITEM BY ITEM.

    Returns (issues, resolutions, rejected). One malformed item is rejected
    with its reason; it no longer discards the whole round (2026-09-23: three
    of eight VANKO-2016-DEEPSEEK41 synthesis rounds were thrown away over a
    single invalid limitation, taking their valid resolutions with them)."""
    rb = result.get('result_block') or {}
    by_id = {e['call_id']: e for e in entries}
    raw_issues = rb.get('issues')
    if raw_issues is None:
        raw_issues = [{'kind': 'unsupported_claim', 'message': b,
                       'finding_call_ids': [], 'evidence_call_ids': []}
                      for b in result.get('blockers') or []]
    prior = {i['issue_id']: i for i in review_state(entries)}
    issues, rejected = [], []
    for raw in raw_issues:
        try:
            issues.append(_check_issue(raw, by_id, prior))
        except ValueError as exc:
            rejected.append({'item': 'issue', 'reason': str(exc),
                             'message': str((raw or {}).get('message') if isinstance(raw, dict) else raw)[:300]})
    resolutions = []
    for r in rb.get('resolutions') or []:
        try:
            resolutions.append(_check_resolution(r, by_id, prior))
        except ValueError as exc:
            rejected.append({'item': 'resolution', 'reason': str(exc),
                             'issue_id': r.get('issue_id') if isinstance(r, dict) else None})
    return issues, resolutions, rejected


def _check_issue(raw, by_id, prior):
    if not isinstance(raw, dict) or raw.get('kind') not in KINDS or not isinstance(raw.get('message'), str) or not raw['message'].strip():
        raise ValueError('Each synthesis issue needs a valid kind and message')
    fids, eids = raw.get('finding_call_ids', []), raw.get('evidence_call_ids', [])
    if not isinstance(fids, list) or not isinstance(eids, list):
        raise ValueError('Issue references must be lists of call IDs')
    if any(not isinstance(cid, int) or cid not in by_id for cid in fids + eids):
        raise ValueError('Synthesis issue references an unknown call ID')
    if any(by_id[cid].get('type') != 'finding' for cid in fids):
        raise ValueError('finding_call_ids must reference findings')
    it = {'kind': raw['kind'], 'message': raw['message'],
          'finding_call_ids': sorted(set(fids)), 'evidence_call_ids': sorted(set(eids))}
    it['issue_id'] = issue_id_for(it['kind'], it['finding_call_ids'], it['message'])
    old = prior.get(raw.get('issue_id')) if raw.get('issue_id') else None
    if old and old.get('kind') == it['kind']:
        it['issue_id'] = old['issue_id']      # the reviewer named the issue it restates
    return it


def _check_resolution(r, by_id, prior):
    if not isinstance(r, dict):
        raise ValueError('Resolution must be an object')
    old = prior.get(r.get('issue_id'))
    refs = r.get('call_ids') or []
    if (not old or not isinstance(r.get('reason'), str) or not r['reason'].strip()
            or not isinstance(refs, list) or not refs
            or any(type(c) is not int or c not in by_id for c in refs)):
        raise ValueError('Resolution needs an existing issue, reason and real supporting call IDs')
    fresh = [by_id[c] for c in refs if c > (old.get('raised_call_id') or 0)]
    if not any(e.get('type') in ('finding', 'tool_call', 'disposition', 'finding_retracted') for e in fresh):
        raise ValueError('Resolution needs new evidence, a corrected finding or a typed disposition')
    basis = r.get('basis')
    if basis not in ('corrected_finding', 'evidence', 'qualified_limitation'):
        raise ValueError('Invalid issue resolution basis')
    # A correction may arrive as a revision of the named finding OR as a new
    # reviewed finding that reconciles it (2026-09-23: every reviewer-endorsed
    # resolution citing such a finding was rejected on form, so no issue could
    # ever close). Either way the resolving finding passed its own SUPPORTED
    # review; evidence resolutions still need a fresh successful evidence call,
    # cited directly or through the resolving finding's own citations.
    from tools._gates._evidence_calls import is_evidence_tool_call

    def _evidence(entry) -> bool:
        return is_evidence_tool_call(entry) and entry.get('success') is True

    def _grounded(f) -> bool:
        # Passed its own SUPPORTED review, or (SUSPECTED needs none) cites at
        # least one successful evidence call.
        return bool(f.get('gated_by_evaluate_call_id')) or any(
            isinstance(c, int) and c in by_id and _evidence(by_id[c])
            for c in (f.get('input_call_ids') or []) + [f.get('linked_call_id')])

    reviewed_new = [e for e in fresh if e.get('type') == 'finding' and _grounded(e)]

    if basis == 'corrected_finding':
        targets = set(old.get('finding_call_ids') or [])
        if not (reviewed_new or any(e.get('type') == 'finding_retracted'
                                    and e.get('finding_call_id') in targets for e in fresh)):
            raise ValueError('Corrected-finding resolution needs a reviewed replacement, '
                             'a reviewed reconciling finding, or a retraction')
    if basis == 'evidence':
        via_findings = [by_id[c] for f in reviewed_new for c in (f.get('input_call_ids') or [])
                        if isinstance(c, int) and c in by_id]
        if not any(_evidence(e) for e in fresh + via_findings):
            raise ValueError('Evidence resolution needs a new successful evidence call')
    if basis == 'qualified_limitation':
        # Unavailable evidence is not permission to retain the unsupported claim.
        if old['kind'] not in ('evidence_gap', 'evidence_unavailable'):
            raise ValueError('A contradiction/unsupported claim cannot become a limitation')
        narrowed = any(e.get('type') == 'finding' and e.get('supersedes') in old.get('finding_call_ids', [])
                       and _grounded(e) for e in fresh)
        unavailable = any(e.get('type') == 'disposition' and e.get('reason') in
                          ('evidence_unavailable', 'absent_from_evidence', 'out_of_scope') for e in fresh)
        if not narrowed or not unavailable:
            raise ValueError('A limitation needs a reviewed narrowed finding and an evidence disposition')
    return {**r, 'status': 'limitation' if basis == 'qualified_limitation' else 'resolved'}
