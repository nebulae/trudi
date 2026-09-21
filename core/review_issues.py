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
        for r in e.get('issue_resolutions') or []:
            if r.get('issue_id') in issues:
                issues[r['issue_id']].update(status=r['status'], resolution=r)
    active = {e['call_id'] for e in active_findings(entries)}
    all_findings = {e['call_id'] for e in entries if e.get('type') == 'finding'}
    for it in issues.values():
        receipt = (it.get('resolution') or {}).get('adjudication_receipt')
        if it['status'] == 'resolved' and receipt:
            from core.evidence_packets import file_version, entry_identity
            from core.evidence_display import renderer_version
            by_id = {e.get('call_id'): e for e in entries}
            if ((receipt.get('display_renderer_version') is not None and
                    receipt['display_renderer_version'] != renderer_version()) or
                    any(file_version(p) != v for p, v in receipt['file_versions'].items()) or
                    any(entry_identity(by_id.get(int(cid), {})) != sig
                        for cid, sig in receipt['entry_identities'].items())):
                it.update(status='open', resolution_stale=True)
        refs = set(it.get('finding_call_ids') or [])
        if it['status'] == 'open' and refs and refs <= all_findings and not refs & active:
            it.update(status='obsolete', resolution={'basis': 'retired_revisions'})
    return list(issues.values())


def normalize_review(result, entries, evidence_packet=None):
    """Validate reviewer IDs and explicit resolution evidence before storing them."""
    rb = result.get('result_block') or {}
    by_id = {e['call_id']: e for e in entries}
    raw_issues = rb.get('issues')
    if raw_issues is None:
        raw_issues = [{'kind': 'unsupported_claim', 'message': b,
                       'finding_call_ids': [], 'evidence_call_ids': []}
                      for b in result.get('blockers') or []]
    prior = {i['issue_id']: i for i in review_state(entries)}
    issues = []
    for raw in raw_issues:
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
        if raw.get('action') is not None:
            action = raw['action']
            if (not isinstance(action, dict) or type(action.get('required')) is not bool
                    or action.get('kind') not in ('collect', 'analyze', 'scan', 'repair', 'report_local')
                    or not isinstance(action.get('arguments', {}), dict)):
                raise ValueError('Issue action needs typed required/kind/arguments fields')
            it['action'] = dict(action)
        it['issue_id'] = 'R-' + digest(it)[:16]
        if raw.get('issue_id'):
            old = prior.get(raw['issue_id'])
            if not old or any(old.get(k) != it[k] for k in ('kind', 'finding_call_ids')):
                raise ValueError('An existing issue ID must keep its kind and finding scope')
            it['issue_id'] = old['issue_id']
        issues.append(it)
    resolutions = []
    for r in rb.get('resolutions') or []:
        if not isinstance(r, dict):
            raise ValueError('Resolution must be an object')
        old = prior.get(r.get('issue_id'))
        refs = r.get('call_ids') or []
        if (not old or not isinstance(r.get('reason'), str) or not r['reason'].strip()
                or not isinstance(refs, list) or not refs
                or any(type(c) is not int or c not in by_id for c in refs)):
            raise ValueError('Resolution needs an existing issue, reason and real supporting call IDs')
        fresh = [by_id[c] for c in refs if c > (old.get('raised_call_id') or 0)]
        basis = r.get('basis')
        if basis not in ('corrected_finding', 'evidence', 'qualified_limitation', 'reviewer_error'):
            raise ValueError('Invalid issue resolution basis')
        if basis != 'reviewer_error' and not any(e.get('type') in (
                'finding', 'tool_call', 'disposition', 'finding_retracted') for e in fresh):
            raise ValueError('Resolution needs new evidence, a corrected finding or a typed disposition')
        if basis == 'reviewer_error':
            premise = r.get('incorrect_premise')
            quotes = r.get('evidence_quotes')
            adjudicator = by_id.get(result.get('_trudi_call_id'), {})
            if (not evidence_packet or adjudicator.get('tool') != 'reason_synthesize'
                    or adjudicator.get('success') is not True
                    or adjudicator.get('call_id', 0) <= old.get('raised_call_id', 0)):
                raise ValueError('Reviewer-error resolution needs a fresh independent synthesis and its evidence packet')
            if not isinstance(premise, str) or not premise.strip() or premise not in old['message']:
                raise ValueError('incorrect_premise must quote the exact objection being corrected')
            if not isinstance(quotes, list) or not quotes:
                raise ValueError('Reviewer-error resolution needs exact evidence_quotes from the packet')
            from core.evidence_packets import entry_identity, file_version
            from core.evidence_display import displayed_text, renderer_version
            identities, versions = {}, {}
            for proof in quotes:
                if not isinstance(proof, dict) or proof.get('call_id') not in refs:
                    raise ValueError('Each evidence quote must name a supporting call_id')
                quote, path, cid = proof.get('quote'), proof.get('path'), proof['call_id']
                sources = [s for s in evidence_packet['evidence']
                           if s['call_id'] == cid and s.get('path') == path]
                # Shared rows remain available under another call's identical
                # physical source/version. Never match a different path.
                sources += [s for s in evidence_packet['evidence'] if path and s.get('path') == path
                            and any(s['output_sha256'] == x['output_sha256'] for x in sources)]
                texts = [displayed_text(span) for s in sources for sel in s['selections'] for span in sel['spans']]
                # Server-generated fetch receipts retain the actual displayed
                # rows. A reviewer may correct a premise after pulling a row
                # that was not in the initial selection.
                texts += [displayed_text(sel) for fetch in result.get('evidence_fetches', [])
                          if sources and fetch.get('call_id') == cid and fetch.get('status') == 'ok'
                          for sel in fetch.get('source_selections', []) if sel.get('path') == path]
                if (not isinstance(quote, str) or not quote.strip() or
                        not any(quote in text for text in texts)):
                    raise ValueError('Reviewer-error quote was not shown in the versioned source selection')
                sig = evidence_packet['entry_identities'].get(str(cid))
                if not sig or entry_identity(by_id[cid]) != sig:
                    raise ValueError('Reviewer-error evidence changed during review')
                identities[str(cid)] = sig
                if path:
                    version = evidence_packet['file_versions'].get(path)
                    if version is None or file_version(path) != version:
                        raise ValueError('Reviewer-error source changed during review')
                    versions[path] = version
            r = {**r, 'adjudication_receipt': {
                'display_renderer_version': renderer_version(),
                'review_call_id': adjudicator['call_id'], 'packet_id': evidence_packet['packet_id'],
                'issue_id': old['issue_id'], 'entry_identities': identities, 'file_versions': versions}}
        if basis == 'corrected_finding':
            targets = set(old.get('finding_call_ids') or [])
            if not any((e.get('type') == 'finding' and e.get('supersedes') in targets
                        and e.get('gated_by_evaluate_call_id')) or
                       (e.get('type') == 'finding_retracted' and e.get('finding_call_id') in targets)
                       for e in fresh):
                raise ValueError('Corrected-finding resolution needs a reviewed replacement or retraction')
        if basis == 'evidence':
            from tools._gates._evidence_calls import is_evidence_tool_call
            if not any(is_evidence_tool_call(e) and e.get('success') is True for e in fresh):
                raise ValueError('Evidence resolution needs a new successful evidence call')
        if basis == 'qualified_limitation':
            # Unavailable evidence is not permission to retain the unsupported claim.
            if old['kind'] not in ('evidence_gap', 'evidence_unavailable'):
                raise ValueError('A contradiction/unsupported claim cannot become a limitation')
            narrowed = any(e.get('type') == 'finding' and e.get('gated_by_evaluate_call_id')
                           and e.get('supersedes') in old.get('finding_call_ids', []) for e in fresh)
            unavailable = any(e.get('type') == 'disposition' and e.get('reason') in
                              ('evidence_unavailable', 'absent_from_evidence', 'out_of_scope') for e in fresh)
            if not narrowed or not unavailable:
                raise ValueError('A limitation needs a reviewed narrowed finding and an evidence disposition')
        resolutions.append({**r, 'status': 'limitation' if basis == 'qualified_limitation' else 'resolved'})
    return issues, resolutions
