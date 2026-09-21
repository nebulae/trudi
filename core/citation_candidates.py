"""Bounded discovery of uncited retained output. Matches are leads, never proof."""
import os
import time

MAX_CALLS = 256
MAX_SOURCES = 128
MAX_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_SECONDS = 1.5
MAX_CANDIDATES = 8


def suggest_sources(log, query, cited_ids=(), claim=None):
    from tools._output_reader import entry_text_sources, _cited_query_terms
    from tools.reasoning import _is_evidence_entry, _authored_paths
    from core.evidence_packets import file_version
    by_id = log.index().by_call_id
    authored = _authored_paths(by_id)
    claim = claim or {}
    terms = _cited_query_terms(query)
    terms += _cited_query_terms(query.title())
    terms += [str(s).lower() for s in [*(claim.get('entities') or []),
              claim.get('principal'), claim.get('actor')] if s]
    terms = sorted({t for t in terms if len(t) > 2 and not t.isdigit()})[:24]
    excluded = set(cited_ids or ())
    started, scanned_bytes, scanned_sources, scanned_calls = time.monotonic(), 0, 0, 0
    candidates, seen, limits = [], set(), set()
    from core.evidence_admission import evidence_usable
    eligible = [e for e in reversed(list(by_id.values())) if e.get('call_id') not in excluded
                and evidence_usable(e) and _is_evidence_entry(e, authored, for_rows=True)]
    if len(eligible) > MAX_CALLS:
        limits.add('call_cap')
    for entry in eligible[:MAX_CALLS] if terms else []:
        scanned_calls += 1
        for source in entry_text_sources(entry):
            if source.stale:
                limits.add('stale_source')
                continue
            if scanned_sources >= MAX_SOURCES or scanned_bytes >= MAX_BYTES or time.monotonic() - started >= MAX_SECONDS:
                limits.add('scan_budget')
                break
            path = os.path.abspath(source.path) if source.path else None
            key = (path, tuple(source.version or ())) if path else ('inline', entry['call_id'])
            if key in seen:
                continue
            seen.add(key)
            # Both output files and stdout may carry independently useful data.
            cap = min(MAX_SOURCE_BYTES, MAX_BYTES - scanned_bytes)
            version = file_version(path) if path else None
            try:
                if path:
                    with open(path, 'rb') as fh:
                        raw = fh.read(cap + 1)
                    if version != file_version(path):
                        limits.add('changed_during_scan')
                        continue
                else:
                    raw = source.text.encode('utf-8')
            except OSError:
                limits.add('unavailable_source')
                continue
            scan_complete = len(raw) <= cap
            raw = raw[:cap]
            scanned_sources += 1
            scanned_bytes += len(raw)
            if not scan_complete or not source.complete:
                limits.add('partial_source')
            text = raw.decode('utf-8', errors='replace')
            hits = [t for t in terms if t in text.lower()]
            if not hits:
                continue
            lines = [line for line in text.splitlines() if any(t in line.lower() for t in hits)]
            candidates.append({'call_id': entry['call_id'], 'path': path, 'kind': source.kind,
                'matched_terms': hits, 'match_count': len(lines), 'excerpt': '\n'.join(lines[:2])[:400],
                'scan_complete': scan_complete, 'retained_complete': source.complete,
                'source_version': version, 'attribution': source.attribution,
                'advisory_only': True})
    if not terms:
        limits.add('no_discriminating_terms')
    candidates.sort(key=lambda c: (-len(c['matched_terms']), -c['call_id']))
    return {'uncited_sources': candidates[:MAX_CANDIDATES], 'candidate_search': {
        'calls_available': len(eligible), 'calls_scanned': scanned_calls,
        'sources_scanned': scanned_sources, 'bytes_scanned': scanned_bytes,
        'scan_complete': not limits, 'limitations': sorted(limits),
        'candidates_omitted': max(0, len(candidates) - MAX_CANDIDATES),
        'guidance': 'Inspect candidates before citing them. A text match is not support. '
                    'No match within this scan does not require collection; narrowing the claim remains available.'}}


def add_suggestions(log, result, query, cited_ids=(), claim=None):
    # Assistance must never replace the actual gate/review result on I/O failure.
    try:
        advice = suggest_sources(log, query, cited_ids, claim)
    except Exception as exc:
        advice = {'uncited_sources': [], 'candidate_search': {
            'scan_complete': False, 'limitations': ['search_error'], 'error': str(exc)[:200]}}
    result.update(advice)
    cid = result.get('_trudi_call_id')
    if cid:
        log.update_reason_call(cid, **advice)
    return result
