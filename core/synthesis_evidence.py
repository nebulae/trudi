"""Finding-scoped evidence handoff to independent cross-finding review."""
from copy import deepcopy
from core.evidence_packets import (PacketError, build_packet, packet_current,
                                   case_identity, review_policy)
from core.findings import active_findings
from core.readiness import digest

MAX_CONTEXT_CHARS = 96000
MAX_ROW_CHARS = 32000


def build_synthesis_index(log, extra_ids=()):
    """Metadata-only handoff. Never scan artifacts just to construct an index.

    The persisted packet retains aliases and complete version bindings. Its
    model presentation deduplicates physical sources separately.
    """
    import os
    from core.evidence_packets import cited_ids, entry_identity, file_version
    from tools._output_reader import entry_text_sources
    from tools._gates._evidence_calls import agent_authored_paths, authored_source_of
    from tools.reasoning import _is_evidence_entry
    by_id = log.index().by_call_id
    findings = active_findings(log._entries)
    authored = agent_authored_paths(log._entries)
    packet = {'schema_version': 2, 'index_only': True, 'purpose': 'cross_finding_review',
              'case': case_identity(log), 'run_id': getattr(log, '_run_id', None),
              'policy': review_policy(), 'request': {}, 'evidence': [],
              'context_only': [], 'entry_identities': {}, 'file_versions': {},
              'finding_sources': [], 'findings': []}
    extra = {int(c) for c in extra_ids if c in by_id and
             _is_evidence_entry(by_id[c], authored, for_rows=True)}
    packet['extra_ids'] = sorted(extra)
    per_finding = {}
    for finding in findings:
        ids = set(cited_ids(finding))
        old = by_id.get(finding.get('gated_by_evaluate_call_id'), {}).get('evidence_packet') or {}
        ids.update(s['call_id'] for s in old.get('evidence', []))
        per_finding[finding['call_id']] = ids
        packet['findings'].append({k: deepcopy(finding.get(k)) for k in
            ('call_id', 'revision', 'description', 'claim', 'confidence', 'gated_by_evaluate_call_id')})
    # Callers often supply the entire cited set. Existing finding bindings must
    # not turn those IDs into dependencies of every other finding.
    unbound = extra - set().union(*per_finding.values()) if per_finding else extra
    for ids in per_finding.values():
        ids.update(unbound)
    for cid in sorted(set().union(extra, *per_finding.values())):
        entry = by_id.get(cid)
        if entry is None:
            raise PacketError(f'Evidence call {cid} is missing', 'needs-evidence')
        if entry.get('type') != 'tool_call':
            continue
        from core.evidence_admission import evidence_usable
        if (not evidence_usable(entry) or authored_source_of(entry, authored)
                or not _is_evidence_entry(entry, authored, for_rows=True)):
            raise PacketError(f'Call {cid} is not admissible evidence', 'needs-evidence')
        packet['entry_identities'][str(cid)] = entry_identity(entry)
        sources = entry_text_sources(entry)
        preferred = [s for s in sources if s.kind == 'file']
        if not preferred:
            preferred = [s for s in sources if s.kind == 'stdout_sidecar'] or sources
        if not preferred:
            raise PacketError(f'No retained output for call {cid}', 'needs-evidence')
        for source in preferred:
            path = os.path.abspath(source.path) if source.path else None
            if source.stale or (path and file_version(path) is None):
                raise PacketError(f'Output changed or unavailable for call {cid}', 'needs-evidence')
            version = file_version(path) if path else digest(source.text)
            if path:
                packet['file_versions'][path] = version
            manifest = next((m for m in (entry.get('output_manifest') or {}).get('files', [])
                             if m.get('path') == path), {})
            source_id = 'S-' + digest([path or ['inline', cid], version])[:24]
            from core.evidence_display import source_schema
            packet['evidence'].append({'source_schema': source_schema(path, source.text or ''), 'source_id': source_id, 'call_id': cid, 'path': path,
                'kind': 'artifact_output' if source.kind == 'file' else 'tool_stdout',
                'output_sha256': manifest.get('sha256'),
                'output_bytes': os.path.getsize(path) if path else len(source.text.encode()),
                'retained_output_complete': bool(source.complete) and entry.get('scope_complete') is not False,
                'extractor_scope_complete': entry.get('scope_complete'), 'selections': [],
                'provenance': {'tool': entry.get('mcp_tool') or entry.get('cmd'),
                    'command': entry.get('cmd'), 'call_timestamp': entry.get('ts'),
                    'producer_call_id': source.producer_call_id, 'targeted_read': source.selector,
                    'artifact_classes': entry.get('artifact_classes'),
                    'reproduction': entry.get('reproduction'), 'attribution': source.attribution}})
    for finding in findings:
        fid = finding['call_id']
        sources = [{'call_id': s['call_id'], 'path': s['path'], 'source_id': s['source_id']}
                   for s in packet['evidence'] if s['call_id'] in per_finding[fid]]
        if not sources:
            raise PacketError(f'Finding {fid} has no retained evidence', 'needs-evidence')
        packet['finding_sources'].append({'finding_call_id': fid, 'sources': sources})
    packet['packet_id'] = 'SI-' + digest(packet)
    return packet


def task_packet(index, finding_ids):
    """Restrict both authority and model context to a review task."""
    result = deepcopy(index)
    result.pop('packet_id', None)
    result.pop('extra_ids', None)
    result['findings'] = [f for f in index['findings'] if f['call_id'] in finding_ids]
    result['finding_sources'] = [f for f in index['finding_sources'] if f['finding_call_id'] in finding_ids]
    permitted = {(s['call_id'], s['path']) for f in result['finding_sources'] for s in f['sources']}
    result['evidence'] = [s for s in result['evidence'] if (s['call_id'], s['path']) in permitted]
    cids = {s['call_id'] for s in result['evidence']}
    paths = {s['path'] for s in result['evidence']}
    result['entry_identities'] = {k: v for k, v in result['entry_identities'].items() if int(k) in cids}
    result['file_versions'] = {k: v for k, v in result['file_versions'].items() if k in paths}
    result['packet_id'] = 'ST-' + digest(result)
    return result


def build_synthesis_packet(log, extra_ids=()):
    """Preserve every finding's sources; share repeated rows without losing IDs.

    Finding receipts are an evidence handoff, never authority over synthesis.
    Stale receipts are rebuilt against current outputs. Missing sources produce
    an explicit access failure instead of a misleading empty search result.
    """
    by_id = log.index().by_call_id
    policy = review_policy()
    result = {'schema_version': 1, 'purpose': 'cross_finding_review',
              'case': case_identity(log), 'policy': policy,
              'request': {}, 'evidence': [], 'context_only': [],
              'entry_identities': {}, 'file_versions': {}, 'finding_sources': []}
    represented, row_keys = set(), {}
    remaining = MAX_ROW_CHARS

    def merge(packet):
        nonlocal remaining
        result['entry_identities'].update(packet['entry_identities'])
        result['file_versions'].update(packet['file_versions'])
        for source in packet['evidence']:
            represented.add(source['call_id'])
            item = deepcopy(source)
            # Same path/version/range is one observation even if several tools
            # or findings cite it. Different paths retain separate provenance.
            for selection in item['selections']:
                spans = []
                aliases = []
                for span in selection['spans']:
                    key = (item.get('path') or ('inline', item['call_id']),
                           item['output_sha256'], span['start_byte'], span['end_byte'],
                           (span.get('display') or {}).get('receipt_id'))
                    if key in row_keys:
                        aliases.append(row_keys[key])
                    elif max(len(span['text']), len((span.get('display') or {}).get('displayed_text', ''))) <= remaining:
                        row_keys[key] = {'call_id': item['call_id'], 'path': item.get('path'),
                                         'start_byte': span['start_byte'], 'end_byte': span['end_byte']}
                        spans.append(span)
                        remaining -= max(len(span['text']), len((span.get('display') or {}).get('displayed_text', '')))
                selection['spans'] = spans
                selection['shared_spans'] = aliases
                selection['shown_lines'] = len(spans)
                selection['selection_complete'] = len(spans) == selection['matched_lines']
                selection['rows_omitted'] = max(0, selection['matched_lines'] - len(spans) - len(aliases))
            # Retain separate selections per finding, including source aliases;
            # source-slot limits never hide a later finding's deciding source.
            result['evidence'].append(item)

    for finding in active_findings(log._entries):
        review = by_id.get(finding.get('gated_by_evaluate_call_id'), {})
        packet = review.get('evidence_packet')
        if packet is None or not packet_current(log, packet):
            request = {'description': finding['description'], 'claim': finding.get('claim') or {},
                       'input_call_ids': finding.get('input_call_ids') or [],
                       'linked_call_id': finding.get('linked_call_id') or 0}
            if packet:
                # The old review's explicit cited set and selections still
                # locate its sources; they do not renew approval of the claim.
                request['input_call_ids'] = sorted(set(request['input_call_ids']) |
                                                   {s['call_id'] for s in packet['evidence']})
            packet = build_packet(log, request, selectors=packet.get('selectors') if packet else None)
        merge(packet)
        result['finding_sources'].append({
            'finding_call_id': finding['call_id'], 'revision': finding.get('revision'),
            'principal': (finding.get('claim') or {}).get('principal'),
            'review_call_id': review.get('call_id'), 'packet_id': packet['packet_id'],
            'sources': [{'call_id': s['call_id'], 'path': s.get('path'),
                         'source_scope': s.get('provenance', {}).get('source_scope')}
                        for s in packet['evidence']]})

    from tools.reasoning import _is_evidence_entry, _authored_paths
    authored = _authored_paths(by_id)
    for cid in extra_ids:
        entry = by_id.get(cid, {})
        if cid in represented or not _is_evidence_entry(entry, authored, for_rows=True):
            continue
        merge(build_packet(log, {'description': 'Additional evidence for open review issues',
                                 'claim': {}, 'input_call_ids': [cid]}))
    result['packet_id'] = 'SP-' + digest(result)
    from core.control_response import encoded
    from core.evidence_display import prompt_packet
    if len(encoded(prompt_packet(result))) > MAX_CONTEXT_CHARS:
        raise PacketError('Synthesis source context exceeds the bounded review budget; '
                          'use narrower traced evidence selections. No sources were silently omitted.',
                          'needs-evidence')
    return result
