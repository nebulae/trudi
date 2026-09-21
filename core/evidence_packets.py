"""Versioned evidence selections shared by finding review and submission.

The text is read from traced outputs, never from the submitted claim. Byte ranges
are half-open and refer to the hashed output. Search completeness is distinct
from how many matching lines fit in the packet.
"""
import csv
import hashlib
import json
import os
import heapq
import math
import re
from pathlib import Path
from core.readiness import digest

VERSION = 3
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_PACKET_CHARS = 32000
MAX_SCAN_BYTES = 256 * 1024 * 1024
MAX_SOURCES = 32
_VOLATILE = {'ts', 'elapsed_seconds', 'input_tokens', 'output_tokens', 'dair_phase', 'dair_depth'}


class PacketError(ValueError):
    def __init__(self, message, status='invalid'):
        super().__init__(message)
        self.status = status


def file_version(path):
    try:
        st = os.stat(path)
        return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]
    except OSError:
        return None


def entry_identity(entry):
    return digest({k: v for k, v in entry.items() if k not in _VOLATILE})


def case_identity(log):
    return [log._case_id, os.path.realpath(log._path or '')]


def cited_ids(request):
    claim = request.get('claim') or {}
    values = list(request.get('input_call_ids') or [])
    if request.get('linked_call_id'):
        values.append(request['linked_call_id'])
    for key in ('session_binding_call_ids', 'transfer_call_ids', 'receipt_call_ids'):
        values += claim.get(key) or []
    for item in claim.get('rule_outs') or []:
        values += item.get('call_ids') or []
    if any(type(c) is not int or c <= 0 for c in values):
        raise PacketError('Evidence references must be positive integer call IDs')
    return sorted(set(values))


def review_policy():
    # No secrets/endpoints in the receipt. The model and deliberate review
    # settings participate in identity; source hashes cover prompt/gate changes.
    from tools import reasoning as R
    root = Path(__file__).resolve().parents[1]
    policy = {}
    for pattern in ('core/evidence_packets.py', 'core/finding_submission.py',
                    'core/synthesis_session.py', 'core/evidence_admission.py',
                    'core/synthesis_evidence.py', 'core/review_issues.py', 'core/output_manifest.py',
                    'core/evidence_display.py', 'core/mail_evidence.py', 'core/evidence_requests.py', 'core/finding_review.py', 'core/correspondent_scope.py', 'core/question_outcomes.py',
                    'tools/reasoning.py', 'tools/_llm_parse.py', 'tools/_output_reader.py',
                    'tools/_gates/*.py', 'data/fk/**/*.yaml'):
        for path in root.glob(pattern):
            policy[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest([VERSION, policy, R._active_backend(), R.REASON_MODEL,
                   R.MAX_TOKENS_EVALUATE, R.COMPAT_EVIDENCE_ROUNDS, R.COMPAT_EVIDENCE_MODE,
                   digest(R.REASON_URL), R.COMPAT_EXTRA_BODY_RAW, R.REASON_FK,
                   R.COMPAT_THINKING_BUDGET, R.COMPAT_NO_THINK_MODE,
                   sorted(R.COMPAT_NO_THINK_TOOLS), R.COMPAT_EVIDENCE_ROUND_CHARS])


def request_identity(request):
    return digest(request)


def _selection(raw, query, selector, budget, path=''):
    from tools.reasoning import COMPAT_PUSH_ROWS_PER_CID
    start, end = selector.get('start_byte', 0), selector.get('end_byte', len(raw))
    if type(start) is not int or type(end) is not int or not 0 <= start <= end <= len(raw):
        raise PacketError('Byte selectors must lie within the retained output')
    explicit = 'start_byte' in selector or 'end_byte' in selector
    terms = [] if explicit else query
    # Preserve a traced targeted read before falling back to claim-wide terms.
    if not explicit and selector.get('query'):
        terms = [t for t in re.split(r'[\s,|]+', selector['query'].lower())
                 if len(t) >= 2 and t not in {'and', 'or', 'not'}][:24] or terms
    from core.mail_evidence import is_mail, scan_mail
    if not explicit and is_mail(path, raw[:100]):
        result = scan_mail(path, terms, budget, raw=raw)
        return {'selectors': {'query_terms': terms}, 'columns': result.available_columns,
                'spans': result.source_selections, 'scanned_rows': result.total_rows,
                'matched_lines': result.matched_rows, 'shown_lines': result.shown_rows,
                'selection_complete': result.scan_complete and result.shown_rows == result.matched_rows and not result.clipped_rows,
                'selected_chars': len(result.body)}
    lower = raw.decode('utf-8', errors='replace').lower()
    weights = {t: math.log1p(max(1, len(lower)) / (1 + lower.count(t))) *
               (0.1 if t.isdigit() and len(t) == 4 and 1900 <= int(t) <= 2100 else 1)
               for t in terms}
    del lower
    spans, offset, matches, used, scanned = [], start, 0, 0, 0
    columns = []
    record_number = 0
    source = raw[start:end].splitlines(keepends=True)
    from core.evidence_display import table_header, display_span, matches_table_header
    header, delimiter = table_header(source[0].decode('utf-8', errors='replace') if source else '', path)
    if header and not path.lower().endswith(('.csv', '.tsv')):
        sample = raw[start + len(source[0]):start + len(source[0]) + 65536].decode('utf-8', errors='replace')
        if not matches_table_header(sample, header, delimiter):
            header = []
    if not explicit and header:
        position = 0
        def lines():
            nonlocal position
            for line in source:
                position += len(line)
                # csv rejects NUL; byte offsets still come from the raw line.
                yield line.decode('utf-8-sig' if position == len(line) else 'utf-8',
                                  errors='replace').replace('\x00', '')
        reader = csv.reader(lines(), delimiter=delimiter)
        try:
            next(reader, [])
            columns = header
            offset = position
        except csv.Error as exc:
            raise PacketError(f'Cannot parse cited table: {exc}', 'needs-evidence') from exc
        def records():
            nonlocal offset, record_number
            try:
                for row in reader:
                    record_number += 1
                    stop = position
                    where = selector.get('where', '')
                    if where and '=' in where:
                        name, value = where.split('=', 1)
                        cells = dict(zip((c.strip().lower() for c in columns), row))
                        if cells.get(name.strip().lower(), '').strip().lower() != value.strip().lower():
                            offset = stop
                            continue
                    yield offset, stop, raw[offset:stop].decode('utf-8', errors='replace')
                    offset = stop
            except csv.Error as exc:
                raise PacketError(f'Cannot parse cited table: {exc}', 'needs-evidence') from exc
    else:
        def records():
            nonlocal offset
            for line in source:
                stop = offset + len(line)
                yield offset, stop, line.decode('utf-8', errors='replace')
                offset = stop
    ranked = []
    for begin, stop, body in records():
        scanned += 1
        if not terms or any(t in body.lower() for t in terms):
            matches += 1
            if explicit and used + len(body) <= budget:
                spans.append({'start_byte': begin, 'end_byte': stop, 'row_number': scanned, 'text': body})
                used += len(body)
            elif not explicit:
                score = sum(w for t, w in weights.items() if t in body.lower())
                item = (score, -begin, stop, record_number if columns else scanned, body)
                if len(ranked) < 400:
                    heapq.heappush(ranked, item)
                elif item[:2] > ranked[0][:2]:
                    heapq.heapreplace(ranked, item)
    for score, neg_begin, stop, row, body in sorted(ranked, reverse=True):
        if len(spans) >= COMPAT_PUSH_ROWS_PER_CID:
            break
        if used + len(body) <= budget:
            spans.append({'start_byte': -neg_begin, 'end_byte': stop, 'row_number': row, 'text': body})
            used += len(body)
    projection = selector.get('columns') or []
    if isinstance(projection, str):
        projection = [c.strip() for c in projection.split(',') if c.strip()]
    fallback = 'Unparseable table header; raw lines shown.' if not header and path.lower().endswith(('.csv', '.tsv')) else ''
    displayed, display_used = [], 0
    for span in spans:
        span['display'] = display_span(span, columns, projection, delimiter, fallback)
        length = len(span['display']['displayed_text'])
        if display_used + length <= budget:
            displayed.append(span)
            display_used += length
    spans = displayed
    if columns:
        scanned = record_number
    return {'selectors': {'start_byte': start, 'end_byte': end, 'query_terms': terms},
            'columns': columns, 'spans': spans, 'scanned_rows': scanned,
            'matched_lines': matches, 'shown_lines': len(spans),
            'selection_complete': len(spans) == matches, 'selected_chars': display_used}


def build_packet(log, request, selectors=None):
    from tools._output_reader import entry_text_sources, _cited_query_terms, _cmd_output_paths
    from tools._gates._evidence_calls import agent_authored_paths, authored_source_of
    from tools.reasoning import _is_evidence_entry
    ids = cited_ids(request)
    if not ids:
        raise PacketError('Cite at least one evidence-producing call')
    by_id = {e['call_id']: e for e in log._entries if e.get('call_id') is not None}
    unknown = [cid for cid in ids if cid not in by_id]
    if unknown:
        raise PacketError(f'Unknown/future evidence call IDs in this case: {unknown}')
    selectors = selectors or []
    if not isinstance(selectors, list) or any(not isinstance(s, dict) for s in selectors):
        raise PacketError('selectors must be a list of byte-selection objects')
    allowed = {'call_id', 'path', 'start_byte', 'end_byte'}
    for sel in selectors:
        if (set(sel) - allowed or type(sel.get('call_id')) is not int
                or sel['call_id'] not in ids
                or ('path' in sel and not isinstance(sel['path'], str))):
            raise PacketError('Each selector must name a cited call and only path/start_byte/end_byte')
    authored = agent_authored_paths(log._entries)
    terms = _cited_query_terms(request['description'])
    if not any(not t.isdigit() for t in terms):
        terms += _cited_query_terms(request['description'].title())
    claim = request.get('claim') or {}
    identifiers = [*(claim.get('entities') or []), *(claim.get('recipients') or []),
                   claim.get('principal', ''), claim.get('actor', '')]
    terms = sorted(set(terms + [str(v).lower() for v in identifiers if str(v).strip()]))
    evidence, contexts, identities, watches = [], [], {}, {}
    remaining = MAX_PACKET_CHARS
    discovered = {cid: entry_text_sources(by_id[cid]) for cid in ids if by_id[cid].get('type') == 'tool_call'}
    def relevant(sources):
        if any(s.kind == 'file' for s in sources):
            return [s for s in sources if s.kind == 'file']
        if any(s.kind == 'stdout_sidecar' for s in sources):
            return [s for s in sources if s.kind == 'stdout_sidecar']
        return sources
    discovered = {cid: relevant(sources) for cid, sources in discovered.items()}
    # Allocate by physical source, not call order; duplicated citations cannot
    # consume the shares reserved for later sources.
    source_keys = {(os.path.abspath(s.path) if s.path else ('inline', cid))
                   for cid, sources in discovered.items() for s in sources}
    share = MAX_PACKET_CHARS // max(1, len(source_keys))
    row_keys, source_used, raw_cache = {}, {}, {}
    scanned_bytes = 0
    used_selectors = set()
    for cid in sorted(ids, key=lambda c: not (any(s.get('call_id') == c for s in selectors)
                     or any(s.selector for s in discovered.get(c, [])))):
        entry = by_id[cid]
        identities[str(cid)] = entry_identity(entry)
        if entry.get('type') != 'tool_call':
            contexts.append({'call_id': cid, 'kind': entry.get('type'), 'primary_evidence': False})
            continue
        from core.evidence_admission import evidence_usable
        if not evidence_usable(entry):
            raise PacketError(f'Cited evidence call {cid} did not succeed', 'needs-evidence')
        if authored_source_of(entry, authored) or not _is_evidence_entry(entry, authored, for_rows=True):
            raise PacketError(f'Call {cid} is not a primary evidence source')
        hashed = entry.get('hash_result') or {}
        if hashed.get('file') and entry.get('hashed_file_version'):
            hashed_path = os.path.abspath(hashed['file'])
            version = file_version(hashed_path)
            if version != entry['hashed_file_version']:
                raise PacketError(f'Hashed source changed after call {cid}; hash it again', 'needs-evidence')
            watches[hashed_path] = version
        sources = discovered[cid]
        has_artifact = any(s.kind == 'file' for s in sources)
        if not has_artifact and (entry.get('output_path') or _cmd_output_paths(entry.get('cmd') or '')):
            raise PacketError(f'Call {cid} has only an invocation log; its artifact output is unavailable', 'needs-evidence')
        if has_artifact:
            sources = [s for s in sources if s.kind == 'file']
        elif any(s.kind == 'stdout_sidecar' for s in sources):
            sources = [s for s in sources if s.kind == 'stdout_sidecar']
        # Discovery may return only a subset of an output directory. Never
        # describe that as exhaustive coverage of the extractor's source.
        provenance = {'tool': entry.get('mcp_tool') or entry.get('cmd'),
                      'command': entry.get('cmd'), 'call_timestamp': entry.get('ts'),
                      'source_hashes': entry.get('source_hashes'),
                      'time_basis': entry.get('time_basis', 'unspecified'),
                      'source_scope': entry.get('coverage') or entry.get('source_manifest'),
                      'artifact_classes': entry.get('artifact_classes')}
        for source in sources:
            if source.stale:
                raise PacketError(f'Output changed since call {cid}; run a new traced read', 'needs-evidence')
            if len(evidence) >= MAX_SOURCES:
                raise PacketError('Too many output sources; cite narrower traced outputs', 'needs-evidence')
            path = os.path.abspath(source.path) if source.path else ''
            if path and any(path == os.path.abspath(a) or path.startswith(os.path.abspath(a) + os.sep)
                            for a in authored):
                raise PacketError(f'Call {cid} points at agent-authored output')
            before = file_version(path) if path else None
            source_key = path or ('inline', cid)
            scan_truncated = False
            if path and path in raw_cache:
                if watches.get(path) != before:
                    raise PacketError('Evidence changed while constructing packet', 'retryable-review-failure')
                raw, scan_truncated = raw_cache[path]
            elif path:
                if before is None:
                    raise PacketError(f'Output unavailable for call {cid}: {path}', 'needs-evidence')
                try:
                    with open(path, 'rb') as stream:
                        raw = stream.read(MAX_SOURCE_BYTES + 1)
                    if len(raw) > MAX_SOURCE_BYTES:
                        # Search the leading MAX_SOURCE_BYTES (whole lines) and
                        # mark the source partial, rather than refusing review of
                        # a large extractor output (MFT/EVTX CSVs). A miss over a
                        # partial scan is never read as absence.
                        cut = raw.rfind(b'\n', 0, MAX_SOURCE_BYTES) + 1 or MAX_SOURCE_BYTES
                        raw, scan_truncated = raw[:cut], True
                except OSError as exc:
                    raise PacketError(f'Cannot read output for call {cid}: {exc}', 'needs-evidence') from exc
                if before != file_version(path):
                    raise PacketError('Evidence changed while constructing packet', 'retryable-review-failure')
                watches[path] = before
            else:
                raw = source.text.encode('utf-8')
            if len(raw) > MAX_SOURCE_BYTES:
                cut = raw.rfind(b'\n', 0, MAX_SOURCE_BYTES) + 1 or MAX_SOURCE_BYTES
                raw, scan_truncated = raw[:cut], True
            if source_key not in raw_cache and scanned_bytes + len(raw) > MAX_SCAN_BYTES:
                cut = raw.rfind(b'\n', 0, max(0, MAX_SCAN_BYTES - scanned_bytes)) + 1
                raw, scan_truncated = raw[:cut], True
            if source_key not in raw_cache:
                scanned_bytes += len(raw)
                raw_cache[source_key] = (raw, scan_truncated)
            if path:
                watches[path] = before
            selected = [(i, s) for i, s in enumerate(selectors) if s['call_id'] == cid
                        and (not s.get('path') or os.path.abspath(s['path']) == path)]
            if selectors and any(s['call_id'] == cid for s in selectors) and not selected:
                continue
            selections = []
            for i, sel in selected or [(-1, source.selector or {})]:
                result = _selection(raw, terms, sel, share, path)
                result.pop('selected_chars')
                spans, aliases = [], []
                for span in result['spans']:
                    # A different projection is a different displayed view.
                    key = (source_key, span['start_byte'], span['end_byte'], span['display']['receipt_id'])
                    if key in row_keys:
                        aliases.append(row_keys[key])
                    elif max(len(span['text']), len(span['display']['displayed_text'])) <= min(remaining, share - source_used.get(source_key, 0)):
                        row_keys[key] = {'call_id': cid, 'path': path or None,
                                         'start_byte': span['start_byte'], 'end_byte': span['end_byte']}
                        spans.append(span)
                        cost = max(len(span['text']), len(span['display']['displayed_text']))
                        remaining -= cost
                        source_used[source_key] = source_used.get(source_key, 0) + cost
                result.update(spans=spans, shared_spans=aliases, shown_lines=len(spans),
                              selection_complete=len(spans) + len(aliases) == result['matched_lines'])
                selections.append(result)
                if i >= 0:
                    used_selectors.add(i)
            retained_complete = bool(source.complete) and not scan_truncated and entry.get('scope_complete') is not False
            if source.kind != 'file':
                retained_complete = retained_complete and not bool(entry.get('stdout_partial'))
                if not raw and entry.get('stdout_chars') is None:
                    retained_complete = False
            evidence.append({'call_id': cid, 'kind': 'artifact_output' if has_artifact else 'tool_stdout',
                             'path': path or None, 'output_sha256': hashlib.sha256(raw).hexdigest(),
                             'output_bytes': len(raw), 'retained_output_complete': retained_complete,
                             'scan_truncated': scan_truncated,
                             'search_scope': 'only this retained output, not the entire original evidence',
                             'extractor_scope_complete': entry.get('scope_complete'),
                             'provenance': {**provenance, 'attribution': source.attribution,
                                            'producer_call_id': source.producer_call_id,
                                            'targeted_read': source.selector}, 'selections': selections})
        # Watch output directories too: discovery of another file invalidates selection.
        if not entry.get('output_manifest') and entry.get('output_path') and os.path.isdir(entry['output_path']):
            path = os.path.abspath(entry['output_path'])
            watches[path] = file_version(path)
    if len(used_selectors) != len(selectors):
        raise PacketError('Selector path does not belong to the cited output')
    if not evidence or not any(e['output_bytes'] or e['retained_output_complete'] for e in evidence):
        raise PacketError('Cited calls contain no retained artifact data; cite the extractor output', 'needs-evidence')
    packet = {'schema_version': VERSION, 'purpose': 'finding_review', 'case': case_identity(log), 'request': request,
              'evidence': evidence, 'context_only': contexts, 'entry_identities': identities,
              'file_versions': watches, 'policy': review_policy(), 'selectors': selectors}
    packet['packet_id'] = 'EP-' + digest(packet)
    return packet


def packet_current(log, packet):
    by_id = {e.get('call_id'): e for e in log._entries}
    return (case_identity(log) == packet['case'] and review_policy() == packet['policy']
            and ('run_id' not in packet or packet['run_id'] == getattr(log, '_run_id', None))
            and all(entry_identity(by_id.get(int(cid), {})) == sig
                    for cid, sig in packet['entry_identities'].items())
            and all(file_version(path) == version for path, version in packet['file_versions'].items()))


def packet_evidence_text(packet):
    # Only observed data enters the deterministic citation check, never the
    # request description, selector query or an agent-authored explanation.
    return '\n'.join(f"call {e['call_id']} {e['provenance']['tool']}: " + span['text']
                     for e in packet['evidence'] for sel in e['selections'] for span in sel['spans'])
