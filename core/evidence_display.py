"""CSV presentation and receipts for exactly what an independent reviewer saw."""
from copy import deepcopy
import csv
import hashlib
import io
import os
from pathlib import Path

from core.readiness import digest

VERSION = 1
FIELD_CHARS = 400
MAX_CONTEXT_CHARS = 96000
MAX_RETAINED_RAW = 4 * 1024 * 1024


def renderer_version():
    return digest([VERSION, FIELD_CHARS, hashlib.sha256(Path(__file__).read_bytes()).hexdigest()])


def table_header(text, path=''):
    """Conservative detection: no blank/duplicate labels or ragged header."""
    delimiter = '\t' if path.lower().endswith('.tsv') else ','
    if text.lstrip().startswith(('{', '[')):
        return [], delimiter
    if not path.lower().endswith(('.csv', '.tsv')):
        delimiter = '\t' if text.count('\t') > text.count(',') else ','
    try:
        rows = list(csv.reader(io.StringIO(text), delimiter=delimiter, strict=True))
    except (csv.Error, ValueError):
        return [], delimiter
    fields = [c.lstrip('\ufeff').strip() for c in rows[0]] if len(rows) == 1 else []
    if (not fields or any(not c or '\n' in c or '\r' in c for c in fields)
            or len({c.lower() for c in fields}) != len(fields)
            or not any(any(ch.isalpha() for ch in c) for c in fields)
            or (len(fields) < 2 and not path.lower().endswith(('.csv', '.tsv')))):
        return [], delimiter
    return fields, delimiter


def matches_table_header(sample, fields, delimiter):
    """Require a data record too before inferring a table in a text/stdout file."""
    try:
        row = next(csv.reader(io.StringIO(sample), delimiter=delimiter, strict=True), None)
        return row is not None and len(row) == len(fields)
    except (csv.Error, ValueError):
        return False


def display_span(span, columns=(), projection=(), delimiter=',', fallback='', raw_limit=None):
    """Raw span is unchanged. Receipt pins format, projection, renderer and text."""
    text = span['text']
    shown, clipped, fields = text, [], []
    fmt = 'raw_fallback' if fallback else 'raw'
    if columns:
        try:
            rows = list(csv.reader(io.StringIO(text.replace('\x00', '\\0')), delimiter=delimiter, strict=True))
            if len(rows) != 1 or len(rows[0]) != len(columns):
                raise ValueError('row does not match header')
            wanted = [c.strip().lower() for c in projection]
            normalized = [c.strip().lower() for c in columns]
            indices = [normalized.index(c) for c in wanted if c in normalized] if wanted else list(range(len(columns)))
            if not indices:
                indices = list(range(len(columns)))
            fields = [columns[i] for i in indices]
            lines = []
            for i in indices:
                value = rows[0][i]
                if not value:
                    continue
                if len(value) > FIELD_CHARS:
                    value = value[:FIELD_CHARS] + ' …[field truncated]'
                    clipped.append(columns[i])
                # Indent continuation lines so embedded newlines cannot appear
                # to introduce another field label.
                lines.append(f'{columns[i]}: ' + value.replace('\r\n', '\n').replace('\r', '\n').replace('\n', '\n  '))
            shown, fmt = '\n'.join(lines) or '[all selected fields empty]', 'labelled_fields'
        except (csv.Error, ValueError):
            fmt, fallback = 'raw_fallback', 'Row could not be aligned with the table header.'
    if fmt != 'labelled_fields' and raw_limit is not None and len(shown) > raw_limit:
        shown = shown[:raw_limit] + ' …[row truncated]'
        clipped.append('raw_text')
    receipt = {'schema_version': VERSION, 'renderer_version': renderer_version(),
               'format': fmt, 'columns': fields, 'field_chars': FIELD_CHARS, 'raw_chars': raw_limit,
               'clipped_fields': clipped, 'displayed_text': shown,
               'raw_text_digest': digest(text),
               **{k: span[k] for k in ('row_number', 'start_byte', 'end_byte') if k in span}}
    if fallback:
        receipt['fallback_reason'] = fallback
    receipt['receipt_id'] = digest(receipt)
    return receipt


def displayed_text(span):
    """Validate the saved receipt, never freshly render hidden data as proof."""
    receipt = span.get('display')
    if receipt is None:
        return span['text']  # old reviews exposed raw text
    if (receipt.get('renderer_version') != renderer_version()
            or receipt.get('raw_text_digest') != digest(span['text'])
            or any(receipt.get(k) != span.get(k) for k in ('row_number', 'start_byte', 'end_byte'))
            or receipt.get('receipt_id') != digest({k: v for k, v in receipt.items() if k != 'receipt_id'})):
        raise ValueError('Evidence display receipt changed; repeat review with the current renderer/source')
    return receipt['displayed_text']


def prompt_packet(packet):
    """Only displayed row text enters the prompt; raw fields stay in the trace."""
    if packet.get('index_only'):
        sources = {}
        for source in packet['evidence']:
            item = sources.setdefault(source['source_id'], {
                'source_id': source['source_id'], 'path': source['path'], 'call_ids': [],
                'bytes': source['output_bytes'], 'complete': source['retained_output_complete'],
                'tool': source['provenance'].get('tool'),
                'selector': source['provenance'].get('targeted_read'),
                'command': str(source['provenance'].get('command') or '')[:2000],
                'schema': source.get('source_schema', {}),
                'scope_complete': source.get('extractor_scope_complete')})
            item['call_ids'].append(source['call_id'])
        return {'purpose': packet['purpose'], 'packet_id': packet['packet_id'],
                'findings': packet['findings'], 'sources': list(sources.values()),
                'finding_sources': [{'finding_call_id': f['finding_call_id'],
                                     'source_ids': sorted({s['source_id'] for s in f['sources']})}
                                    for f in packet['finding_sources']],
                'display_renderer': renderer_version(),
                'rows': [], 'instructions': 'Pull evidence before issuing factual approval. '
                    'Use a listed call_id, exact path and finding_call_id. Provenance is retained in the saved packet.'}
    out = deepcopy(packet)
    out['display_renderer'] = renderer_version()
    for source in out['evidence']:
        for selection in source['selections']:
            for span in selection['spans']:
                shown = displayed_text(span)
                receipt = span.pop('display', {})
                span.update(text=shown, display_receipt_id=receipt.get('receipt_id'),
                            display_format=receipt.get('format', 'raw'))
                if receipt.get('fallback_reason'):
                    span['display_note'] = receipt['fallback_reason']
    return out


def scan_review_rows(path, terms, budget, columns=None, *, text=None):
    """Stream canonical rows with byte positions; rank before rendering/projecting.

    Bounded raw retention is separate from the displayed-character budget. A
    partially scanned/retained selection never establishes global absence.
    """
    import heapq
    from tools._output_reader import ScanResult, COMPAT_CITED_FILE_BYTES, _CITED_TOPK, _ROW_CHARS
    result = ScanResult()
    result.source_selections = []
    heap, retained, position, row_bytes = [], 0, 0, 0
    fields, delimiter, fallback = [], ',', ''
    terms = [t.lower() for t in terms if t]
    class ScanLimit(Exception):
        pass
    try:
        csv.field_size_limit(max(csv.field_size_limit(), MAX_RETAINED_RAW))
        with (io.BytesIO(text.encode('utf-8')) if text is not None else open(path, 'rb')) as stream:
            first = stream.readline(MAX_RETAINED_RAW + 1)
            from core.mail_evidence import is_mail, scan_mail
            if is_mail(path, first):
                result = scan_mail(path, terms, budget, raw=text.encode() if text is not None else None)
                result.missing_columns = [c for c in (columns or []) if c.lower() not in {f.lower() for f in result.available_columns}]
                result.columns_ignored = bool(result.missing_columns)
                return result
            fields, delimiter = table_header(first.decode('utf-8', errors='replace'), path)
            if fields and not path.lower().endswith(('.csv', '.tsv')):
                sample = stream.read(65536).decode('utf-8', errors='replace')
                if not matches_table_header(sample, fields, delimiter):
                    fields = []
            is_table = bool(fields)
            if not is_table and path.lower().endswith(('.csv', '.tsv')):
                fallback = 'Unparseable table header; raw lines shown.'
            stream.seek(len(first) if is_table else 0)
            position = stream.tell()
            retained_lines = []
            def lines():
                nonlocal position, row_bytes
                while True:
                    raw = stream.readline(MAX_RETAINED_RAW + 1)
                    if not raw:
                        return
                    position += len(raw)
                    row_bytes += len(raw)
                    if position > COMPAT_CITED_FILE_BYTES or len(raw) > MAX_RETAINED_RAW:
                        raise ScanLimit()
                    retained_lines.append(raw)
                    if row_bytes > MAX_RETAINED_RAW:
                        raise ScanLimit()
                    yield raw.decode('utf-8', errors='replace').replace('\x00', '\\0')
            iterator = csv.reader(lines(), delimiter=delimiter, strict=True) if is_table else lines()
            start = position
            for row_number, row in enumerate(iterator, 1):
                raw = b''.join(retained_lines)
                retained_lines.clear()
                row_bytes = 0
                text = raw.decode('utf-8', errors='replace')
                result.total_rows += 1
                score = sum(t in text.lower() for t in terms)
                span = {'text': text, 'start_byte': start, 'end_byte': position, 'row_number': row_number}
                start = position
                if terms and not score:
                    continue
                result.matched_rows += 1
                item = (score, -row_number, span)
                heapq.heappush(heap, item)
                retained += len(raw)
                while len(heap) > _CITED_TOPK or retained > MAX_RETAINED_RAW:
                    dropped = heapq.heappop(heap)[2]
                    retained -= dropped['end_byte'] - dropped['start_byte']
                    result._note_trunc('budget')
    except ScanLimit:
        result._note_trunc('scan_cap')
    except (OSError, csv.Error, ValueError) as exc:
        result.scan_error = f'{type(exc).__name__}: {str(exc)[:80]}'
        result._note_trunc('scan_error')
    result.available_columns = fields
    want = columns or []
    result.missing_columns = [c for c in want if c.strip().lower() not in {f.lower() for f in fields}]
    result.columns_ignored = bool(want and (not fields or len(result.missing_columns) == len(want)))
    used, bodies = 0, []
    for _, _, span in sorted(heap, key=lambda item: (-item[0], -item[1])):
        receipt = display_span(span, fields, want, delimiter, fallback, raw_limit=_ROW_CHARS)
        shown = receipt['displayed_text']
        # Include row location in the prompt budget; it is kept separate from
        # the quoteable field text in the display receipt.
        prefix = f"[row {span['row_number']}; bytes {span['start_byte']}:{span['end_byte']}]\n"
        if receipt.get('fallback_reason'):
            prefix += '[raw fallback: ' + receipt['fallback_reason'] + ']\n'
        if used + len(prefix) + len(shown) + 2 > budget:
            result._note_trunc('budget')
            continue
        span['display'] = receipt
        result.source_selections.append(span)
        bodies.append(prefix + shown)
        used += len(prefix) + len(shown) + 2
        result.clipped_rows += bool(receipt['clipped_fields'])
    result.shown_rows = len(result.source_selections)
    result.body = '\n\n'.join(bodies)
    if result.clipped_rows:
        result._note_trunc('row_clip')
    if result.shown_rows < result.matched_rows:
        result._note_trunc('budget')
    return result


def source_schema(path, text=''):
    """Bounded header metadata, not a scan of evidence rows."""
    from core.mail_evidence import is_mail, FIELDS
    try:
        if path:
            with open(path, 'rb') as stream:
                first = stream.readline(16385)
        else:
            first = text.encode()[:16385].split(b'\n', 1)[0]
        if is_mail(path or '', first):
            return {'format': 'mail_message', 'columns': FIELDS, 'unit': 'message',
                    'body_mode': 'bounded_context', 'attachments': 'metadata_only'}
        columns, _ = table_header(first.decode('utf-8', errors='replace'), path or '')
        return {'format': 'table' if columns else 'text', 'columns': columns,
                'header_truncated': len(first) > 16384, 'field_character_limit': FIELD_CHARS}
    except OSError as exc:
        return {'format': 'unavailable', 'error': str(exc)[:200]}
