"""Message-bound review selections; headers and body never cross messages."""
import heapq
import io
from email import policy
from email.parser import BytesParser

FIELDS = ['Date', 'From', 'To', 'Cc', 'Bcc', 'Subject', 'Message-ID',
          'has_attachment', 'attachments', 'Body']


def is_mail(path, first):
    return (path.lower().endswith(('.mbox', '.eml')) or first.startswith(b'From '))


def render(raw, terms):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    lines = [f'{name}: {str(msg[name])}' for name in FIELDS[:7] if msg[name] is not None]
    attachments, bodies = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == 'attachment':
            attachments.append({'filename': filename, 'content_type': part.get_content_type()})
        elif part.get_content_maintype() == 'text':
            payload = part.get_payload(decode=True) or b''
            try:
                bodies.append(payload.decode(part.get_content_charset() or 'utf-8', errors='replace'))
            except LookupError:
                bodies.append(payload.decode('utf-8', errors='replace'))
    import json
    lines += ['has_attachment: ' + str(bool(attachments)).lower(),
              'attachments: ' + json.dumps(attachments, ensure_ascii=False)]
    body = '\n'.join(bodies)
    # Bounded excerpts retain deciding context, not just a detached match line.
    positions = sorted({body.lower().find(t) for t in terms if t and t in body.lower()}) or [0]
    ranges = []
    for pos in positions[:4]:
        lo, hi = max(0, pos - 200), min(len(body), pos + 700)
        if ranges and lo <= ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], max(hi, ranges[-1][1]))
        else:
            ranges.append((lo, hi))
    lines += [f'Body [characters {lo}:{hi}]:\n' + body[lo:hi] for lo, hi in ranges]
    clipped = bool(ranges and (ranges[0][0] or ranges[-1][1] < len(body) or len(ranges) > 1))
    if clipped:
        lines.append('[Body excerpt; search more specific terms to display other passages.]')
    defects = [str(d) for part in msg.walk() for d in part.defects]
    return '\n'.join(lines), clipped, defects


def scan_mail(path, terms, budget, *, raw=None):
    from core.evidence_display import MAX_RETAINED_RAW, display_span
    from core.readiness import digest
    from tools._output_reader import ScanResult, COMPAT_CITED_FILE_BYTES, _CITED_TOPK
    result = ScanResult()
    result.source_selections = []
    result.available_columns = FIELDS
    terms = [t.lower() for t in terms if t]
    heap, retained = [], 0
    def consider(data, start, end, number):
        nonlocal retained
        result.total_rows += 1
        shown, clipped, defects = render(data, terms)
        if defects:
            result.scan_error = 'Malformed MIME message: ' + ', '.join(defects)
            result._note_trunc('scan_error')
        score = sum(t in shown.lower() or t in data.decode('utf-8', errors='replace').lower() for t in terms)
        if terms and not score:
            return
        result.matched_rows += 1
        span = {'text': data.decode('utf-8', errors='replace'), 'start_byte': start,
                'end_byte': end, 'row_number': number}
        receipt = display_span(span)
        receipt.update(format='mail_message', columns=FIELDS, displayed_text=shown,
                       clipped_fields=['Body'] if clipped else [])
        receipt['receipt_id'] = digest({k: v for k, v in receipt.items() if k != 'receipt_id'})
        span['display'] = receipt
        heapq.heappush(heap, (score, -number, span))
        retained += len(data)
        while len(heap) > _CITED_TOPK or retained > MAX_RETAINED_RAW:
            removed = heapq.heappop(heap)[2]
            retained -= removed['end_byte'] - removed['start_byte']
            result._note_trunc('budget')
    try:
        with (io.BytesIO(raw) if raw is not None else open(path, 'rb')) as stream:
            start = position = 0
            data = bytearray()
            number = 1
            overlong = False
            while True:
                line = stream.readline(MAX_RETAINED_RAW + 1)
                if not line:
                    if data and not overlong:
                        consider(bytes(data), start, position, number)
                    break
                if position + len(line) > COMPAT_CITED_FILE_BYTES:
                    result._note_trunc('scan_cap')
                    break
                if line.startswith(b'From ') and position:
                    if data and not overlong:
                        consider(bytes(data), start, position, number)
                    data.clear()
                    start, number, overlong = position, number + 1, False
                position += len(line)
                if len(data) + len(line) > MAX_RETAINED_RAW:
                    overlong = True
                    result.scan_error = 'Message exceeds retained-byte bound; use a narrower mail export'
                    result._note_trunc('scan_error')
                if not overlong:
                    data.extend(line)
    except (OSError, ValueError) as exc:
        result.scan_error = str(exc)
        result._note_trunc('scan_error')
    bodies, used = [], 0
    for _, _, span in sorted(heap, key=lambda t: (-t[0], -t[1])):
        body = f"[message {span['row_number']}; bytes {span['start_byte']}:{span['end_byte']}]\n" + span['display']['displayed_text']
        if used + len(body) + 2 > budget:
            result._note_trunc('budget')
            continue
        used += len(body) + 2
        bodies.append(body)
        result.source_selections.append(span)
        result.clipped_rows += bool(span['display']['clipped_fields'])
    result.shown_rows = len(bodies)
    result.body = '\n\n'.join(bodies)
    return result
