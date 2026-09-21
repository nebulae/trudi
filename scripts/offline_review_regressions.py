"""Read-only replay of saved fetch selectors; no model calls or trace writes."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def replay(trace, limit=12):
    from core.execution_log import ExecutionLog
    from core.evidence_requests import normalize_requests
    from core.synthesis_evidence import build_synthesis_index
    from core.evidence_packets import PacketError
    from tools.reasoning import _resolve_evidence_requests
    data = json.loads(Path(trace).read_text())
    log = ExecutionLog()
    log._entries = data['entries']
    log._case_id = data['case_id']
    log._run_id = data.get('run_id') or 'offline'
    log._path = str(Path(trace).resolve())
    saved = [r for e in log._entries if e.get('type') == 'reason_evidence_fetch'
             for r in e.get('requests', [])]
    report = {'trace': str(trace), 'entries': len(log._entries), 'model_calls': 0,
              'trace_writes': 0, 'saved_fetch_requests': len(saved), 'replay': []}
    try:
        with patch('core.execution_log.log', log):
            index = build_synthesis_index(log)
            permitted = {e['call_id'] for e in index['evidence']}
            active = {f['call_id'] for f in index['findings']}
            candidates = [r for r in saved if r.get('call_id') in permitted and
                          (not r.get('finding_call_id') or r['finding_call_id'] in active)]
            # Include mail/column failures; do not claim distinct queries measure progress.
            selected = candidates[-limit:]
            for old in selected:
                request = {k: old[k] for k in ('call_id', 'query', 'columns', 'finding_call_id') if k in old}
                if old.get('requested_path'):
                    request['path'] = old['requested_path']
                request = normalize_requests([request])
                _, records = _resolve_evidence_requests(request, list(permitted), 6000, index)
                new = records[0]
                report['replay'].append({'call_id': old['call_id'], 'query': old['query'],
                    'old_status': old.get('status'), 'new_status': new.get('status'),
                    'displayed_records': new.get('rows_returned'),
                    'missing_columns': new.get('missing_columns'),
                    'formats': sorted({s.get('display', {}).get('format') for s in new.get('source_selections', [])}),
                    'scan_complete': new.get('scan_complete')})
    except (PacketError, ValueError) as exc:
        report['replay_limitation'] = str(exc)
    report['status_counts'] = dict(Counter(r['new_status'] for r in report['replay']))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace')
    parser.add_argument('--limit', type=int, default=12)
    args = parser.parse_args()
    print(json.dumps(replay(args.trace, args.limit), indent=2))
