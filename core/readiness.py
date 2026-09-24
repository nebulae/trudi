"""Semantic report snapshots, independent of narration and logging churn."""
import hashlib
import json
from pathlib import Path
from core.findings import current_entries

POLICY_VERSION = 'review-readiness-1'
_IGNORED_TOOLS = {'reason_pre_report_check', 'reason_readiness_status', 'reason_audit_findings'}
_IGNORED_TYPES = {'call_initiated', 'call_abandoned', 'reason_evidence_fetch',
                  'investigation_narration', 'system_error'}


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str,
                                     separators=(',', ':')).encode()).hexdigest()


# What a cross-finding review actually judged: the recorded claims and how
# leads were settled. Tool calls, output-file stats and source hashes are not
# claims; counting them made every later read force another full synthesis.
_CLAIM_TYPES = {'finding', 'finding_retracted', 'disposition'}


def state_fingerprint(entries, case_id='', include_synthesis=True, scope='full') -> str:
    """scope='full' binds the pre-report approval to the whole semantic state;
    scope='claims' is the synthesis staleness key (claims + dispositions)."""
    records, files = [], {}
    for e in current_entries(entries):
        typ, tool = e.get('type'), e.get('tool')
        if typ in _IGNORED_TYPES or tool in _IGNORED_TOOLS:
            continue
        if scope == 'claims' and typ not in _CLAIM_TYPES and not (
                include_synthesis and tool == 'reason_synthesize'):
            continue
        if tool == 'reason_synthesize' and not include_synthesis:
            continue
        if typ == 'tool_call' and any(t in e.get('cmd', '') for t in (
                'misc_write_final_report', 'misc_export_execution_log', 'misc_serve_dashboard')):
            continue
        # Timestamps and accounting are not changes to the evidence or claim.
        records.append({k: v for k, v in e.items() if k not in {
            'ts', 'input_tokens', 'output_tokens', 'elapsed_seconds', 'backend_meta',
            'inputs', 'dair_phase', 'dair_depth', 'readiness_fingerprint'}})
        for k in ('stdout_path', 'output_file', 'output_path'):
            path = e.get(k)
            if isinstance(path, str):
                try:
                    st = Path(path).stat()
                    files[path] = [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino]
                except OSError:
                    files[path] = 'unavailable'
    if scope == 'claims':
        return digest([POLICY_VERSION, case_id, records])
    root = Path(__file__).resolve().parents[1]
    policy = {}
    for pattern in ('core/findings.py', 'core/readiness.py', 'core/review_issues.py',
                    'core/evidence_packets.py', 'core/finding_submission.py',
                    'tools/_readiness.py', 'tools/reasoning.py', 'tools/_llm_parse.py',
                    'tools/dair.py', 'tools/_gates/*.py', 'data/fk/tiering.yaml'):
        for p in root.glob(pattern):
            policy[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return digest([POLICY_VERSION, case_id, records, files, policy])


def issue_records(messages):
    """Stable IDs for legacy deterministic checks while preserving full messages."""
    return [{'issue_id': 'G-' + digest(m)[:16], 'kind': 'policy_requirement',
             'status': 'open', 'message': m} for m in messages]
