"""Durable, deterministic DAIR routing for work discovered during reporting.

The trace is the work ledger. Model suggestions never execute tools here.
"""
from copy import deepcopy
from pathlib import Path
import os

from core.readiness import digest

TERMINAL = {'completed', 'dispositioned', 'superseded'}
_TOOL_SCHEMAS = {}


def remember_schema(tool, schema):
    """Metadata only; visibility is checked again at actual tool invocation."""
    _TOOL_SCHEMAS[normalized(tool)] = deepcopy(schema)


def validate_arguments(schema, arguments):
    from jsonschema import Draft202012Validator
    schema = deepcopy(schema)
    schema.setdefault('additionalProperties', False)
    Draft202012Validator(schema).validate(arguments)
    canonical = dict(arguments)
    for key, spec in schema.get('properties', {}).items():
        if 'default' in spec:
            canonical.setdefault(key, deepcopy(spec['default']))
    return canonical


def process_identity(pid):
    try:
        # Linux process start time distinguishes PID reuse after a restart.
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
    except OSError:
        return None


def normalized(tool):
    return tool.replace('.', '_')


def execution_policy(tool):
    """Code changes must not silently reuse a result produced by another parser."""
    from core.evidence_packets import file_version
    root = Path(__file__).resolve().parents[1]
    namespace = normalized(tool).split('_', 1)[0]
    namespace = {'ez': 'eztools', 'tsk': 'sleuthkit', 'carve': 'carving', 'net': 'network', 'strings': 'strings_tools', 'hash': 'hashing', 'vol': 'volatility'}.get(namespace, namespace)
    return digest([file_version(str(root / 'tools' / (namespace + '.py'))),
                   file_version(str(root / 'core/executor.py')),
                   file_version(str(root / 'core/job_adapters.py'))])


def source_versions(arguments):
    """Watch actual input paths, not directories that the operation will write."""
    versions = {}
    for key, value in arguments.items():
        if (any(x in key.lower() for x in ('output', 'export', 'destination', 'report'))
                or key.lower() in ('csv', 'csv_dir', 'csv_name', 'csv_filename')):
            continue
        for p in value if isinstance(value, list) else [value]:
            if isinstance(p, str) and p and (os.path.isabs(p) or any(
                    part in key.lower() for part in ('path', 'file', 'dir', 'hive', 'profile', 'volume', 'image', 'store', 'dump'))):
                path = os.path.realpath(os.path.expanduser(p))
                try:
                    st = os.stat(path)
                    if os.path.isdir(path):
                        # Directory mtime does not change when a child is edited.
                        # Stat members (no content reads); include names to detect
                        # addition/removal, and never follow directory symlinks.
                        members, errors = [], []
                        for root, dirs, files in os.walk(path, onerror=lambda e: errors.append(str(e))):
                            dirs.sort()
                            for name in sorted(files):
                                child = os.path.join(root, name)
                                try:
                                    c = os.stat(child)
                                    version = [c.st_dev, c.st_ino, c.st_size, c.st_mtime_ns, c.st_ctime_ns]
                                except OSError:
                                    version = None
                                members.append([os.path.relpath(child, path), version])
                        versions[path] = {'kind': 'directory_manifest', 'members': len(members),
                                          'root': [st.st_dev, st.st_ino, st.st_mode],
                                          'version': digest(members), 'errors': errors}
                    else:
                        versions[path] = [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]
                except OSError:
                    versions[path] = None
    return versions


def retained_source(log, path):
    if not isinstance(path, str) or not path:
        return False
    target = Path(path).resolve()
    for entry in log._entries:
        from core.evidence_admission import evidence_usable
        if entry.get('type') != 'tool_call' or not evidence_usable(entry):
            continue
        if entry.get('output_manifest') is not None:
            from tools._output_reader import entry_text_sources
            if any(s.path and Path(s.path).resolve() == target and not s.stale
                   for s in entry_text_sources(entry)):
                return True
            continue
        from tools._output_reader import _cmd_output_paths
        paths = [entry.get(k) for k in ('stdout_path', 'output_path', 'output_file')]
        paths += _cmd_output_paths(entry.get('cmd', ''))
        for produced in paths:
            if not isinstance(produced, str):
                continue
            root = Path(produced).resolve()
            if root == target or (root.is_dir() and root in target.parents):
                return True
    return False


def action_phase(tool, arguments=None, log=None):
    """Classify registered tool actions; validation/visibility is the caller's job."""
    tool, arguments = normalized(tool), arguments or {}
    if tool in ('read_output', 'read_mail'):
        path = arguments.get('path') or arguments.get('output') or arguments.get('mail_path')
        return '' if log and retained_source(log, path) else 'Collect'
    if tool in ('misc_record_finding', 'misc_submit_finding'):
        return '' if arguments.get('supersedes') else 'Analyze'
    if tool.startswith(('reason_', 'dair_', 'coverage_', 'accuracy_', 'monitor_')):
        return ''
    if tool.startswith(('misc_record_', 'misc_retract_', 'misc_start_', 'misc_export_execution',
                        'misc_write_final_report', 'misc_serve_', 'misc_declare_questions', 'misc_review_correspondent_scope', 'correlate_mitre_validate')):
        return ''
    if tool.endswith(('job_status', 'job_cancel', 'job_list', 'operation_status', 'job_recover')):
        return ''
    if tool.startswith(('correlate_', 'attribution_', 'af_', 'hash_')):
        return 'Analyze'
    from tools.tool_capabilities import tool_capability_manifest
    wire = tool.replace('_', '.', 1)
    for cap in tool_capability_manifest()['capabilities']:
        if wire in cap['tools']:
            phases = cap['phases']
            return 'Collect' if 'Collect' in phases else 'Analyze' if 'Analyze' in phases else 'Scan'
    if tool.startswith(('yara_', 'carve_', 'clamav_')):
        return 'Scan'
    return 'Collect'


def work_state(log):
    latest = {}
    for entry in log._entries:
        if entry.get('type') == 'phase_work':
            latest[entry['request_id']] = deepcopy(entry)
    for work in latest.values():
        if work.get('scope_unspecified'):
            continue
        if (work['status'] == 'running' and not work.get('job_id') and work.get('owner_pid')
                and process_identity(work['owner_pid']) != work.get('owner_start')):
            work['status'] = 'unknown'
        if work['status'] in TERMINAL and source_versions(work['arguments']) != work['source_versions']:
            work['status'] = 'stale'
        if work['status'] in TERMINAL:
            from core.evidence_packets import file_version
            if work.get('execution_policy') and work['execution_policy'] != execution_policy(work['tool']):
                work['status'] = 'stale'
            if any(file_version(p) != v for p, v in work.get('output_versions', {}).items()):
                work['status'] = 'stale'
            if any(file_version(p) != v for p, v in work.get('executable_versions', {}).items()):
                work['status'] = 'stale'
    for work in latest.values():
        if work['status'] not in ('stale', 'failed', 'pending'):
            continue
        successor = next((other for other in latest.values()
                          if other['status'] == 'completed' and other['call_id'] > work['call_id']
                          and other['tool'] == work['tool'] and other['arguments'] == work['arguments']), None)
        if successor:
            work.update(status='superseded', superseded_by=successor['request_id'])
    return latest


def pending_work(log):
    return [w for w in work_state(log).values() if w['status'] not in TERMINAL]


def append_event(log, kind, **fields):
    from core.execution_log import _utcnow
    entry = {'call_id': log._next_id(), 'type': kind, 'ts': _utcnow(), **deepcopy(fields)}
    log._append_entry(entry)
    return entry


def apply_return(log, target, reason):
    """Same reducer for live policy transitions and historical replay.

    Only the Report frame is retired. Never unwind an unrelated child scope.
    """
    if log._phase_stack and log._phase_stack[-1]['phase'] == 'Report':
        log._phase_stack.pop()
    if not log._phase_stack or log._phase_stack[-1]['phase'] != target:
        log._phase_stack.append({'phase': target, 'entry_reason': reason,
                                 'depth': len(log._phase_stack), 'report_follow_up': True})
    log._current_phase = target


def transition(log, target, request_id, trigger_call_id=0):
    if log._current_phase != 'Report':
        return None
    checkpoint = next((e['call_id'] for e in reversed(log._entries)
                       if e.get('tool') == 'reason_synthesize' or
                       (e.get('type') == 'dair_call' and e.get('dair_phase') == 'Report')), 0)
    apply_return(log, target, 'required_report_follow_up')
    return append_event(log, 'phase_transition', authority='policy', from_phase='Report',
                        to_phase=target, request_id=request_id, trigger_call_id=trigger_call_id,
                        report_checkpoint=checkpoint, scope=log._case_id,
                        reason='required_report_follow_up')


def request_identity(log, tool, arguments, refresh=False):
    return 'W-' + digest([log._case_id, normalized(tool), arguments,
                          source_versions(arguments)])[:24]


def reserve(log, tool, arguments, phase, *, refresh=False, issue_id='', trigger_call_id=0,
            execute=True):
    """Under the transaction lock: reserve once, then transition before execution."""
    from core.work_obligations import canonical
    arguments = canonical(normalized(tool), arguments)
    rid = request_identity(log, tool, arguments, refresh)
    existing = work_state(log)
    old = existing.get(rid)
    if old is None:
        # Keep a stable obligation when its original ID predates canonical
        # argument normalization; never accept a subset of its scope.
        old = next((w for w in reversed(list(existing.values()))
                    if w['tool'] == normalized(tool)
                    and not w.get('scope_unspecified')
                    and canonical(normalized(tool), w['arguments']) == arguments
                    and w['source_versions'] == source_versions(arguments)), None)
        if old:
            rid = old['request_id']
    if old and old['status'] != 'pending' and not (refresh and old['status'] in ('failed', 'unknown', 'completed', 'stale')):
        return old, None, False
    work = append_event(log, 'phase_work', request_id=rid, tool=normalized(tool),
                        arguments=arguments, source_versions=source_versions(arguments),
                        execution_policy=execution_policy(tool),
                        required_phase=phase, status='running' if execute else 'pending',
                        owner_pid=os.getpid(), owner_start=process_identity(os.getpid()),
                        issue_id=issue_id or (old or {}).get('issue_id', ''),
                        trigger_call_id=trigger_call_id, scope=log._case_id)
    event = transition(log, phase, rid, trigger_call_id)
    return work, event, True


def finish(log, work, payload=None, *, status=None, error=''):
    with log.transaction():
        current = work_state(log).get(work['request_id'], work)
        body = deepcopy(payload) if isinstance(payload, dict) else {}
        if status is None:
            if body.get('success') is False or body.get('isError'):
                status = 'failed'
            elif body.get('status') in ('running', 'queued', 'pending', 'started', 'awaiting_collection') or (
                    body.get('job_id') and body.get('status') not in ('finished', 'completed')):
                status = 'running'
            elif body.get('scope_complete') is False:
                status = 'incomplete'
            elif body.get('success') is True:
                status = 'completed'
            else:
                status = 'unknown'
        fields = {k: v for k, v in current.items() if k not in
                  ('call_id', 'type', 'ts', 'dair_phase', 'dair_depth')}
        fields.update(status=status, result=body, error=error,
                      executed=body.get('success') is not None,
                      execution_success=body.get('success'), scope_complete=status == 'completed',
                      evidential_outcome='not_adjudicated',
                      result_call_id=body.get('_trudi_call_id'), job_id=body.get('job_id'))
        from core.evidence_packets import file_version
        entry = log.index().by_call_id.get(body.get('_trudi_call_id'), {})
        fields['output_versions'] = {entry[k]: file_version(entry[k]) for k in
                                     ('stdout_path', 'output_path', 'output_file')
                                     if isinstance(entry.get(k), str) and not os.path.isdir(entry[k])}
        fields['output_versions'].update({s['path']: file_version(s['path'])
            for s in (entry.get('output_manifest') or {}).get('files', [])})
        import shlex
        try:
            tokens = shlex.split(entry.get('cmd') or '')
            fields['executable_versions'] = {p: file_version(p) for p in tokens
                if os.path.isabs(p) and os.path.isfile(p) and (os.access(p, os.X_OK) or p.endswith(('.dll', '.py', '.pl')))}
        except ValueError:
            fields['executable_versions'] = {}

        return append_event(log, 'phase_work', **fields)


def reconcile_job(log, tool, arguments, payload):
    if not normalized(tool).endswith('job_status') or not isinstance(payload, dict):
        return
    for work in pending_work(log):
        job = work.get('job_id')
        if job and job == arguments.get('job_id') and payload.get('status') in ('completed', 'finished', 'failed', 'cancelled'):
            from core.evidence_admission import scope_complete
            finish(log, work, payload, status='completed' if scope_complete(payload) else 'incomplete')


def route_issues(log, issues, trigger_call_id=0):
    """Hand off typed required work; never infer commands from reviewer prose."""
    result = []
    for issue in issues:
        action = issue.get('action') or {}
        if not action.get('required') or action.get('kind') not in ('collect', 'analyze', 'scan'):
            continue
        tool, arguments = action.get('tool'), action.get('arguments')
        if not tool or not isinstance(arguments, dict) or not action.get('target'):
            result.append({'issue_id': issue.get('issue_id'), 'status': 'needs_specification'})
            continue
        if action['target'] not in arguments.values():
            result.append({'issue_id': issue.get('issue_id'), 'status': 'needs_specification'})
            continue
        schema = _TOOL_SCHEMAS.get(normalized(tool))
        try:
            if schema is None:
                raise ValueError('Tool schema must be discovered before accepting work')
            arguments = validate_arguments(schema, arguments)
        except Exception as exc:
            result.append({'issue_id': issue.get('issue_id'), 'status': 'needs_specification',
                           'tool': tool, 'error': str(exc)[:300]})
            continue
        from tools.tool_capabilities import allowed_tool_names
        if normalized(tool).replace('_', '.', 1) not in allowed_tool_names():
            result.append({'issue_id': issue.get('issue_id'), 'status': 'needs_specification'})
            continue
        phase = action_phase(tool, arguments, log)
        if not phase:
            continue
        with log.transaction():
            work, event, _ = reserve(log, tool, arguments, phase, execute=False,
                                     issue_id=issue.get('issue_id', ''), trigger_call_id=trigger_call_id)
        if work['status'] in TERMINAL:
            continue
        result.append({'request_id': work['request_id'], 'status': work['status'],
                       'tool': tool, 'arguments': arguments,
                       'required_phase': phase,
                       **({'phase_returned_to': phase, 'transition_call_id': event['call_id']} if event else {})})
    return result


async def validate_request(context, tool, arguments):
    """Use the live, session-visible MCP schema before any phase mutation."""
    server = getattr(getattr(context, 'fastmcp_context', None), 'fastmcp', None)
    if server is None:
        raise ValueError('needs_specification: tool schema unavailable in Report')
    definition = await server.get_tool(tool)
    if definition is None or not isinstance(definition.parameters, dict):
        raise ValueError('needs_specification: unknown or unavailable tool in Report')
    remember_schema(tool, definition.parameters)
    return validate_arguments(definition.parameters, arguments)


def profile_fingerprints():
    root = Path(__file__).resolve().parents[1]
    paths = [root / 'claude/CLAUDE.md', root / 'claude/PILOT.md',
             root / 'opencode/AGENTS.md', root / 'opencode/agent/trudi-pilot.md',
             Path.home() / '.claude/CLAUDE.md', Path.home() / '.config/opencode/AGENTS.md']
    import hashlib
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
