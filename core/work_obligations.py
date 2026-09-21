"""Exact scoped work declarations shared by DAIR and phase routing."""
import ast
import re
from copy import deepcopy


def parse_work(item):
    if isinstance(item, dict):
        tool, arguments = item.get('tool'), item.get('arguments')
        if isinstance(tool, str) and isinstance(arguments, dict):
            return tool.replace('.', '_'), deepcopy(arguments)
        return None
    if not isinstance(item, str) or '(' not in item:
        return None
    try:
        expr = ast.parse(item.strip(), mode='eval').body
        if not isinstance(expr, ast.Call) or expr.args or any(k.arg is None for k in expr.keywords):
            return None
        tool = ast.unparse(expr.func)
        if not re.fullmatch(r'[a-zA-Z_][\w.]*', tool):
            return None
        arguments = {}
        for kw in expr.keywords:
            try:
                arguments[kw.arg] = ast.literal_eval(kw.value)
            except ValueError:
                if isinstance(kw.value, ast.Name):
                    arguments[kw.arg] = kw.value.id
                else:
                    return None
        return tool.replace('.', '_'), arguments
    except (SyntaxError, ValueError):
        return None


def names_bare_tool(directives, tool):
    declared = directives.get('required_work') or directives.get('priority_tools') or []
    return any(not parse_work(item) and str(item).strip().replace('.', '_') == tool
               for item in declared)


def canonical(tool, arguments):
    from core.phase_routing import _TOOL_SCHEMAS, validate_arguments
    schema = _TOOL_SCHEMAS.get(tool)
    return validate_arguments(schema, arguments) if schema else arguments


def completed(entries, item):
    parsed = parse_work(item)
    if not parsed:
        return False
    tool, arguments = parsed
    from core.phase_routing import source_versions
    try:
        arguments = canonical(tool, arguments)
    except Exception:
        return False
    versions = source_versions(arguments)
    latest = {}
    for entry in entries:
        if entry.get('type') == 'phase_work':
            latest[entry['request_id']] = entry
    for entry in latest.values():
        if (entry.get('tool') == tool and not entry.get('scope_unspecified')
                and canonical(tool, entry.get('arguments') or {}) == arguments
                and entry.get('source_versions') == versions
                and entry.get('status') in ('completed', 'dispositioned')):
            from core.evidence_packets import file_version
            if all(file_version(p) == v for p, v in entry.get('output_versions', {}).items()):
                return True
    # Historical execution is reusable only with verifiable exact arguments.
    return any(e.get('type') == 'tool_call' and e.get('mcp_tool', '').replace('.', '_') == tool
               and e.get('mcp_arguments') == arguments and e.get('input_versions') == versions
               and e.get('success') is True and e.get('scope_complete', True)
               for e in entries)


def register(log, items, call_id=0):
    from core.phase_routing import (reserve, action_phase, work_state, append_event, normalized,
                                    supersede_unspecified)
    from core.readiness import digest
    from tools._gates.work_order import _control_plane_tool
    registered = []
    for item in items:
        parsed = parse_work(item)
        if not parsed:
            tool = str(item).strip()
            if _control_plane_tool(tool):
                continue
            rid = 'W-' + digest([log._run_id, normalized(tool), 'unspecified_scope'])[:24]
            with log.transaction():
                old = work_state(log).get(rid)
                if not old:
                    append_event(log, 'phase_work', request_id=rid, tool=normalized(tool),
                                 arguments={}, source_versions={}, required_phase=action_phase(tool, {}, log),
                                 status='needs_specification', scope_unspecified=True, scope=log._case_id,
                                 trigger_call_id=call_id)
            registered.append({'request_id': rid, 'status': 'needs_specification', 'requested': item,
                               'next_action': 'Supply exact arguments in directives.required_work; reuse completed coverage when equivalent'})
            continue
        tool, arguments = parsed
        try:
            arguments = canonical(tool, arguments)
        except Exception as exc:
            registered.append({'status': 'needs_specification', 'requested': item, 'error': str(exc)[:200]})
            continue
        phase = action_phase(tool, arguments, log)
        if not phase:
            continue
        with log.transaction():
            work, _, _ = reserve(log, tool, arguments, phase, execute=False, trigger_call_id=call_id)
            supersede_unspecified(log, tool, work['request_id'])
        registered.append({'request_id': work['request_id'], 'status': work['status'],
                           'tool': tool, 'arguments': arguments})
    return registered
