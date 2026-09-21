"""Bounded control messages with lossless, version-checked detail retrieval."""
import json
from core.readiness import digest

# Leave transport headroom below the 8 KiB client budget.
MAX_BYTES = 6000


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), default=str)


def size(value):
    return len(encoded(value).encode('utf-8'))


def detail_page(result, section, offset=0, limit=2048, state_version=''):
    """Return consecutive characters of serialized JSON, never a silent excerpt.

    Join json_chunk values, then parse JSON. Character offsets (not byte
    offsets) allow splitting large individual fields without losing Unicode.
    """
    version = digest(result)
    if state_version and version != state_version:
        return {'success': False, 'gate': 'stale_control_snapshot',
                'error': 'State changed; restart detail retrieval.', 'state_version': version}
    if section not in result:
        return {'success': False, 'error': 'Unknown section', 'sections': sorted(result)}
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 4096:
        return {'success': False, 'error': 'offset must be nonnegative; limit must be 1..4096'}
    data = encoded(result[section])
    if offset > len(data):
        return {'success': False, 'error': 'offset exceeds the serialized section'}
    take = min(limit, len(data) - offset)
    while True:
        end = offset + take
        page = {'success': True, 'state_version': version, 'section': section,
                'encoding': 'json', 'offset_unit': 'unicode_characters',
                'offset': offset, 'next_offset': end if end < len(data) else None,
                'total_characters': len(data), 'json_chunk': data[offset:end]}
        from core.review_delivery import wire_size, MAX_WIRE_BYTES
        if size(page) <= MAX_BYTES and wire_size(page) <= MAX_WIRE_BYTES - 256:
            return page
        take //= 2


def control_response(result, detail_tool, detail_args=None):
    """Small results keep legacy fields; large ones retain explicit references."""
    version = digest(result)
    base = {'control_schema_version': 1, 'state_version': version}
    full = {**result, **base}
    if size(full) <= MAX_BYTES:
        return full
    args = dict(detail_args or {})
    args['state_version'] = version
    summary = {**base, 'details_required': True,
               'details': {'tool': detail_tool, 'arguments': args,
                           'sections': sorted(result)},
               'section_counts': {k: len(v) for k, v in result.items()
                                  if isinstance(v, (list, dict))}}
    for key, value in result.items():
        if not isinstance(value, (list, dict)) and size(value) <= 512:
            candidate = {**summary, key: value}
            if size(candidate) <= MAX_BYTES - 2200:
                summary[key] = value
    required_section = next((k for k in ('blocking_issues', 'review_issues', 'blockers', 'issues', 'follow_up')
                             if result.get(k)), 'blocking_issues')
    issues = result.get(required_section) or []
    summary['required_count'] = sum(not isinstance(i, dict) or i.get('kind') != 'advisory' for i in issues)
    summary['suggestion_count'] = len(result.get('warnings') or [])
    # Fetching the exact requirement is a valid action; do not invent forensic
    # arguments from a legacy English message or make an advisory binding.
    summary['next_actions'] = [{
        'kind': 'retrieve_required_guidance',
        'tool': detail_tool,
        'arguments': {**args, 'section': required_section, 'offset': 0},
        'completion_condition': f'Read all pages of {required_section} at this state_version.',
    }] if summary['required_count'] else []
    for key in ('coverage', 'next_arguments', 'budget_blockers', 'blocking_issues', 'issues', 'warnings', 'curiosity'):
        value = result.get(key)
        if value is not None and size({**summary, key: value}) <= MAX_BYTES:
            summary[key] = value
    return summary
