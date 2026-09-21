"""Reviewed, explicitly enumerated correspondent scope; inventory is unchanged."""
from core.evidence_packets import build_packet, packet_current, packet_evidence_text
from core.readiness import digest


def required_alias_reads(members, inventory, evidence):
    for member in members:
        if '@' not in member:
            continue
        local, domain = member.rsplit('@', 1)
        near = any('@' in other and other != member and other.rsplit('@', 1)[1] == domain
                   and len(other.rsplit('@', 1)[0]) == len(local)
                   and sum(a != b for a, b in zip(local, other.rsplit('@', 1)[0])) == 1 for other in inventory)
        if near and not any('read.mail' in str(e.get('cmd', '')).lower()
                and 'mode=messages' in str(e.get('cmd', '')).lower()
                and member in str(e.get('cmd', '')).lower() for e in evidence):
            return member
    return None


def current_groups(log):
    groups = []
    for entry in log._entries:
        if entry.get('type') == 'correspondent_scope' and packet_current(log, entry['review_packet']):
            groups.append(entry)
    return groups


def review(log, question_id, members, scope, rationale, evidence_ids):
    from core.question_outcomes import questions
    from core.findings import active_findings
    from tools._gates._entities import entity_matches
    from core.phase_routing import append_event
    from core.finding_review import advance
    from tools import reasoning as R
    from tools.verdict import normalize_verdict, parse_verdict
    questions_now = questions(log._entries)
    if question_id not in questions_now or not rationale.strip() or not isinstance(scope, dict) or not scope:
        return {'success': False, 'error': 'Name a declared question, explicit source/time/relationship scope and shared rationale'}
    inventory = log.index().correspondents
    # The inventory preserves punctuation. Entity alias folding would merge
    # distinct mailboxes and no longer match the actual inventoried addresses.
    members = sorted(set(str(m).strip().lower() for m in members))
    if not members or any(m not in inventory for m in members):
        return {'success': False, 'error': 'Every member must be an exact inventoried correspondent'}
    # Referenced parties remain material; narrowing policy never hides them.
    related = [value for f in active_findings(log._entries)
               for value in ((f.get('claim') or {}).get('entities') or []) + ((f.get('claim') or {}).get('recipients') or [])]
    if any(entity_matches(m, value) for m in members for value in related):
        return {'success': False, 'error': 'Group includes a material party already referenced by an active finding'}
    evidence = [log.index().by_call_id.get(cid, {}) for cid in evidence_ids]
    alias = required_alias_reads(members, inventory, evidence)
    if alias:
        return {'success': False, 'error': 'Near-alias needs its own message-body read: ' + alias}
    import json
    description = ('These enumerated correspondents are outside this question’s required work: ' +
                   json.dumps(members) + '. Rationale: ' + rationale)
    packet = build_packet(log, {'description': description, 'input_call_ids': evidence_ids,
                               'scope': scope, 'question': questions_now[question_id]})
    sid = 'CS-' + digest([question_id, members, scope, packet['packet_id']])[:24]
    existing = next((e for e in current_groups(log) if e['scope_id'] == sid), None)
    if existing:
        return {'success': True, 'scope_id': sid, 'cached': True, 'members': members}
    result = advance(log, R._EVALUATE_SYS,
        'Review this case-scope proposition against the deciding records. Require separate treatment of any material or ambiguous lead. '
        'Return SUPPORTED only if the shared justification holds for EVERY exact member; otherwise request evidence or refuse.\n' +
        json.dumps({'question': questions_now[question_id], 'scope': scope, 'description': description}), packet, evidence_ids)
    verdict = normalize_verdict((result.get('result_block') or {}).get('verdict')) or parse_verdict(result.get('conclusion', ''))
    if not result.get('success') or verdict != 'SUPPORTED':
        return {**result, 'success': False, 'error': result.get('error') or 'The scope group was not independently supported'}
    if not packet_evidence_text(packet) and not result.get('evidence_fetches'):
        return {'success': False, 'error': 'Scope approval requires displayed deciding evidence'}
    with log.transaction():
        if not packet_current(log, packet):
            return {'success': False, 'error': 'Scope evidence changed during review'}
        cid = append_event(log, 'correspondent_scope', scope_id=sid, question_id=question_id,
            members=members, scope=scope, rationale=rationale, review_packet=packet,
            review_call_id=result.get('_trudi_call_id'), evidence_call_ids=evidence_ids)['call_id']
    return {'success': True, '_trudi_call_id': cid, 'scope_id': sid, 'members': members,
            'inventory_preserved': True, 'global_absence_coverage_unchanged': True}
