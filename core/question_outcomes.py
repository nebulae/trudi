"""Reviewed question closure using ordinary independently reviewed findings.

An indeterminate outcome is an assertion about the limits of completed work,
never a substitute for doing that work. Its finding passes the ordinary gates.
"""
from core.readiness import digest


def questions(entries):
    declared = {}
    for e in entries:
        if e.get('type') == 'question_declared':
            declared[e['question_id']] = {'question': e['question'], 'scope': e['scope']}
    if not declared:
        text = next((e['case_question'].strip() for e in reversed(entries)
                     if isinstance(e.get('case_question'), str) and e['case_question'].strip()), '')
        if text:
            declared['Q-' + digest(text)[:16]] = {'question': text, 'scope': {}}
    return declared


def answered(log):
    from core.findings import active_findings
    from core.evidence_packets import packet_current
    from core.phase_routing import work_state, TERMINAL
    active = {f['call_id']: f for f in active_findings(log._entries)}
    work = work_state(log)
    outcomes = {}
    for event in log._entries:
        if event.get('type') != 'question_outcome' or event.get('finding_call_id') not in active:
            continue
        finding = active[event['finding_call_id']]
        review = log.index().by_call_id.get(finding.get('gated_by_evaluate_call_id'), {})
        packet = review.get('evidence_packet')
        if not packet or not packet_current(log, packet):
            continue
        if any(work.get(w, {}).get('status') not in TERMINAL for w in event['obligation_ids']):
            continue
        outcomes[event['question_id']] = event
    return outcomes


def record(log, question_id, outcome, explanation, evidence_ids, obligation_ids,
           remaining_uncertainty, unavailable_ids, key):
    from core.phase_routing import pending_work, work_state, TERMINAL, append_event
    from core.review_issues import review_state
    from core.finding_submission import make_request, submit
    declared = questions(log._entries)
    if question_id not in declared or outcome not in ('supported', 'refuted', 'indeterminate'):
        return {'success': False, 'error': 'Name a declared question_id and supported/refuted/indeterminate outcome',
                'questions': declared}
    work = work_state(log)
    if pending_work(log):
        return {'success': False, 'gate': 'unfinished_scope', 'error': 'Complete or justify the exact outstanding work before question closure'}
    if not obligation_ids or any(w not in work or work[w]['status'] not in TERMINAL for w in obligation_ids):
        return {'success': False, 'error': 'Identify completed or justified work obligations establishing the examined scope'}
    if any(i['status'] == 'open' and i['kind'] != 'advisory' for i in review_state(log._entries)):
        return {'success': False, 'error': 'Resolve the outstanding independent review issues before closure'}
    if outcome == 'indeterminate' and not remaining_uncertainty.strip():
        return {'success': False, 'error': 'State what remains unknown and why the completed scope cannot decide it'}
    unavailable = []
    for cid in unavailable_ids:
        entry = log.index().by_call_id.get(cid, {})
        if entry.get('type') != 'disposition' or entry.get('reason') not in ('evidence_unavailable', 'absent_from_evidence'):
            return {'success': False, 'error': 'Unavailable sources require real scope dispositions'}
        unavailable.append({k: entry.get(k) for k in ('call_id', 'target_kind', 'target_id', 'reason', 'note')})
    import json
    description = (f"Question {question_id}: {declared[question_id]['question']}\n"
        f"Outcome: {outcome}. {explanation}\nRemaining uncertainty: {remaining_uncertainty or 'None declared.'}")
    context = json.dumps({'declared_scope': declared[question_id]['scope'],
        'completed_work': [{k: work[w].get(k) for k in ('request_id', 'tool', 'arguments', 'status', 'result_call_id')}
                           for w in obligation_ids], 'unavailable_sources': unavailable})
    request = make_request(description, 'LIKELY', evidence_ids,
        {'claim_kind': 'positive', 'category': 'other', 'act': 'other', 'entities': []},
        case_context='Review the adequacy of question coverage and this outcome, including remaining uncertainty. ' + context)
    result = submit(log, request, key)
    if result.get('success'):
        with log.transaction():
            if pending_work(log):
                return {'success': False, 'error': 'New work appeared during review; conclusion recorded but question remains open'}
            old = next((e for e in log._entries if e.get('type') == 'question_outcome'
                        and e.get('finding_call_id') == result['_trudi_call_id']), None)
            if not old:
                append_event(log, 'question_outcome', question_id=question_id, outcome=outcome,
                    finding_call_id=result['_trudi_call_id'], obligation_ids=obligation_ids,
                    remaining_uncertainty=remaining_uncertainty, unavailable_disposition_ids=unavailable_ids)
        result['question_id'], result['outcome'] = question_id, outcome
    return result
