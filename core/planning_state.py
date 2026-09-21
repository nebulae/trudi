"""Bounded, authoritative investigation state for the DAIR planner."""
import os
import shutil
from pathlib import Path

from core.readiness import digest


def environment():
    specs = {'misc.chainsaw_hunt': ('chainsaw', ['ez.evtxecmd', 'misc.evtx_filter']),
             'misc.capa_analyze': ('capa', ['misc.pe_scanner', 'strings.grep']),
             'misc.hindsight_chrome': ('/usr/local/bin/hindsight.py', ['ez.sqlecmd'])}
    results = {}
    for tool, (binary, alternatives) in specs.items():
        path = binary if os.path.isabs(binary) and os.path.isfile(binary) else shutil.which(binary)
        if not path:
            path = next((str(p) for p in (Path('/usr/local/bin') / binary, Path('/usr/bin') / binary)
                         if p.is_file() and os.access(p, os.X_OK)), None)
        state = {'executable': path, 'available': bool(path), 'alternatives': alternatives,
                 'validation': 'executable_presence_only; parsing not certified'}
        if path:
            try:
                with open(path, 'rb') as stream:
                    first = stream.readline(256)
                if first.startswith(b'#!'):
                    interpreter = first[2:].decode(errors='replace').strip().split()[0]
                    state['interpreter'] = interpreter
                    state['available'] = os.access(interpreter, os.X_OK)
            except OSError:
                state['available'] = False
        results[tool] = state
    return results


def platforms(entries):
    declared = set()
    for entry in entries:
        inventory = entry.get('evidence_inventory') or entry.get('inventory') or {}
        if isinstance(inventory, dict):
            for value in inventory.get('platforms', []):
                declared.add(str(value).lower())
        if entry.get('type') == 'tool_call' and entry.get('success') is True:
            classes = entry.get('artifact_classes') or []
            if any(str(c).lower() in ('evtx', 'windows_event_log', 'registry', 'prefetch', 'amcache') for c in classes):
                declared.add('windows')
            if entry.get('platform'):
                declared.add(str(entry['platform']).lower())
    return sorted(declared)


def snapshot(log, question=''):
    from core.phase_routing import work_state, TERMINAL
    from core.findings import active_findings
    from core.review_issues import review_state
    work = list(work_state(log).values())
    from core.question_outcomes import questions as declared_questions
    questions = declared_questions(log._entries)
    if question.strip() and not questions:
        questions['Q-' + digest(question.strip())[:16]] = {'question': question.strip(), 'scope': {}}
    pending = [w for w in work if w['status'] not in TERMINAL]
    findings = active_findings(log._entries)
    result = {'run_id': log._run_id, 'phase': log._current_phase, 'phase_stack': log._phase_stack,
            'questions': questions, 'platforms': platforms(log._entries), 'environment': environment(),
            'work_counts': {'pending': len(pending), 'total': len(work)},
            'pending_work': [{k: w.get(k) for k in ('request_id', 'tool', 'arguments', 'status', 'required_phase', 'error')}
                             for w in pending[:24]],
            'completed_work': [{k: w.get(k) for k in ('request_id', 'tool', 'arguments', 'result_call_id')}
                               for w in work if w['status'] == 'completed'][-12:],
            'findings': [{k: f.get(k) for k in ('call_id', 'description', 'claim', 'confidence')}
                         for f in findings[:24]],
            'review_issues': [i for i in review_state(log._entries) if i['status'] == 'open'][:16],
            'limits': {'pending_shown': min(len(pending), 24), 'findings_total': len(findings)},
            'authority': 'Server state governs phase, pending work and evidence. Caller summary is supplementary.'}

    import json
    # No source rows or unbounded descriptions in a planning prompt. Counts
    # remain authoritative when detail is omitted; readiness exposes full work.
    for key in ('findings', 'completed_work', 'review_issues', 'pending_work'):
        while len(json.dumps(result, default=str)) > 24000 and result[key]:
            result[key].pop()
            result['limits']['omitted_for_budget'] = True
    if len(json.dumps(result, default=str)) > 24000:
        result['questions'] = {qid: {'question': str(q['question'])[:1000], 'scope': 'See question declaration'}
                               for qid, q in list(questions.items())[:16]}
        result['limits']['questions_total'] = len(questions)
        result['limits']['omitted_for_budget'] = True
    return result
