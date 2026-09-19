"""Regressions for retired findings, stale approvals and review loops from case traces."""
import json
from unittest.mock import patch
import pytest
from core.execution_log import ExecutionLog
from core.findings import active_findings, finding_view
from core.readiness import state_fingerprint
from core.review_issues import normalize_review, review_state


@pytest.fixture
def case(tmp_path):
    log = ExecutionLog()
    log.configure('REVIEW', str(tmp_path / 'trace.json'), save_session=False)
    return log


def approve(log, limitations=None):
    log.record_reason_call('reason_pre_report_check', True, 'READY_TO_REPORT: true', {},
                          extra={'ready_to_report': True,
                                 'readiness_fingerprint': state_fingerprint(log._entries, log._case_id),
                                 'synthesize_blockers_unresolved': limitations or []})


def test_revision_shared_by_consumers_and_retains_qualifier(case):
    from tools.reasoning import _typed_findings_block, _synthesize_citable_ids
    old = case.record_finding('HP attached and printed bills', 'SUSPECTED')
    description = 'HP attached. ' + 'Source detail. ' * 50 + 'Actual printing is NOT established.'
    new = case.record_finding(description, 'SUSPECTED', supersedes=old)
    assert [e['call_id'] for e in active_findings(case._entries)] == [new]
    assert len(case.index().by_type['finding']) == 2
    assert case.index().active_findings[0]['revision'] == 2
    assert case.index().active_findings[0]['finding_id'] == f'F-{old}'
    text, count = _typed_findings_block(case._entries, max_chars=10)
    assert count == 1 and 'printed bills' not in text
    assert text.endswith('Actual printing is NOT established.')
    assert old not in _synthesize_citable_ids(case._entries, [old, new])


def test_legacy_branch_is_visible_and_blocks_readiness(case):
    from tools.reasoning import reason_readiness_status
    old = case.record_finding('HP printed', 'SUSPECTED')
    new = case.record_finding('HP attached', 'SUSPECTED', supersedes=old)
    case._entries.append({'type': 'finding', 'call_id': 100, 'supersedes': old,
                          'description': 'Second successor', 'confidence': 'SUSPECTED'})
    case._flush()
    view = finding_view(case._entries)
    assert view.anomalies[0]['code'] == 'branching_revision'
    assert {e['call_id'] for e in view.active} == {old, new, 100}
    with patch('core.execution_log.log', case):
        result = reason_readiness_status()
    assert any('lifecycle anomaly' in s for s in result['blocking_issues'])


def test_wrong_proposition_revision_rejected(case):
    old = case.record_finding('No privilege escalation', 'UNCONFIRMED',
                              claim={'kind': 'negative', 'category': 'privilege'})
    with pytest.raises(ValueError, match='proposition'):
        case.record_finding('Files renamed in C journal', 'SUSPECTED', supersedes=old,
                            claim={'kind': 'positive', 'category': 'destruction'})
    assert len(active_findings(case._entries)) == 1


def test_two_log_instances_cannot_branch_same_parent(case):
    old = case.record_finding('original', 'SUSPECTED')
    other = ExecutionLog()
    other.configure('REVIEW', case._path, save_session=False)
    new = case.record_finding('corrected', 'SUSPECTED', supersedes=old)
    with pytest.raises(ValueError, match='current revision'):
        other.record_finding('competing correction', 'SUSPECTED', supersedes=old)
    assert active_findings(other._entries)[0]['call_id'] == new


def test_retraction_invalidates_report_and_preserves_history(case, tmp_path):
    from tools.misc import retract_finding, write_final_report
    fid = case.record_finding('Unsupported claim', 'SUSPECTED')
    approve(case)
    with patch('core.execution_log.log', case):
        assert retract_finding(fid, 'Withdraw unsupported claim', [fid])['success']
        r = write_final_report(str(tmp_path / 'report.md'), '# Report')
    assert not r['success'] and not active_findings(case._entries)
    assert case.index().by_call_id[fid]['description'] == 'Unsupported claim'


def test_report_approval_survives_chatter_but_not_changed_finding(case, tmp_path):
    from tools.misc import write_final_report
    old = case.record_finding('original', 'SUSPECTED')
    approve(case)
    for n in range(55):
        case.record_agent_message(f'Planning step {n}')
    with patch('core.execution_log.log', case):
        assert write_final_report(str(tmp_path / 'report.md'), '# Report')['success']
        case.record_finding('corrected', 'SUSPECTED', supersedes=old)
        assert not write_final_report(str(tmp_path / 'new.md'), '# Report')['success']
    assert not (tmp_path / 'new.md').exists()


def test_sidecar_change_invalidates_snapshot(case, tmp_path):
    p = tmp_path / 'output.txt'
    p.write_text('fact one')
    cid = case.record_tool_call('read file', True, False, 0, 0)
    case.annotate_tool_call(cid, stdout_path=str(p))
    before = state_fingerprint(case._entries, case._case_id)
    p.write_text('fact two')
    assert state_fingerprint(case._entries, case._case_id) != before


def test_report_heading_cannot_suppress_typed_limitation(case, tmp_path):
    from tools.misc import write_final_report
    approve(case, ['R-example: exact unresolved source limitation'])
    with patch('core.execution_log.log', case):
        r = write_final_report(str(tmp_path / 'report.md'), '# Reviewer limitations\nAgent summary.')
    assert r['success'] and r['limitations_appended'] == 1
    assert 'R-example' in (tmp_path / 'report.md').read_text()


def test_readiness_never_calls_a_model(case):
    from tools.reasoning import reason_pre_report_check, reason_readiness_status
    with patch('core.execution_log.log', case), patch('tools.reasoning._ask') as ask:
        status = reason_readiness_status()
        reason_pre_report_check()
    ask.assert_not_called()
    assert status['ready_for_synthesis'] is False
    assert not any('synthesize was not called' in s for s in status['blocking_issues'])


def test_audit_only_new_narration_and_cache_survives_restart(case):
    import tools.reasoning as R
    case.record_agent_message('A material account fact')
    seen = []
    def fake(system, user, **kwargs):
        seen.append(user)
        cid = case.record_reason_call('reason_audit_findings', True, 'ok', {})
        return {'success': True, 'result_block': {'audit_findings': []}, '_trudi_call_id': cid}
    with patch('core.execution_log.log', case), patch.object(R, '_ask', fake):
        R.reason_audit_findings()
        assert R.reason_audit_findings()['cached']
        case.record_agent_message('A second material fact')
        R.reason_audit_findings()
        assert 'A material account fact' not in seen[-1]
        assert len(seen) == 2
        case.configure('REVIEW', case._path, save_session=False)
        assert R.reason_audit_findings()['cached']
        case.record_finding('fact corrected', 'SUSPECTED')
        R.reason_audit_findings()
        assert len(seen) == 3 and 'A material account fact' in seen[-1]


def test_issue_omission_does_not_resolve_and_revision_retires_scoped_issue(case):
    fid = case.record_finding('printing established', 'SUSPECTED')
    result = {'result_block': {'issues': [{'kind': 'unsupported_claim', 'message': 'No print job',
                                         'finding_call_ids': [fid], 'evidence_call_ids': []}]}}
    issues, resolutions = normalize_review(result, case._entries)
    case.record_reason_call('reason_synthesize', True, 'issue', {},
                            extra={'review_issues': issues, 'issue_resolutions': resolutions})
    case.record_reason_call('reason_synthesize', True, 'nothing new', {}, extra={'review_issues': []})
    assert review_state(case._entries)[0]['status'] == 'open'
    case.record_finding('attachment only', 'SUSPECTED', supersedes=fid)
    assert review_state(case._entries)[0]['status'] == 'obsolete'


def test_contradiction_cannot_be_demoted_to_limitation(case):
    fid = case.record_finding('wrong', 'SUSPECTED')
    issues, _ = normalize_review({'result_block': {'issues': [{'kind': 'contradiction',
        'message': 'Source says otherwise', 'finding_call_ids': [fid]}]}}, case._entries)
    case.record_reason_call('reason_synthesize', True, 'no', {}, extra={'review_issues': issues})
    new = case.record_tool_call('new evidence', True, False, 0, 0)
    with pytest.raises(ValueError, match='cannot become a limitation'):
        normalize_review({'result_block': {'issues': [], 'resolutions': [{
            'issue_id': issues[0]['issue_id'], 'basis': 'qualified_limitation',
            'reason': 'Tried twice', 'call_ids': [new]}]}}, case._entries)


def test_malformed_dair_is_failure_without_phase_mutation(case):
    import tools.dair as D
    phase = case._current_phase
    with patch('core.execution_log.log', case), patch.object(D, '_ask', return_value={
            'success': True, 'raw': 'RESULT: {broken', 'input_tokens': 1, 'output_tokens': 5}) as ask:
        r = D.dair_assess('batch results')
    assert not r['success'] and r['retryable'] and ask.call_count == 2
    assert not case.index().by_type.get('dair_call')
    assert case._current_phase == phase


def test_schema_repair_preserves_fetching(case):
    from tools._llm_parse import validate_result
    assert not validate_result({'_raw': 'EVIDENCE_REQUEST: []',
                                'evidence_requests': [{'call_id': 1, 'query': 'account'}]},
                               'reason_evaluate_finding')
    assert validate_result({'_raw': 'RESULT: {broken', 'result_block': None}, 'reason_synthesize')


def test_retraction_adjudicates_legacy_competing_revision(case):
    from tools.misc import retract_finding
    old = case.record_finding('attachment', 'SUSPECTED')
    good = case.record_finding('attachment only', 'SUSPECTED', supersedes=old)
    case._entries.append({'type': 'finding', 'call_id': 100, 'supersedes': old,
                          'description': 'Invalid competing assertion', 'confidence': 'SUSPECTED'})
    case._flush()
    with patch('core.execution_log.log', case):
        assert retract_finding(100, 'Duplicate revision without support', [good])['success']
    assert not finding_view(case._entries).anomalies
    assert [e['call_id'] for e in active_findings(case._entries)] == [good]


@pytest.mark.parametrize('failure', ['backend', 'round_limit'])
def test_failed_fetch_review_cannot_preserve_preliminary_verdict(case, failure):
    import tools.reasoning as R
    cid = case.record_reason_call('reason_evaluate_finding', True, 'VERDICT: SUPPORTED', {})
    first = {'success': True, '_trudi_call_id': cid, 'conclusion': 'VERDICT: SUPPORTED',
             'evidence_requests': [{'call_id': cid, 'query': 'more'}]}
    follow = {'success': False, 'error': 'backend unavailable'} if failure == 'backend' else first.copy()
    with patch('core.execution_log.log', case), patch.object(R, 'COMPAT_EVIDENCE_ROUNDS', 1), \
         patch.object(R, '_resolve_evidence_requests', return_value=('rows', [])):
        result = R._evidence_round_trip(first, lambda *a: follow, 'review',
                                       'reason_evaluate_finding', [cid])
    assert result['success'] is False
    assert result['_trudi_call_id'] == cid


def test_failed_evaluation_with_supported_text_cannot_authorize_finding(case):
    from types import SimpleNamespace
    from tools._gates.confirmed_requires_supported_evaluate import check
    cid = case.record_reason_call('reason_evaluate_finding', False, 'VERDICT: SUPPORTED', {})
    ctx = SimpleNamespace(tier='CONFIRMED', claim={}, description='fact', confidence='CONFIRMED',
                          window=case._entries, idx=case.index(), log=case)
    result = check(ctx)
    assert result['success'] is False and result['evaluate_call_id'] == cid


def test_report_inventory_contains_only_current_findings(case, tmp_path):
    from tools.misc import write_final_report
    old = case.record_finding('Unsupported old claim', 'SUSPECTED')
    case.record_finding('Corrected and qualified claim', 'SUSPECTED', supersedes=old)
    approve(case)
    dest = tmp_path / 'report.md'
    with patch('core.execution_log.log', case):
        assert write_final_report(str(dest), '# Summary')['success']
    assert 'Corrected and qualified claim' in dest.read_text()
    assert 'Unsupported old claim' not in dest.read_text()


@pytest.mark.parametrize('bad', [{'current_phase': {}}, {'phase_rationale': []},
                                 {'transition_recommended': 1}])
def test_invalid_dair_field_types_are_schema_errors(bad):
    from tools._llm_parse import validate_assessment
    assessment = {'current_phase': 'Analyze', 'phase_rationale': 'review',
                  'stack_action': 'stay', 'transition_recommended': False, **bad}
    assert validate_assessment(assessment)


def test_audit_policy_change_invalidates_incremental_cursor(case):
    import tools.reasoning as R
    case.record_agent_message('A material fact')
    def fake(*args, **kw):
        cid = case.record_reason_call('reason_audit_findings', True, 'ok', {})
        return {'success': True, 'result_block': {'audit_findings': []}, '_trudi_call_id': cid}
    with patch('core.execution_log.log', case), patch.object(R, '_ask', side_effect=fake) as ask:
        R.reason_audit_findings()
        with patch.object(R, 'REASON_MODEL', 'different-reviewer'):
            R.reason_audit_findings()
        assert ask.call_count == 2


def test_truncated_dair_cannot_advance_even_with_valid_json(case):
    import tools.dair as D
    raw = json.dumps({'schema_version': 1, 'assessment': {
        'current_phase': 'Triage', 'phase_rationale': 'done', 'stack_action': 'push',
        'transition_recommended': True, 'next_phase': 'Collect'}})
    with patch('core.execution_log.log', case), patch.object(D, '_ask', return_value={
            'success': True, 'raw': 'RESULT: ' + raw, 'truncated': True}) as ask:
        result = D.dair_assess('facts')
    assert not result['success'] and ask.call_count == 2
    assert not case.index().by_type.get('dair_call')



def test_retracting_current_revision_never_revives_superseded_claim(case):
    from tools.misc import retract_finding
    old = case.record_finding('Unsupported original claim', 'SUSPECTED')
    new = case.record_finding('Narrower revised claim', 'SUSPECTED', supersedes=old)
    with patch('core.execution_log.log', case):
        assert retract_finding(new, 'Withdraw entire claim', [new])['success']
    assert not active_findings(case._entries)
    assert len(finding_view(case._entries).history) == 2
    assert not finding_view(case._entries).anomalies



def test_partial_structured_dair_does_not_invent_default_phase(case):
    import tools.dair as D
    with patch('core.execution_log.log', case), patch.object(D, '_ask', return_value={
            'success': True, 'raw': 'RESULT: {"assessment": {"phase_rationale": "done"}}'}):
        result = D.dair_assess('facts')
    assert not result['success']
    assert not case.index().by_type.get('dair_call')
