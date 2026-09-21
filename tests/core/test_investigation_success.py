"""Regression fixtures for review continuation, scope and truthful completion."""
import json
import threading
from contextvars import ContextVar
from unittest.mock import patch

import pytest

from core.execution_log import log
from core.evidence_display import scan_review_rows, displayed_text, prompt_packet
from core.evidence_packets import build_packet
from core.phase_routing import source_versions, reserve, finish, work_state


def test_input_manifest_detects_child_edit(tmp_path):
    folder = tmp_path / 'input'
    folder.mkdir()
    child = folder / 'one.txt'
    child.write_text('one')
    before = source_versions({'directory': str(folder)})
    child.write_text('two')
    assert source_versions({'directory': str(folder)}) != before


def test_completed_work_ignores_unrelated_output_sibling(tmp_path):
    from core.output_manifest import read_manifest
    from core.evidence_packets import file_version
    folder = tmp_path / 'outputs'
    folder.mkdir()
    output = folder / 'records.csv'
    output.write_text('ID\nfirst\n')
    work, _, _ = reserve(log, 'parser.run', {'path': '/input'}, 'Collect')
    cid = log.record_tool_call('parser', True, False, 0, 0, output_path=str(folder),
                               output_manifest=read_manifest(str(output), file_version(output), {}))
    finish(log, work, {'success': True, '_trudi_call_id': cid})
    (folder / 'unrelated.txt').write_text('later')
    assert work_state(log)[work['request_id']]['status'] == 'completed'
    output.write_text('ID\nchanged\n')
    assert work_state(log)[work['request_id']]['status'] == 'stale'


def test_same_tool_other_target_does_not_complete_work(tmp_path):
    from tools._gates.work_order import unrun_from_list
    a, b = str(tmp_path / 'alpha'), str(tmp_path / 'beta')
    work, _, _ = reserve(log, 'strings.grep', {'path': a, 'pattern': 'invoice'}, 'Collect')
    finish(log, work, {'success': True})
    todo = [{'tool': 'strings.grep', 'arguments': {'path': b, 'pattern': 'invoice'}}]
    assert unrun_from_list(log._entries, todo)
    assert not unrun_from_list(log._entries, [{'tool': 'strings.grep', 'arguments': work['arguments']}])


def test_repetition_never_instructs_manufacturing_absence(tmp_path):
    from core import middleware as M
    path = tmp_path / 'artifact'
    path.write_text('one')
    args = {'path': str(path)}
    key = M._repeat_key('strings_grep', args)
    with patch.object(M, '_repeat_state', {}):
        for _ in range(M.REPEAT_BLOCK_AFTER + 2):
            notice = M._repeat_update(key, 'strings_grep', {'success': False, 'error': 'parse failure'})
        refusal = M._repeat_precheck(key, 'strings_grep')
        assert 'does not prove absence' in notice
        assert 'record_finding' not in refusal and 'neither absence nor scan completeness' in refusal
    path.write_text('two')
    assert M._repeat_key('strings_grep', args) != key


def test_mail_fetch_binds_body_headers_and_attachments(tmp_path):
    path = tmp_path / 'mail.mbox'
    raw = (b'From one@example.com Sat Jan 01 00:00:00 2022\nFrom: one@example.com\n'
           b'To: recipient@example.com\nDate: Sat, 01 Jan 2022 00:00:00 +0000\nSubject: Proposal\n'
           b'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n'
           b'--x\nContent-Type: text/plain\n\nPlease examine the invoice.\n'
           b'--x\nContent-Type: application/pdf\nContent-Disposition: attachment; filename="invoice.pdf"\n\nbytes\n--x--\n'
           b'From stranger@example.com Sun Jan 02 00:00:00 2022\nFrom: stranger@example.com\n'
           b'To: unrelated@example.com\nSubject: Other\n\nUnrelated message.\n')
    path.write_bytes(raw)
    fetched = scan_review_rows(str(path), ['invoice'], 4000, ['Date', 'From', 'To', 'Subject', 'has_attachment'])
    assert fetched.shown_rows == 1 and fetched.scan_complete
    assert 'has_attachment: true' in fetched.body and 'invoice.pdf' in fetched.body
    assert 'recipient@example.com' in fetched.body and 'unrelated@example.com' not in fetched.body
    span = fetched.source_selections[0]
    assert raw[span['start_byte']:span['end_byte']].decode() == span['text']
    cid = log.record_tool_call('parse mail', True, False, 0, 0, output_path=str(path))
    packet = build_packet(log, {'description': 'invoice', 'input_call_ids': [cid]})
    shown = packet['evidence'][0]['selections'][0]['spans'][0]
    assert 'has_attachment: true' in displayed_text(shown)


def test_source_index_keeps_command_and_actual_columns(tmp_path):
    from core.synthesis_evidence import build_synthesis_index
    path = tmp_path / 'deleted.csv'
    path.write_text('Name,DeletedOn\nthing,2022-01-01\n')
    cid = log.record_tool_call('parse /input/registry', True, False, 0, 0, output_path=str(path))
    log.record_finding('thing deleted', 'LIKELY', input_call_ids=[cid])
    shown = prompt_packet(build_synthesis_index(log))['sources'][0]
    assert shown['command'] == 'parse /input/registry'
    assert shown['schema']['columns'] == ['Name', 'DeletedOn']


def test_string_projection_is_not_split_into_characters():
    from core.evidence_requests import normalize_requests
    assert normalize_requests([{'call_id': 1, 'query': 'invoice', 'columns': 'Date,From,To'}])[0]['columns'] == ['Date', 'From', 'To']


def test_unspecified_work_can_be_refined_with_required_schema(monkeypatch):
    from core.phase_routing import _TOOL_SCHEMAS
    from core.work_obligations import register, completed
    monkeypatch.setitem(_TOOL_SCHEMAS, 'strings_grep', {
        'type': 'object', 'properties': {'path': {'type': 'string'}, 'pattern': {'type': 'string'}},
        'required': ['path', 'pattern']})
    bare = register(log, ['strings.grep'])[0]
    scoped = {'tool': 'strings.grep', 'arguments': {'path': '/specific/source', 'pattern': 'needle'}}
    assert not completed(log._entries, scoped)
    precise = register(log, [scoped])[0]
    assert precise['status'] == 'pending'
    assert work_state(log)[bare['request_id']]['status'] == 'superseded'
    assert not completed(log._entries, scoped)


def test_exact_completed_run_settles_bare_tool_obligation():
    """A bare DAIR tool name carries no target, so the analyst's exact completed run is its scope."""
    from core.phase_routing import pending_work
    from core.work_obligations import register
    bare = register(log, ['misc.regripper_hive', 'ez.evtxecmd'])
    work, _, _ = reserve(log, 'misc.regripper_hive', {'hive_path': '/mnt/x/SAM', 'plugin': 'samparse'}, 'Collect')
    assert work_state(log)[bare[0]['request_id']]['status'] == 'needs_specification'
    cid = log.record_tool_call('rip.pl -r SAM -p samparse', True, False, 0, 0)
    finish(log, work, {'success': True, '_trudi_call_id': cid})
    settled = work_state(log)[bare[0]['request_id']]
    assert settled['status'] == 'superseded' and settled['superseded_by'] == work['request_id']
    # Another tool's bare obligation, and a failed run of the same tool, stay open.
    assert [w['tool'] for w in pending_work(log)] == ['ez_evtxecmd']
    failed, _, _ = reserve(log, 'ez.evtxecmd', {'path': '/mnt/x/Security.evtx'}, 'Collect')
    finish(log, failed, {'success': False})
    assert work_state(log)[bare[1]['request_id']]['status'] == 'needs_specification'
    # Naming the bare tool again does not reopen a settled obligation.
    register(log, ['misc.regripper_hive'])
    assert work_state(log)[bare[0]['request_id']]['status'] == 'superseded'


def test_bare_tool_obligation_can_be_dispositioned_by_its_dair_call():
    from core.work_obligations import register
    from tools.misc import record_disposition
    bare = register(log, ['misc.evtx_filter'])[0]
    other = log.record_dair_call('Triage', '', False, '', '', 'stay', '',
                                 directives={'priority_tools': ['strings.grep']})
    named = log.record_dair_call('Triage', '', False, '', '', 'stay', '',
                                 directives={'required_work': ['misc.evtx_filter']})
    refused = record_disposition('follow_up', bare['request_id'], 'inapplicable', [other], 'Wrong trigger')
    assert not refused['success']
    result = record_disposition('follow_up', bare['request_id'], 'inapplicable', [named],
                                'No event logs are present in this evidence set')
    assert result['success'] and work_state(log)[bare['request_id']]['status'] == 'dispositioned'


def test_question_outcome_commits_reviewed_indeterminate_answer():
    from tools.misc import declare_questions
    from core.question_outcomes import record, answered
    from tests.tools.test_finding_submission import fake_review
    log.record_dair_call('Analyze', '', False, '', '', 'stay', '')
    assert declare_questions([{'question_id': 'Q-one', 'question': 'Who changed the record?',
                               'scope': {'sources': ['audit']}}])['success']
    cid = log.record_tool_call('read.output /audit.csv', True, False, 0, 0,
                               stdout_full='Record changed; actor unavailable in retained audit.\n')
    work, _, _ = reserve(log, 'read.output', {'path': '/audit.csv'}, 'Analyze')
    finish(log, work, {'success': True, '_trudi_call_id': cid})
    with patch('tools.reasoning._ask', side_effect=fake_review(log)):
        result = record(log, 'Q-one', 'indeterminate', 'Audit identifies no actor', [cid],
                        [work['request_id']], 'Actor identity remains unknown', [], 'question-outcome')
    assert result['success'], result
    assert answered(log)['Q-one']['outcome'] == 'indeterminate'


def test_reviewed_correspondent_scope_preserves_inventory():
    from tools.misc import declare_questions
    from core.correspondent_scope import review, current_groups
    from tests.tools.test_finding_submission import fake_review
    log.record_dair_call('Analyze', '', False, '', '', 'stay', '')
    declare_questions([{'question_id': 'Q-one', 'question': 'Who changed the record?',
                        'scope': {'sources': ['audit']}}])
    cid = log.record_tool_call('read.mail mode=messages', True, False, 0, 0,
        stdout_full='newsletter@example.test sent a public newsletter unrelated to the audit.\n')
    log.annotate_tool_call(cid, observed_correspondents=['newsletter@example.test'])
    before = dict(log.index().correspondents)
    with patch('tools.reasoning._ask', side_effect=fake_review(log)):
        result = review(log, 'Q-one', ['newsletter@example.test'], {'relationship': 'public newsletter'},
                        'Public informational newsletter unrelated to the audit question', [cid])
    assert result['success'], result
    assert log.index().correspondents == before
    assert len(current_groups(log)) == 1


def test_synthesis_pending_provisional_blockers_are_not_actionable():
    from core import synthesis_session as S
    from tests.core.test_synthesis_session import setup_findings, reviewer
    setup_findings(sources=13)
    def provisional(system, user, **kwargs):
        r = reviewer(system, user, **kwargs)
        r.update(blockers=['Revise now'], directives={'priority_tools': ['new collection']})
        return r
    with patch('tools.reasoning._ask', side_effect=provisional):
        result = S.advance(log)
    assert result['status'] == 'in_progress'
    assert result['next_action'] == 'resume_reason.synthesize'
    assert result['blockers'] == [] and result['directives'] == {}


def test_finding_thirteen_requests_resume_and_failure_is_cached():
    from core.finding_review import advance
    from tools import reasoning as R
    ids = [log.record_tool_call('inspect artifact', True, False, 0, 0,
                               stdout_full=f'observation {i}') for i in range(13)]
    packet = build_packet(log, {'description': 'observations', 'input_call_ids': ids})
    def reviewer(system, user, **kw):
        task = kw['review_progress']
        task['provider_calls'] += 1
        missing = [cid for cid in ids if cid not in {v['record']['call_id'] for v in task['cache'].values()}]
        block = {'evidence_request': [{'call_id': cid, 'query': 'observation'} for cid in missing[:4]]} if missing else {'verdict': 'UNVERIFIABLE'}
        cid = log.record_reason_call('reason_evaluate_finding', True, 'review', {})
        return {'success': True, '_trudi_call_id': cid, 'result_block': block}
    with patch.object(R, '_ask', side_effect=reviewer) as ask, patch.object(R, '_resolve_evidence_requests', wraps=R._resolve_evidence_requests) as fetch:
        first = advance(log, 'system', 'finding', packet, ids)
        assert first['status'] == 'in_progress' and first['pending_requests'] == 1
        final = advance(log, 'system', 'finding', packet, ids)
        count = ask.call_count
        cached = advance(log, 'system', 'finding', packet, ids)
        assert cached['cached'] and ask.call_count == count
        assert fetch.call_count == 13 and final['result_block']['verdict'] == 'UNVERIFIABLE'


def test_output_safe_versions_retained_path(tmp_path):
    from core.paths import output_safe
    path = tmp_path / 'records.csv'
    path.write_text('old evidence')
    log.record_tool_call('extract', True, False, 0, 0, output_path=str(path))
    @output_safe
    def produce(output_path):
        from pathlib import Path
        Path(output_path).write_text('new evidence')
        return {'success': True, 'path': output_path}
    result = produce(str(path))
    assert path.read_text() == 'old evidence' and result['path'] != str(path)
    assert result['output_versions']['output_path']['published'] == result['path']


def test_scheduled_tasks_single_utf16_and_invalid_scope(tmp_path):
    from tools.misc import parse_scheduled_tasks
    task = tmp_path / 'one.xml'
    task.write_bytes(('<?xml version="1.0" encoding="utf-16"?><Task><Command>' + 'a' * 9000 + '</Command></Task>').encode('utf-16'))
    result = parse_scheduled_tasks(str(task))
    assert result['success'] and result['scope_complete'] and result['tasks'][0]['content_truncated']
    entry = log.index().by_call_id[result['_trudi_call_id']]
    assert entry['output_manifest']['files'][0]['path'] == str(task)
    task.write_text('<Task>broken')
    failed = parse_scheduled_tasks(str(task))
    assert not failed['success'] and not failed['scope_complete']


def test_timeout_is_owned_reconnectable_and_cannot_duplicate(tmp_path):
    from core.timeout import with_tool_timeout
    from core.operations import status
    from core.jobs import reset_guard
    release, started = threading.Event(), threading.Event()
    marker = ContextVar('test_marker', default='lost')
    seen = []
    @with_tool_timeout(.02)
    def slow():
        seen.append(marker.get())
        started.set()
        release.wait(2)
        return {'success': True, 'value': 'finished'}
    token = marker.set('preserved')
    try:
        first = slow()
        assert first['status'] == 'running' and 'killed_after_seconds' not in first
        assert slow()['operation_id'] == first['operation_id'] and len(seen) == 1
        @reset_guard
        def reset(case_dir):
            return {'success': True}
        assert reset(str(tmp_path))['gate'] == 'running_operations'
    finally:
        release.set()
        marker.reset(token)
    from core import operations
    worker = next(v[0] for v in operations._active.values() if v[2]['operation_id'] == first['operation_id'])
    worker.join(2)
    assert status(first['operation_id'], log)['result']['value'] == 'finished'
    assert seen == ['preserved']


def test_question_closure_does_not_waive_feasible_work():
    from tools.misc import declare_questions
    from core.question_outcomes import record
    conflict = declare_questions([
        {'question_id': 'Q-one', 'question': 'First meaning', 'scope': {}},
        {'question_id': 'Q-one', 'question': 'Different meaning', 'scope': {}}])
    assert not conflict['success'] and not log.index().by_type.get('question_declared')
    assert declare_questions([{'question_id': 'Q-one', 'question': 'What occurred?', 'scope': {'sources': ['disk']}}])['success']
    work, _, _ = reserve(log, 'strings.grep', {'path': '/unexamined', 'pattern': 'one'}, 'Collect', execute=False)
    result = record(log, 'Q-one', 'indeterminate', 'Insufficient evidence', [], [work['request_id']], 'Unknown actor', [], 'question-key')
    assert result['gate'] == 'unfinished_scope'
    assert work_state(log)[work['request_id']]['status'] == 'pending'


def test_scoped_failure_is_not_a_waiver():
    from tools.misc import record_disposition
    log.record_dair_call('Collect', '', False, '', '', 'stay', '')
    one, _, _ = reserve(log, 'parse.run', {'path': '/first'}, 'Collect')
    two, _, _ = reserve(log, 'parse.run', {'path': '/second'}, 'Collect')
    cid = log.record_tool_call('parser /first', False, False, 0, 1, stderr='Invalid container')
    finish(log, one, {'success': False, '_trudi_call_id': cid})
    result = record_disposition('follow_up', one['request_id'], 'parse_failed', [cid], 'Invalid container; try an alternate parser')
    assert result['success'] and result['obligation_open']
    assert work_state(log)[two['request_id']]['status'] == 'running'
    refused = record_disposition('follow_up', one['request_id'], 'inapplicable', [cid], 'Parser failed')
    assert not refused['success']


def test_near_alias_group_needs_exact_member_body_read():
    from core.correspondent_scope import required_alias_reads
    inventory = {'nina_kwai@example.test': {}, 'nina_kwa1@example.test': {}}
    read = {'cmd': 'read.mail mode=messages query=nina_kwai@example.test'}
    assert required_alias_reads(['nina_kwa1@example.test'], inventory, [read]) == 'nina_kwa1@example.test'
    assert required_alias_reads(['nina_kwai@example.test'], inventory, [read]) is None


def test_non_windows_inventory_does_not_get_windows_fallback():
    from tools._gates._lifecycle import prescribe_for_gaps
    assert prescribe_for_gaps([{'type': 'tool_call', 'success': True, 'platform': 'linux', 'cmd': 'read journal'}]) == []
    assert prescribe_for_gaps([]) == []


def test_legacy_recovery_archives_metadata_and_keeps_output(tmp_path):
    from core import jobs
    path = tmp_path / 'retained.txt'
    path.write_text('uncollected observation')
    with jobs.registry_lock():
        jobs.write_state({'job_id': 'legacy-one', 'pid': 2147483647, 'status': 'running',
                          'collected': False, 'output_path': str(path)})
    result = jobs.recover_legacy('legacy-one', 'Owner no longer exists; retain outputs for traced validation')
    assert result['success'] and result['uncollected_results_preserved']
    assert path.read_text() == 'uncollected observation'
    from pathlib import Path
    assert Path(result['archive']).is_file()
    assert not jobs.states()


def test_legacy_recovery_refuses_unknown_owner():
    from core import jobs
    with jobs.registry_lock():
        jobs.write_state({'job_id': 'legacy-unknown', 'status': 'running', 'collected': False})
    assert not jobs.recover_legacy('legacy-unknown', 'Cannot identify owner')['success']


def test_changed_run_rejects_owned_thread_write():
    from core.operations import operation_run
    token = operation_run.set('a-prior-run')
    try:
        with pytest.raises(RuntimeError, match='previous investigation run'):
            log.record_tool_call('late parser result', True, False, 0, 0)
    finally:
        operation_run.reset(token)
