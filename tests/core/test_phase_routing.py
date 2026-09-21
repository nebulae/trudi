"""Generic report re-entry contracts, with no investigation-specific fixtures."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from core.execution_log import ExecutionLog
from core.middleware import NarrationMiddleware
from core import phase_routing as P


@pytest.fixture
def log(tmp_path):
    P.remember_schema('ez.mftecmd', {'type': 'object', 'required': ['mft_path'],
                                   'properties': {'mft_path': {'type': 'string'}}})
    log = ExecutionLog()
    log.configure('ROUTING', str(tmp_path / 'trace.json'), save_session=False)
    log.record_dair_call('Analyze', '', True, 'Report', '', 'push', '')
    return log


def context(tool, args, schema=None):
    schema = schema or {'type': 'object', 'properties': {'source': {'type': 'string'}},
                        'required': ['source'], 'additionalProperties': False}
    server = SimpleNamespace(get_tool=AsyncMock(return_value=SimpleNamespace(parameters=schema)))
    return SimpleNamespace(message=SimpleNamespace(name=tool, arguments=args),
                           fastmcp_context=SimpleNamespace(fastmcp=server))


def test_transition_precedes_execution_and_same_call_completes(log):
    async def execute(ctx):
        assert log._current_phase == 'Collect'
        assert P.pending_work(log)[0]['status'] == 'running'
        assert log._entries[-1]['type'] == 'phase_transition'
        return {'success': True, 'rows': [1]}
    with patch('core.execution_log.log', log):
        result = asyncio.run(NarrationMiddleware().on_call_tool(
            context('cloud_collect_records', {'source': 'tenant-a'}), execute))
    assert result['success']
    assert result['phase_transition']['to'] == 'Collect'
    assert not P.pending_work(log)
    assert not any(e['type'] == 'tool_blocked' for e in log._entries)


def test_invalid_arguments_do_not_change_phase(log):
    from fastmcp.exceptions import ToolError
    call = AsyncMock()
    with patch('core.execution_log.log', log), pytest.raises(ToolError, match='needs_specification'):
        asyncio.run(NarrationMiddleware().on_call_tool(context('cloud_collect_records', {}), call))
    assert log._current_phase == 'Report' and not P.pending_work(log)
    call.assert_not_called()


def test_duplicate_delivery_reuses_committed_result(log):
    call = AsyncMock(return_value={'success': True, 'data': 'one execution'})
    ctx = context('cloud_collect_records', {'source': 'tenant-a'})
    with patch('core.execution_log.log', log):
        asyncio.run(NarrationMiddleware().on_call_tool(ctx, call))
        result = asyncio.run(NarrationMiddleware().on_call_tool(ctx, call))
    assert result.structured_content['cached'] and call.await_count == 1


def test_concurrent_request_and_report_entry_cannot_bypass_running_work(log):
    async def scenario():
        started, release = asyncio.Event(), asyncio.Event()
        async def execute(ctx):
            started.set()
            await release.wait()
            return {'success': True}
        ctx = context('cloud_collect_records', {'source': 'tenant-a'})
        first = asyncio.create_task(NarrationMiddleware().on_call_tool(ctx, execute))
        await started.wait()
        second = await NarrationMiddleware().on_call_tool(ctx, AsyncMock())
        assert second.structured_content['status'] == 'running'
        log.record_dair_call('Collect', '', True, 'Report', '', 'push', '')
        assert log._current_phase == 'Collect'
        release.set()
        await first
    with patch('core.execution_log.log', log):
        asyncio.run(scenario())
    assert len([e for e in log._entries if e['type'] == 'phase_transition']) == 1


def test_restart_replays_phase_and_pending_work(log):
    with log.transaction():
        work, _, _ = P.reserve(log, 'vol_pslist', {'image': 'snapshot'}, 'Analyze')
    restored = ExecutionLog()
    restored.configure(log._case_id, log._path, save_session=False)
    assert restored._current_phase == 'Analyze'
    assert restored._phase_stack == log._phase_stack
    assert P.pending_work(restored)[0]['request_id'] == work['request_id']


def test_other_process_refreshes_phase_before_reservation(log):
    other = ExecutionLog()
    other.configure(log._case_id, log._path, save_session=False)
    with log.transaction():
        P.reserve(log, 'ez_mftecmd', {'mft_path': 'disk-a'}, 'Collect')
    with other.transaction():
        assert other._current_phase == 'Collect'
        assert len(P.pending_work(other)) == 1


def test_unrelated_evidence_and_dair_do_not_settle_failure(log):
    with log.transaction():
        work, _, _ = P.reserve(log, 'ez_mftecmd', {'mft_path': 'disk-a'}, 'Collect')
    P.finish(log, work, {'success': False})
    log.record_tool_call('other source', True, False, 0, 0)
    for _ in range(3):
        log.record_dair_call('Collect', '', True, 'Report', '', 'push', '')
    assert log._current_phase == 'Collect'
    assert P.pending_work(log)[0]['status'] == 'failed'


@pytest.mark.parametrize('tool,args,phase', [
    ('cloud_collect_records', {'source': 'tenant-a'}, 'Collect'),
    ('vol_pslist', {'image': 'snapshot'}, 'Analyze'),
    ('correlate_process_to_file', {'source': 'parsed'}, 'Analyze'),
    ('yara_scan', {'source': 'collection'}, 'Scan'),
    ('reason_synthesize', {}, ''),
    ('misc_record_disposition', {}, ''),
    ('misc_record_finding', {'supersedes': 2}, ''),
])
def test_action_classification(log, tool, args, phase):
    assert P.action_phase(tool, args, log) == phase


def test_retained_output_read_stays_in_report_but_new_source_does_not(log, tmp_path):
    output = tmp_path / 'rows.csv'
    output.write_text('value\n1\n')
    log.record_tool_call('parse', True, False, 0, 0, output_path=str(output))
    assert P.action_phase('read_output', {'path': str(output)}, log) == ''
    assert P.action_phase('read_output', {'path': str(tmp_path / 'uncollected')}, log) == 'Collect'


def test_missing_synthesis_check_stays_in_report(log):
    from tools.reasoning import reason_pre_report_check
    readiness = {'ready_to_report': False, 'blocking_issues': ['synthesis missing'],
                 'issues': [{'kind': 'policy_requirement', 'message': 'synthesis missing'}]}
    with patch('core.execution_log.log', log), patch('tools._readiness.assess_readiness', return_value=readiness):
        result = reason_pre_report_check()
    assert not result['ready_to_report'] and log._current_phase == 'Report'
    assert not any(e['type'] == 'phase_transition' for e in log._entries)


def issue(required=True, kind='collect'):
    return {'issue_id': 'R-test', 'kind': 'evidence_gap', 'message': 'need scoped extraction',
            'action': {'required': required, 'kind': kind, 'tool': 'ez.mftecmd',
                       'target': 'disk-a', 'arguments': {'mft_path': 'disk-a'},
                       'completion_criterion': 'Parse this source'}}


def test_synthesis_handoff_is_durable_and_never_executes_tool(log):
    result = P.route_issues(log, [issue()], 1)
    assert result[0]['status'] == 'pending' and log._current_phase == 'Collect'
    assert not any(e['type'] == 'tool_call' for e in log._entries)
    P.route_issues(log, [issue()], 1)
    assert len(P.work_state(log)) == 1
    from tools.reasoning import reason_synthesize
    with patch('core.execution_log.log', log), patch('tools.reasoning._ask') as ask:
        result = reason_synthesize('pending')
    assert result['status'] == 'follow_up_required'
    ask.assert_not_called()


@pytest.mark.parametrize('required,kind', [(False, 'collect'), (True, 'repair'), (True, 'report_local')])
def test_optional_and_repair_actions_do_not_transition(log, required, kind):
    assert not P.route_issues(log, [issue(required, kind)])
    assert log._current_phase == 'Report'


def test_malformed_target_needs_specification_without_phase_change(log):
    request = issue()
    request['action']['target'] = 'different-disk'
    result = P.route_issues(log, [request])
    assert result[0]['status'] == 'needs_specification'
    assert log._current_phase == 'Report'


def test_same_request_does_not_inflate_stack(log):
    depth = len(log._phase_stack)
    for _ in range(3):
        with log.transaction():
            work, _, _ = P.reserve(log, 'vol_pslist', {'image': 'snapshot'}, 'Analyze', refresh=True)
        P.finish(log, work, {'success': True})
        log.record_dair_call('Analyze', '', True, 'Report', '', 'push', '')
    assert len(log._phase_stack) == depth


def test_changed_output_cannot_reuse_approval(log, tmp_path):
    output = tmp_path / 'parsed.csv'
    output.write_text('one')
    with log.transaction():
        work, _, _ = P.reserve(log, 'parser', {'source': 'cloud'}, 'Collect')
    cid = log.record_tool_call('parse', True, False, 0, 0, output_path=str(output))
    P.finish(log, work, {'success': True, '_trudi_call_id': cid})
    output.write_text('two different rows')
    assert P.pending_work(log)[0]['status'] == 'stale'


def test_expanded_arguments_never_reuse_completed_scope(log):
    with log.transaction():
        work, _, _ = P.reserve(log, 'cloud_export', {'source': 'tenant'}, 'Collect')
    P.finish(log, work, {'success': True})
    with log.transaction():
        expanded, _, execute = P.reserve(log, 'cloud_export', {'source': 'tenant', 'query': 'new'}, 'Collect')
    assert execute and expanded['request_id'] != work['request_id']


def test_csv_input_version_is_watched(tmp_path):
    source = tmp_path / 'input.csv'
    source.write_text('initial')
    before = P.source_versions({'csv_path': str(source)})
    source.write_text('updated records')
    assert before and before != P.source_versions({'csv_path': str(source)})


def test_failed_synthesis_is_not_a_forensic_violation(log):
    from core.execution_log import current_mcp_tool
    token = current_mcp_tool.set('reason_synthesize')
    try:
        cid = log.record_tool_call('<py>:reason_synthesize', False, False, 0, 1)
    finally:
        current_mcp_tool.reset(token)
    assert 'protocol_violation' not in log.index().by_call_id[cid]


def test_report_writer_readiness_gate(log):
    with patch('tools._readiness.assess_readiness', return_value={'ready_for_synthesis': False, 'issues': []}):
        log.record_dair_call('Analyze', '', True, 'Report', '', 'push', '', enforce_readiness=True)
    assert log._entries[-1]['server_override']['kind'] == 'report_prerequisites'


def test_real_fastmcp_request_validates_transitions_and_executes(log):
    from fastmcp import FastMCP, Client
    server = FastMCP('routing-contract')
    server.add_middleware(NarrationMiddleware())
    calls = []

    @server.tool()
    def acquire_records(source: str, limit: int = 10) -> dict:
        assert log._current_phase == 'Collect'
        calls.append((source, limit))
        return {'success': True, 'rows': ['record']}

    async def scenario():
        async with Client(server) as client:
            listed = await client.list_tools()
            assert '_refresh' in listed[0].inputSchema['properties']
            first = await client.call_tool('acquire_records', {'source': 'tenant'})
            assert first.data['success']
            second = await client.call_tool('acquire_records', {'source': 'tenant', 'limit': 10})
            assert second.data['cached']
            third = await client.call_tool('acquire_records', {'source': 'tenant', '_refresh': True})
            assert third.data['success']
    with patch('core.execution_log.log', log):
        asyncio.run(scenario())
    assert calls == [('tenant', 10), ('tenant', 10)]


def test_typed_pre_report_action_returns_collect(log):
    from tools.reasoning import reason_pre_report_check
    readiness = {'ready_to_report': False, 'blocking_issues': ['required scoped extraction'],
                 'issues': [issue()]}
    with patch('core.execution_log.log', log), patch('tools._readiness.assess_readiness', return_value=readiness):
        result = reason_pre_report_check()
    assert result['status'] == 'follow_up_required' and log._current_phase == 'Collect'


def test_synthesis_packet_defect_stays_in_report(log):
    from tools.reasoning import reason_synthesize
    from core.evidence_packets import PacketError
    with patch('core.execution_log.log', log), \
         patch('tools._readiness.assess_readiness', return_value={'ready_for_synthesis': True}), \
         patch('core.synthesis_session.build_synthesis_index', side_effect=PacketError('output unavailable')), \
         patch('tools.reasoning._ask') as ask:
        result = reason_synthesize('review')
    assert result['status'] == 'blocked' and not result['retryable']
    assert log._current_phase == 'Report'
    ask.assert_not_called()


def test_background_job_keeps_report_blocked_until_completion(log):
    with log.transaction():
        work, _, _ = P.reserve(log, 'cloud_export', {'source': 'tenant'}, 'Collect')
    P.finish(log, work, {'success': True, 'status': 'running', 'job_id': 'job-1'})
    P.reconcile_job(log, 'misc_job_status', {'job_id': 'other'}, {'success': True, 'status': 'completed'})
    assert P.pending_work(log)
    P.reconcile_job(log, 'misc_job_status', {'job_id': 'job-1'}, {'success': True, 'status': 'finished'})
    assert not P.pending_work(log)


def test_dead_owner_is_unknown_not_silently_retried(log):
    with log.transaction():
        P.reserve(log, 'cloud_export', {'source': 'tenant'}, 'Collect')
    with patch.object(P, 'process_identity', return_value='different-start-time'):
        assert P.pending_work(log)[0]['status'] == 'unknown'


def test_only_matching_disposition_settles_request(log):
    from tools.misc import record_disposition
    with log.transaction():
        work, _, _ = P.reserve(log, 'cloud_export', {'source': 'tenant'}, 'Collect')
    result_cid = log.record_tool_call('cloud export tenant', False, False, 0, 1)
    P.finish(log, work, {'success': False, '_trudi_call_id': result_cid})
    unrelated = log.record_tool_call('unrelated', True, False, 0, 0)
    with patch('core.execution_log.log', log):
        bad = record_disposition('follow_up', work['request_id'], 'evidence_unavailable',
                                 evidence_call_ids=[unrelated], note='unrelated')
        assert not bad['success'] and P.pending_work(log)
        good = record_disposition('follow_up', work['request_id'], 'evidence_unavailable',
                                  evidence_call_ids=[result_cid], note='Scoped export unavailable',
                                  alternatives_exhausted=True, remaining_scope='Tenant export cannot be acquired')
    assert good['success'] and not P.pending_work(log)
