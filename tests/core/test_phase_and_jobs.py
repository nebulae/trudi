"""Server-owned phase, Triage only for new scope, Report -> Collect routing,
background jobs for long tools, and always-kept tool output."""
import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from core.execution_log import ExecutionLog


@pytest.fixture
def log(tmp_path):
    l = ExecutionLog()
    l.configure("PJ", str(tmp_path / "trace.json"), save_session=False)
    return l


def _raw(cur, nxt, action, **extra):
    a = {"phase_rationale": "r", "current_phase": cur, "transition_recommended": action != "stay",
         "next_phase": nxt, "stack_action": action, "directives": {"priority_tools": []}, **extra}
    return "RESULT:\n" + json.dumps({"assessment": a})


def _dair(log, raw, stack="[]"):
    import tools.dair as D
    with patch("core.execution_log.log", log), \
         patch.object(D, "_ask", return_value={"success": True, "raw": raw,
                                               "input_tokens": 1, "output_tokens": 1}) as ask:
        r = D.dair_assess("summary", stack, "ctx")
    return r, ask.call_args[0][1]


# ── server-owned phase ─────────────────────────────────────────────────────────

def test_model_echo_does_not_move_the_phase(log):
    log.record_dair_call("Triage", "", True, "Collect", "", "push", "")
    assert log._current_phase == "Collect"
    # 2026-09-23: the agent passed "[]", the model answered "Triage, stay".
    log.record_dair_call("Triage", "", False, "", "", "stay", "")
    assert log._current_phase == "Collect"


def test_dair_prompt_uses_the_recorded_phase_not_the_agents_stack(log):
    log.record_dair_call("Triage", "", True, "Collect", "", "push", "")
    _, user = _dair(log, _raw("Collect", "", "stay"), stack="[]")
    assert "CURRENT PHASE: Collect" in user


# ── Triage only for new scope ──────────────────────────────────────────────────

def test_triage_push_without_reason_is_redirected_to_collect(log):
    log.record_dair_call("Triage", "", True, "Collect", "", "push", "")
    log.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
    r, _ = _dair(log, _raw("Analyze", "Triage", "push"))
    assert r["next_phase"] == "Collect" and r["server_override"]["kind"] == "triage_redirected"
    assert log._current_phase == "Collect"


def test_triage_push_with_a_typed_reason_is_kept(log):
    log.record_dair_call("Triage", "", True, "Collect", "", "push", "")
    log.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
    r, _ = _dair(log, _raw("Analyze", "Triage", "push", triage_reason="new_evidence_item"))
    assert r["next_phase"] == "Triage" and log._current_phase == "Triage"


# ── Report -> Collect ──────────────────────────────────────────────────────────

def test_server_transition_is_recorded_and_replayed(log, tmp_path):
    for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze"), ("Analyze", "Report")):
        log.record_dair_call(cur, "", True, nxt, "", "push", "")
    cid = log.record_phase_transition("Collect", "report_follow_up", trigger="ez_evtxecmd")
    assert cid and log._current_phase == "Collect"
    assert [f["phase"] for f in log._phase_stack][-2:] == ["Report", "Collect"]
    again = ExecutionLog()
    again.configure("PJ", str(tmp_path / "trace.json"), save_session=False)
    assert again._current_phase == "Collect"           # rehydration replays it
    log.record_dair_call("Collect", "", False, "Report", "", "pop", "")
    assert log._current_phase == "Report"


def test_forensic_tool_in_report_moves_to_collect_instead_of_refusing(log):
    from core.middleware import NarrationMiddleware
    from tests.core.test_middleware import _build_context
    for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze"), ("Analyze", "Report")):
        log.record_dair_call(cur, "", True, nxt, "", "push", "")
    call_next = AsyncMock(return_value={"success": True, "_trudi_call_id": 99})
    with patch("core.execution_log.log", log):
        out = asyncio.run(NarrationMiddleware().on_call_tool(
            _build_context("misc_regripper_hive"), call_next))
    assert call_next.await_count == 1 and log._current_phase == "Collect"
    assert any(e.get("type") == "phase_transition" and e["reason"] == "report_follow_up"
               for e in log._entries)
    assert "phase_transition" in json.dumps(out)


def test_not_ready_pre_report_returns_to_collect(log):
    from tools.reasoning import reason_pre_report_check
    for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze"), ("Analyze", "Report")):
        log.record_dair_call(cur, "", True, nxt, "", "push", "")
    with patch("core.execution_log.log", log):
        r = reason_pre_report_check()
    assert not r["ready_to_report"] and r["phase_returned_to"] == "Collect"
    assert log._current_phase == "Collect" and log._phase_stack[-2]["phase"] == "Report"


# ── background jobs ────────────────────────────────────────────────────────────

def test_long_tools_become_jobs_run_concurrently_and_keep_their_identity(log, monkeypatch):
    import core.jobs as J
    from core.middleware import NarrationMiddleware
    from core.execution_log import current_mcp_tool
    from tests.core.test_middleware import _build_context
    monkeypatch.setattr(J, "INLINE_WAIT", 0.2)
    monkeypatch.setattr(J, "_SLOTS", None)
    seen = []

    async def slow_tool(context):
        seen.append(current_mcp_tool.get())
        await asyncio.sleep(0.6)
        cid = log.record_tool_call(f"fake {context.message.name}", True, False, 0, 0,
                                   stdout_excerpt="rows")
        return {"success": True, "_trudi_call_id": cid}

    async def scenario():
        mw = NarrationMiddleware()
        t0 = asyncio.get_running_loop().time()
        results = await asyncio.gather(*[
            mw.on_call_tool(_build_context(name), slow_tool)
            for name in ("ez_evtxecmd", "vol_pslist", "ewf_verify")])
        # A handle reaches FastMCP as a ToolResult (a bare dict is rejected).
        handles = [r.structured_content for r in results]
        started = asyncio.get_running_loop().time() - t0
        assert started < 0.5                           # none waited out a full run
        assert all(h["status"] in ("running", "queued") and h["job_id"] for h in handles)
        await asyncio.sleep(0.9)
        done = [J.task_job_status(h["job_id"]) for h in handles]
        return asyncio.get_running_loop().time() - t0, handles, done

    with patch("core.execution_log.log", log):
        elapsed, handles, done = asyncio.run(scenario())
    assert elapsed < 1.6                               # three 0.6 s runs overlapped
    assert all(d["status"] == "finished" and d["success"] and d["_trudi_call_id"] for d in done)
    assert sorted(seen) == ["ewf_verify", "ez_evtxecmd", "vol_pslist"]
    stamped = {e["cmd"]: e.get("mcp_tool") for e in log._entries if e.get("type") == "tool_call"}
    assert stamped == {"fake ez_evtxecmd": "ez_evtxecmd", "fake vol_pslist": "vol_pslist",
                       "fake ewf_verify": "ewf_verify"}


def test_a_short_run_of_a_maybe_long_tool_stays_a_normal_call(log, monkeypatch):
    import core.jobs as J
    from core.middleware import NarrationMiddleware
    from tests.core.test_middleware import _build_context
    monkeypatch.setattr(J, "_SLOTS", None)
    with patch("core.execution_log.log", log):
        out = asyncio.run(NarrationMiddleware().on_call_tool(
            _build_context("ez_evtxecmd"), AsyncMock(return_value={"success": True,
                                                                  "_trudi_call_id": 7})))
    assert "job_id" not in out and out["_trudi_call_id"] == 7


def test_unfinished_job_blocks_the_report(log, monkeypatch):
    import core.jobs as J
    from tools._readiness import assess_readiness

    class Pending:
        def done(self):
            return False
    monkeypatch.setattr(J, "_TASK_JOBS", {})
    J.register_task("ewf_verify", Pending(), "image")
    assert any("background job" in b for b in assess_readiness(log)["blocking_issues"])


# ── tool output always kept ────────────────────────────────────────────────────

def test_short_output_is_kept_and_read_output_explains_non_tool_ids(log):
    import os
    from tools.read_output import _sidecar_hint
    cid = log.record_tool_call("stat x", True, False, 0, 0, stdout_excerpt="size 4")
    e = log.index().by_call_id[cid]
    assert e.get("stdout_path") and os.path.exists(e["stdout_path"])
    note = log.record_agent_message("thinking")
    with patch("core.execution_log.log", log):
        assert "not a tool call" in _sidecar_hint(note)
