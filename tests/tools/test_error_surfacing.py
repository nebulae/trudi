"""Tests for the global error-surfacing pipeline.

Every error class — pure-Python tool exception, trace write failure,
gate-logic bug, dashboard discovery exception — must now reach (a) the
trace as a `tool_call` or `system_error` entry AND (b) the agent as a
structured `ToolError`. These tests pin that contract in place.
"""
from __future__ import annotations

import asyncio
import json
import os
import stat
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── helpers (mirror tests/core/test_middleware.py) ──────────────────────────

def _build_context(tool_name: str, args: dict | None = None):
    msg = MagicMock()
    msg.name = tool_name
    msg.arguments = args or {}
    msg.model_copy = MagicMock(return_value=msg)
    ctx = MagicMock()
    ctx.message = msg
    ctx.copy = MagicMock(return_value=ctx)
    return ctx


def _run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _configured_log(tmp_path, case_id="ERR-CASE"):
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure(case_id, str(tmp_path / "trace.json"))
    return l


# ── 1. Tool body exception → tool_call entry + ToolError ────────────────────

class TestToolBodyExceptionCapture:
    def test_unhandled_exception_writes_tool_call_entry(self, tmp_path):
        from core.middleware import NarrationMiddleware
        from fastmcp.exceptions import ToolError

        l = _configured_log(tmp_path)
        # Engage DAIR so the gate doesn't block our test tool first.
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        mw = NarrationMiddleware()
        ctx = _build_context("dummy_tool")

        async def _boom(_ctx):
            raise ValueError("boom")

        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError, match="dummy_tool raised ValueError: boom"):
                _run_async(mw.on_call_tool(ctx, _boom))

        tool_calls = [e for e in l._entries if e.get("type") == "tool_call"]
        py_entry = next((e for e in tool_calls
                         if e.get("cmd") == "<py>:dummy_tool"), None)
        assert py_entry, f"no <py>:dummy_tool entry: {tool_calls}"
        assert py_entry["success"] is False
        assert py_entry["exit_code"] == -1
        assert "ValueError" in py_entry["stderr"]
        assert "boom" in py_entry["stderr"]
        # Traceback (not just str(e)) must be captured.
        assert "Traceback" in py_entry["stderr"]

    def test_exception_chain_preserved(self, tmp_path):
        from core.middleware import NarrationMiddleware
        from fastmcp.exceptions import ToolError

        l = _configured_log(tmp_path)
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        mw = NarrationMiddleware()
        ctx = _build_context("dummy_tool")

        original = ValueError("root cause")

        async def _boom(_ctx):
            raise original

        with patch("core.execution_log.log", l):
            try:
                _run_async(mw.on_call_tool(ctx, _boom))
                pytest.fail("expected ToolError")
            except ToolError as te:
                assert te.__cause__ is original

    def test_cancellation_writes_call_abandoned(self, tmp_path):
        """Client cancellation (asyncio.CancelledError) used to slip past the
        global capture because it derives from BaseException, not Exception.
        That made every client-side timeout on a long-running tool a silent
        failure. Now it lands as a call_abandoned entry, then re-raises so
        asyncio still unwinds correctly."""
        from core.middleware import NarrationMiddleware

        l = _configured_log(tmp_path)
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        mw = NarrationMiddleware()
        ctx = _build_context("slow_tool")

        async def _cancelled(_ctx):
            raise asyncio.CancelledError()

        with patch("core.execution_log.log", l):
            with pytest.raises(asyncio.CancelledError):
                _run_async(mw.on_call_tool(ctx, _cancelled))

        abandoned = [e for e in l._entries
                     if e.get("type") == "call_abandoned"
                     and e.get("tool") == "slow_tool"]
        assert abandoned, ("client cancellation must land as a "
                           f"call_abandoned entry; got {[e.get('type') for e in l._entries]}")
        assert "cancellation" in abandoned[0]["reason"].lower()

    def test_successful_pure_python_tool_gets_baseline_entry(self, tmp_path):
        """Pure-Python tools that don't self-log (correlate_mitre_validate,
        accuracy_compare, etc.) used to leave NO trace entry on success —
        the silent-failure mode reported on the mitre_validate batch.
        Middleware now writes a baseline tool_call entry whenever the
        global log didn't grow during call_next."""
        from core.middleware import NarrationMiddleware

        l = _configured_log(tmp_path)
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        before_len = len(l._entries)
        mw = NarrationMiddleware()
        ctx = _build_context("correlate_mitre_validate",
                             {"technique_id": "T1078"})

        async def _ok(_ctx):
            return {"success": True, "exists": True, "technique_id": "T1078"}

        with patch("core.execution_log.log", l):
            r = _run_async(mw.on_call_tool(ctx, _ok))

        assert r["exists"] is True
        new_entries = l._entries[before_len:]
        baselines = [e for e in new_entries
                     if e.get("type") == "tool_call"
                     and e.get("cmd") == "<py>:correlate_mitre_validate"]
        assert baselines, ("middleware must write a baseline tool_call entry "
                           f"for a successful pure-Python tool; got {new_entries}")
        assert baselines[0]["success"] is True

    def test_self_logging_tool_is_not_double_logged(self, tmp_path):
        """Tools that already write their own record_* entry (subprocess
        tools via _log_tool, reason_* via record_reason_call) must NOT
        get a duplicate baseline from the middleware."""
        from core.middleware import NarrationMiddleware

        l = _configured_log(tmp_path)
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        before_len = len(l._entries)
        mw = NarrationMiddleware()
        ctx = _build_context("reason_some_tool")

        async def _self_logging(_ctx):
            # Simulate a self-logging tool — write an entry inside the body
            # the way reason_*/_log_tool do.
            l.record_tool_call("internal subprocess cmd", True, False, 0, 0)
            return {"success": True, "data": "x"}

        with patch("core.execution_log.log", l):
            _run_async(mw.on_call_tool(ctx, _self_logging))

        new_entries = l._entries[before_len:]
        # Exactly one new tool_call entry — the one the body wrote. No
        # `<py>:reason_some_tool` baseline.
        py_baselines = [e for e in new_entries
                        if e.get("cmd", "").startswith("<py>:")]
        assert not py_baselines, (
            f"baseline duplicates self-logged entry: {py_baselines}")
        assert len([e for e in new_entries
                    if e.get("type") == "tool_call"]) == 1

    def test_tool_error_passes_through_unmodified(self, tmp_path):
        """ToolError already carries structured info; don't double-wrap or
        emit a duplicate tool_call entry for it."""
        from core.middleware import NarrationMiddleware
        from fastmcp.exceptions import ToolError

        l = _configured_log(tmp_path)
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        mw = NarrationMiddleware()
        ctx = _build_context("dummy_tool")

        async def _refuse(_ctx):
            raise ToolError("gate said no")

        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError, match="gate said no"):
                _run_async(mw.on_call_tool(ctx, _refuse))

        py_entries = [e for e in l._entries
                      if e.get("type") == "tool_call"
                      and e.get("cmd", "").startswith("<py>:")]
        assert not py_entries, ("ToolError must not produce a synthetic "
                                f"tool_call entry: {py_entries}")


# ── 2. Trace write failure bubbles up through the executor ──────────────────

class TestTraceWriteBubbleUp:
    def test_flush_oserror_bubbles_up(self, tmp_path):
        l = _configured_log(tmp_path)
        with patch("os.replace", side_effect=OSError("disk full")):
            with pytest.raises(OSError, match="disk full"):
                l.record_tool_call("vol psscan", True, False, 0, 0)

    def test_log_tool_re_raises_on_trace_failure(self, tmp_path):
        """core/executor.py:_log_tool used to swallow trace-write failures and
        return _trudi_call_id=0. Now it re-raises so the middleware can wrap
        the failure as a ToolError the agent must see."""
        from core import executor

        l = _configured_log(tmp_path)
        result = {
            "success": True, "stdout": "", "stderr": "", "exit_code": 0,
            "elapsed_seconds": 0.0, "truncated": False, "cmd": "ls",
            "retries": 0, "progress_lines": [],
        }
        with patch("core.execution_log.log", l), \
             patch("os.replace", side_effect=OSError("perms")):
            with pytest.raises(OSError, match="perms"):
                executor._log_tool(result)


# ── 3. record_* before configure must raise ─────────────────────────────────

class TestRequireConfigured:
    @pytest.mark.parametrize("method,args", [
        ("record_tool_call", ("ls", True, False, 0, 0)),
        ("record_agent_message", ("hi",)),
        ("record_finding", ("desc", "LIKELY")),
        ("record_self_correction", ("trig", "old", "new")),
        ("record_call_initiated", ("tool", "backend", {})),
        ("record_call_abandoned", ("tool", "reason")),
    ])
    def test_unconfigured_log_raises(self, method, args, monkeypatch, tmp_path):
        # The conftest autouse fixture configures the singleton AND writes a
        # session file; a fresh ExecutionLog().record_*() would auto-recover
        # from that session and appear configured. Point at a nonexistent
        # session AND a cwd with no CLAUDE.md to keep this instance truly
        # uninitialised.
        import core.execution_log as elog
        monkeypatch.setattr(elog, "_SESSION_FILE", str(tmp_path / "nope.json"))
        monkeypatch.chdir(tmp_path)
        l = elog.ExecutionLog()
        with pytest.raises(RuntimeError, match="trace log not configured"):
            getattr(l, method)(*args)


# ── 4. start_execution_log self-test ────────────────────────────────────────

class TestStartExecutionLogSelfTest:
    def test_rejects_unwritable_directory(self, tmp_path):
        from tools.misc import start_execution_log

        ro_dir = tmp_path / "readonly"
        ro_dir.mkdir()
        bad_path = str(ro_dir / "trace.json")
        # Make the directory unwritable so flush fails immediately.
        original_mode = ro_dir.stat().st_mode
        os.chmod(ro_dir, stat.S_IRUSR | stat.S_IXUSR)
        try:
            with patch("core.execution_log._SESSION_FILE",
                       str(tmp_path / "sess.json")):
                r = start_execution_log("RO-CASE", bad_path,
                                        launch_dashboard=False)
        finally:
            os.chmod(ro_dir, original_mode)
        assert r["success"] is False
        assert "trace setup failed" in r["error"]

    def test_writes_trace_initialized_sentinel(self, tmp_path):
        from tools.misc import start_execution_log
        from core.execution_log import log as global_log

        log_path = str(tmp_path / "trace.json")
        with patch("core.execution_log._SESSION_FILE",
                   str(tmp_path / "sess.json")):
            r = start_execution_log("OK-CASE", log_path, launch_dashboard=False)
        assert r["success"] is True
        sentinels = [e for e in global_log._entries
                     if e.get("type") == "system_error"
                     and e.get("category") == "trace_initialized"]
        assert sentinels, "trace_initialized sentinel missing"


# ── 5. record_system_error is best-effort ───────────────────────────────────

class TestRecordSystemErrorBestEffort:
    def test_returns_zero_on_inner_failure(self, tmp_path):
        l = _configured_log(tmp_path)
        # Force the next _append_entry to blow up; record_system_error must
        # swallow it and return 0 (never raise from a failure-handling path).
        with patch.object(l, "_append_entry",
                          side_effect=RuntimeError("nope")):
            cid = l.record_system_error("test_category", "test detail")
        assert cid == 0  # documented best-effort return

    def test_pre_configure_returns_zero(self):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        # Unlike the other record_* methods, system_error is best-effort even
        # before configure() — it's used by error handlers that may run
        # during boot. Returns 0 without raising.
        cid = l.record_system_error("early", "before configure")
        assert cid == 0


# ── 6. DAIR gate bug → fail-open + visible ──────────────────────────────────

class _GateBreakingLog:
    """Test stand-in: raises RuntimeError on `_entries` access (to trigger
    the gate's exception path) but delegates everything else — including
    record_system_error — to the wrapped real log."""

    def __init__(self, real):
        self._real = real

    @property
    def _entries(self):
        raise RuntimeError("entries unreadable")

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_real"), name)


class TestGateFailOpenVisible:
    def test_gate_exception_fails_open_and_writes_system_error(self, tmp_path):
        from core import execution_log, middleware as mw_mod

        l = _configured_log(tmp_path)
        broken = _GateBreakingLog(l)
        saved = execution_log.log
        try:
            execution_log.log = broken
            should_block, reason = mw_mod._gate_decision()
        finally:
            execution_log.log = saved
        assert should_block is False, "gate must fail open on internal error"
        assert "fail-open" in reason
        gate_errors = [e for e in l._entries
                       if e.get("type") == "system_error"
                       and e.get("category") == "dair_gate"]
        assert gate_errors, (
            f"dair_gate system_error missing; entry types: "
            f"{[e.get('type') for e in l._entries]}"
        )
        assert "RuntimeError" in gate_errors[0]["detail"]


# ── 7a. configure(save_session=False) does NOT clobber the session beacon ───

class TestConfigureDoesNotPolluteSession:
    """Regression for the silent-failure incident: ad-hoc smoke scripts
    calling configure() on a tmp path used to overwrite the global
    session.json beacon, silently rerouting the active investigation's
    writes when the MCP server next restarted. configure(save_session=False)
    must leave the beacon alone."""

    def test_no_session_write_when_save_session_false(self, tmp_path,
                                                      monkeypatch):
        import core.execution_log as elog
        beacon = tmp_path / "session.json"
        beacon.write_text('{"case_id": "REAL-CASE", "path": "/cases/real/trace.json"}')
        monkeypatch.setattr(elog, "_SESSION_FILE", str(beacon))
        l = elog.ExecutionLog()
        l.configure("SMOKE", str(tmp_path / "smoke_trace.json"),
                    save_session=False)
        # Beacon must be unchanged.
        assert beacon.read_text() == (
            '{"case_id": "REAL-CASE", "path": "/cases/real/trace.json"}'
        )

    def test_default_save_session_true_writes_beacon(self, tmp_path,
                                                    monkeypatch):
        import core.execution_log as elog
        beacon = tmp_path / "session.json"
        monkeypatch.setattr(elog, "_SESSION_FILE", str(beacon))
        l = elog.ExecutionLog()
        l.configure("REAL-CASE", str(tmp_path / "real_trace.json"))
        assert beacon.exists()
        import json
        assert json.loads(beacon.read_text())["case_id"] == "REAL-CASE"

    def test_cross_case_overwrite_emits_warn(self, tmp_path, monkeypatch,
                                             capsys):
        import core.execution_log as elog
        # Prior session: a real-looking case dir
        case_dir = tmp_path / "prior-case"
        case_dir.mkdir()
        prior_trace = case_dir / "trace.json"
        beacon = tmp_path / "session.json"
        beacon.write_text(
            f'{{"case_id": "PRIOR", "path": "{prior_trace}"}}'
        )
        monkeypatch.setattr(elog, "_SESSION_FILE", str(beacon))
        l = elog.ExecutionLog()
        l.configure("HIJACKER", str(tmp_path / "hijack.json"))
        err = capsys.readouterr().err
        assert "session.json overwrite" in err
        assert "PRIOR" in err
        assert "HIJACKER" in err


# ── 7. Dashboard discovery exception → system_error, non-fatal ──────────────

class TestDashboardDiscoveryFailureLogged:
    def test_unexpected_exception_records_system_error(self, tmp_path):
        from tools import misc
        from tools.misc import start_execution_log
        from core.execution_log import log as global_log

        log_path = str(tmp_path / "trace.json")

        def _boom(*a, **k):
            raise RuntimeError("dashboard boom")

        with patch("core.execution_log._SESSION_FILE",
                   str(tmp_path / "sess.json")), \
             patch.object(misc, "launch_dashboard", _boom):
            r = start_execution_log("DB-FAIL", log_path)

        # start_execution_log itself still succeeds (dashboard is optional).
        assert r["success"] is True
        assert "RuntimeError" in r["dashboard_error"]
        # But the failure is now visible in the trace.
        sysrs = [e for e in global_log._entries
                 if e.get("type") == "system_error"
                 and e.get("category") == "dashboard"]
        assert sysrs, "dashboard system_error missing"
        assert "RuntimeError" in sysrs[0]["detail"]
