"""Tests for core/middleware.py — narration capture and DAIR gate enforcement."""
import asyncio
import datetime
import re
import pytest
from unittest.mock import patch, MagicMock, AsyncMock


def _build_context(tool_name: str, args: dict | None = None):
    """Construct a fake MiddlewareContext that mirrors what fastmcp passes."""
    msg = MagicMock()
    msg.name = tool_name
    msg.arguments = args or {}
    # The middleware does context.copy(message=...) and msg.model_copy(...);
    # make those produce a fresh MagicMock so chains don't blow up.
    msg.model_copy = MagicMock(return_value=msg)
    ctx = MagicMock()
    ctx.message = msg
    ctx.copy = MagicMock(return_value=ctx)
    return ctx


async def _run_middleware(mw, tool_name: str, args: dict | None = None,
                          call_next_return="OK"):
    ctx = _build_context(tool_name, args)
    call_next = AsyncMock(return_value=call_next_return)
    result = await mw.on_call_tool(ctx, call_next)
    return result, call_next


class TestDairGateMiddleware:
    """dair_required: tools outside the allowlist refused when no recent dair_call."""

    def test_allowlisted_tool_runs_without_dair(self, tmp_path):
        from core.execution_log import ExecutionLog
        from core.middleware import NarrationMiddleware
        l = ExecutionLog()
        l.configure("MW-001", str(tmp_path / "trace.json"))
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            result, call_next = asyncio.get_event_loop().run_until_complete(
                _run_middleware(mw, "dair_assess")
            )
        # call_next was invoked → tool ran
        assert call_next.await_count == 1
        assert result == "OK"

    def test_cold_start_allows_non_allowlisted_tools(self, tmp_path):
        """Before any dair_call exists, non-allowlisted tools run freely so the
        agent can do the mandatory pre-plan reads."""
        from core.execution_log import ExecutionLog
        from core.middleware import NarrationMiddleware
        l = ExecutionLog()
        l.configure("MW-002", str(tmp_path / "trace.json"))
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            result, call_next = asyncio.get_event_loop().run_until_complete(
                _run_middleware(mw, "vol_vol_psscan")
            )
        assert call_next.await_count == 1

    def test_non_allowlisted_tool_blocked_after_dair_drops_out(self, tmp_path):
        """Once DAIR has been engaged, falling out of the window blocks tools."""
        from core.execution_log import ExecutionLog
        from core.middleware import NarrationMiddleware
        from fastmcp.exceptions import ToolError
        l = ExecutionLog()
        l.configure("MW-002b", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        # Push the dair_call out of the 20-entry window
        for _ in range(21):
            l.record_agent_message("filler")
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            with pytest.raises(ToolError, match="DAIR engaged earlier"):
                asyncio.get_event_loop().run_until_complete(
                    _run_middleware(mw, "vol_vol_psscan")
                )

    def test_non_allowlisted_tool_runs_after_dair(self, tmp_path):
        from core.execution_log import ExecutionLog
        from core.middleware import NarrationMiddleware
        l = ExecutionLog()
        l.configure("MW-003", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        mw = NarrationMiddleware()
        with patch("core.execution_log.log", l):
            result, call_next = asyncio.get_event_loop().run_until_complete(
                _run_middleware(mw, "vol_vol_psscan")
            )
        assert call_next.await_count == 1

    def test_pre_plan_tools_allowlisted(self):
        """The 4 pre-plan reads (per CLAUDE.md) must be on the allowlist so
        they can run before the first dair_assess at the start of a case."""
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "ez_ez_recmd_hive" in DAIR_GATE_ALLOWLIST
        assert "strings_stat_file" in DAIR_GATE_ALLOWLIST

    def test_dair_assess_allowlisted(self):
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "dair_assess" in DAIR_GATE_ALLOWLIST
        assert "dair_dair_assess" in DAIR_GATE_ALLOWLIST

    def test_start_execution_log_allowlisted(self):
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "misc_start_execution_log" in DAIR_GATE_ALLOWLIST

    def test_hash_verify_allowlisted(self):
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "hash_verify_evidence_hash" in DAIR_GATE_ALLOWLIST

    def test_reason_plan_allowlisted(self):
        from core.middleware import DAIR_GATE_ALLOWLIST
        assert "reason_plan" in DAIR_GATE_ALLOWLIST


class TestUtcTimestamps:
    """Execution log timestamps are always UTC (ISO 8601 with +00:00 suffix)."""

    def test_utcnow_helper_returns_utc(self):
        from core.execution_log import _utcnow
        ts = _utcnow()
        # ISO 8601 ending with +00:00 (timezone-aware UTC).
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$", ts)

    def test_tool_call_entry_has_utc_timestamp(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("UTC-001", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        ts = l._entries[-1]["ts"]
        assert ts.endswith("+00:00")
        # Round-trip parses as a UTC datetime
        parsed = datetime.datetime.fromisoformat(ts)
        assert parsed.utcoffset() == datetime.timedelta(0)

    def test_no_naive_datetime_usage_in_core(self):
        """Lint-style: core/ modules must not call datetime.now() without tz."""
        import pathlib
        offenders = []
        core_dir = pathlib.Path(__file__).parent.parent.parent / "core"
        for py in core_dir.glob("*.py"):
            text = py.read_text()
            # Allow datetime.now(timezone...) but flag bare datetime.now() or
            # datetime.datetime.now() with no argument.
            if re.search(r"datetime\.now\(\s*\)", text):
                offenders.append(str(py))
            if re.search(r"datetime\.datetime\.now\(\s*\)", text):
                offenders.append(str(py))
        assert offenders == [], f"naive datetime.now() in: {offenders}"


class TestForensicBinaryPatterns:
    """Constants used by record_finding's mcp_routing gate."""

    def test_constants_exported(self):
        from core.middleware import FORENSIC_BINARY_PATTERNS, MCP_WRAPPER_HINTS
        assert isinstance(FORENSIC_BINARY_PATTERNS, tuple)
        assert len(FORENSIC_BINARY_PATTERNS) > 5
        assert isinstance(MCP_WRAPPER_HINTS, dict)
        for key, hint in MCP_WRAPPER_HINTS.items():
            assert isinstance(hint, str) and hint, key

    def test_identify_forensic_binary_vol(self):
        from core.middleware import _identify_forensic_binary
        assert _identify_forensic_binary(
            "/usr/local/bin/vol -f mem.img windows.psscan"
        ) == "vol"

    def test_identify_forensic_binary_eztool(self):
        from core.middleware import _identify_forensic_binary
        out = _identify_forensic_binary(
            "dotnet /opt/zimmermantools/EvtxECmd/EvtxECmd.dll -f sec.evtx"
        )
        assert out == "EvtxECmd"

    def test_identify_forensic_binary_tcpdump(self):
        from core.middleware import _identify_forensic_binary
        assert _identify_forensic_binary("tcpdump -nn -r capture.pcap") == "tcpdump"

    def test_identify_forensic_binary_returns_none_for_safe_cmd(self):
        from core.middleware import _identify_forensic_binary
        assert _identify_forensic_binary("ls /cases/example-case/analysis") is None
        assert _identify_forensic_binary("jq '.entries[0]' trace.json") is None

    def test_identify_forensic_binary_word_boundary(self):
        # Regression: word boundaries prevent matching inside unrelated tokens.
        from core.middleware import _identify_forensic_binary
        assert _identify_forensic_binary("evolve --options") is None
        assert _identify_forensic_binary("./icatcher --help") is None
        assert _identify_forensic_binary("./tsk_recover -h") == "tsk_recover"
