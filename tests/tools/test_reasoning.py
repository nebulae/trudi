"""Tests for tools/reasoning.py — covers both claude and openai-compat backends."""
import pytest
from contextlib import contextmanager
from unittest.mock import patch, MagicMock


_DIRECTIVES_JSON = (
    'DIRECTIVES:\n'
    '{"priority_tools": ["vol.psscan", "vol.cmdline"], '
    '"skip_tools": [], "focus_pids": [5024], '
    '"focus_paths": ["C:\\\\ProgramData\\\\staging\\\\"], '
    '"max_depth": "targeted", "next_hypothesis_triggers": []}'
)


# ── Mock factories ────────────────────────────────────────────────────────────

def _claude_mock(text: str):
    """Return a mock anthropic.Anthropic client whose create() returns text."""
    resp = MagicMock()
    resp.content = [MagicMock(text=text)]
    client = MagicMock()
    client.messages.create.return_value = resp
    anthro = MagicMock(return_value=client)
    return anthro, client


def _http_resp(content: str):
    """Return a mock httpx response with an OpenAI-compatible chat completion."""
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json.return_value = {
        "choices": [{"message": {"content": content, "reasoning": ""}}]
    }
    return m


# ── Backend context managers ──────────────────────────────────────────────────

@contextmanager
def _claude_ctx(text: str):
    """Context manager that routes calls through the claude backend."""
    anthro, client = _claude_mock(text)
    with patch("anthropic.Anthropic", anthro), \
         patch("tools.reasoning.ANTHROPIC_API_KEY", "sk-test"), \
         patch("tools.reasoning.REASON_BACKEND", "claude"):
        yield client


@contextmanager
def _compat_ctx(text: str):
    """Context manager that routes calls through the openai-compat backend."""
    http_mock = MagicMock(return_value=_http_resp(text))
    with patch("httpx.post", http_mock), \
         patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
         patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
        yield http_mock


# ── Shared behavioural tests (both backends) ──────────────────────────────────

class TestReasonPlan:
    def _run(self, ctx_fn, text="Investigation plan.\n" + _DIRECTIVES_JSON):
        from tools.reasoning import reason_plan
        with ctx_fn(text):
            return reason_plan("Suspected keylogger on wkstn-01", "memory.img, c-drive.E01")

    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_returns_success(self, ctx_fn):
        assert self._run(ctx_fn)["success"] is True

    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_directives_parsed(self, ctx_fn):
        r = self._run(ctx_fn)
        assert r["directives"].get("priority_tools") == ["vol.psscan", "vol.cmdline"]

    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_conclusion_strips_directives(self, ctx_fn):
        r = self._run(ctx_fn)
        assert "DIRECTIVES" not in r["conclusion"]
        assert "Investigation plan." in r["conclusion"]

    def test_evidence_capped_at_300_lines_claude(self):
        from tools.reasoning import reason_plan
        big = "\n".join(f"line{i}" for i in range(400))
        anthro, client = _claude_mock("ok")
        with patch("anthropic.Anthropic", anthro), \
             patch("tools.reasoning.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.reasoning.REASON_BACKEND", "claude"):
            reason_plan("case", big)
        user_msg = client.messages.create.call_args[1]["messages"][0]["content"]
        assert "line399" not in user_msg
        assert "omitted for brevity" in user_msg

    def test_evidence_capped_at_300_lines_compat(self):
        from tools.reasoning import reason_plan
        big = "\n".join(f"line{i}" for i in range(400))
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_plan("case", big)
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "line399" not in user_msg
        assert "omitted for brevity" in user_msg

    def test_short_evidence_not_trimmed(self):
        from tools.reasoning import reason_plan
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_plan("case", "line1\nline2\nline3")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "line1" in user_msg
        assert "omitted for brevity" not in user_msg

    def test_server_error_has_directives_key_compat(self):
        from tools.reasoning import reason_plan
        with patch("httpx.post", side_effect=Exception("refused")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_plan("case", "evidence")
        assert "directives" in r

    def test_server_error_has_directives_key_claude(self):
        from tools.reasoning import reason_plan
        anthro, client = _claude_mock("")
        client.messages.create.side_effect = Exception("refused")
        with patch("anthropic.Anthropic", anthro), \
             patch("tools.reasoning.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.reasoning.REASON_BACKEND", "claude"):
            r = reason_plan("case", "evidence")
        assert "directives" in r


class TestReasonHypothesize:
    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_returns_success(self, ctx_fn):
        from tools.reasoning import reason_hypothesize
        with ctx_fn("Hypothesis A.\n" + _DIRECTIVES_JSON):
            r = reason_hypothesize("cmd.exe from orphaned PPID 2748 in Session 0")
        assert r["success"] is True

    def test_conclusion_strips_directives(self):
        from tools.reasoning import reason_hypothesize
        content = "Hypothesis: malicious.\nDIRECTIVES:\n{\"priority_tools\": [\"vol.psscan\"]}"
        with patch("httpx.post", return_value=_http_resp(content)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("cmd.exe from orphaned PPID")
        assert "DIRECTIVES" not in r["conclusion"]
        assert "Hypothesis: malicious." in r["conclusion"]

    def test_conclusion_returned_in_full(self):
        from tools.reasoning import reason_hypothesize
        long_text = "A" * 2000
        with patch("httpx.post", return_value=_http_resp(long_text)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert len(r["conclusion"]) == 2000

    def test_context_included_in_request(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_hypothesize("observation", context="Windows 10, CRIMSON OSPREY")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "CRIMSON OSPREY" in user_msg

    def test_server_unreachable_returns_error(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", side_effect=Exception("connection refused")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert r["success"] is False
        assert "connection refused" in r["error"]

    def test_server_unreachable_has_directives_key(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", side_effect=Exception("refused")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert "directives" in r


class TestReasonEvaluateFinding:
    def test_supported_verdict(self):
        from tools.reasoning import reason_evaluate_finding
        with patch("httpx.post", return_value=_http_resp("VERDICT: SUPPORTED.\n" + _DIRECTIVES_JSON)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_evaluate_finding("Keylogger installed", "Amcache entry, 48/77 VT detections")
        assert r["success"] is True
        assert "SUPPORTED" in r["conclusion"]

    def test_challenged_verdict(self):
        from tools.reasoning import reason_evaluate_finding
        with patch("httpx.post", return_value=_http_resp("VERDICT: CHALLENGED.")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_evaluate_finding("gpupdate.exe run by attacker", "Process in memory")
        assert "CHALLENGED" in r["conclusion"]

    def test_case_context_included(self):
        from tools.reasoning import reason_evaluate_finding
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_evaluate_finding("finding", "evidence", case_context="FOR508 dataset")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "FOR508" in user_msg

    def test_directives_present(self):
        from tools.reasoning import reason_evaluate_finding
        with patch("httpx.post", return_value=_http_resp(_DIRECTIVES_JSON)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_evaluate_finding("finding", "evidence")
        assert "directives" in r


class TestReasonSynthesize:
    def test_returns_success(self):
        from tools.reasoning import reason_synthesize
        with patch("httpx.post", return_value=_http_resp("Gap: initial access unknown.")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_synthesize("1. Keylogger\n2. BITS exfil")
        assert r["success"] is True

    def test_investigation_summary_included(self):
        from tools.reasoning import reason_synthesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_synthesize("finding 1\nfinding 2", investigation_summary="ran psscan, netscan")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "psscan" in user_msg

    def test_openai_compat_posts_to_completions_endpoint(self):
        from tools.reasoning import reason_synthesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_synthesize("findings")
        call_url = m.call_args[0][0]
        assert "v1/chat/completions" in call_url

    def test_directives_present(self):
        from tools.reasoning import reason_synthesize
        with patch("httpx.post", return_value=_http_resp(_DIRECTIVES_JSON)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_synthesize("findings")
        assert "directives" in r


class TestBackendConfig:
    def test_missing_anthropic_key_returns_error(self):
        from tools.reasoning import reason_hypothesize
        with patch("tools.reasoning.ANTHROPIC_API_KEY", ""), \
             patch("tools.reasoning.REASON_BACKEND", "claude"):
            r = reason_hypothesize("observation")
        assert r["success"] is False
        assert "ANTHROPIC_API_KEY" in r["error"]

    def test_missing_anthropic_key_has_directives_key(self):
        from tools.reasoning import reason_hypothesize
        with patch("tools.reasoning.ANTHROPIC_API_KEY", ""), \
             patch("tools.reasoning.REASON_BACKEND", "claude"):
            r = reason_hypothesize("observation")
        assert "directives" in r

    def test_missing_reason_url_returns_error(self):
        from tools.reasoning import reason_hypothesize
        with patch("tools.reasoning.REASON_URL", ""), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert r["success"] is False
        assert "REASON_URL" in r["error"]

    def test_auto_detect_claude_when_api_key_set(self):
        from tools.reasoning import _active_backend
        with patch("tools.reasoning.REASON_BACKEND", ""), \
             patch("tools.reasoning.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.reasoning.REASON_URL", ""):
            assert _active_backend() == "claude"

    def test_auto_detect_compat_when_url_set_no_key(self):
        from tools.reasoning import _active_backend
        with patch("tools.reasoning.REASON_BACKEND", ""), \
             patch("tools.reasoning.ANTHROPIC_API_KEY", ""), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"):
            assert _active_backend() == "openai-compat"

    def test_explicit_backend_overrides_autodetect(self):
        from tools.reasoning import _active_backend
        with patch("tools.reasoning.REASON_BACKEND", "openai-compat"), \
             patch("tools.reasoning.ANTHROPIC_API_KEY", "sk-test"):
            assert _active_backend() == "openai-compat"

    def test_claude_backend_uses_anthropic_sdk(self):
        from tools.reasoning import reason_hypothesize
        anthro, client = _claude_mock("Hypothesis A.")
        with patch("anthropic.Anthropic", anthro), \
             patch("tools.reasoning.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.reasoning.REASON_BACKEND", "claude"):
            r = reason_hypothesize("cmd.exe from orphaned PPID")
        assert r["success"] is True
        client.messages.create.assert_called_once()

    def test_claude_backend_sends_system_with_cache_control(self):
        from tools.reasoning import reason_hypothesize
        anthro, client = _claude_mock("ok")
        with patch("anthropic.Anthropic", anthro), \
             patch("tools.reasoning.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.reasoning.REASON_BACKEND", "claude"):
            reason_hypothesize("observation")
        kwargs = client.messages.create.call_args[1]
        system = kwargs["system"]
        assert isinstance(system, list)
        assert system[0]["cache_control"]["type"] == "ephemeral"


class TestParseDirectives:
    def test_parses_valid_json_block(self):
        from tools.reasoning import _parse_directives
        text = 'analysis\nDIRECTIVES:\n{"priority_tools": ["vol.psscan"], "skip_tools": []}'
        d = _parse_directives(text)
        assert d["priority_tools"] == ["vol.psscan"]

    def test_returns_keyed_defaults_on_no_marker(self):
        from tools.reasoning import _parse_directives
        result = _parse_directives("no directives here")
        assert "priority_tools" in result
        assert "skip_tools" in result
        assert result["priority_tools"] == []

    def test_returns_keyed_defaults_on_bad_json(self):
        from tools.reasoning import _parse_directives
        result = _parse_directives("DIRECTIVES:\n{bad json!!!}")
        assert "priority_tools" in result
        assert result["priority_tools"] == []

    def test_returns_keyed_defaults_on_empty_input(self):
        from tools.reasoning import _parse_directives
        result = _parse_directives("")
        assert "priority_tools" in result
        assert result["priority_tools"] == []

    def test_partial_directives_merged_with_defaults(self):
        from tools.reasoning import _parse_directives
        result = _parse_directives('DIRECTIVES:\n{"priority_tools": ["vol.psscan"]}')
        assert result["priority_tools"] == ["vol.psscan"]
        assert "skip_tools" in result
        assert "focus_pids" in result

    def test_case_insensitive_marker(self):
        from tools.reasoning import _parse_directives
        text = 'directives:\n{"focus_pids": [1234]}'
        d = _parse_directives(text)
        assert d["focus_pids"] == [1234]

    def test_accepts_bare_json_without_fences(self):
        from tools.reasoning import _parse_directives
        text = 'DIRECTIVES:\n{"priority_tools": ["ez.amcache"], "skip_tools": ["plaso.*"]}'
        d = _parse_directives(text)
        assert "plaso.*" in d["skip_tools"]

    def test_handles_markdown_bold_marker(self):
        from tools.reasoning import _parse_directives
        text = '**DIRECTIVES:**\n{"priority_tools": ["vol.netscan"], "skip_tools": []}'
        d = _parse_directives(text)
        assert d["priority_tools"] == ["vol.netscan"]

    def test_handles_json_code_fence(self):
        from tools.reasoning import _parse_directives
        text = 'DIRECTIVES:\n```json\n{"priority_tools": ["vol.malfind"], "focus_pids": [5024]}\n```'
        d = _parse_directives(text)
        assert d["priority_tools"] == ["vol.malfind"]
        assert d["focus_pids"] == [5024]

    def test_strips_line_comments(self):
        from tools.reasoning import _parse_directives
        text = 'DIRECTIVES:\n{"priority_tools": ["vol.psscan"], "focus_pids": [1234] // check pid\n}'
        d = _parse_directives(text)
        assert d["priority_tools"] == ["vol.psscan"]

    def test_bold_marker_with_code_fence(self):
        from tools.reasoning import _parse_directives
        text = (
            '**DIRECTIVES:**\n```json\n'
            '{"priority_tools": ["vol.cmdline"], "skip_tools": [], '
            '"focus_pids": [5024], "focus_paths": ["C:\\\\staging\\\\"], '
            '"max_depth": "targeted", "next_hypothesis_triggers": []}\n```'
        )
        d = _parse_directives(text)
        assert d["priority_tools"] == ["vol.cmdline"]
        assert d["max_depth"] == "targeted"


class TestReasonHypothesizeEvidence:
    """Tests for the new `evidence` parameter on reason_hypothesize."""

    def test_evidence_included_in_prompt(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_hypothesize(
                "rsydow-a beacon from DC to file server every 2 minutes",
                evidence="1. EID 4624 × 66 at 120-second intervals\n2. PerfSvc.exe MD5 62/77 VT",
            )
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "SUPPORTING EVIDENCE" in user_msg
        assert "EID 4624" in user_msg

    def test_observation_always_first(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_hypothesize("orphaned PPID", evidence="psscan output", context="CRIMSON OSPREY")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        obs_pos = user_msg.index("OBSERVATION")
        ev_pos = user_msg.index("SUPPORTING EVIDENCE")
        ctx_pos = user_msg.index("CASE CONTEXT")
        assert obs_pos < ev_pos < ctx_pos

    def test_backward_compat_no_evidence(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_hypothesize("observation", context="Windows 10")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "OBSERVATION" in user_msg
        assert "CASE CONTEXT" in user_msg
        assert "SUPPORTING EVIDENCE" not in user_msg

    def test_no_evidence_no_section(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_hypothesize("observation only")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "SUPPORTING EVIDENCE" not in user_msg
        assert "CASE CONTEXT" not in user_msg


class TestTokenExtraction:
    """Tests for token usage extraction in both backends."""

    def test_claude_backend_returns_tokens(self):
        from tools.reasoning import reason_hypothesize
        resp = MagicMock()
        resp.content = [MagicMock(text="ok")]
        resp.usage = MagicMock(input_tokens=512, output_tokens=128)
        client = MagicMock()
        client.messages.create.return_value = resp
        anthro = MagicMock(return_value=client)
        with patch("anthropic.Anthropic", anthro), \
             patch("tools.reasoning.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.reasoning.REASON_BACKEND", "claude"):
            r = reason_hypothesize("observation")
        assert r["input_tokens"] == 512
        assert r["output_tokens"] == 128

    def test_compat_backend_returns_tokens(self):
        from tools.reasoning import reason_hypothesize
        m = MagicMock()
        m.raise_for_status = MagicMock()
        m.json.return_value = {
            "choices": [{"message": {"content": "ok", "reasoning": ""}}],
            "usage": {"prompt_tokens": 400, "completion_tokens": 75},
        }
        with patch("httpx.post", return_value=m), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert r["input_tokens"] == 400
        assert r["output_tokens"] == 75

    def test_compat_backend_missing_usage_defaults_zero(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert r["input_tokens"] == 0
        assert r["output_tokens"] == 0

    def test_claude_error_result_has_token_keys(self):
        from tools.reasoning import reason_hypothesize
        with patch("tools.reasoning.ANTHROPIC_API_KEY", ""), \
             patch("tools.reasoning.REASON_BACKEND", "claude"):
            r = reason_hypothesize("observation")
        assert "input_tokens" in r
        assert "output_tokens" in r


class TestReasonPreReportCheck:
    """Tests for reason_pre_report_check."""

    @pytest.fixture
    def configured_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-PRE", str(tmp_path / "trace.json"))
        return l

    def test_empty_trace_not_ready(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("empty" in issue.lower() for issue in r["blocking_issues"])

    def test_missing_plan_is_blocking(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("reason.plan" in issue for issue in r["blocking_issues"])

    def test_missing_synthesize_is_blocking(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("reason.synthesize" in issue for issue in r["blocking_issues"])

    def test_confirmed_findings_without_evaluate_is_warning(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_finding("PerfSvc.exe", "CONFIRMED", "ez.mftecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True  # warning only, not blocking
        assert len(r["warnings"]) > 0

    def test_all_checks_pass(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding("PerfSvc.exe", "CONFIRMED", "ez.mftecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert r["blocking_issues"] == []

    def test_token_totals_reported(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_reason_call("reason_plan", True, "plan", {}, input_tokens=300, output_tokens=100)
        configured_log.record_reason_call("reason_synthesize", True, "ok", {}, input_tokens=500, output_tokens=200)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["total_input_tokens"] == 800
        assert r["total_output_tokens"] == 300
