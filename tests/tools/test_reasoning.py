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

    def test_conclusion_capped_at_1200_chars(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("A" * 2000)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert len(r["conclusion"]) <= 1200

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

    def test_returns_empty_on_no_marker(self):
        from tools.reasoning import _parse_directives
        assert _parse_directives("no directives here") == {}

    def test_returns_empty_on_bad_json(self):
        from tools.reasoning import _parse_directives
        assert _parse_directives("DIRECTIVES:\n{bad json!!!}") == {}

    def test_returns_empty_on_empty_input(self):
        from tools.reasoning import _parse_directives
        assert _parse_directives("") == {}

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
