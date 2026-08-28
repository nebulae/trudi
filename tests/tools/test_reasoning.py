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
            reason_hypothesize("observation", context="Windows 10, REDFOX")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "REDFOX" in user_msg

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

    def test_challenged_auto_emits_self_correction(self, tmp_path):
        """When the model returns VERDICT: CHALLENGED, a self_correction trace
        entry must be auto-emitted with trigger='evaluate_challenged' and a
        linked_call_id pointing at the eval call itself. This ensures every
        CHALLENGED moment lands in the chain view even when the agent abandons
        the claim instead of attempting record_finding."""
        from core.execution_log import ExecutionLog
        import core.execution_log as elog_mod
        from tools.reasoning import reason_evaluate_finding

        # Bind a fresh log so we can inspect emitted entries deterministically
        inst = ExecutionLog()
        inst.configure("CHALLENGE-AUTO", str(tmp_path / "trace.json"))
        with patch.object(elog_mod, "log", inst), \
             patch("httpx.post", return_value=_http_resp("VERDICT: CHALLENGED. Process record stub.")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            result = reason_evaluate_finding(
                "Suspicious binary X is the C2 implant",
                "vol.psscan PID=5024",
            )
        sc_entries = [e for e in inst._entries if e.get("type") == "self_correction"]
        assert len(sc_entries) == 1, f"expected exactly 1 self_correction, got {len(sc_entries)}"
        sc = sc_entries[0]
        assert sc["trigger"] == "evaluate_challenged"
        # linked_call_id should point at the reason_call eval entry (not the
        # call_initiated stub that precedes it)
        eval_entries = [
            e for e in inst._entries
            if e.get("type") == "reason_call" and e.get("tool") == "reason_evaluate_finding"
        ]
        assert len(eval_entries) == 1
        assert sc["linked_call_id"] == eval_entries[0]["call_id"]
        # prior_belief should carry the finding text
        assert "Suspicious binary X" in sc["prior_belief"]

    def test_supported_does_not_emit_self_correction(self, tmp_path):
        """SUPPORTED verdict should leave the trace clean — no self_correction."""
        from core.execution_log import ExecutionLog
        import core.execution_log as elog_mod
        from tools.reasoning import reason_evaluate_finding

        inst = ExecutionLog()
        inst.configure("SUPPORTED-NOEMIT", str(tmp_path / "trace.json"))
        with patch.object(elog_mod, "log", inst), \
             patch("httpx.post", return_value=_http_resp("VERDICT: SUPPORTED. Solid evidence.")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_evaluate_finding("legit finding", "good evidence")
        sc_entries = [e for e in inst._entries if e.get("type") == "self_correction"]
        assert sc_entries == []


def _seed_report_phase(tmp_path):
    """Helper: configure execution log + seed a Report-phase dair_call."""
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("TEST", str(tmp_path / "trace.json"))
    l.record_dair_call(
        current_phase="Report",
        phase_rationale="Investigation complete",
        transition_recommended=False,
        next_phase="",
        transition_rationale="",
        stack_action="stay",
        investigation_focus="Synthesize findings",
    )
    return l


class TestReasonSynthesize:
    def test_returns_success(self, tmp_path):
        from tools.reasoning import reason_synthesize
        l = _seed_report_phase(tmp_path)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp("Gap: initial access unknown.")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_synthesize("1. Keylogger\n2. BITS exfil")
        assert r["success"] is True

    def test_investigation_summary_included(self, tmp_path):
        from tools.reasoning import reason_synthesize
        l = _seed_report_phase(tmp_path)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_synthesize("finding 1\nfinding 2", investigation_summary="ran psscan, netscan")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "psscan" in user_msg

    def test_openai_compat_posts_to_completions_endpoint(self, tmp_path):
        from tools.reasoning import reason_synthesize
        l = _seed_report_phase(tmp_path)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_synthesize("findings")
        call_url = m.call_args[0][0]
        assert "v1/chat/completions" in call_url

    def test_directives_present(self, tmp_path):
        from tools.reasoning import reason_synthesize
        l = _seed_report_phase(tmp_path)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp(_DIRECTIVES_JSON)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_synthesize("findings")
        assert "directives" in r


class TestSynthesizeGate:
    def test_synthesize_refused_without_dair_call(self, tmp_path):
        from tools.reasoning import reason_synthesize
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = reason_synthesize("findings")
        assert r["success"] is False
        assert "No dair_assess call" in r["error"]

    def test_synthesize_refused_outside_report_phase(self, tmp_path):
        from tools.reasoning import reason_synthesize
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call(
            current_phase="Triage",
            phase_rationale="",
            transition_recommended=False,
            next_phase="",
            transition_rationale="",
            stack_action="stay",
            investigation_focus="",
        )
        with patch("core.execution_log.log", l):
            r = reason_synthesize("findings")
        assert r["success"] is False
        assert "Report phase" in r["error"]
        assert "Triage" in r["error"]

    def test_synthesize_succeeds_in_report_phase(self, tmp_path):
        from tools.reasoning import reason_synthesize
        l = _seed_report_phase(tmp_path)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp("ok")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_synthesize("findings")
        assert r["success"] is True

    def test_synthesize_uses_most_recent_dair_call(self, tmp_path):
        """Older dair_call in non-Report doesn't block if most recent is Report."""
        from tools.reasoning import reason_synthesize
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_dair_call("Collect", "", False, "", "", "stay", "")
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp("ok")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_synthesize("findings")
        assert r["success"] is True


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
            reason_hypothesize("orphaned PPID", evidence="psscan output", context="REDFOX")
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


from tools._gates._claims import normalize_claim as _normc


def _EGRESS_CLAIM(channel):
    return _normc(claim_kind="positive", category="exfil", act="egress", channel=channel)


_HUMAN_VERDICT = _normc(claim_kind="positive", category="attribution", act="attribution",
                        actor_kind="human", actor="Johnny Coach")


class TestReasonPreReportCheck:
    """Tests for reason_pre_report_check."""

    @pytest.fixture
    def configured_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-PRE", str(tmp_path / "trace.json"))
        # K-1 phase coverage: these tests exercise the OTHER pre-report checks;
        # give the trace a transited Collect/Analyze history so the (separately
        # tested) phase_coverage blocker stays out of the way.
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
            l.record_dair_call(cur, "", True, nxt, "", "push", "")
        return l

    def test_empty_trace_not_ready(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_pre_report_check
        bare = ExecutionLog()
        bare.configure("TEST-PRE-EMPTY", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", bare):
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

    def test_one_check_failing_does_not_void_the_others(self, configured_log,
                                                        monkeypatch):
        # Regression for the single bare except that silently voided all six
        # structural checks whenever any one of them raised: crash check #1's
        # dependency and assert check #2 (multi-channel warning) still runs.
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log, "ok",
            finding_desc="data was exfiltrated to Dropbox cloud storage",
            claim=_EGRESS_CLAIM("cloud"))
        configured_log.record_finding(
            "archive was exfiltrated to a removable USB drive", "CONFIRMED",
            "ez.lecmd", claim=_EGRESS_CLAIM("removable"))
        import tools._gates._dispositions as disp_mod

        def _boom(*a, **k):
            raise RuntimeError("check #1 dependency exploded")

        monkeypatch.setattr(disp_mod, "find_disposition", _boom)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert any("exfiltration channels" in w for w in r["warnings"])

    # ── Correspondent-registry exhaustion (check #3, registry-driven) ─────────

    def _recipient_trace(self, log):
        self._full_passing_trace(
            log, "ok",
            finding_desc="research data was exfiltrated; the recipient is "
                         "contact-a@ext.example",
            claim=_normc(claim_kind="positive", category="delivery", act="delivery",
                         recipients=["contact-a@ext.example"]))

    def test_registry_leftover_correspondent_blocks(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        self._recipient_trace(configured_log)
        cid = configured_log.record_tool_call(
            "read.read_mail -o /x/mail", True, False, 0, 0)
        configured_log.annotate_tool_call(
            cid,
            observed_correspondents=["contact-a@ext.example",
                                     "handler-b@far.example",
                                     "mailer-daemon@x.example"],
            observed_correspondent_stats={"contact-a@ext.example": {"from": 1, "to": 2},
                                          "handler-b@far.example": {"from": 1, "to": 1}},
            correspondents_partial=False)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        # A2-v2: a never-referenced correspondent the subject WROTE TO blocks BY
        # NAME; the referenced one and mailbox noise do not.
        assert any("handler-b@far.example" in i for i in r["blocking_issues"])
        assert not any("contact-a@ext.example" in i for i in r["blocking_issues"])
        assert not any("mailer-daemon" in i for i in r["blocking_issues"])

    def test_registry_one_shot_inbound_senders_warn_not_block(self, configured_log):
        # Bulk newsletter/notification senders once became
        # mandatory dispositions. With direction stats, only correspondents the
        # subject WROTE TO (or roster/chat) block; inbound volume alone does not.
        from tools.reasoning import reason_pre_report_check
        self._recipient_trace(configured_log)
        cid = configured_log.record_tool_call("read.read_mail -o /x/mail", True, False, 0, 0)
        configured_log.annotate_tool_call(
            cid,
            observed_correspondents=["contact-a@ext.example", "handler-b@far.example",
                                     "news@apple.example", "promo@shop.example", "repeat@spam.example"],
            observed_correspondent_stats={"contact-a@ext.example": {"from": 1, "to": 2},
                                          "handler-b@far.example": {"from": 1, "to": 1},
                                          "news@apple.example": {"from": 1, "to": 0},
                                          "promo@shop.example": {"from": 1, "to": 0},
                                          "repeat@spam.example": {"from": 3, "to": 0}},
            correspondents_partial=False)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        blocking = " ".join(r["blocking_issues"])
        # A2-v2: only the wrote-to correspondent blocks; inbound-only (incl. the
        # repeat sender) goes to inventory, warned, never blocking.
        assert "handler-b@far.example" in blocking
        assert "repeat@spam.example" not in blocking
        assert "news@apple.example" not in blocking and "promo@shop.example" not in blocking
        assert any("inbound-only correspondent" in w and "news@apple.example" in w for w in r["warnings"])
        pre = [e for e in configured_log._entries if e.get("tool") == "reason_pre_report_check"][-1]
        assert set(pre["correspondents_auto_noise"]) == {
            "news@apple.example", "promo@shop.example", "repeat@spam.example"}

    def test_registry_partial_scan_falls_back_to_warning(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        self._recipient_trace(configured_log)
        cid = configured_log.record_tool_call(
            "read.read_mail -o /x/mail", True, False, 0, 0)
        configured_log.annotate_tool_call(
            cid, observed_correspondents=["handler-b@far.example"],
            correspondents_partial=True)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        # Truncated roster ⇒ never blocking set arithmetic.
        assert not any("handler-b" in i for i in r["blocking_issues"])

    def test_claim_entity_dispositions_correspondent(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        self._recipient_trace(configured_log)
        cid = configured_log.record_tool_call(
            "read.read_mail -o /x/mail", True, False, 0, 0)
        configured_log.annotate_tool_call(
            cid, observed_correspondents=["handler-b@far.example"],
            correspondents_partial=False)
        configured_log.record_finding(
            "handler correspondence assessed as an unrelated vendor thread",
            "UNCONFIRMED", "read.read_mail",
            claim=_normc(claim_kind="negative", category="other", act="presence",
                         entities=["Handler-B@far.example"]))
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("handler-b" in i for i in r["blocking_issues"])

    def test_typed_correspondent_disposition_clears(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        self._recipient_trace(configured_log)
        cid = configured_log.record_tool_call(
            "read.read_mail -o /x/mail", True, False, 0, 0)
        configured_log.annotate_tool_call(
            cid, observed_correspondents=["handler-b@far.example"],
            correspondents_partial=False)
        configured_log.record_disposition("correspondent", "handler-b@far.example", "noise")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("handler-b" in i for i in r["blocking_issues"])

    # ── BLOCKER detection (negation-aware fallback) ───────────────────────────

    def _full_passing_trace(self, log, synth_conclusion, finding_desc="PerfSvc.exe persistence",
                            claim=None):
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        log.record_reason_call("reason_plan", True, "plan", {})
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        log.record_reason_call("reason_synthesize", True, synth_conclusion, {})
        log.record_finding(finding_desc, "CONFIRMED", "ez.mftecmd", claim=claim)

    def test_negated_blocker_prose_passes(self, configured_log):
        # The old bare-word \bBLOCKER\b fallback wrongly blocked clean syntheses
        # that merely said there were none.
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log,
            "All artifact categories exhausted; no blocker conditions found.")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert not any("BLOCKER" in i for i in r["blocking_issues"])

    def test_canonical_blockers_none_passes(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(configured_log, "Synthesis complete.\nBLOCKERS: None")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True

    def test_real_blocker_header_blocks(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log, "Findings incomplete.\nBLOCKERS: identity unresolved")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("BLOCKER" in i for i in r["blocking_issues"])

    def test_unnegated_blocker_prose_blocks(self, configured_log):
        # Non-canonical prose flagging a real blocker still blocks (fallback).
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log, "One blocker remains: registry hive was never parsed.")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("BLOCKER" in i for i in r["blocking_issues"])

    # ── Case-question gate (typed) ────────────────────────────────────────────

    def _cq_trace(self, log):
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        cid = log.record_reason_call("reason_plan", True, "plan", {})
        log.update_reason_call(cid, case_question="What hacking tools did the suspect install and use?")
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        log.record_reason_call("reason_synthesize", True, "done\nBLOCKERS: None", {})

    def test_declared_case_question_answered_by_typed_finding(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        self._cq_trace(configured_log)
        configured_log.record_finding(
            "The suspect installed and used hacking tools", "CONFIRMED", "ez.pecmd",
            claim=_normc(claim_kind="positive", category="execution", act="execution",
                         answers_case_question=True))
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("Case question" in i for i in r["blocking_issues"]), r["blocking_issues"]
        assert r["ready_to_report"] is True

    def test_case_question_unanswered_still_blocks(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        self._cq_trace(configured_log)
        # Wording that "matches" the question but no declaration → still blocks.
        configured_log.record_finding(
            "The suspect installed and used hacking tools", "CONFIRMED", "ez.pecmd",
            claim=_normc(claim_kind="positive", category="execution", act="execution"))
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert any("Case question" in i and "answers_case_question" in i for i in r["blocking_issues"])
        assert r["ready_to_report"] is False

    def test_prose_case_question_marker_is_not_read(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_agent_message("CASE_QUESTION: who did it? Plan: everything")
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding("Disk image acquired and hashed", "CONFIRMED", "ewf.info")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("Case question" in i for i in r["blocking_issues"])

    def test_reason_plan_case_question_stamped(self, configured_log):
        from tools.reasoning import reason_plan
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning._ask", return_value={"success": True, "conclusion": "p",
                                                         "directives": {}, "_trudi_call_id": 0}):
            r = reason_plan("case", "evidence", case_question=" Who sent it? ")
        assert r["case_question"] == "Who sent it?"

    def test_token_totals_reported(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_reason_call("reason_plan", True, "plan", {}, input_tokens=300, output_tokens=100)
        configured_log.record_reason_call("reason_synthesize", True, "ok", {}, input_tokens=500, output_tokens=200)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["total_input_tokens"] == 800
        assert r["total_output_tokens"] == 300

    def test_persists_ready_to_report_in_trace(self, configured_log):
        # The pre_report_check_required gate (on export_execution_log) reads
        # READY_TO_REPORT from the trace
        # entry — pre_report_check must write it.
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
        # Trace entry should exist with the parseable marker.
        pre = [e for e in configured_log._entries
               if e.get("type") == "reason_call"
               and e.get("tool") == "reason_pre_report_check"]
        assert len(pre) == 1
        assert "READY_TO_REPORT: true" in pre[0]["conclusion"]
        assert pre[0]["ready_to_report"] is True and pre[0]["blocking_issues"] == []

    def test_persists_ready_false_when_blocked(self, configured_log):
        # Empty trace → blocking issue (start_execution_log not called).
        from tools.reasoning import reason_pre_report_check
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        pre = [e for e in configured_log._entries
               if e.get("type") == "reason_call"
               and e.get("tool") == "reason_pre_report_check"]
        assert len(pre) == 1
        assert "READY_TO_REPORT: false" in pre[0]["conclusion"]
        assert pre[0]["ready_to_report"] is False and pre[0]["blocking_issues"]

    def test_multi_host_findings_without_correlate_warns(self, configured_log):
        # When findings span ≥2 hosts but no correlate.process_to_file /
        # correlate.network_to_process call was logged, a warning fires
        # (non-blocking).
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call(
            "reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_dair_call("Analyze", "", False, "", "", "stay", "",
                                        observed_hosts=["10.0.6.11", "10.0.4.7"])
        configured_log.record_finding(
            "Beacon on 10.0.6.11 PID 4044 (T1055)",
            "CONFIRMED", "vol.netscan")
        configured_log.record_finding(
            "Beacon on 10.0.4.7 PID 1820 (T1021)",
            "CONFIRMED", "vol.netscan")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True  # warning-level
        assert any("correlate" in w for w in r["warnings"])
        assert any("cross-host" in w.lower() for w in r["warnings"])

    def test_multi_host_with_correlate_no_warning(self, configured_log):
        # Same multi-host setup, but a correlate.network_to_process tool_call
        # is present → no cross-host correlation warning.
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call(
            "<py>:correlate_network_to_process", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call(
            "reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_dair_call("Analyze", "", False, "", "", "stay", "",
                                        observed_hosts=["10.0.6.11", "10.0.4.7"])
        configured_log.record_finding(
            "Beacon on 10.0.6.11 PID 4044 (T1055)",
            "CONFIRMED", "vol.netscan")
        configured_log.record_finding(
            "Beacon on 10.0.4.7 PID 1820 (T1021)",
            "CONFIRMED", "vol.netscan")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert not any("cross-host" in w.lower() for w in r["warnings"])

    def test_single_host_does_not_trigger_correlation_warning(self, configured_log):
        # Single-host case — no correlate.* needed; warning must not fire.
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call(
            "reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding(
            "Beacon on 10.0.6.11 PID 4044 (T1055)",
            "CONFIRMED", "vol.netscan")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert not any("cross-host" in w.lower() for w in r["warnings"])

    def test_synthesize_blockers_are_blocking(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call(
            "reason_synthesize", True,
            "SUMMARY: draft\nBLOCKERS: run roster sweep before attribution\nWARNINGS: none",
            {},
        )
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("reason.synthesize" in issue for issue in r["blocking_issues"])

    def test_synthesize_inline_blocker_labels_are_blocking(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call(
            "reason_synthesize", True,
            "LOGICAL GAPS:\n1. TEMP.ZIP CONTENT GAP (BLOCKER): temp.zip contents were not characterized.\n",
            {},
        )
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("rewording findings" in issue for issue in r["blocking_issues"])

    def test_pcap_human_attribution_requires_identity_closure(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call(
            "tcpdump -r /cases/nitroba/evidence/nitroba.pcap -A",
            True, False, 0, 0,
        )
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding(
            "Johnny Coach was responsible for the anonymous email from 192.168.15.4",
            "CONFIRMED",
            "net.ngrep_search", claim=_HUMAN_VERDICT,
        )
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("structured PCAP identity inventory" in issue for issue in r["blocking_issues"])
        assert any("roster/knowns sweep" in issue for issue in r["blocking_issues"])

    def test_pcap_human_attribution_with_identity_closure_passes(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call(
            "<py>:pcap_identity_timeline roster=CHEM109", True, False, 0, 0
        )
        configured_log.record_tool_call(
            "<py>:knowns_pattern_generate person_username CHEM109", True, False, 0, 0
        )
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding(
            "Johnny Coach was responsible for the anonymous email from 192.168.15.4",
            "CONFIRMED",
            "net.pcap_identity_timeline", claim=_HUMAN_VERDICT,
        )
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True

    def test_pcap_identity_finding_source_counts_as_closure(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call(
            "sudo tcpdump -r /cases/nitroba/evidence/nitroba.pcap -nn -A tcp port 80",
            True, False, 0, 0,
        )
        configured_log.record_tool_call(
            "<py>:knowns_pattern_generate person_username CHEM109", True, False, 0, 0
        )
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding(
            "Structured PCAP identity inventory dispositions every account and the sender is LIKELY Johnny Coach.",
            "LIKELY",
            "net.http_session_inventory", claim=_HUMAN_VERDICT,
        )
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True


class TestCallInitiatedLogging:
    """Tests for pre-flight call_initiated trace entries in reason.* tools."""

    def test_initiated_and_reason_entries_both_present_on_success(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        text = "Plan.\n" + _DIRECTIVES_JSON
        with patch("core.execution_log.log", inst), _claude_ctx(text):
            reason_plan("keylogger on wkstn-01", "memory.img")
        types = [e["type"] for e in inst._entries]
        assert "call_initiated" in types
        assert "reason_call" in types
        assert types.index("call_initiated") < types.index("reason_call")

    def test_initiated_entry_tool_matches_reason_tool(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_hypothesize
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _claude_ctx("Hypothesis.\n" + _DIRECTIVES_JSON):
            reason_hypothesize("svchost.exe with no parent")
        initiated = [e for e in inst._entries if e["type"] == "call_initiated"]
        assert initiated[0]["tool"] == "reason_hypothesize"
        assert initiated[0]["backend"] == "claude"

    def test_initiated_entry_on_timeout(self, tmp_path):
        import anthropic
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = anthropic.APITimeoutError(request=MagicMock())
        with patch("core.execution_log.log", inst), \
             patch("anthropic.Anthropic", return_value=mock_client), \
             patch("tools.reasoning.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.reasoning.REASON_BACKEND", "claude"):
            r = reason_plan("case", "evidence")
        assert r["success"] is False
        initiated = [e for e in inst._entries if e["type"] == "call_initiated"]
        assert len(initiated) == 1

    def test_initiated_entry_compat_backend(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        text = "Plan.\n" + _DIRECTIVES_JSON
        with patch("core.execution_log.log", inst), _compat_ctx(text):
            reason_plan("case", "evidence")
        initiated = [e for e in inst._entries if e["type"] == "call_initiated"]
        assert initiated[0]["backend"] == "openai-compat"


_CITE_ALL = (
    'Citation analysis complete.\n'
    'CITE_CHECK:\n'
    '{"verdict": "ALL_CITED", "cited_claims": ["STUN.exe at C:\\\\Windows\\\\Temp"],'
    ' "uncited_claims": [], "rationale": "all claims backed by tool output"}'
)
_CITE_UNCITED = (
    'Two uncited claims.\n'
    'CITE_CHECK:\n'
    '{"verdict": "UNCITED_CLAIMS_PRESENT",'
    ' "cited_claims": ["PID 5024"],'
    ' "uncited_claims": ["parent PID 2748 was orphaned", "process ran from Session 0"],'
    ' "rationale": "two claims without tool citation"}'
)
_CITE_INSUFFICIENT = (
    'CITE_CHECK:\n'
    '{"verdict": "INSUFFICIENT_EVIDENCE", "cited_claims": [], "uncited_claims": [],'
    ' "rationale": "supporting_evidence empty"}'
)


class TestReasonCiteCheck:
    """reason.cite_check verifies claims are backed by citations."""

    def test_all_cited_verdict(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_cite_check
        inst = ExecutionLog()
        inst.configure("CC-001", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CITE_ALL):
            r = reason_cite_check("STUN.exe at C:\\Windows\\Temp confirmed",
                                  "stat_file: C:\\Windows\\Temp\\STUN.exe size 45312")
        assert r["success"] is True
        assert r["verdict"] == "ALL_CITED"
        assert "STUN.exe at C:\\Windows\\Temp" in r["cited_claims"]
        assert r["uncited_claims"] == []

    def test_uncited_claims_present(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_cite_check
        inst = ExecutionLog()
        inst.configure("CC-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CITE_UNCITED):
            r = reason_cite_check(
                "PID 5024 spawned from orphaned PPID 2748 in Session 0",
                "vol.psscan: PID=5024 PPID=2748",
            )
        assert r["verdict"] == "UNCITED_CLAIMS_PRESENT"
        assert len(r["uncited_claims"]) == 2

    def test_insufficient_evidence_verdict(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_cite_check
        inst = ExecutionLog()
        inst.configure("CC-003", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CITE_INSUFFICIENT):
            r = reason_cite_check("anything", "")
        assert r["verdict"] == "INSUFFICIENT_EVIDENCE"

    def test_malformed_cite_check_block_returns_defaults(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_cite_check
        inst = ExecutionLog()
        inst.configure("CC-004", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("no cite_check block here"):
            r = reason_cite_check("finding", "evidence")
        assert r["verdict"] == "INSUFFICIENT_EVIDENCE"
        assert r["cited_claims"] == []
        assert r["uncited_claims"] == []

    def test_cite_check_logged_as_reason_call(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_cite_check
        inst = ExecutionLog()
        inst.configure("CC-005", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CITE_ALL):
            reason_cite_check("finding", "evidence")
        reason_entries = [e for e in inst._entries if e["type"] == "reason_call"]
        assert any(e.get("tool") == "reason_cite_check" for e in reason_entries)


_CONF_CONFIRMED = (
    'CONFIDENCE_SCORE:\n'
    '{"tier": "CONFIRMED", "score": 0.92, '
    '"rationale": "Multiple independent artifacts agree.", '
    '"downgrade_reasons": []}'
)
_CONF_DOWNGRADE = (
    'CONFIDENCE_SCORE:\n'
    '{"tier": "SUSPECTED", "score": 0.40, '
    '"rationale": "YARA hit alone is never above SUSPECTED.", '
    '"downgrade_reasons": ["YARA-only evidence", "no corroborating artifact"]}'
)


class TestReasonConfidenceScore:
    """J-1: reason.confidence_score is a deterministic tier lookup over the
    cited calls' artifact classes (data/fk/tiering.yaml) — no model call."""

    def _log(self, tmp_path, case):
        from core.execution_log import ExecutionLog
        inst = ExecutionLog()
        inst.configure(case, str(tmp_path / "trace.json"))
        return inst

    def test_confirmed_from_two_independent_execution_artifacts(self, tmp_path):
        from tools.reasoning import reason_confidence_score
        inst = self._log(tmp_path, "CS-001")
        ua = inst.record_tool_call("rip.pl -r NTUSER.DAT -p userassist", True, False, 0, 0,
                                   stdout_excerpt="STUN.exe (2)")
        pf = inst.record_tool_call("dotnet PECmd.dll -d Prefetch --csv /out", True, False, 0, 0,
                                   stdout_excerpt="STUN.EXE-1A2B.pf")
        with patch("core.execution_log.log", inst), \
             patch("httpx.post", MagicMock(side_effect=AssertionError("no model call"))):
            r = reason_confidence_score("STUN.exe executed", "UserAssist + Prefetch",
                                        intended_tier="CONFIRMED", input_call_ids=[ua, pf],
                                        claim_kind="positive", category="execution", act="execution",
                                        entities=["STUN.exe"])
        assert r["success"] is True and r["deterministic"] is True
        assert r["tier"] == "CONFIRMED" and r["score"] >= 0.85
        assert r["downgrade_reasons"] == [] and r["tier_path"] == ""
        assert set(r["artifact_classes"]) >= {"userassist", "prefetch"}
        e = [x for x in inst._entries if x.get("call_id") == r["_trudi_call_id"]][0]
        assert e["tool"] == "reason_confidence_score" and e["tier"] == "CONFIRMED"
        assert e["input_call_ids"] == [ua, pf]

    def test_downgrade_with_the_path_to_the_intended_tier(self, tmp_path):
        from tools.reasoning import reason_confidence_score
        inst = self._log(tmp_path, "CS-002")
        y = inst.record_tool_call("yara -r rules/ /mnt/c/Windows/SystemSettings.dll", True, False, 0, 0,
                                  stdout_excerpt="CobaltStrike_Beacon SystemSettings.dll")
        with patch("core.execution_log.log", inst):
            r = reason_confidence_score("SystemSettings.dll is a Cobalt Strike beacon",
                                        "YARA rule match only", intended_tier="CONFIRMED",
                                        input_call_ids=[y], claim_kind="positive",
                                        category="other", act="c2")
        assert r["tier"] == "SUSPECTED" and r["score"] < 0.60
        assert r["downgrade_reasons"][0].startswith("intended CONFIRMED")
        assert "LIKELY for act=c2" in r["tier_path"] and "vol.netscan" in r["tier_path"]

    def test_no_act_or_no_calls_is_unconfirmed_with_reason(self, tmp_path):
        from tools.reasoning import reason_confidence_score
        inst = self._log(tmp_path, "CS-003")
        with patch("core.execution_log.log", inst):
            r = reason_confidence_score("any finding", "any evidence")
            r2 = reason_confidence_score("any finding", "any evidence", act="execution")
        assert r["tier"] == "UNCONFIRMED" and "no typed act" in r["rationale"]
        assert r2["tier"] == "UNCONFIRMED" and "no input_call_ids" in r2["rationale"]


class TestHypothesisIdLineage:
    """Hypothesis lineage: reason_hypothesize generates a hypothesis_id and logs it on reason_call."""

    def test_hypothesize_returns_hypothesis_id(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_hypothesize
        inst = ExecutionLog()
        inst.configure("HY-001", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("Hypothesis A.\n" + _DIRECTIVES_JSON):
            r = reason_hypothesize("orphan PID 5024")
        assert r["success"] is True
        assert r.get("hypothesis_id", "").startswith("H")

    def test_reason_call_entry_includes_hypothesis_id(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_hypothesize
        inst = ExecutionLog()
        inst.configure("HY-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("ok\n" + _DIRECTIVES_JSON):
            reason_hypothesize("anomaly")
        reason_entries = [e for e in inst._entries if e["type"] == "reason_call"]
        assert reason_entries[-1].get("hypothesis_id", "").startswith("H")

    def test_hypothesis_id_sequence_increments(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_hypothesize
        inst = ExecutionLog()
        inst.configure("HY-003", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("ok\n" + _DIRECTIVES_JSON):
            r1 = reason_hypothesize("obs 1")
            r2 = reason_hypothesize("obs 2")
        assert r1["hypothesis_id"] == "H0001"
        assert r2["hypothesis_id"] == "H0002"

    def test_plan_does_not_get_hypothesis_id(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("HY-004", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("Plan.\n" + _DIRECTIVES_JSON):
            r = reason_plan("case", "evidence")
        assert "hypothesis_id" not in r
        reason_entries = [e for e in inst._entries if e["type"] == "reason_call"]
        assert "hypothesis_id" not in reason_entries[-1]


class TestReasonInputsCaptured:
    """Inputs sent to reason.* models are stored on the reason_call entry."""

    def test_plan_records_user_message(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("IN-001", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("Plan.\n" + _DIRECTIVES_JSON):
            reason_plan("test case description", "pre-enum data")
        entry = [e for e in inst._entries if e.get("tool") == "reason_plan"][-1]
        assert "inputs" in entry
        assert "test case description" in entry["inputs"]["user_message"]
        assert "pre-enum data" in entry["inputs"]["user_message"]
        assert entry["inputs"]["system_prompt_kind"] == "reason_plan"
        assert entry["inputs"]["max_tokens"] > 0

    def test_hypothesize_records_inputs(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_hypothesize
        inst = ExecutionLog()
        inst.configure("IN-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("Hypo.\n" + _DIRECTIVES_JSON):
            reason_hypothesize("orphan PID 5024", evidence="vol.psscan output")
        entry = [e for e in inst._entries if e.get("tool") == "reason_hypothesize"][-1]
        assert "inputs" in entry
        assert "orphan PID 5024" in entry["inputs"]["user_message"]
        assert "vol.psscan output" in entry["inputs"]["user_message"]

    def test_evaluate_finding_records_inputs(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_evaluate_finding
        inst = ExecutionLog()
        inst.configure("IN-003", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("Eval.\n" + _DIRECTIVES_JSON):
            reason_evaluate_finding("malicious .exe", "stat output", case_context="REDFOX")
        entry = [e for e in inst._entries if e.get("tool") == "reason_evaluate_finding"][-1]
        assert "inputs" in entry
        assert "malicious .exe" in entry["inputs"]["user_message"]
        assert "REDFOX" in entry["inputs"]["user_message"]

    def test_error_path_still_records_inputs(self, tmp_path):
        # When the reasoning backend is misconfigured, the resulting failed
        # reason_call entry must still capture what was sent.
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("IN-004", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), \
             patch("tools.reasoning.REASON_URL", ""), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"), \
             patch("tools.reasoning.ANTHROPIC_API_KEY", ""):
            reason_plan("case desc", "evidence")
        entry = [e for e in inst._entries if e.get("tool") == "reason_plan"][-1]
        assert "inputs" in entry
        assert "case desc" in entry["inputs"]["user_message"]


_AUDIT_TWO_CANDIDATES = (
    'I see two unrecorded factual claims.\n'
    'AUDIT_FINDINGS:\n'
    '[\n'
    '  {"narration_call_id": 10, "narration_excerpt": "ngentask.exe is CS beacon",\n'
    '   "suggested_finding": {"description": "ngentask.exe (PID 7092) is a CS beacon implant",\n'
    '                          "suggested_confidence": "CONFIRMED",\n'
    '                          "suggested_source": "vol.netscan"},\n'
    '   "suggested_linked_call_id": 5,\n'
    '   "rationale": "Specific PID + C2 IP/port claim with no finding entry."},\n'
    '  {"narration_call_id": 11, "narration_excerpt": "Rar.exe archiving",\n'
    '   "suggested_finding": {"description": "Rar.exe archived data Sep 5",\n'
    '                          "suggested_confidence": "CONFIRMED",\n'
    '                          "suggested_source": "vol.cmdline"},\n'
    '   "suggested_linked_call_id": 6,\n'
    '   "rationale": "Specific timestamped exfil staging action."}\n'
    ']'
)
_AUDIT_EMPTY = "All claims accounted for.\nAUDIT_FINDINGS:\n[]"


class TestReasonAuditFindings:
    """reason.audit_findings — model-based scan for unrecorded findings."""

    def test_empty_trace_returns_no_candidates(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_audit_findings
        inst = ExecutionLog()
        inst.configure("AF-001", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst):
            r = reason_audit_findings()
        assert r["candidates"] == []
        assert r["summary"]["total_narrations"] == 0
        assert r["summary"]["candidate_count"] == 0

    def test_candidates_parsed_from_model(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_audit_findings
        inst = ExecutionLog()
        inst.configure("AF-002", str(tmp_path / "trace.json"))
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        inst.record_agent_message("ngentask.exe (PID 7092) is CS beacon")
        inst.record_agent_message("Rar.exe ran Sep 5 archiving data")
        with patch("core.execution_log.log", inst), _compat_ctx(_AUDIT_TWO_CANDIDATES):
            r = reason_audit_findings()
        assert r["summary"]["candidate_count"] == 2
        assert r["candidates"][0]["suggested_finding"]["description"].startswith("ngentask")
        assert r["candidates"][1]["narration_call_id"] == 11

    def test_no_candidates_when_findings_already_recorded(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_audit_findings
        inst = ExecutionLog()
        inst.configure("AF-003", str(tmp_path / "trace.json"))
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        inst.record_agent_message("ngentask.exe is CS beacon")
        inst.record_finding("ngentask.exe is CS beacon (PID 7092)", "CONFIRMED",
                            "vol.netscan", linked_call_id=2)
        with patch("core.execution_log.log", inst), _compat_ctx(_AUDIT_EMPTY):
            r = reason_audit_findings()
        assert r["summary"]["candidate_count"] == 0

    def test_logged_as_reason_call(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_audit_findings
        inst = ExecutionLog()
        inst.configure("AF-004", str(tmp_path / "trace.json"))
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        inst.record_agent_message("some narration")
        with patch("core.execution_log.log", inst), _compat_ctx(_AUDIT_EMPTY):
            reason_audit_findings()
        # _ask emits both a call_initiated and a reason_call for the same tool
        # name — count only the reason_call.
        rcs = [
            e for e in inst._entries
            if e.get("type") == "reason_call"
            and e.get("tool") == "reason_audit_findings"
        ]
        assert len(rcs) == 1

    def test_narration_window_truncates(self, tmp_path):
        """If 100 narrations exist, narration_window=5 sends only the last 5."""
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_audit_findings
        inst = ExecutionLog()
        inst.configure("AF-005", str(tmp_path / "trace.json"))
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        for i in range(50):
            inst.record_agent_message(f"narration {i}")
        with patch("core.execution_log.log", inst), _compat_ctx(_AUDIT_EMPTY):
            r = reason_audit_findings(narration_window=5)
        assert r["summary"]["total_narrations"] == 5


class TestPreReportCheckSurfacesAuditWarnings:
    """reason.pre_report_check folds audit_findings results into warnings."""

    def test_warning_added_when_candidates(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_pre_report_check
        inst = ExecutionLog()
        inst.configure("PRC-A1", str(tmp_path / "trace.json"))
        # Minimal trace that passes the major blocking checks:
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        inst.record_reason_call("reason_plan", True, "ok", {})
        inst.record_reason_call("reason_hypothesize", True, "ok", {})
        inst.record_reason_call("reason_synthesize", True, "ok", {})
        # A narration that the audit will flag
        inst.record_agent_message("ngentask.exe is CS beacon")
        with patch("core.execution_log.log", inst), _compat_ctx(_AUDIT_TWO_CANDIDATES):
            r = reason_pre_report_check()
        # Audit count surfaces in warnings; we don't care about other warnings
        assert any("aren't recorded as structured" in w for w in r["warnings"])
        assert r["audit_summary"]["candidate_count"] == 2


class TestPreReportStructuralIntegrity:
    """Structural-integrity checks keyed on typed claims and dispositions:
    covert-account controller (blocking), multi-channel exfil (warning),
    declared recipient without comms read (warning)."""

    @pytest.fixture
    def base_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-STRUCT", str(tmp_path / "trace.json"))
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        l.record_reason_call("reason_hypothesize", True, "hyp", {})
        return l

    _CREATED = _normc(claim_kind="positive", category="persistence", act="account_creation",
                      principal="svc_x", entities=["svc_x"])

    def test_covert_account_without_controller_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("Covert local admin account 'svc_x' was created (RID 1500)",
                                "CONFIRMED", "ez.recmd", claim=self._CREATED)
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("svc_x" in i.lower() and "controls it" in i.lower() for i in r["blocking_issues"])

    def test_wording_alone_does_not_trigger(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("Covert local admin account 'svc_x' was created (RID 1500)",
                                "CONFIRMED", "ez.recmd")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("svc_x" in i.lower() for i in r["blocking_issues"])

    def test_controller_established_by_bound_finding_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("svc_x created", "CONFIRMED", "ez.recmd", claim=self._CREATED)
        base_log.record_finding(
            "Account svc_x logged in via RDP logon type 10 from 10.0.0.5", "CONFIRMED", "ez.evtxecmd",
            claim=_normc(claim_kind="positive", category="identity", act="attribution",
                         actor_kind="human", actor="Mallory", principal="SVC_X",
                         session_binding_call_ids=[1]))
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("svc_x" in i.lower() for i in r["blocking_issues"])

    def test_typed_parking_disposition_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("svc_x created", "LIKELY", "ez.recmd", claim=self._CREATED)
        base_log.record_disposition("principal", "svc_x", "controller_unknown")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("svc_x" in i.lower() for i in r["blocking_issues"])

    def test_prose_parking_no_longer_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("svc_x created", "LIKELY", "ez.recmd", claim=self._CREATED)
        base_log.record_finding("Controller of account svc_x is unknown — requires authentication logs",
                                "UNCONFIRMED", "analysis")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("svc_x" in i.lower() for i in r["blocking_issues"])

    def test_multiple_exfil_channels_warns(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("data exfiltrated to cloud", "CONFIRMED", "mft", claim=_EGRESS_CLAIM("cloud"))
        base_log.record_finding("data exfiltrated over FTP", "CONFIRMED", "ftp", claim=_EGRESS_CLAIM("ftp"))
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("channel" in w.lower() for w in r["warnings"])

    def test_declared_recipient_without_comms_read_warns(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("research exfiltrated to buyer", "CONFIRMED", "ost",
                                claim=_normc(claim_kind="positive", category="delivery", act="delivery",
                                             recipients=["buyer@evil.example"]))
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("roster" in w.lower() for w in r["warnings"])

    def test_declared_recipient_with_mail_read_no_warn(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("research exfiltrated to buyer", "CONFIRMED", "ost",
                                claim=_normc(claim_kind="positive", category="delivery", act="delivery",
                                             recipients=["buyer@evil.example"]))
        base_log.record_tool_call("read.read_mail --output /x/mail", True, False, 0, 0)
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("roster" in w.lower() for w in r["warnings"])


class TestPreReportHypothesisLedger:
    """Every raised hypothesis must be resolved (cited by a finding's
    tested_hypothesis_id) or dispositioned before Report. A hypothesis DECLARED
    hypothesis_kind='distinct_principal' left open BLOCKS; generic ones WARN.
    The kind is declared, never inferred from wording."""

    @pytest.fixture
    def base_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-HYP", str(tmp_path / "trace.json"))
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        return l

    def _hyp(self, log, hid, kind="", contested=None, obs="OBSERVATION: x"):
        cid = log.record_reason_call("reason_hypothesize", True, "h", {}, hypothesis_id=hid,
                                     inputs={"user_message": obs})
        log.update_reason_call(cid, hypothesis_kind=kind or None,
                               contested_principals=contested or None)
        return cid

    def test_open_generic_hypothesis_warns_not_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._hyp(base_log, "H0001", obs="OBSERVATION: orphaned cmd.exe under session 0")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("H0001" in w and "never resolved" in w.lower() for w in r["warnings"])
        assert not any("H0001" in i for i in r["blocking_issues"])

    def test_resolved_generic_hypothesis_no_warn(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._hyp(base_log, "H0001")
        base_log.record_finding("Orphaned cmd.exe (PID 4012) is a benign scheduler artifact",
                                "LIKELY", "vol", tested_hypothesis_id="H0001")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("H0001" in w for w in r["warnings"])
        assert not any("H0001" in i for i in r["blocking_issues"])

    def test_declared_distinct_principal_open_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._hyp(base_log, "H0002", kind="distinct_principal")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("H0002" in i and "distinct_principal" in i for i in r["blocking_issues"])

    def test_wording_does_not_make_it_distinct(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._hyp(base_log, "H0003", obs="OBSERVATION: an inbound RDP session (logon type 10) "
                                         "preceded the copy; who controls account svc_rdp?")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("H0003" in i for i in r["blocking_issues"])
        assert any("H0003" in w for w in r["warnings"])

    def test_distinct_principal_resolved_by_finding_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._hyp(base_log, "H0002", kind="distinct_principal")
        base_log.record_finding("svc_rdp is controlled by an external actor", "CONFIRMED", "ez.evtxecmd",
                                tested_hypothesis_id="H0002")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("H0002" in i for i in r["blocking_issues"])

    def test_distinct_principal_hypothesis_disposition_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._hyp(base_log, "H0002", kind="distinct_principal")
        base_log.record_disposition("hypothesis", "H0002", "evidence_unavailable")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("H0002" in i for i in r["blocking_issues"])

    def test_contested_principals_tracked_per_entity(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._hyp(base_log, "H0004", kind="distinct_principal", contested=["svc_rdp"])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("svcrdp" in i and "never driven to a verdict" in i for i in r["blocking_issues"])
        base_log.record_disposition("principal", "SVC_RDP", "refuted",
                                    evidence_call_ids=[base_log.record_tool_call(
                                        "dotnet EvtxECmd.dll -f Security.evtx", True, False, 0, 0)])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("svcrdp" in i for i in r["blocking_issues"])

    def test_hypothesize_typed_kwargs_stamped(self, base_log):
        from tools.reasoning import reason_hypothesize
        with patch("core.execution_log.log", base_log), \
             patch("tools.reasoning._ask", return_value={"success": True, "conclusion": "h",
                                                         "directives": {}, "hypothesis_id": "H0009",
                                                         "_trudi_call_id": 0}):
            r = reason_hypothesize("obs", hypothesis_kind="distinct_principal",
                                   contested_principals=["CORP\\J.Doe"])
            bad = reason_hypothesize("obs", hypothesis_kind="wild")
        assert r["hypothesis_kind"] == "distinct_principal" and r["contested_principals"] == ["CORP\\J.Doe"]
        assert bad["success"] is False and bad["gate"] == "typed_hypothesis"


class TestPreReportAttributionClosure:
    """A DECLARED human/account verdict needs a logon/RDP inventory somewhere in
    the trace, and every surfaced principal candidate must be dispositioned
    (bound by a finding or settled by a typed disposition) before Report."""

    @pytest.fixture
    def base_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-CLOSURE", str(tmp_path / "trace.json"))
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        l.record_reason_call("reason_hypothesize", True, "hyp", {})
        return l

    _DANA = _normc(claim_kind="positive", category="exfil", act="egress", channel="removable",
                   actor_kind="human", actor="Dana")

    def test_verdict_without_logon_enum_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("Dana exfiltrated the classified data", "CONFIRMED", "mft", claim=self._DANA)
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("session-enumeration" in i.lower() for i in r["blocking_issues"])

    def test_verdict_wording_without_claim_not_gated(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("Dana exfiltrated the classified data", "CONFIRMED", "mft")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("session-enumeration" in i.lower() for i in r["blocking_issues"])

    def test_verdict_with_evtxecmd_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("Dana exfiltrated the classified data", "CONFIRMED", "mft", claim=self._DANA)
        base_log.record_tool_call("dotnet /opt/EZ/EvtxECmd/EvtxECmd.dll -f Security.evtx --inc 4624,4625",
                                  True, False, 0, 0)
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("session-enumeration" in i.lower() for i in r["blocking_issues"])

    def test_verdict_with_session_marker_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("Mallory copied the research", "CONFIRMED", "mft", claim=self._DANA)
        cid = base_log.record_tool_call("<py>:misc_evtx_filter", True, False, 0, 0)
        base_log.annotate_tool_call(cid, session_artifact=True)
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("session-enumeration" in i.lower() for i in r["blocking_issues"])

    def test_verdict_with_linux_last_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("Dana exfiltrated the classified data", "CONFIRMED", "mft", claim=self._DANA)
        base_log.record_tool_call("last -f /var/log/wtmp", True, False, 0, 0)
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("session-enumeration" in i.lower() for i in r["blocking_issues"])

    def test_process_attribution_verdict_not_blocked(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("ngentask.exe exfiltrated data to C2 192.0.2.10", "CONFIRMED", "vol",
                                claim=_normc(claim_kind="positive", category="exfil", act="egress",
                                             channel="c2", actor_kind="process", actor="ngentask.exe"))
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("session-enumeration" in i.lower() for i in r["blocking_issues"])

    def _forced(self, log, value="SVC_RDP"):
        log.record_dair_call(
            current_phase="Analyze", phase_rationale="assess auth artifacts",
            transition_recommended=False, next_phase="", transition_rationale="",
            stack_action="stay", investigation_focus="Review authentication anomalies",
            candidate_pivots=[{"kind": "principal", "value": value, "phase": "Triage", "cue": "forced"}])

    def test_forced_candidate_pivot_principal_undispositioned_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._forced(base_log)
        base_log.record_tool_call("<py>:misc_evtx_filter", True, False, 0, 0)
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("SVC_RDP" in i and "forced principal candidate" in i and "record_disposition" in i
                   for i in r["blocking_issues"])

    def test_focus_string_is_not_harvested(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_dair_call(
            current_phase="Triage", phase_rationale="pivot", transition_recommended=False,
            next_phase="", transition_rationale="", stack_action="stay",
            investigation_focus="Establish who controls principal SVC_RDP")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("SVC_RDP" in i for i in r["blocking_issues"])

    def test_surfaced_principal_attributed_with_bound_finding_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._forced(base_log)
        cid = base_log.record_tool_call("<py>:misc_evtx_filter", True, False, 0, 0)
        base_log.annotate_tool_call(cid, session_artifact=True)
        base_log.record_finding(
            "svc_rdp logged in via RDP type 10 from 10.0.0.5 — external actor", "CONFIRMED", "ez.evtxecmd",
            claim=_normc(claim_kind="positive", category="identity", act="attribution",
                         actor_kind="human", actor="external actor", principal="svc_rdp",
                         session_binding_call_ids=[cid]))
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("SVC_RDP" in i for i in r["blocking_issues"])

    def test_surfaced_principal_typed_disposition_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._forced(base_log)
        base_log.record_disposition("principal", "svc_rdp", "controller_unknown")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("SVC_RDP" in i for i in r["blocking_issues"])

    def test_surfaced_principal_prose_parking_no_longer_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._forced(base_log)
        base_log.record_finding("Controller of account svc_rdp is unknown — requires authentication logs",
                                "UNCONFIRMED", "analysis")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("SVC_RDP" in i for i in r["blocking_issues"])

    def test_no_verdict_no_block(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("A suspicious archive was observed in the staging folder", "SUSPECTED", "mft")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("session-enumeration" in i.lower() for i in r["blocking_issues"])


class TestHypothesizeSplit:
    """Part 1 — reason_hypothesize splits ranked H1…Hn into per-hypothesis records."""

    def test_five_hypotheses_parsed(self):
        from tools.reasoning import _parse_sub_hypotheses
        concl = (
            "ANALYSIS\n\n"
            "H1 — Second principal staged exfil tooling (Likelihood: MEDIUM-HIGH)\n"
            "Rationale: account name 'helpsvc' mimics a system artifact.\n\n"
            "H2 — Mallory created helpsvc as a deniable persona (Likelihood: HIGH)\n"
            "Rationale: PC User is already admin.\n\n"
            "H3 — Guest account is the actual vector (Likelihood: LOW-MEDIUM)\n"
            "Rationale: Guest is NOT disabled.\n\n"
            "H4 — benign printer service account (Likelihood: LOW)\n\n"
            "H5 — malware-created account (Likelihood: LOW)\n"
        )
        subs = _parse_sub_hypotheses(concl, "H0001")
        assert [s["sub_id"] for s in subs] == [f"H0001.{i}" for i in range(1, 6)]
        by = {s["label"]: s for s in subs}
        assert by["H1"]["likelihood_tier"] == "HIGH"    # MEDIUM-HIGH → HIGH
        assert by["H2"]["likelihood_tier"] == "HIGH"
        assert by["H3"]["likelihood_tier"] == "MEDIUM"   # LOW-MEDIUM → MEDIUM
        assert by["H4"]["likelihood_tier"] == "LOW"
        assert "HELPSVC" in by["H1"]["entities"]
        assert "GUEST" in by["H3"]["entities"]

    def test_unstructured_conclusion_returns_empty(self):
        from tools.reasoning import _parse_sub_hypotheses
        assert _parse_sub_hypotheses("A single prose hypothesis, no headers.", "H0002") == []
        assert _parse_sub_hypotheses("", "H0003") == []


class TestPreReportHypothesisExhaustion:
    """Every MEDIUM+ contested principal must reach a verdict (controller
    established by a bound finding, or refuted by a finding with
    resolves='refuted' / a typed disposition). Parking ≠ terminal."""

    @pytest.fixture
    def base_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-EXHAUST", str(tmp_path / "trace.json"))
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        # J-3 relevance model: a principal only the REVIEWER listed is
        # mandatory when it matches the case roster (or is a forced DAIR
        # candidate); these tests exercise the verdict semantics of mandatory
        # principals, so the roster names them.
        rc = l.record_tool_call("misc.knowns_pattern_generate person_username n=3", True, False, 0, 0)
        l.annotate_tool_call(rc, knowns_roster=["helpsvc", "helpdesk", "guest"])
        return l

    def _seed_hyp(self, log, subs):
        cid = log.record_reason_call("reason_hypothesize", True, "ranked", {}, hypothesis_id="H0001")
        log.update_reason_call(cid, sub_hypotheses=subs)

    _H1 = {"sub_id": "H0001.1", "label": "H1", "title": "second principal",
           "likelihood_tier": "HIGH", "entities": ["HELPSVC"]}

    def test_unresolved_contested_principal_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [self._H1])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("helpsvc" in i and "never driven to a verdict" in i for i in r["blocking_issues"])

    def test_parked_only_still_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [self._H1])
        base_log.record_disposition("principal", "helpsvc", "controller_unknown")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("helpsvc" in i for i in r["blocking_issues"])

    def test_controller_established_with_bound_finding_clears_pair(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [self._H1, {**self._H1, "sub_id": "H0001.2", "label": "H2"}])
        cid = base_log.record_tool_call("dotnet EvtxECmd.dll -f Security.evtx", True, False, 0, 0)
        base_log.record_finding(
            "helpsvc operated by an external actor — 4624 type 10 from 10.0.0.5", "CONFIRMED", "ez.evtxecmd",
            claim=_normc(claim_kind="positive", category="identity", act="attribution",
                         actor_kind="human", actor="external actor", principal="HelpSvc",
                         session_binding_call_ids=[cid]))
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("helpsvc" in i for i in r["blocking_issues"])

    def test_refutation_by_typed_finding_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [{"sub_id": "H0001.3", "label": "H3", "title": "Guest vector",
                                   "likelihood_tier": "MEDIUM", "entities": ["GUEST"]}])
        base_log.record_finding("Guest-vector hypothesis refuted — profile empty", "UNCONFIRMED", "analysis",
                                tested_hypothesis_id="H0001",
                                claim=_normc(claim_kind="negative", category="other", act="presence",
                                             entities=["Guest"], resolves="refuted"))
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("guest" in i for i in r["blocking_issues"])

    def test_refutation_wording_no_longer_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [{"sub_id": "H0001.3", "label": "H3", "title": "helpdesk vector",
                                   "likelihood_tier": "MEDIUM", "entities": ["HELPDESK"]}])
        base_log.record_finding("helpdesk-vector hypothesis REFUTED — profile empty", "UNCONFIRMED", "analysis")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("helpdesk" in i for i in r["blocking_issues"])

    def test_builtin_contested_principal_skipped_unless_a_finding_names_it(self, base_log):
        # The reviewer listed "Guest" among contested principals; a
        # built-in nobody used must not force a disposition.
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [{"sub_id": "H0001.3", "label": "H3", "title": "Guest vector",
                                   "likelihood_tier": "MEDIUM", "entities": ["GUEST"]}])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("guest" in i for i in r["blocking_issues"])
        # …but once a finding names it, it is tracked like any principal.
        base_log.record_finding("Guest logged on interactively", "SUSPECTED", "ez.evtxecmd",
                                claim=_normc(claim_kind="positive", category="logon_auth", act="logon",
                                             entities=["Guest"]))
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("guest" in i for i in r["blocking_issues"])

    def test_typed_principal_disposition_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [self._H1])
        ev = base_log.record_tool_call("rip.pl -r SAM -p samparse", True, False, 0, 0)
        base_log.record_disposition("principal", "helpsvc", "excluded", evidence_call_ids=[ev])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("helpsvc" in i for i in r["blocking_issues"])

    def test_low_only_entity_warns_not_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [{"sub_id": "H0001.5", "label": "H5", "title": "malware account",
                                   "likelihood_tier": "LOW", "entities": ["SVCBOT"]}])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("svcbot" in i for i in r["blocking_issues"])
        assert any("svcbot" in w for w in r["warnings"])

    # ── live-run follow-ups ────────────────────────────────────────────────────

    def test_tier_only_synthesize_blockers_are_advisories(self):
        from tools.reasoning import _split_tier_blockers
        kept, tiers = _split_tier_blockers([
            "Systematic under-tiering: F4, F5, F6 are supported by physical logs but incorrectly tiered SUSPECTED/LIKELY.",
            "F5 (FTP pull) should be CONFIRMED given transfers.log",
            "Timeline discrepancy: FTP transfer (18:21) predates account creation (20:40).",
            "Unsubstantiated persistence: auto-run FTP server claim lacks registry artifact evidence.",
        ])
        assert len(tiers) == 2 and len(kept) == 2
        assert all("tier" in t.lower() or "CONFIRMED" in t for t in tiers)
        # synth 207's "refinement loop" objections are all tier opinions
        kept, tiers = _split_tier_blockers([
            "Anti-forensics claim relies solely on UserAssist execution; usage intent is SUSPECTED, not CONFIRMED.",
            "FTP server operational status conflated with binary execution; server binding/listening state is SUSPECTED.",
            "Credential brute-force (4648) success vector not linked to 4624; authentication vector is UNCONFIRMED.",
        ])
        assert kept == [] and len(tiers) == 3

    def test_synthesize_depth_gate_and_typed_findings_block(self, base_log, monkeypatch):
        # H-6: third synthesize without new evidence is refused; the reviewer
        # is shown the RECORDED findings (typed tiers), not only the narrative.
        import tools.reasoning as R
        seen = {}

        def _fake_ask(system, user, **kw):
            seen["user"] = user
            return {"success": True, "conclusion": "ok", "blockers": ["Verification of X needed"],
                    "_trudi_call_id": 0}
        monkeypatch.setattr(R, "_ask", _fake_ask)
        base_log.record_dair_call("Report", "", False, "", "", "stay", "")
        base_log.record_finding("defaultprinter created 2016-06-18", "LIKELY", "ez.evtxecmd",
                                claim=_normc(claim_kind="positive", category="persistence",
                                             act="account_creation", principal="defaultprinter"))
        with patch("core.execution_log.log", base_log):
            r1 = R.reason_synthesize("F1 CONFIRMED: defaultprinter created")   # round 1
            base_log.record_reason_call("reason_synthesize", True, "ok", {}, blockers=["Verification of X needed"])
            r2 = R.reason_synthesize("F1 …")                                    # round 2 (logged above as #1)
            base_log.record_reason_call("reason_synthesize", True, "ok", {}, blockers=["still"])
            r3 = R.reason_synthesize("F1 …")                                    # round 3 → refused
        assert r1["success"] is True and "RECORDED FINDINGS" in seen["user"]
        assert "[LIKELY] cid" in seen["user"] and "positive|persistence|account_creation" in seen["user"]
        assert r3["success"] is False and r3["gate"] == "synthesize_depth_limit"
        assert any(e.get("trigger") == "synthesize_depth_gate" for e in base_log._entries
                   if e.get("type") == "self_correction")
        # New evidence resets the counter.
        base_log.record_tool_call("dotnet EvtxECmd.dll -f Security.evtx", True, False, 0, 0)
        with patch("core.execution_log.log", base_log):
            r4 = R.reason_synthesize("F1 …")
        assert r4["success"] is True

    def test_pre_report_demotes_synthesize_blockers_after_round_two(self, base_log):
        # H-6 (c): round 2+ with no evidence in between → blockers become
        # warnings stamped synthesize_blockers_unresolved; write_final_report
        # appends them as 'Reviewer limitations'.
        from tools.reasoning import reason_pre_report_check
        # base_log already holds one synthesize; evidence work resets the round count.
        base_log.record_tool_call("dotnet EvtxECmd.dll -f Security.evtx", True, False, 0, 0)
        base_log.record_reason_call("reason_synthesize", True, "ok", {},
                                    blockers=["Verification of the UserAssist entry is needed"])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("unresolved BLOCKERS" in i for i in r["blocking_issues"])
        base_log.record_reason_call("reason_synthesize", True, "ok", {},
                                    blockers=["Verification of the UserAssist entry is needed"])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("unresolved BLOCKERS" in i for i in r["blocking_issues"])
        assert any("Reviewer limitations" in w for w in r["warnings"])
        pre = [e for e in base_log._entries if e.get("tool") == "reason_pre_report_check"][-1]
        assert pre["synthesize_blockers_unresolved"] == ["Verification of the UserAssist entry is needed"]

    def test_synthesize_accepts_the_report_push(self, base_log, monkeypatch):
        # G-13: DAIR's transition INTO Report is the Report entry.
        import tools.reasoning as R
        base_log.record_dair_call("Triage", "", True, "Report", "done", "push", "")
        monkeypatch.setattr(R, "_ask", lambda *a, **k: {"success": True, "conclusion": "ok",
                                                      "blockers": ["F1 should be CONFIRMED"],
                                                      "_trudi_call_id": 0})
        with patch("core.execution_log.log", base_log):
            r = R.reason_synthesize("F1 …")
        assert r["success"] is True and r["blockers"] == [] and r["tier_blockers_demoted"]
        base_log.record_dair_call("Analyze", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", base_log):
            r = R.reason_synthesize("F1 …")
        assert r["success"] is False and "only callable in Report" in r["error"]

    # ── single-user-device follow-ups: no session logs in evidence ───────────

    def test_placeholder_principals_are_not_contested(self, base_log):
        # The reviewer's RESULT.hypotheses listed "unknown" as a principal and
        # the agent had to "refute" it. Role words are not identities.
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [{"sub_id": "H0001.2", "label": "H2", "title": "someone else",
                                   "likelihood_tier": "HIGH", "entities": ["unknown"]}])
        cid = base_log.record_reason_call("reason_hypothesize", True, "h", {}, hypothesis_id="H0002")
        base_log.update_reason_call(cid, contested_principals=["Unknown actor", "attacker"])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("unknown" in i or "attacker" in i for i in r["blocking_issues"])

    def test_same_as_disposition_settles_contested_principal(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [self._H1])
        ev = base_log.record_tool_call("dotnet RECmd.dll -f SOFTWARE", True, False, 0, 0)
        base_log.record_disposition("principal", "helpsvc", "same_as", evidence_call_ids=[ev])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("helpsvc" in i for i in r["blocking_issues"])

    def test_evidence_unavailable_with_logon_source_waiver_warns_not_blocks(self, base_log):
        # XP with auditing off: no session artifact can exist. A park grounded
        # in a typed SOURCE waiver becomes a report caveat, not a blocker —
        # the alternative was a backwards 'refuted' on the prime subject.
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [self._H1])
        base_log.record_disposition("principal", "helpsvc", "evidence_unavailable")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("helpsvc" in i for i in r["blocking_issues"])        # park alone: still blocks
        base_log.record_disposition("source", "security_logon", "absent_from_evidence")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("helpsvc" in i for i in r["blocking_issues"])
        assert any("helpsvc" in w and "caveat" in w for w in r["warnings"])
