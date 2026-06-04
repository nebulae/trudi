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
        configured_log.record_finding(
            "Beacon on 172.16.6.11 PID 4044 (T1055)",
            "CONFIRMED", "vol.netscan")
        configured_log.record_finding(
            "Beacon on 172.16.4.7 PID 1820 (T1021)",
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
        configured_log.record_finding(
            "Beacon on 172.16.6.11 PID 4044 (T1055)",
            "CONFIRMED", "vol.netscan")
        configured_log.record_finding(
            "Beacon on 172.16.4.7 PID 1820 (T1021)",
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
            "Beacon on 172.16.6.11 PID 4044 (T1055)",
            "CONFIRMED", "vol.netscan")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert not any("cross-host" in w.lower() for w in r["warnings"])


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
    """G-Quality: reason.confidence_score returns evidence-grounded tier."""

    def test_confirmed_score_parsed(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_confidence_score
        inst = ExecutionLog()
        inst.configure("CS-001", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CONF_CONFIRMED):
            r = reason_confidence_score(
                "STUN.exe is the implant",
                "vol.psscan PID=5024 + tsk.fls match + VT 60/76 + ez.evtxecmd 7045",
                intended_tier="CONFIRMED",
            )
        assert r["success"] is True
        assert r["tier"] == "CONFIRMED"
        assert r["score"] >= 0.85
        assert r["downgrade_reasons"] == []

    def test_downgrade_with_reasons(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_confidence_score
        inst = ExecutionLog()
        inst.configure("CS-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CONF_DOWNGRADE):
            r = reason_confidence_score(
                "SystemSettings.dll is Cobalt Strike beacon",
                "YARA rule match only",
                intended_tier="CONFIRMED",
            )
        assert r["tier"] == "SUSPECTED"
        assert len(r["downgrade_reasons"]) > 0
        assert r["score"] < 0.60

    def test_unparseable_returns_unconfirmed_default(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_confidence_score
        inst = ExecutionLog()
        inst.configure("CS-003", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("no score block here"):
            r = reason_confidence_score("any finding", "any evidence")
        assert r["tier"] == "UNCONFIRMED"
        assert r["score"] == 0.0

    def test_score_clamped_to_unit_range(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_confidence_score
        inst = ExecutionLog()
        inst.configure("CS-004", str(tmp_path / "trace.json"))
        weird = (
            'CONFIDENCE_SCORE:\n{"tier":"CONFIRMED","score":99.0,'
            '"rationale":"x","downgrade_reasons":[]}'
        )
        with patch("core.execution_log.log", inst), _compat_ctx(weird):
            r = reason_confidence_score("a", "b")
        assert 0.0 <= r["score"] <= 1.0


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
            reason_evaluate_finding("malicious .exe", "stat output", case_context="CRIMSON OSPREY")
        entry = [e for e in inst._entries if e.get("tool") == "reason_evaluate_finding"][-1]
        assert "inputs" in entry
        assert "malicious .exe" in entry["inputs"]["user_message"]
        assert "CRIMSON OSPREY" in entry["inputs"]["user_message"]

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
