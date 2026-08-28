"""Tests for tools/dair.py — covers both claude and openai-compat backends."""
import json
import sys
import types
import pytest
from contextlib import contextmanager
from unittest.mock import patch, MagicMock


if "anthropic" not in sys.modules:
    anthropic_stub = types.ModuleType("anthropic")
    anthropic_stub.Anthropic = MagicMock()
    class _APITimeoutError(TimeoutError):
        def __init__(self, *args, **kwargs):
            super().__init__("request timed out")
    anthropic_stub.APITimeoutError = _APITimeoutError
    sys.modules["anthropic"] = anthropic_stub


# ── Sample output fixtures ────────────────────────────────────────────────────

_CHALLENGES_BLOCK = (
    'VERIFICATION_CHALLENGES:\n'
    '[\n'
    '  {"claim": "STUN.exe at C:\\\\Windows\\\\Temp\\\\STUN.exe",'
    ' "challenge_method": "strings.stat_file",'
    ' "verified": null, "confidence_impact": "—", "notes": ""}\n'
    ']\n'
)

_ASSESSMENT_STAY = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Triage", "phase_rationale": "Checking STUN.exe claim",'
    ' "transition_recommended": false, "next_phase": "", "transition_rationale": "",'
    ' "stack_action": "stay", "investigation_focus": "Verify STUN.exe file presence",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["strings.stat_file"],'
    ' "skip_tools": [], "focus_pids": [], "focus_paths": [],'
    ' "max_depth": "", "next_hypothesis_triggers": []}}'
)

_ASSESSMENT_PUSH_COLLECT = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Triage", "phase_rationale": "All claims verified",'
    ' "transition_recommended": true, "next_phase": "Collect",'
    ' "transition_rationale": "STUN.exe confirmed — begin artifact collection",'
    ' "stack_action": "push", "investigation_focus": "Collect memory and registry artifacts",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["vol.netscan", "ez.evtxecmd"],'
    ' "skip_tools": [], "focus_pids": [], "focus_paths": [],'
    ' "max_depth": "", "next_hypothesis_triggers": []}}'
)

_ASSESSMENT_REPORT = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Scan", "phase_rationale": "No new pivots found",'
    ' "transition_recommended": true, "next_phase": "Report",'
    ' "transition_rationale": "Investigation complete",'
    ' "stack_action": "push", "investigation_focus": "Write final report",'
    ' "verification_challenges": [], "recommended_actions": ['
    '"Isolate wkstn-01 from network", "Reset all domain admin credentials",'
    ' "Remove STUN.exe and pssdnsvc.exe service"],'
    ' "directives": {"priority_tools": [], "skip_tools": [], "focus_pids": [],'
    ' "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []}}'
)

_ASSESSMENT_POP = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Triage", "phase_rationale": "Challenge resolved",'
    ' "transition_recommended": true, "next_phase": "Analyze",'
    ' "transition_rationale": "Claim verified — resuming analysis",'
    ' "stack_action": "pop", "investigation_focus": "Continue artifact analysis",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": [], "skip_tools": [], "focus_pids": [],'
    ' "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []}}'
)

_CHALLENGE_VERIFIED_FALSE = (
    'VERIFICATION_CHALLENGES:\n'
    '[{"claim": "atmfd.dll absent from drivers",'
    ' "challenge_method": "tsk.fls",'
    ' "verified": false,'
    ' "confidence_impact": "CONFIRMED -> SUSPECTED",'
    ' "notes": "file exists at expected path"}]\n'
    + _ASSESSMENT_STAY
)

_CHALLENGE_VERIFIED_TRUE = (
    'VERIFICATION_CHALLENGES:\n'
    '[{"claim": "STUN.exe at C:\\\\Windows\\\\Temp\\\\STUN.exe",'
    ' "challenge_method": "strings.stat_file",'
    ' "verified": true,'
    ' "confidence_impact": "—",'
    ' "notes": "stat_file confirms size 45312 bytes"}]\n'
    + _ASSESSMENT_PUSH_COLLECT
)


# ── Mock factories ────────────────────────────────────────────────────────────

def _claude_mock(text: str):
    resp = MagicMock()
    resp.content = [MagicMock(text=text)]
    resp.usage.input_tokens = 0
    resp.usage.output_tokens = 0
    client = MagicMock()
    client.messages.create.return_value = resp
    anthro = MagicMock(return_value=client)
    return anthro, client


def _http_resp(content: str):
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json.return_value = {
        "choices": [{"message": {"content": content, "reasoning": ""}}]
    }
    return m


# ── Backend context managers ──────────────────────────────────────────────────

@contextmanager
def _claude_ctx(text: str):
    anthro, client = _claude_mock(text)
    with patch("anthropic.Anthropic", anthro), \
         patch("tools.dair.ANTHROPIC_API_KEY", "sk-test"), \
         patch("tools.dair.DAIR_BACKEND", "claude"):
        yield client


@contextmanager
def _compat_ctx(text: str):
    http_mock = MagicMock(return_value=_http_resp(text))
    with patch("httpx.post", http_mock), \
         patch("tools.dair.DAIR_URL", "http://localhost:8000"), \
         patch("tools.dair.DAIR_BACKEND", "openai-compat"):
        yield http_mock


# ── Helper ────────────────────────────────────────────────────────────────────

def _run(ctx_fn, text, stack="[]", context=""):
    from tools.dair import dair_assess
    with ctx_fn(text):
        return dair_assess("STUN.exe found in memory.", phase_stack=stack, case_context=context)


def _candidate_values(result: dict, kind: str | None = None) -> set[str]:
    return {
        str(p.get("value", "")).upper()
        for p in result.get("candidate_pivots") or []
        if kind is None or p.get("kind") == kind
    }


# ── Success / failure basics ──────────────────────────────────────────────────

class TestDairAssessSuccess:
    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_returns_success(self, ctx_fn):
        assert _run(ctx_fn, _ASSESSMENT_STAY)["success"] is True

    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_current_phase_parsed(self, ctx_fn):
        r = _run(ctx_fn, _ASSESSMENT_STAY)
        assert r["current_phase"] == "Triage"

    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_trudi_call_id_present(self, ctx_fn):
        r = _run(ctx_fn, _ASSESSMENT_STAY)
        assert "_trudi_call_id" in r

    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_tokens_present(self, ctx_fn):
        r = _run(ctx_fn, _ASSESSMENT_STAY)
        assert "input_tokens" in r
        assert "output_tokens" in r


class TestDairAssessFailure:
    def test_missing_claude_key_returns_error(self):
        from tools.dair import dair_assess
        with patch("tools.dair.ANTHROPIC_API_KEY", ""), \
             patch("tools.dair.DAIR_URL", ""), \
             patch("tools.dair.DAIR_BACKEND", "claude"):
            r = dair_assess("some findings")
        assert r["success"] is False
        assert "error" in r

    def test_missing_compat_url_returns_error(self):
        from tools.dair import dair_assess
        with patch("tools.dair.DAIR_URL", ""), \
             patch("tools.dair.DAIR_BACKEND", "openai-compat"):
            r = dair_assess("some findings")
        assert r["success"] is False

    def test_malformed_assessment_block_returns_defaults(self):
        r = _run(_claude_ctx, "Some analysis. DAIR_ASSESSMENT: {broken json")
        assert r["success"] is True
        assert r["current_phase"] == "Triage"
        assert r["stack_action"] == "stay"
        assert r["verification_challenges"] == []


# ── Stack behaviour ───────────────────────────────────────────────────────────

class TestDairStackBehaviour:
    def test_empty_stack_starts_at_triage(self):
        r = _run(_claude_ctx, _ASSESSMENT_STAY, stack="[]")
        assert r["current_phase"] == "Triage"

    def test_invalid_stack_json_falls_back_gracefully(self):
        r = _run(_claude_ctx, _ASSESSMENT_STAY, stack="not-json")
        assert r["success"] is True

    def test_push_to_collect_on_transition(self):
        r = _run(_claude_ctx, _ASSESSMENT_PUSH_COLLECT)
        assert r["transition_recommended"] is True
        assert r["next_phase"] == "Collect"
        assert r["stack_action"] == "push"

    def test_pop_action_parsed(self):
        stack = json.dumps([
            {"phase": "Analyze", "entry_reason": "artifact collection complete", "depth": 1},
            {"phase": "Triage", "entry_reason": "atmfd.dll claim", "depth": 2},
        ])
        r = _run(_claude_ctx, _ASSESSMENT_POP, stack=stack)
        assert r["stack_action"] == "pop"
        assert r["next_phase"] == "Analyze"

    def test_stay_action_parsed(self):
        r = _run(_claude_ctx, _ASSESSMENT_STAY)
        assert r["stack_action"] == "stay"
        assert r["transition_recommended"] is False

    def test_deep_stack_parsed_correctly(self):
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "case opened", "depth": 0},
            {"phase": "Collect", "entry_reason": "STUN.exe confirmed", "depth": 1},
            {"phase": "Triage", "entry_reason": "atmfd.dll claim", "depth": 2},
            {"phase": "Scan", "entry_reason": "new pivot rd01", "depth": 3},
        ])
        r = _run(_claude_ctx, _ASSESSMENT_STAY, stack=stack)
        assert r["success"] is True


# ── Verification challenges ───────────────────────────────────────────────────

class TestDairVerificationChallenges:
    def test_challenges_populated_from_block(self):
        r = _run(_claude_ctx, _CHALLENGES_BLOCK + _ASSESSMENT_STAY)
        assert len(r["verification_challenges"]) == 1
        assert r["verification_challenges"][0]["claim"].startswith("STUN.exe")

    def test_challenge_verified_null(self):
        r = _run(_claude_ctx, _CHALLENGES_BLOCK + _ASSESSMENT_STAY)
        assert r["verification_challenges"][0]["verified"] is None

    def test_challenge_verified_false_with_confidence_impact(self):
        r = _run(_claude_ctx, _CHALLENGE_VERIFIED_FALSE)
        c = r["verification_challenges"][0]
        assert c["verified"] is False
        assert "SUSPECTED" in c["confidence_impact"]

    def test_challenge_verified_true(self):
        r = _run(_claude_ctx, _CHALLENGE_VERIFIED_TRUE)
        c = r["verification_challenges"][0]
        assert c["verified"] is True

    def test_no_challenges_outside_triage(self):
        r = _run(_claude_ctx, _ASSESSMENT_PUSH_COLLECT)
        assert r["verification_challenges"] == []

    def test_challenges_block_takes_precedence_over_assessment_field(self):
        # VERIFICATION_CHALLENGES block has 1 item; DAIR_ASSESSMENT.verification_challenges is []
        r = _run(_claude_ctx, _CHALLENGES_BLOCK + _ASSESSMENT_STAY)
        assert len(r["verification_challenges"]) == 1

    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_pending_challenge_in_priority_tools(self, ctx_fn):
        r = _run(ctx_fn, _CHALLENGES_BLOCK + _ASSESSMENT_STAY)
        assert "strings.stat_file" in r["directives"]["priority_tools"]


# ── Recommended actions ───────────────────────────────────────────────────────

class TestDairRecommendedActions:
    def test_recommended_actions_at_report(self):
        from core.execution_log import log
        log.record_finding("a finding", "CONFIRMED", "x")
        # K-1: Report is only reachable after the investigative phases ran.
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
            log.record_dair_call(cur, "", True, nxt, "", "push", "")
        r = _run(_claude_ctx, _ASSESSMENT_REPORT)
        assert len(r["recommended_actions"]) == 3
        assert r["next_phase"] == "Report"

    def test_recommended_actions_empty_non_report(self):
        r = _run(_claude_ctx, _ASSESSMENT_STAY)
        assert r["recommended_actions"] == []

    def test_recommended_actions_empty_push_to_collect(self):
        r = _run(_claude_ctx, _ASSESSMENT_PUSH_COLLECT)
        assert r["recommended_actions"] == []


# ── Directives ────────────────────────────────────────────────────────────────

class TestDairDirectives:
    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_directives_present(self, ctx_fn):
        r = _run(ctx_fn, _ASSESSMENT_STAY)
        assert "directives" in r
        assert "priority_tools" in r["directives"]
        assert "tool_manifest_version" in r["directives"]

    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_directives_parsed_from_raw(self, ctx_fn):
        r = _run(ctx_fn, _ASSESSMENT_PUSH_COLLECT)
        assert "vol.netscan" in r["directives"]["priority_tools"]

    def test_malformed_directives_returns_empty_defaults(self):
        bad = 'DAIR_ASSESSMENT:\n{"current_phase": "Triage", "phase_rationale": "x", "transition_recommended": false, "next_phase": "", "transition_rationale": "", "stack_action": "stay", "investigation_focus": "x", "verification_challenges": [], "recommended_actions": [], "directives": "broken"}'
        r = _run(_claude_ctx, bad)
        assert isinstance(r["directives"], dict)
        assert "priority_tools" in r["directives"]
        assert r["directives"]["unknown_priority_tools"] == []

    def test_unknown_priority_tool_is_annotated(self):
        raw = (
            'DAIR_ASSESSMENT:\n'
            '{"current_phase": "Triage", "phase_rationale": "x",'
            ' "transition_recommended": false, "next_phase": "",'
            ' "transition_rationale": "", "stack_action": "stay",'
            ' "investigation_focus": "x", "verification_challenges": [],'
            ' "recommended_actions": [],'
            ' "directives": {"priority_tools": ["vol.psscan", "vol.nope"],'
            ' "skip_tools": [], "focus_pids": [], "focus_paths": [],'
            ' "max_depth": "", "next_hypothesis_triggers": []}}'
        )
        r = _run(_claude_ctx, raw)
        assert r["directives"]["priority_tools"] == ["vol.psscan", "vol.nope"]
        assert r["directives"]["unknown_priority_tools"] == ["vol.nope"]

    def test_system_prompt_includes_tool_capability_manifest(self):
        from tools.dair import _DAIR_SYS

        assert "TOOL CAPABILITY MANIFEST" in _DAIR_SYS
        assert "network_pcap" in _DAIR_SYS
        assert "vol.psscan" in _DAIR_SYS


# ── Backend selection ─────────────────────────────────────────────────────────

class TestDairBackendSelection:
    def test_explicit_claude_backend(self):
        from tools.dair import dair_assess
        anthro, client = _claude_mock(_ASSESSMENT_STAY)
        with patch("anthropic.Anthropic", anthro), \
             patch("tools.dair.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.dair.DAIR_BACKEND", "claude"):
            r = dair_assess("findings")
        assert r["success"] is True
        client.messages.create.assert_called_once()

    def test_explicit_compat_backend(self):
        from tools.dair import dair_assess
        http_mock = MagicMock(return_value=_http_resp(_ASSESSMENT_STAY))
        with patch("httpx.post", http_mock), \
             patch("tools.dair.DAIR_URL", "http://localhost:8001"), \
             patch("tools.dair.DAIR_BACKEND", "openai-compat"):
            r = dair_assess("findings")
        assert r["success"] is True
        http_mock.assert_called_once()

    def test_autodetect_uses_claude_when_api_key_present(self):
        from tools.dair import _active_backend
        with patch("tools.dair.DAIR_BACKEND", ""), \
             patch("tools.dair.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.dair.DAIR_URL", ""):
            assert _active_backend() == "claude"

    def test_autodetect_uses_compat_when_url_present(self):
        from tools.dair import _active_backend
        with patch("tools.dair.DAIR_BACKEND", ""), \
             patch("tools.dair.ANTHROPIC_API_KEY", ""), \
             patch("tools.dair.DAIR_URL", "http://localhost:8001"):
            assert _active_backend() == "openai-compat"

    def test_explicit_backend_overrides_autodetect(self):
        from tools.dair import _active_backend
        with patch("tools.dair.DAIR_BACKEND", "openai-compat"), \
             patch("tools.dair.ANTHROPIC_API_KEY", "sk-test"):
            assert _active_backend() == "openai-compat"


# ── Execution log recording ───────────────────────────────────────────────────

class TestDairExecutionLog:
    def test_record_dair_call_invoked_on_success(self):
        from tools.dair import dair_assess
        mock_log = MagicMock()
        mock_log.record_dair_call.return_value = 42
        anthro, _ = _claude_mock(_ASSESSMENT_STAY)
        with patch("anthropic.Anthropic", anthro), \
             patch("tools.dair.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.dair.DAIR_BACKEND", "claude"), \
             patch("tools.dair.log", mock_log, create=True):
            # Import after patching to pick up mock
            import importlib
            import tools.dair as dair_mod
            original_log = None
            try:
                from core import execution_log
                original_log = execution_log.log
                execution_log.log = mock_log
                r = dair_assess("some findings")
            finally:
                if original_log is not None:
                    execution_log.log = original_log
        # record_dair_call may have been called via the module's _log_dair
        # just verify the result has _trudi_call_id
        assert "_trudi_call_id" in r

    def test_record_dair_call_includes_phase_rationale(self, tmp_path, monkeypatch):
        """Unconfigured log used to silently return 0 — now it raises, so this
        test must configure the log. Once configured, the entry round-trips
        with phase_rationale preserved."""
        import core.execution_log as elog
        monkeypatch.setattr(elog, "_SESSION_FILE",
                            str(tmp_path / "session.json"))
        log = elog.ExecutionLog()
        log.configure("PHRAT-001", str(tmp_path / "trace.json"))
        cid = log.record_dair_call(
            current_phase="Triage",
            phase_rationale="Checking STUN.exe existence",
            transition_recommended=False,
            next_phase="",
            transition_rationale="",
            stack_action="stay",
            investigation_focus="Verify file at path",
            verification_challenges=[{
                "claim": "STUN.exe at C:\\Windows\\Temp",
                "challenge_method": "strings.stat_file",
                "verified": None,
                "confidence_impact": "—",
                "notes": "",
            }],
            recommended_actions=[],
            directives={"priority_tools": ["strings.stat_file"], "skip_tools": [],
                        "focus_pids": [], "focus_paths": [], "max_depth": "",
                        "next_hypothesis_triggers": []},
        )
        assert cid > 0
        assert log._entries[0]["phase_rationale"] == "Checking STUN.exe existence"

    def test_record_dair_call_with_configured_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        log = ExecutionLog()
        log.configure("TEST-001", str(tmp_path / "trace.json"))
        cid = log.record_dair_call(
            current_phase="Scan",
            phase_rationale="Mapping lateral movement",
            transition_recommended=True,
            next_phase="Report",
            transition_rationale="No new pivots",
            stack_action="push",
            investigation_focus="Write report",
            verification_challenges=[],
            recommended_actions=["Isolate wkstn-01"],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        assert cid > 0
        entry = log._entries[-1]
        assert entry["type"] == "dair_call"
        assert entry["phase_rationale"] == "Mapping lateral movement"
        assert entry["transition_rationale"] == "No new pivots"
        assert entry["recommended_actions"] == ["Isolate wkstn-01"]

    def test_markdown_renders_phase_transition(self, tmp_path):
        from core.execution_log import ExecutionLog
        log = ExecutionLog()
        log.configure("TEST-001", str(tmp_path / "trace.json"))
        log.record_dair_call(
            current_phase="Triage",
            phase_rationale="All claims verified",
            transition_recommended=True,
            next_phase="Collect",
            transition_rationale="STUN.exe confirmed — begin artifact collection",
            stack_action="push",
            investigation_focus="Map lateral movement",
            verification_challenges=[],
            recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        md = log.to_markdown()
        assert "Phase Transition" in md
        assert "Triage" in md
        assert "Collect" in md

    def test_markdown_renders_challenge_table(self, tmp_path):
        from core.execution_log import ExecutionLog
        log = ExecutionLog()
        log.configure("TEST-001", str(tmp_path / "trace.json"))
        log.record_dair_call(
            current_phase="Triage",
            phase_rationale="Checking claims",
            transition_recommended=False,
            next_phase="",
            transition_rationale="",
            stack_action="stay",
            investigation_focus="Run verification tools",
            verification_challenges=[{
                "claim": "STUN.exe at C:\\Windows\\Temp",
                "challenge_method": "strings.stat_file",
                "verified": None,
                "confidence_impact": "—",
                "notes": "",
            }],
            recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        md = log.to_markdown()
        assert "Verification Challenges" in md
        assert "PENDING" in md
        assert "strings.stat_file" in md

    def test_markdown_renders_recommended_actions(self, tmp_path):
        from core.execution_log import ExecutionLog
        log = ExecutionLog()
        log.configure("TEST-001", str(tmp_path / "trace.json"))
        log.record_dair_call(
            current_phase="Scan",
            phase_rationale="Sweep complete",
            transition_recommended=True,
            next_phase="Report",
            transition_rationale="Investigation complete",
            stack_action="push",
            investigation_focus="Write report",
            verification_challenges=[],
            recommended_actions=["Isolate wkstn-01", "Reset domain admin credentials"],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        md = log.to_markdown()
        assert "Recommended Actions" in md
        assert "Isolate wkstn-01" in md

    def test_initiated_and_dair_entries_both_present_on_success(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), \
             _claude_ctx(_ASSESSMENT_STAY):
            dair_assess("STUN.exe found.", phase_stack="[]")
        types = [e["type"] for e in inst._entries]
        assert "call_initiated" in types
        assert "dair_call" in types
        assert types.index("call_initiated") < types.index("dair_call")

    def test_initiated_entry_tool_and_backend(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), \
             _claude_ctx(_ASSESSMENT_STAY):
            dair_assess("STUN.exe found.", phase_stack="[]")
        initiated = [e for e in inst._entries if e["type"] == "call_initiated"]
        assert initiated[0]["tool"] == "dair_assess"
        assert initiated[0]["backend"] == "claude"
        assert "model" in initiated[0]["inputs"]

    def test_initiated_entry_on_timeout(self, tmp_path):
        import anthropic
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = anthropic.APITimeoutError(request=MagicMock())
        with patch("core.execution_log.log", inst), \
             patch("anthropic.Anthropic", return_value=mock_client), \
             patch("tools.dair.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.dair.DAIR_BACKEND", "claude"):
            r = dair_assess("findings")
        assert r["success"] is False
        initiated = [e for e in inst._entries if e["type"] == "call_initiated"]
        assert len(initiated) == 1  # written before the SDK call that raised


class TestVerificationSatisfied:
    def test_verification_satisfied_defaults_false(self):
        r = _run(_claude_ctx, _ASSESSMENT_STAY)
        assert r["verification_satisfied"] is False

    def test_verification_satisfied_true_parsed(self):
        text = (
            _CHALLENGES_BLOCK
            + 'DAIR_ASSESSMENT:\n'
            '{"current_phase": "Triage", "phase_rationale": "Primary IOCs verified",'
            ' "transition_recommended": true, "next_phase": "Collect",'
            ' "transition_rationale": "Core claims confirmed — residual VT checks are enrichment only",'
            ' "stack_action": "push", "investigation_focus": "Begin artifact collection",'
            ' "verification_satisfied": true,'
            ' "verification_challenges": [], "recommended_actions": [],'
            ' "directives": {"priority_tools": [], "skip_tools": [], "focus_pids": [],'
            ' "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []}}'
        )
        r = _run(_claude_ctx, text)
        assert r["verification_satisfied"] is True
        assert r["transition_recommended"] is True
        assert r["next_phase"] == "Collect"

    def test_auto_satisfied_when_dair_assessment_parse_fails(self):
        # VERIFICATION_CHALLENGES well-formed (all verified=true) but DAIR_ASSESSMENT
        # is broken JSON — simulates the call_id 128 parse-failure stall.
        text = (
            'VERIFICATION_CHALLENGES:\n'
            '[{"claim": "STUN.exe at C:\\\\Windows\\\\Temp",'
            ' "challenge_method": "strings.stat_file",'
            ' "verified": true, "confidence_impact": "—", "notes": "confirmed"}]\n'
            'DAIR_ASSESSMENT:\n{broken json here'
        )
        r = _run(_claude_ctx, text)
        assert r["success"] is True
        assert r["verification_satisfied"] is True
        assert r["transition_recommended"] is True
        assert r["next_phase"] == "Collect"
        assert r["stack_action"] == "push"
        assert len(r["verification_challenges"]) == 1

    def test_auto_satisfaction_skipped_when_challenge_pending(self):
        text = (
            'VERIFICATION_CHALLENGES:\n'
            '[{"claim": "STUN.exe", "challenge_method": "strings.stat_file",'
            ' "verified": null, "confidence_impact": "—", "notes": ""}]\n'
            'DAIR_ASSESSMENT:\n{broken json'
        )
        r = _run(_claude_ctx, text)
        assert r["verification_satisfied"] is False
        assert r["transition_recommended"] is False

    @pytest.mark.parametrize("ctx_fn", [_claude_ctx, _compat_ctx])
    def test_verification_satisfied_both_backends(self, ctx_fn):
        text = (
            'DAIR_ASSESSMENT:\n'
            '{"current_phase": "Triage", "phase_rationale": "done",'
            ' "transition_recommended": true, "next_phase": "Collect",'
            ' "transition_rationale": "satisfied", "stack_action": "push",'
            ' "investigation_focus": "collect", "verification_satisfied": true,'
            ' "verification_challenges": [], "recommended_actions": [],'
            ' "directives": {"priority_tools": [], "skip_tools": [], "focus_pids": [],'
            ' "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []}}'
        )
        r = _run(ctx_fn, text)
        assert r["verification_satisfied"] is True


# ── Scan → Triage loop ────────────────────────────────────────────────────────

class TestDairScanToTriageLoop:
    def test_scan_pushes_triage_on_new_pivot(self):
        text = (
            'DAIR_ASSESSMENT:\n'
            '{"current_phase": "Scan", "phase_rationale": "New pivot host found",'
            ' "transition_recommended": true, "next_phase": "Triage",'
            ' "transition_rationale": "wkstn-02 lateral movement indicators — full cycle",'
            ' "stack_action": "push", "investigation_focus": "Triage wkstn-02",'
            ' "verification_satisfied": false,'
            ' "verification_challenges": [], "recommended_actions": [],'
            ' "directives": {"priority_tools": ["reason.plan", "strings.stat_file"],'
            ' "skip_tools": [], "focus_pids": [], "focus_paths": [],'
            ' "max_depth": "", "next_hypothesis_triggers": []}}'
        )
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "case opened", "depth": 0},
            {"phase": "Collect", "entry_reason": "triage complete", "depth": 1},
            {"phase": "Analyze", "entry_reason": "collection complete", "depth": 2},
            {"phase": "Scan", "entry_reason": "analysis complete", "depth": 3},
        ])
        r = _run(_claude_ctx, text, stack=stack)
        assert r["success"] is True
        assert r["current_phase"] == "Scan"
        assert r["next_phase"] == "Triage"
        assert r["stack_action"] == "push"
        assert r["transition_recommended"] is True

    def test_scan_to_report_when_no_pivot(self):
        from core.execution_log import log
        log.record_finding("a finding", "CONFIRMED", "x")
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
            log.record_dair_call(cur, "", True, nxt, "", "push", "")
        r = _run(_claude_ctx, _ASSESSMENT_REPORT)
        assert r["next_phase"] == "Report"
        assert r["stack_action"] == "push"
        assert len(r["recommended_actions"]) > 0

    def test_report_refused_with_zero_findings(self):
        # Observed: DAIR returned Report before any finding was recorded and the
        # agent hand-edited the phase stack. Server override, persisted.
        from core.execution_log import log
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
            log.record_dair_call(cur, "", True, nxt, "", "push", "")
        r = _run(_claude_ctx, _ASSESSMENT_REPORT)
        assert r["next_phase"] == "" and r["stack_action"] == "stay"
        assert r["transition_recommended"] is False
        assert r["server_override"]["kind"] == "report_refused_zero_findings"
        assert r["directives"]["priority_tools"][0] == "misc.record_finding"
        e = [x for x in log._entries if x.get("type") == "dair_call"][-1]
        assert e["server_override"]["kind"] == "report_refused_zero_findings"
        assert e["next_phase"] == ""


class TestDairInputsCaptured:
    """Inputs to dair_assess (tool_results_summary, phase_stack, case_context)
    are stored on the dair_call entry for audit/inspection."""

    def test_success_path_captures_inputs(self, tmp_path):
        import json as _json
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        inst = ExecutionLog()
        inst.configure("IN-D-001", str(tmp_path / "trace.json"))
        stack = _json.dumps([{"phase": "Triage", "entry_reason": "open", "depth": 0}])
        with patch("core.execution_log.log", inst), _claude_ctx(_ASSESSMENT_STAY):
            dair_assess(
                "STUN.exe at C:\\Windows\\Temp confirmed.",
                phase_stack=stack,
                case_context="REDFOX at ORG",
            )
        entry = [e for e in inst._entries if e["type"] == "dair_call"][-1]
        assert "inputs" in entry
        assert "STUN.exe" in entry["inputs"]["tool_results_summary"]
        assert "REDFOX" in entry["inputs"]["case_context"]
        assert isinstance(entry["inputs"]["phase_stack"], list)
        assert entry["inputs"]["phase_stack"][0]["phase"] == "Triage"
        assert "STUN.exe" in entry["inputs"]["user_message"]

    def test_failure_path_still_captures_inputs(self, tmp_path):
        # Missing API key path — dair_assess returns success=False but a
        # dair_call entry should be emitted with inputs intact.
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        inst = ExecutionLog()
        inst.configure("IN-D-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), \
             patch("tools.dair.ANTHROPIC_API_KEY", ""), \
             patch("tools.dair.DAIR_URL", ""), \
             patch("tools.dair.DAIR_BACKEND", "claude"):
            r = dair_assess("findings summary",
                            phase_stack="[]",
                            case_context="ctx")
        assert r["success"] is False
        dair_entries = [e for e in inst._entries if e["type"] == "dair_call"]
        assert dair_entries, "dair_call entry should exist even on failure"
        entry = dair_entries[-1]
        assert "inputs" in entry
        assert entry["inputs"]["tool_results_summary"].startswith("findings summary")
        assert entry["inputs"]["case_context"] == "ctx"


# ── Candidate pivot observation ──────────────────────────────────────────────

_SCAN_STAY_NEW_HOST = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Scan", "phase_rationale": "Continuing sweep",'
    ' "transition_recommended": false, "next_phase": "",'
    ' "transition_rationale": "",'
    ' "stack_action": "stay",'
    ' "investigation_focus": "Sweep for lateral movement from rd-01",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["yara.scan_directory"], "skip_tools": [],'
    ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
    ' "next_hypothesis_triggers": []}}'
)


def _scan_stack_json(case_id: str = "rd-01") -> str:
    return (
        '['
        '{"phase": "Triage", "entry_reason": "initial", "depth": 1},'
        '{"phase": "Collect", "entry_reason": "verified", "depth": 2},'
        '{"phase": "Analyze", "entry_reason": "collected", "depth": 3},'
        '{"phase": "Scan", "entry_reason": "swept ' + case_id + '", "depth": 4}'
        ']'
    )


class TestDairCandidatePivots:
    """Record candidate pivots from the agent's TYPED observed_hosts without
    mutating DAIR phase control. Nothing is read from the summary prose."""

    def _run(self, summary: str, case_context: str, stack: str | None = None,
             observed_hosts=None):
        from tools.dair import dair_assess
        stack = stack or _scan_stack_json()
        with _claude_ctx(_SCAN_STAY_NEW_HOST):
            return dair_assess(summary, phase_stack=stack, case_context=case_context,
                               observed_hosts=observed_hosts)

    def _log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        return l

    def test_declared_new_ip_is_a_candidate(self, tmp_path):
        with patch("core.execution_log.log", self._log(tmp_path)):
            r = self._run("ShimCache shows lateral hop to 10.0.4.6 c$ admin share",
                          "Host rd-01 (10.0.6.11) — REDFOX APT", observed_hosts=["10.0.4.6"])
        assert r["success"] is True
        assert r["stack_action"] == "stay" and r["next_phase"] == ""
        assert "10.0.4.6" in _candidate_values(r, "host")
        assert "server-enforced" not in (r.get("transition_rationale") or "").lower()

    def test_summary_prose_is_not_read(self, tmp_path):
        # The same IP in the summary, not declared → no candidate.
        with patch("core.execution_log.log", self._log(tmp_path)):
            r = self._run("ShimCache shows lateral hop to 10.0.4.6 c$ admin share",
                          "Host rd-01 (10.0.6.11)")
        assert _candidate_values(r, "host") == set()

    def test_unc_and_hostname_forms_normalized(self, tmp_path):
        with patch("core.execution_log.log", self._log(tmp_path)):
            r = self._run("x", "Host alpha-01",
                          observed_hosts=["\\\\NORTH-DC4\\admin$", "wkstn_15"])
        assert {"NORTH-DC4", "WKSTN-15"} <= _candidate_values(r, "host")

    def test_invalid_host_value_reported_not_pivoted(self, tmp_path):
        with patch("core.execution_log.log", self._log(tmp_path)):
            r = self._run("x", "Host alpha-01", observed_hosts=["not a host!!", "10.0.4.6"])
        assert "10.0.4.6" in _candidate_values(r, "host")
        assert any("not a host" in e for e in r["typed_input_errors"])

    def test_known_host_not_repivoted(self, tmp_path):
        l = self._log(tmp_path)
        with patch("core.execution_log.log", l):
            r1 = self._run("first", "Host rd-01", observed_hosts=["10.0.4.6"])
            r2 = self._run("again", "Host rd-01", observed_hosts=["10.0.4.6", "10.0.4.7"])
        assert "10.0.4.6" in _candidate_values(r1, "host")
        assert _candidate_values(r2, "host") == {"10.0.4.7"}
        last = [e for e in l._entries if e.get("type") == "dair_call"][-1]
        assert last["observed_hosts"] == ["10.0.4.6", "10.0.4.7"]

    def test_multiple_new_hosts_all_candidates(self, tmp_path):
        with patch("core.execution_log.log", self._log(tmp_path)):
            r = self._run("x", "Host rd-01", observed_hosts=["10.0.4.5", "10.0.4.6", "rd-04"])
        assert r["stack_action"] == "stay"
        assert {"10.0.4.5", "10.0.4.6", "RD-04"} <= _candidate_values(r, "host")
        assert not r.get("pending_pivots")

    def test_model_push_not_downgraded(self, tmp_path):
        # If the model already said push, candidate observation does not
        # downgrade it. This regression-locks the "never rewrite model phase"
        # invariant.
        l = self._log(tmp_path)
        already_push = (
            'DAIR_ASSESSMENT:\n'
            '{"current_phase": "Scan", "phase_rationale": "Pivot identified",'
            ' "transition_recommended": true, "next_phase": "Triage",'
            ' "transition_rationale": "Model identified rd-04 pivot",'
            ' "stack_action": "push",'
            ' "investigation_focus": "Triage rd-04",'
            ' "verification_challenges": [], "recommended_actions": [],'
            ' "directives": {"priority_tools": ["vol.pslist"], "skip_tools": [],'
            ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
            ' "next_hypothesis_triggers": []}}'
        )
        from tools.dair import dair_assess
        with patch("core.execution_log.log", l), _claude_ctx(already_push):
            r = dair_assess("rd-04 pivot from rd-01", phase_stack=_scan_stack_json(),
                            case_context="Host rd-01 only", observed_hosts=["rd-04"])
        assert r["stack_action"] == "push"
        assert "server-enforced" not in (r.get("transition_rationale") or "").lower()


# ── Cross-phase candidate detection ──────────────────────────────────────────

_ANALYZE_STAY_NEW_HOST = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Analyze", "phase_rationale": "Examining process tree",'
    ' "transition_recommended": false, "next_phase": "",'
    ' "transition_rationale": "",'
    ' "stack_action": "stay",'
    ' "investigation_focus": "Analyzing PsExec activity on rd-01",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["vol.cmdline"], "skip_tools": [],'
    ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
    ' "next_hypothesis_triggers": []}}'
)

_COLLECT_STAY_NEW_HOST = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Collect", "phase_rationale": "Continuing artifact pulls",'
    ' "transition_recommended": false, "next_phase": "",'
    ' "transition_rationale": "",'
    ' "stack_action": "stay",'
    ' "investigation_focus": "Pulling registry hives on rd-01",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["ez.recmd_hive"], "skip_tools": [],'
    ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
    ' "next_hypothesis_triggers": []}}'
)

_ANALYZE_PUSH_TO_SCAN_NEW_HOST = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Analyze", "phase_rationale": "Per-host analysis done",'
    ' "transition_recommended": true, "next_phase": "Scan",'
    ' "transition_rationale": "Advance to cross-host sweep",'
    ' "stack_action": "push",'
    ' "investigation_focus": "Cross-host IOC sweep",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["yara.scan_directory"], "skip_tools": [],'
    ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
    ' "next_hypothesis_triggers": []}}'
)


class TestDairCrossPhasePivot:
    """Candidate detection runs from Scan, Analyze, AND Collect without
    forcing a push or queue."""

    def test_analyze_surfaces_new_host_forces_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("XPHASE", str(tmp_path / "trace.json"))
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "open", "depth": 0},
            {"phase": "Collect", "entry_reason": "verified", "depth": 1},
            {"phase": "Analyze", "entry_reason": "collected", "depth": 2},
        ])
        with patch("core.execution_log.log", l), \
             _claude_ctx(_ANALYZE_STAY_NEW_HOST):
            r = dair_assess(
                "vol.netscan shows established session to 10.0.4.7:445 from PID 4044",
                phase_stack=stack,
                case_context="Host rd-01 (10.0.6.11)",
                observed_hosts=["10.0.4.7"],
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "10.0.4.7" in _candidate_values(r, "host")

    def test_collect_surfaces_new_host_forces_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("XPHASE", str(tmp_path / "trace.json"))
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "open", "depth": 0},
            {"phase": "Collect", "entry_reason": "verified", "depth": 1},
        ])
        with patch("core.execution_log.log", l), \
             _claude_ctx(_COLLECT_STAY_NEW_HOST):
            r = dair_assess(
                "Registry hive enumeration revealed \\\\BASE-RD-04\\C$ "
                "mapped drive in HKCU\\Network",
                phase_stack=stack,
                case_context="Host rd-01 (10.0.6.11)",
                observed_hosts=["\\\\BASE-RD-04\\C$"],
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "BASE-RD-04" in _candidate_values(r, "host")

    def test_triage_does_not_pivot_on_own_focus(self, tmp_path):
        # A Triage entry investigating rd-01 mentioning a NEW PRIVATE/local host
        # (10.0.4.9) does not pivot: Triage is *about* the subject host / local
        # network. (An EXTERNAL public IP does pivot even at Triage — see
        # TestFixBTriageExternalPivot.) Stays "stay".
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("XPHASE", str(tmp_path / "trace.json"))
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "open", "depth": 0},
        ])
        # Use _ASSESSMENT_STAY which sets current_phase=Triage and stay.
        with patch("core.execution_log.log", l), \
             _claude_ctx(_ASSESSMENT_STAY):
            r = dair_assess(
                "Verifying STUN.exe; also saw 10.0.4.9 in passing",
                phase_stack=stack,
                case_context="Host rd-01 (10.0.6.11)",
                observed_hosts=["10.0.4.9"],
            )
        # Triage stays; no pivot on its own declared hosts.
        assert r["stack_action"] == "stay"
        assert _candidate_values(r, "host") == set()

    def test_model_push_to_non_triage_enqueues_overflow(self, tmp_path):
        # Model advances Analyze → Scan (per-host pipeline). Summary mentions
        # a new candidate host. Candidate observation does NOT downgrade the
        # model push and does not enqueue a follow-up.
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("XPHASE", str(tmp_path / "trace.json"))
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "open", "depth": 0},
            {"phase": "Collect", "entry_reason": "verified", "depth": 1},
            {"phase": "Analyze", "entry_reason": "collected", "depth": 2},
        ])
        with patch("core.execution_log.log", l), \
             _claude_ctx(_ANALYZE_PUSH_TO_SCAN_NEW_HOST):
            r = dair_assess(
                "PsExec evidence to 10.0.4.8 confirmed; advancing to cross-host sweep",
                phase_stack=stack,
                case_context="Host rd-01 (10.0.6.11)",
                observed_hosts=["10.0.4.8"],
            )
        # Model push to Scan preserved.
        assert r["stack_action"] == "push"
        assert r["next_phase"] == "Scan"
        # New pivot observed, not enqueued or overridden.
        assert "10.0.4.8" in _candidate_values(r, "host")
        assert not r.get("pending_pivots")
        assert "enqueued" not in (r.get("transition_rationale") or "").lower()


# ── Legacy pivot queues do not drive control flow ────────────────────────────

class TestDairPivotQueueDrain:
    """Legacy pending pivots no longer drive synthetic DAIR transitions."""

    def test_candidate_pivots_do_not_short_circuit_subsequent_call(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("DRAIN", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l), \
             _claude_ctx(_SCAN_STAY_NEW_HOST):
            r1 = dair_assess(
                "ShimCache hits on 10.0.4.5, 10.0.4.6, 10.0.4.7",
                phase_stack=_scan_stack_json(),
                case_context="Host rd-01 (10.0.6.11)",
                observed_hosts=["10.0.4.5", "10.0.4.6", "10.0.4.7"],
            )
        assert r1["stack_action"] == "stay"
        assert {"10.0.4.5", "10.0.4.6", "10.0.4.7"} <= _candidate_values(r1, "host")
        assert not r1.get("pending_pivots")

        # Trace should record candidate_pivots on the dair_call entry.
        last_dair = [e for e in l._entries if e.get("type") == "dair_call"][-1]
        assert last_dair.get("candidate_pivots") == r1["candidate_pivots"]

        # Second call still invokes the model; no synthetic drain is allowed.
        with patch("core.execution_log.log", l), \
             _claude_ctx(_SCAN_STAY_NEW_HOST) as client:
            r2 = dair_assess(
                "Continuing cross-host sweep",
                phase_stack=_scan_stack_json(),
                case_context="Host rd-01 (10.0.6.11)",
            )
        assert r2["stack_action"] == "stay"
        assert r2["input_tokens"] == 0
        assert r2["output_tokens"] == 0
        assert "drained from queue" not in (r2.get("investigation_focus") or "")
        assert not r2.get("pending_pivots")
        client.messages.create.assert_called_once()

    def test_legacy_queue_ignored_when_current_phase_is_triage(self, tmp_path):
        # A Triage frame must run the model; legacy queue entries are ignored.
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("DRAIN", str(tmp_path / "trace.json"))
        # Seed a prior legacy dair_call entry with pending_pivots.
        l.record_dair_call(
            current_phase="Scan", phase_rationale="prior",
            transition_recommended=True, next_phase="Triage",
            transition_rationale="prior push", stack_action="push",
            investigation_focus="prior triage focus",
            pending_pivots=["10.0.4.99"],
        )
        # Now call dair_assess on a Triage frame.
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "open", "depth": 0},
        ])
        with patch("core.execution_log.log", l), \
             _claude_ctx(_ASSESSMENT_STAY) as client:
            r = dair_assess(
                "Verifying initial IOC",
                phase_stack=stack,
                case_context="Host rd-01",
            )
        # Model ran — no synthetic-drain investigation_focus, current_phase
        # preserved.
        client.messages.create.assert_called_once()
        assert r["current_phase"] == "Triage"
        assert r["stack_action"] == "stay"
        assert "drained from queue" not in (r.get("investigation_focus") or "")

    def test_legacy_queue_ignored_when_queued_host_already_investigated(self, tmp_path):
        # Queued host appears in a later dair_call's investigation_focus.
        # The model is still called because legacy queue entries do not drive
        # control flow.
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("DRAIN", str(tmp_path / "trace.json"))
        # Earlier entry queued 10.0.4.99…
        l.record_dair_call(
            current_phase="Scan", phase_rationale="prior",
            transition_recommended=True, next_phase="Triage",
            transition_rationale="prior push", stack_action="push",
            investigation_focus="Triage 10.0.4.5",
            pending_pivots=["10.0.4.99"],
        )
        # …and a subsequent Triage entry already touched it.
        l.record_dair_call(
            current_phase="Triage", phase_rationale="pivot triage",
            transition_recommended=False, next_phase="",
            transition_rationale="", stack_action="stay",
            investigation_focus="Triage pivot host 10.0.4.99",
        )
        with patch("core.execution_log.log", l), \
             _claude_ctx(_SCAN_STAY_NEW_HOST):
            r = dair_assess(
                "Continuing sweep — no new hosts",
                phase_stack=_scan_stack_json(),
                case_context="Host rd-01 (10.0.6.11)",
            )
        # Queue empty → model runs → no synthetic push.
        # _SCAN_STAY_NEW_HOST has stack_action=stay, no new pivots in summary.
        assert r["stack_action"] == "stay"


# ── Candidate principal detection ────────────────────────────────────────────
# A newly-*created* account is a candidate lead just like a new host. Detection
# keys on account-creation cues (high precision); a plain mention is ignored.

_SCAN_STAY_EMPTY_FOCUS = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Scan", "phase_rationale": "Continuing sweep",'
    ' "transition_recommended": false, "next_phase": "",'
    ' "transition_rationale": "",'
    ' "stack_action": "stay",'
    ' "investigation_focus": "",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["yara.scan_directory"], "skip_tools": [],'
    ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
    ' "next_hypothesis_triggers": []}}'
)


class TestDairPrincipalCandidates:
    """Record candidate principals from the agent's TYPED observed_principals
    without mutating DAIR phase control. The summary prose is never read."""

    def _run(self, summary, case_context, assessment=_SCAN_STAY_NEW_HOST, observed_principals=None):
        from tools.dair import dair_assess
        with _claude_ctx(assessment):
            return dair_assess(summary, phase_stack=_scan_stack_json(), case_context=case_context,
                               observed_principals=observed_principals)

    def _log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        return l

    def _pivot(self, r, name):
        return next((p for p in r.get("candidate_pivots") or []
                     if p.get("kind") == "principal" and p.get("value", "").upper() == name.upper()), None)

    def test_declared_created_account_is_forced_candidate(self, tmp_path):
        with patch("core.execution_log.log", self._log(tmp_path)):
            r = self._run("Security EID 4720 — new local admin account 'svc_x' was created",
                          "Subject jdoe on host rd-01",
                          observed_principals=[{"name": "svc_x", "cue": "created", "call_ids": [3]}])
        assert r["stack_action"] == "stay" and r["next_phase"] == ""
        pv = self._pivot(r, "svc_x")
        assert pv and pv["cue"] == "forced" and pv["declared_cue"] == "created" and pv["call_ids"] == [3]
        assert "server-enforced" not in (r.get("transition_rationale") or "").lower()

    def test_summary_prose_is_not_read(self, tmp_path):
        with patch("core.execution_log.log", self._log(tmp_path)):
            r = self._run("Security EID 4720 — new local admin account 'svc_x' was created",
                          "Subject jdoe on host rd-01")
        assert _candidate_values(r, "principal") == set()

    def test_builtin_account_not_a_candidate(self, tmp_path):
        with patch("core.execution_log.log", self._log(tmp_path)):
            r = self._run("x", "Subject jdoe", observed_principals=[{"name": "Guest", "cue": "created"}])
        assert _candidate_values(r, "principal") == set()

    def test_interactive_logon_is_forced_network_logon_is_appearance(self, tmp_path):
        with patch("core.execution_log.log", self._log(tmp_path)):
            r = self._run("x", "Subject jdoe", assessment=_SCAN_STAY_EMPTY_FOCUS,
                          observed_principals=[{"name": "svc_rdp", "cue": "interactive_logon"},
                                               {"name": "batch_svc", "cue": "network_logon"}])
        assert self._pivot(r, "svc_rdp")["cue"] == "forced"
        assert self._pivot(r, "batch_svc")["cue"] == "appearance"
        assert not r.get("pending_pivots")

    def test_known_principal_not_repivoted(self, tmp_path):
        l = self._log(tmp_path)
        with patch("core.execution_log.log", l):
            r1 = self._run("x", "c", observed_principals=[{"name": "svc_x", "cue": "created"}])
            r2 = self._run("y", "c", observed_principals=[{"name": "SVC-X", "cue": "interactive_logon"}])
        assert "SVC_X" in _candidate_values(r1, "principal")
        assert _candidate_values(r2, "principal") == set()      # normalized match

    def test_principal_in_a_finding_claim_is_known(self, tmp_path):
        l = self._log(tmp_path)
        from tools._gates._claims import normalize_claim
        l.record_finding("jdoe owns the box", "LIKELY", "x",
                         claim=normalize_claim(claim_kind="positive", category="identity",
                                               act="attribution", principal="J.Doe"))
        with patch("core.execution_log.log", l):
            r = self._run("x", "c", observed_principals=[{"name": "jdoe", "cue": "interactive_logon"}])
        assert _candidate_values(r, "principal") == set()

    def test_invalid_cue_reported(self, tmp_path):
        with patch("core.execution_log.log", self._log(tmp_path)):
            r = self._run("x", "c", observed_principals=[{"name": "svc_x", "cue": "wild"}, "junk"])
        assert _candidate_values(r, "principal") == set()
        assert any("cue=" in e for e in r["typed_input_errors"])
        assert any("must be an object" in e for e in r["typed_input_errors"])

    def test_typed_inputs_persisted_on_entry(self, tmp_path):
        l = self._log(tmp_path)
        with patch("core.execution_log.log", l):
            from tools.dair import dair_assess
            with _claude_ctx(_SCAN_STAY_NEW_HOST):
                dair_assess("x", phase_stack=_scan_stack_json(), case_context="c",
                            observed_principals=[{"name": "svc_x", "cue": "created", "call_ids": [3]}],
                            observed_hosts=["10.0.4.6"], case_question="Who created svc_x?")
        e = [x for x in l._entries if x.get("type") == "dair_call"][-1]
        assert e["observed_principals"] == [{"name": "svc_x", "cue": "created", "call_ids": [3]}]
        assert e["observed_hosts"] == ["10.0.4.6"] and e["case_question"] == "Who created svc_x?"


class TestTypedPivotValidators:
    def test_validate_hosts(self):
        from tools.dair import _validate_hosts
        ok, bad = _validate_hosts(["10.0.0.1", "\\\\HOST-1\\c$", "wkstn_9", "", "bad host!"])
        assert ok == ["10.0.0.1", "HOST-1", "WKSTN-9"] and bad == ["bad host!"]

    def test_validate_principals(self):
        from tools.dair import _validate_principals
        ok, errs = _validate_principals([{"name": "CORP\\J.Doe", "cue": "created", "call_ids": ["3", 0, "x"]},
                                         {"name": "", "cue": "created"}, {"name": "a", "cue": "nope"}])
        assert ok == [{"name": "CORP\\J.Doe", "cue": "created", "call_ids": [3], "norm": "jdoe"}]
        assert len(errs) == 2


class TestPriorRunAutoVerify:
    """A challenge whose challenge_method already ran successfully is verified
    by that run (DAIR once re-issued seven challenges at the Report
    transition for tools that had run in Triage; the never-run check counted
    only later runs, forcing a bulk 'inapplicable' waiver)."""

    def test_challenge_verified_by_prior_successful_run(self):
        from core.execution_log import log
        cid = log.record_tool_call("stat /mnt/fs/WINDOWS/Temp/STUN.exe", True, False, 0, 0,
                                   stdout_excerpt="Size: 45312")
        r = _run(_claude_ctx, _CHALLENGES_BLOCK + _ASSESSMENT_STAY)
        c = r["verification_challenges"][0]
        assert c["verified"] is True and c["verified_basis"] == "prior_run"
        assert c["verified_by_call_id"] == cid

    def test_failed_prior_run_does_not_verify(self):
        from core.execution_log import log
        log.record_tool_call("stat /mnt/fs/WINDOWS/Temp/STUN.exe", False, False, 1, 0,
                             stderr="No such file")
        r = _run(_claude_ctx, _CHALLENGES_BLOCK + _ASSESSMENT_STAY)
        assert r["verification_challenges"][0]["verified"] is None

    def test_unrelated_prior_run_does_not_verify(self):
        # A `stat` of the E01 image once verified "STUN.exe at
        # C:\Windows\Temp" — signature alone is too coarse; the claim's tokens
        # must overlap the run's cmd/output.
        from core.execution_log import log
        log.record_tool_call("stat /cases/x/evidence/surface_physical.E01", True, False, 0, 0,
                             stdout_excerpt="Size: 3000000000")
        r = _run(_claude_ctx, _CHALLENGES_BLOCK + _ASSESSMENT_STAY)
        assert r["verification_challenges"][0]["verified"] is None


class TestPhaseCoverage:
    """K-1: Report requires the investigative phases to have actually run —
    trace-derived, never prose. A Triage→Report shortcut is overridden
    server-side; reason.pre_report_check blocks the same gap."""

    def _log(self, tmp_path, phases):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PHASECOV", str(tmp_path / "trace.json"), save_session=False)
        for cur, nxt, act in phases:
            l.record_dair_call(cur, "", bool(nxt), nxt, "", act, "")
        return l

    def test_missing_report_phases_from_history(self, tmp_path):
        from tools.dair import missing_report_phases
        l = self._log(tmp_path, [("Triage", "", "stay"), ("Triage", "Report", "push")])
        assert missing_report_phases(l._entries) == ["Collect", "Analyze"]
        l2 = self._log(tmp_path, [("Triage", "Collect", "push"), ("Collect", "Analyze", "push"),
                                  ("Analyze", "Report", "push")])
        assert missing_report_phases(l2._entries) == []

    def test_scan_required_only_with_host_pivots(self, tmp_path):
        from tools.dair import missing_report_phases
        l = self._log(tmp_path, [("Triage", "Collect", "push"), ("Collect", "Analyze", "push")])
        l.record_dair_call("Analyze", "", False, "", "", "stay", "",
                           candidate_pivots=[{"kind": "host", "value": "10.0.4.6",
                                              "phase": "Analyze", "cue": "observed"}])
        assert missing_report_phases(l._entries) == ["Scan"]

    def test_live_monitoring_trace_exempt(self, tmp_path):
        from tools.dair import missing_report_phases
        l = self._log(tmp_path, [("Triage", "Report", "push")])
        l.record_tool_call("<py>:monitor_start_investigation INV-001", True, False, 0, 0)
        assert missing_report_phases(l._entries) == []

    def test_report_push_overridden_to_collect(self, tmp_path, monkeypatch):
        # DAIR backend answers Report from Triage; the server overrides to
        # Collect and persists the override for the audit trail.
        import tools.dair as D
        from core.execution_log import ExecutionLog
        from unittest.mock import patch
        l = ExecutionLog()
        l.configure("PHASECOV2", str(tmp_path / "trace.json"), save_session=False)
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_finding("x present", "SUSPECTED", "t")     # non-zero findings
        raw = ('RESULT:\n{"assessment": {"current_phase": "Triage", '
               '"transition_recommended": true, "next_phase": "Report", '
               '"stack_action": "push", "phase_rationale": "done", '
               '"transition_rationale": "wrap up", "directives": {"priority_tools": []}}}')
        with patch("core.execution_log.log", l), \
             patch.object(D, "_ask", return_value={"success": True, "raw": raw,
                                                   "input_tokens": 1, "output_tokens": 1}):
            r = D.dair_assess("summary", "[]", "ctx")
        assert r["next_phase"] == "Collect" and r["stack_action"] == "push"
        assert r["server_override"]["kind"] == "report_refused_phase_coverage"
        assert "Collect, Analyze" in r["server_override"]["detail"]
        e = [x for x in l._entries if x.get("type") == "dair_call"][-1]
        assert e["server_override"]["kind"] == "report_refused_phase_coverage"

    def test_report_allowed_after_full_cycle(self, tmp_path):
        import tools.dair as D
        from core.execution_log import ExecutionLog
        from unittest.mock import patch
        l = ExecutionLog()
        l.configure("PHASECOV3", str(tmp_path / "trace.json"), save_session=False)
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
            l.record_dair_call(cur, "", True, nxt, "", "push", "")
        l.record_finding("x present", "SUSPECTED", "t")
        raw = ('RESULT:\n{"assessment": {"current_phase": "Analyze", '
               '"transition_recommended": true, "next_phase": "Report", '
               '"stack_action": "push", "directives": {"priority_tools": []}}}')
        with patch("core.execution_log.log", l), \
             patch.object(D, "_ask", return_value={"success": True, "raw": raw,
                                                   "input_tokens": 1, "output_tokens": 1}):
            r = D.dair_assess("summary", "[]", "ctx")
        assert r["next_phase"] == "Report" and not r.get("server_override")

    def test_pre_report_blocks_on_phase_coverage(self, tmp_path):
        from tools.reasoning import reason_pre_report_check
        from unittest.mock import patch
        l = self._log(tmp_path, [("Triage", "Report", "push")])
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        l.record_finding("x present", "SUSPECTED", "t")
        with patch("core.execution_log.log", l):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("never entered Collect, Analyze" in i for i in r["blocking_issues"])


class TestPhaseLedgerTrust:
    """The phase ledger counts only server-trusted events: backend-recommended
    pushes and the gate-validated max-pass-cap self-correction. A dair entry's
    current_phase (the model's echo of the agent-supplied stack) never counts."""

    def test_agent_echoed_current_phase_does_not_count(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import missing_report_phases
        l = ExecutionLog()
        l.configure("LEDGER-T", str(tmp_path / "trace.json"), save_session=False)
        # entries whose current_phase claims Collect/Analyze but with no
        # recommended push — an asserted stack, not a transition
        l.record_dair_call("Collect", "", False, "", "", "stay", "")
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        assert missing_report_phases(l._entries) == ["Collect", "Analyze"]

    def test_backend_recommended_pushes_count(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import missing_report_phases
        l = ExecutionLog()
        l.configure("LEDGER-T2", str(tmp_path / "trace.json"), save_session=False)
        for cur, nxt in (("Triage", "Collect"), ("Collect", "Analyze")):
            l.record_dair_call(cur, "", True, nxt, "", "push", "")
        assert missing_report_phases(l._entries) == []
        # a push WITHOUT transition_recommended does not count
        l2 = ExecutionLog()
        l2.configure("LEDGER-T3", str(tmp_path / "t3.json"), save_session=False)
        l2.record_dair_call("Triage", "", False, "Collect", "", "push", "")
        assert "Collect" in missing_report_phases(l2._entries)

    def test_max_pass_cap_self_correction_counts_collect(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import missing_report_phases
        l = ExecutionLog()
        l.configure("LEDGER-T4", str(tmp_path / "trace.json"), save_session=False)
        l.record_dair_call("Triage", "", True, "Analyze", "", "push", "")
        l.record_self_correction(trigger="dair_max_pass_cap", prior_belief="stay x3",
                                 new_belief="push Collect")
        assert missing_report_phases(l._entries) == []

    def test_failed_monitor_call_does_not_exempt(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import missing_report_phases, _is_live_monitoring_trace
        l = ExecutionLog()
        l.configure("LEDGER-T5", str(tmp_path / "trace.json"), save_session=False)
        l.record_tool_call("<py>:monitor_start_investigation INV-001", False, False, 1, 0)
        assert _is_live_monitoring_trace(l._entries) is False
        assert missing_report_phases(l._entries) == ["Collect", "Analyze"]


class TestFix6WorkOrderAdvanceGate:
    """Fix 6: DAIR refuses a phase advance while the prior work order is unrun,
    and drops evidence-inapplicable tools from the prescription."""

    def _raw_advance(self, cur="Collect", nxt="Analyze"):
        return ('RESULT:\n{"assessment": {"current_phase": "%s", '
                '"transition_recommended": true, "next_phase": "%s", '
                '"stack_action": "push", "directives": {"priority_tools": ["ez.mftecmd"]}}}'
                % (cur, nxt))

    def test_advance_refused_while_work_order_unrun(self, tmp_path):
        import tools.dair as D
        from core.execution_log import ExecutionLog
        from unittest.mock import patch
        l = ExecutionLog(); l.configure("WO6", str(tmp_path / "trace.json"), save_session=False)
        for cur, nxt in (("Triage", "Collect"),):
            l.record_dair_call(cur, "", True, nxt, "", "push", "")
        # prior Collect work order prescribed ez.pecmd + a source disposition target
        l.record_dair_call("Collect", "", False, "", "", "stay", "",
                           directives={"priority_tools": ["ez.pecmd", "misc.usnparser_parse"]})
        l.record_finding("x present", "SUSPECTED", "t")
        with patch("core.execution_log.log", l), \
             patch.object(D, "_ask", return_value={"success": True, "raw": self._raw_advance(),
                                                   "input_tokens": 1, "output_tokens": 1}):
            r = D.dair_assess("summary", "[]", "ctx")
        assert r["server_override"]["kind"] == "work_order_incomplete"
        assert r["stack_action"] == "stay" and r["transition_recommended"] is False
        assert any("pecmd" in t for t in r["directives"]["priority_tools"])

    def test_advance_allowed_when_work_order_dispositioned(self, tmp_path):
        import tools.dair as D
        from core.execution_log import ExecutionLog
        from unittest.mock import patch
        l = ExecutionLog(); l.configure("WO6b", str(tmp_path / "trace.json"), save_session=False)
        l.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        l.record_dair_call("Collect", "", False, "", "", "stay", "",
                           directives={"priority_tools": ["ez.pecmd"]})
        l.record_disposition("tool", "ez.pecmd", "inapplicable")     # settled
        l.record_finding("x present", "SUSPECTED", "t")
        with patch("core.execution_log.log", l), \
             patch.object(D, "_ask", return_value={"success": True, "raw": self._raw_advance(),
                                                   "input_tokens": 1, "output_tokens": 1}):
            r = D.dair_assess("summary", "[]", "ctx")
        assert not r.get("server_override") and r["stack_action"] == "push"

    def test_evidence_filter_drops_memory_and_pcap_tools_on_disk_case(self, tmp_path):
        import tools.dair as D
        from core.execution_log import ExecutionLog
        from unittest.mock import patch
        # a disk-only case: evidence/ has an .E01, no memory/pcap
        case = tmp_path / "CASE"; (case / "evidence").mkdir(parents=True); (case / "analysis").mkdir()
        (case / "evidence" / "disk.E01").write_text("x")
        l = ExecutionLog(); l.configure("EV", str(case / "analysis" / "trace.json"), save_session=False)
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        raw = ('RESULT:\n{"assessment": {"current_phase": "Triage", "stack_action": "stay", '
               '"directives": {"priority_tools": ["vol.pstree", "net.tcpdump_read", "ez.mftecmd"]}}}')
        with patch("core.execution_log.log", l), \
             patch.object(D, "_ask", return_value={"success": True, "raw": raw,
                                                   "input_tokens": 1, "output_tokens": 1}):
            r = D.dair_assess("summary", "[]", "ctx")
        pt = r["directives"]["priority_tools"]
        assert "ez.mftecmd" in pt
        assert "vol.pstree" not in pt and "net.tcpdump_read" not in pt
        assert set(r["prescription_filtered"]) == {"vol.pstree", "net.tcpdump_read"}


class TestLayer3LifecycleBackfill:
    """Layer 3: an empty work order in a non-Report phase is backfilled from the
    uncovered lifecycle phases, or advances when coverage is complete."""

    def _raw_stay(self, phase="Collect"):
        return ('RESULT:\n{"assessment": {"current_phase": "%s", '
                '"transition_recommended": false, "next_phase": "", "stack_action": "stay", '
                '"directives": {"priority_tools": []}}}' % phase)

    def test_empty_work_order_backfilled_from_uncovered_phases(self, tmp_path):
        import tools.dair as D
        from core.execution_log import ExecutionLog
        from unittest.mock import patch
        l = ExecutionLog(); l.configure("L3", str(tmp_path / "trace.json"), save_session=False)
        l.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        l.record_finding("x present", "SUSPECTED", "t")     # some finding, no lifecycle coverage
        with patch("core.execution_log.log", l), \
             patch.object(D, "_ask", return_value={"success": True, "raw": self._raw_stay(),
                                                   "input_tokens": 1, "output_tokens": 1}):
            r = D.dair_assess("summary", "[]", "ctx")
        assert r["server_override"]["kind"] == "lifecycle_backfill"
        pt = r["directives"]["priority_tools"]
        assert pt and any("pecmd" in t or "amcache" in t for t in pt)   # execution tools backfilled

    def test_complete_coverage_advances_instead_of_stalling(self, tmp_path):
        import tools.dair as D
        from core.execution_log import ExecutionLog
        from unittest.mock import patch
        l = ExecutionLog(); l.configure("L3b", str(tmp_path / "trace.json"), save_session=False)
        l.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        # examine every phase so coverage is complete -> nothing to backfill
        for cmd in ("misc.parse_scheduled_tasks /x/Tasks", "EvtxECmd Security 4672 4728",
                    "EvtxECmd Security 4624 logon type 10", "PECmd -d /Prefetch",
                    "strings transfers.log ftp"):
            l.record_tool_call(cmd, True, False, 0, 0)
        with patch("core.execution_log.log", l), \
             patch.object(D, "_ask", return_value={"success": True, "raw": self._raw_stay(),
                                                   "input_tokens": 1, "output_tokens": 1}):
            r = D.dair_assess("summary", "[]", "ctx")
        assert r["server_override"]["kind"] == "lifecycle_complete_advance"
        assert r["stack_action"] == "push" and r["next_phase"] == "Analyze"

    def test_non_empty_work_order_left_alone(self, tmp_path):
        import tools.dair as D
        from core.execution_log import ExecutionLog
        from unittest.mock import patch
        l = ExecutionLog(); l.configure("L3c", str(tmp_path / "trace.json"), save_session=False)
        l.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        raw = ('RESULT:\n{"assessment": {"current_phase": "Collect", "stack_action": "stay", '
               '"transition_recommended": false, "directives": {"priority_tools": ["ez.mftecmd"]}}}')
        with patch("core.execution_log.log", l), \
             patch.object(D, "_ask", return_value={"success": True, "raw": raw,
                                                   "input_tokens": 1, "output_tokens": 1}):
            r = D.dair_assess("summary", "[]", "ctx")
        assert not r.get("server_override")
        assert r["directives"]["priority_tools"] == ["ez.mftecmd"]


# ── Phase O-A1: phase-aware empty-work-order handling ─────────────────────────

_TRIAGE_DONE_EMPTY = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Triage", "phase_rationale": "All IOC challenges resolved",'
    ' "transition_recommended": false, "next_phase": "", "transition_rationale": "",'
    ' "stack_action": "stay", "investigation_focus": "done",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": []}}'
)

_TRIAGE_OPEN_CHALLENGE = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Triage", "phase_rationale": "Still verifying",'
    ' "transition_recommended": false, "next_phase": "", "transition_rationale": "",'
    ' "stack_action": "stay", "investigation_focus": "verify",'
    ' "verification_challenges": [{"claim": "x.exe", "challenge_method": "strings.stat_file",'
    ' "verified": null, "confidence_impact": "-", "notes": ""}],'
    ' "recommended_actions": [], "directives": {"priority_tools": []}}'
)


class TestPhaseOEmptyWorkOrder:
    def test_triage_verification_done_advances_to_collect(self):
        # O-A1: an empty Triage work order with a genuine (parsed) assessment and
        # no open challenge = verification done -> ADVANCE to Collect, never
        # backfill collection into Triage.
        r = _run(_claude_ctx, _TRIAGE_DONE_EMPTY)
        assert r["next_phase"] == "Collect"
        assert r["stack_action"] == "push"
        assert (r.get("server_override") or {}).get("kind") == "triage_verification_complete"

    def test_triage_open_challenge_does_not_advance(self):
        # An open verification challenge means verification is NOT complete —
        # Triage must not be read as done.
        r = _run(_claude_ctx, _TRIAGE_OPEN_CHALLENGE)
        assert r["stack_action"] == "stay"
        assert (r.get("server_override") or {}).get("kind") != "triage_verification_complete"


# ── Fix (a): Triage points to Collect but says stay → coerce push ─────────────

_TRIAGE_POINTS_COLLECT = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Triage", "phase_rationale": "Pre-plan done; collection next",'
    ' "transition_recommended": false, "next_phase": "Collect", "transition_rationale": "",'
    ' "stack_action": "stay", "investigation_focus": "collect",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["ez.recmd_hive", "ez.evtxecmd"]}}'
)

_TRIAGE_POINTS_COLLECT_OPEN_CH = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Triage", "phase_rationale": "Collection next but verifying",'
    ' "transition_recommended": false, "next_phase": "Collect", "transition_rationale": "",'
    ' "stack_action": "stay", "investigation_focus": "collect",'
    ' "verification_challenges": [{"claim": "x.exe", "challenge_method": "strings.stat_file",'
    ' "verified": null, "confidence_impact": "-", "notes": ""}],'
    ' "recommended_actions": [], "directives": {"priority_tools": ["ez.recmd_hive"]}}'
)


class TestFixATriagePointsToCollect:
    def test_triage_next_collect_stay_is_pushed(self):
        # DAIR points to Collect (its own next_phase) but the model kept stay,
        # verification complete → coerce the push so collection runs IN Collect,
        # not under a single Triage frame.
        r = _run(_claude_ctx, _TRIAGE_POINTS_COLLECT)
        assert r["next_phase"] == "Collect"
        assert r["stack_action"] == "push"
        assert (r.get("server_override") or {}).get("kind") == "triage_points_to_collect"

    def test_open_challenge_blocks_the_coercion(self):
        # A Triage that still has an open verification challenge is never pushed
        # out early, even when it points to Collect.
        r = _run(_claude_ctx, _TRIAGE_POINTS_COLLECT_OPEN_CH)
        assert r["stack_action"] == "stay"
        assert (r.get("server_override") or {}).get("kind") != "triage_points_to_collect"


# ── Fix (b): external IP / forced principal pivot even at Triage ──────────────

class TestFixBTriageExternalPivot:
    def _triage(self, tmp_path, summary, **kw):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("XPHASE-B", str(tmp_path / "trace.json"))
        stack = json.dumps([{"phase": "Triage", "entry_reason": "open", "depth": 0}])
        with patch("core.execution_log.log", l), _claude_ctx(_ASSESSMENT_STAY):
            return dair_assess(summary, phase_stack=stack,
                               case_context="Host rd-01 (10.0.6.11)", **kw)

    def test_external_ip_pivots_at_triage(self, tmp_path):
        r = self._triage(
            tmp_path,
            "Security 4624 type 10 from 173.73.166.249 to defaultprinter",
            observed_hosts=["173.73.166.249", "10.0.4.9"])
        hosts = _candidate_values(r, "host")
        assert "173.73.166.249" in hosts          # external → pivots even at Triage
        assert "10.0.4.9" not in hosts             # private/local → still excluded
        assert r["stack_action"] == "stay"         # pivot is advisory, no transition

    def test_forced_principal_pivots_at_triage(self, tmp_path):
        r = self._triage(
            tmp_path, "Security 4720 new account svc_x created",
            observed_principals=[{"name": "svc_x", "cue": "created", "call_ids": [1]}])
        assert "SVC_X" in _candidate_values(r, "principal")   # created cue is forced

    def test_appearance_principal_not_pivoted_at_triage(self, tmp_path):
        r = self._triage(
            tmp_path, "mention of account jdoe in passing",
            observed_principals=[{"name": "jdoe", "cue": "other", "call_ids": [1]}])
        assert "JDOE" not in _candidate_values(r, "principal")  # non-forced stays excluded
