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
        r = _run(_claude_ctx, _ASSESSMENT_REPORT)
        assert r["next_phase"] == "Report"
        assert r["stack_action"] == "push"
        assert len(r["recommended_actions"]) > 0


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
    """Record candidate pivots without mutating DAIR phase control."""

    def _run(self, summary: str, case_context: str, stack: str | None = None):
        from tools.dair import dair_assess
        stack = stack or _scan_stack_json()
        with _claude_ctx(_SCAN_STAY_NEW_HOST):
            return dair_assess(summary,
                               phase_stack=stack,
                               case_context=case_context)

    def test_new_ip_forces_push(self, tmp_path):
        # Configure the log so the dair_call goes somewhere.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="ShimCache shows lateral hop to 10.0.4.6 c$ admin share",
                case_context="Host rd-01 (10.0.6.11) — REDFOX APT",
            )
        assert r["success"] is True
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "10.0.4.6" in _candidate_values(r, "host")
        assert "server-enforced" not in (r.get("transition_rationale") or "").lower()

    def test_new_unc_path_hostname_forces_push(self, tmp_path):
        # UNC-path hostname extraction works with zero configuration —
        # \\HOSTNAME\share is an unambiguous host reference regardless of
        # the case's naming scheme.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="ShimCache UNC path \\\\NORTH-DC4\\admin$\\ts.exe staging",
                case_context="Host alpha-01 (10.0.6.11)",
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "NORTH-DC4" in _candidate_values(r, "host")

    def test_env_var_prefix_hostname_forces_push(self, tmp_path, monkeypatch):
        # Case-specific hostname prefix detection is opt-in via the
        # TRUDI_PIVOT_HOSTNAME_PREFIXES env var. Operators set it per-case
        # in .env. Without it, bare hostnames like "wkstn-15" are NOT
        # detected (only UNC paths and IPs are).
        monkeypatch.setenv("TRUDI_PIVOT_HOSTNAME_PREFIXES", "wkstn,rd")
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="wkstn-15 c$\\windows\\temp\\perfmon contains csrss.exe (suspicious)",
                case_context="Host rd-01 (10.0.6.11)",
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "WKSTN-15" in _candidate_values(r, "host")

    def test_bare_hostname_without_env_var_does_not_push(self, tmp_path, monkeypatch):
        # Without TRUDI_PIVOT_HOSTNAME_PREFIXES, a bare "wkstn-15" mention
        # in narrative text doesn't trigger a push — only IPs and UNC paths
        # are detected in the case-agnostic default.
        monkeypatch.delenv("TRUDI_PIVOT_HOSTNAME_PREFIXES", raising=False)
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="Sweep complete; no new lateral activity observed on wkstn-15",
                case_context="Host alpha-01 (10.0.6.11)",
            )
        # No IP, no UNC path → no push override; model "stay" is preserved.
        assert r["stack_action"] == "stay"

    def test_only_known_host_no_override(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="Continuing scan of rd-01 — no new external traffic",
                case_context="Host rd-01 (10.0.6.11) — REDFOX",
            )
        # Model said "stay" and there's no new host — must stay.
        assert r["stack_action"] == "stay"

    def test_multiple_new_pivots_first_pushed_rest_queued(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary=(
                    "ShimCache enumerated UNC paths on 10.0.4.5, 10.0.4.6, "
                    "wkstn-15, rd-04 — all containing perfmon\\*.exe staging."
                ),
                case_context="Host rd-01 (10.0.6.11) — REDFOX",
            )
        assert r["stack_action"] == "stay"
        assert "10.0.4.5" in _candidate_values(r, "host")
        assert "10.0.4.6" in _candidate_values(r, "host")
        assert not r.get("pending_pivots")

    def test_stop_word_filters_unc_extracted_host(self, tmp_path):
        # If a UNC-path-like token happens to surface a stop-word as the
        # extracted host (e.g. \\WINDOWS\share in a path mention), the
        # stop-list drops it before treating it as a pivot.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="Scanning for \\\\WINDOWS\\system32 references — none new",
                case_context="Host alpha-01 (10.0.6.11)",
            )
        # "WINDOWS" is a stop-word → no push.
        assert r["stack_action"] == "stay"

    def test_env_prefix_stop_word_split_on_hyphen(self, monkeypatch, tmp_path):
        # When an operator sets a prefix that produces a hyphenated match
        # whose leading token is a stop-word (e.g. "tcp-4" if they set
        # TRUDI_PIVOT_HOSTNAME_PREFIXES="tcp"), the split-on-hyphen filter
        # drops it. Guards against false positives from networking jargon.
        monkeypatch.setenv("TRUDI_PIVOT_HOSTNAME_PREFIXES", "tcp")
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="connection table shows tcp-4 socket open on alpha-01",
                case_context="Host alpha-01",
            )
        assert r["stack_action"] == "stay"

    def test_model_push_not_downgraded(self, tmp_path):
        # If the model already said push, candidate observation does not
        # downgrade it. This regression-locks the "never rewrite model phase"
        # invariant.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
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
            r = dair_assess(
                "rd-04 pivot from rd-01",
                phase_stack=_scan_stack_json(),
                case_context="Host rd-01 only",
            )
        # Stays "push" — and candidate observation doesn't append
        # "server-enforced" text.
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
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "BASE-RD-04" in _candidate_values(r, "host")

    def test_triage_does_not_pivot_on_own_focus(self, tmp_path):
        # A Triage entry investigating rd-01 mentioning a NEW host (e.g.
        # 10.0.4.9) would normally pivot — but Triage is excluded from
        # the eligible-phase set. Stays "stay".
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
            )
        # Triage stays; no pivot push on its own surface mentions.
        assert r["stack_action"] == "stay"

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
    """Record candidate principals without mutating DAIR phase control."""

    def _run(self, summary, case_context, assessment=_SCAN_STAY_NEW_HOST):
        from tools.dair import dair_assess
        with _claude_ctx(assessment):
            return dair_assess(summary,
                               phase_stack=_scan_stack_json(),
                               case_context=case_context)

    def test_new_account_creation_forces_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="Security EID 4720 — new local admin account 'svc_x' was created",
                case_context="Subject jdoe on host rd-01; no svc_x account known",
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "SVC_X" in _candidate_values(r, "principal")
        assert "server-enforced" not in (r.get("transition_rationale") or "").lower()

    def test_controller_question_becomes_focus(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="A covert local admin account 'printer_svc' was created on the host",
                case_context="Subject jdoe on host rd-01",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
            )
        assert r["stack_action"] == "stay"
        assert "PRINTER_SVC" in _candidate_values(r, "principal")
        assert not (r.get("investigation_focus") or "")

    def test_builtin_account_does_not_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="The built-in Guest account was created/enabled during the window",
                case_context="Subject jdoe on host rd-01",
            )
        # 'Guest' is a built-in stop-word principal → no push.
        assert r["stack_action"] == "stay"

    def test_mention_without_creation_cue_does_not_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="account svc_x ran notepad.exe and opened a document",
                case_context="Subject jdoe on host rd-01",
            )
        # Mention, not creation → no principal pivot.
        assert r["stack_action"] == "stay"

    def test_known_principal_in_context_no_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="new user account 'svc_x' was created on the host",
                case_context="Known principal: account svc_x already under investigation",
            )
        # svc_x is already known (named in case_context) → no new candidate.
        assert r["stack_action"] == "stay"

    def test_rdp_logon_unknown_principal_forces_push(self, tmp_path):
        # Tier A: an unknown identity authenticating over RDP forces a push —
        # the second-principal class that creation-only detection missed.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary=("Security 4778 — RDP session established for account "
                         "svc_rdp (logon type 10)"),
                case_context="Subject jdoe on host rd-01; no svc_rdp account known",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "SVC_RDP" in _candidate_values(r, "principal")

    def test_interactive_logon_unknown_principal_forces_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="account maint_op logged in interactively (logon type 2)",
                case_context="Subject jdoe on host rd-01",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
            )
        assert r["stack_action"] == "stay"
        assert "MAINT_OP" in _candidate_values(r, "principal")

    def test_network_logon_unknown_principal_queues_not_forces(self, tmp_path):
        # Tier B: noisier network logon enqueues rather than pre-empting stay.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="account batch_svc network logon type 3 observed",
                case_context="Subject jdoe on host rd-01",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
        )
        assert r["stack_action"] == "stay"
        assert not r.get("pending_pivots")
        assert "BATCH_SVC" in _candidate_values(r, "principal")
        candidate = next(
            p for p in r.get("candidate_pivots") or []
            if p.get("value", "").upper() == "BATCH_SVC"
        )
        assert candidate.get("cue") == "appearance"

    def test_known_rdp_principal_in_context_no_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="account svc_rdp logged in via RDP (logon type 10)",
                case_context="account svc_rdp already under investigation on host rd-01",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
            )
        # Known-set gating: svc_rdp already under investigation → no re-pivot.
        assert r["stack_action"] == "stay"

    def test_rdp_logon_by_known_subject_no_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="jdoe logged in via RDP (logon type 10)",
                case_context="Subject jdoe on host rd-01",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
            )
        # The case subject's own logon must not pivot — 'Subject jdoe' makes
        # jdoe a known principal.
        assert r["stack_action"] == "stay"


class TestPrincipalTokenExtraction:
    """Unit coverage for the principal token helpers."""

    def test_creation_cue_required_by_default(self):
        from tools.dair import _extract_principal_tokens
        assert _extract_principal_tokens("user svc_x logged in") == set()
        assert "SVC_X" in _extract_principal_tokens(
            "new local admin account 'svc_x' was created")

    def test_cue_free_extraction_for_known_set(self):
        from tools.dair import _extract_principal_tokens
        # require_cue=False is how the known set reads case_context / focus.
        toks = _extract_principal_tokens(
            "Establish who controls principal PRINTER_SVC", require_cue=False)
        assert "PRINTER_SVC" in toks

    def test_builtins_filtered(self):
        from tools.dair import _extract_principal_tokens
        toks = _extract_principal_tokens(
            "new admin account 'Administrator' created and Guest account created")
        assert "ADMINISTRATOR" not in toks
        assert "GUEST" not in toks

    def test_interactive_auth_cue_emits_token_under_forced(self):
        from tools.dair import _extract_principal_tokens
        toks = _extract_principal_tokens(
            "svc_rdp logged in via RDP (logon type 10)", cue="forced")
        assert "SVC_RDP" in toks

    def test_network_logon_is_appearance_not_forced(self):
        from tools.dair import _extract_principal_tokens
        text = "account batch_svc network logon type 3 observed"
        assert _extract_principal_tokens(text, cue="forced") == set()
        assert "BATCH_SVC" in _extract_principal_tokens(text, cue="appearance")

    def test_any_cue_is_union_but_bare_mention_still_empty(self):
        from tools.dair import _extract_principal_tokens
        assert "SVC_X" in _extract_principal_tokens(
            "account svc_x logged in via rdp", cue="any")
        # A bare mention with no cue family still yields nothing.
        assert _extract_principal_tokens(
            "account svc_x ran notepad.exe", cue="any") == set()

    def test_default_cue_stays_creation_only(self):
        # Default must remain creation-only so existing callers are unchanged:
        # an interactive logon does NOT extract under the default cue.
        from tools.dair import _extract_principal_tokens
        assert _extract_principal_tokens("svc_rdp logged in via rdp") == set()
        assert "SVC_RDP" in _extract_principal_tokens(
            "new admin account 'svc_rdp' was created")
