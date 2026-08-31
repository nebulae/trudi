"""Tests for the thinking-aware openai-compat client shared by reason.* and dair.*.

Regression context: a locally served Qwen3 (thinking mode) returned
finish_reason="length" with an empty `content` and the chain-of-thought in
`reasoning_content`; tools/reasoning.py read only `content`/`reasoning`, so
every reason_hypothesize failed as a bare "Model returned empty response"
with no cause in the trace.
"""
import json
import pytest
from unittest.mock import patch, MagicMock

from tests.tools.test_dair import _ASSESSMENT_STAY

_DIRECTIVES_JSON = (
    'DIRECTIVES:\n'
    '{"priority_tools": ["net.http_session_inventory"], "skip_tools": [], '
    '"focus_pids": [], "focus_paths": [], "max_depth": "targeted", '
    '"next_hypothesis_triggers": []}'
)
_ANSWER = "Hypothesis H1: a room occupant used webmail.\n" + _DIRECTIVES_JSON


# ── Mock factories ────────────────────────────────────────────────────────────

def _resp(content=None, reasoning_content=None, finish_reason="stop",
          prompt_tokens=100, completion_tokens=50, reasoning_tokens=None):
    """Mock httpx response shaped like a vLLM/SGLang reasoning-parser reply."""
    message = {"role": "assistant", "content": content}
    if reasoning_content is not None:
        message["reasoning_content"] = reasoning_content
    usage = {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens}
    if reasoning_tokens is not None:
        usage["completion_tokens_details"] = {"reasoning_tokens": reasoning_tokens}
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json.return_value = {
        "model": "Qwen/Qwen3-8B",
        "choices": [{"finish_reason": finish_reason, "message": message}],
        "usage": usage,
    }
    return m


def _exhausted():
    """Budget consumed entirely by thinking — the observed Qwen3 failure shape."""
    return _resp(content=None, reasoning_content="Let me think about who sent…",
                 finish_reason="length", completion_tokens=2048,
                 reasoning_tokens=2048)


@pytest.fixture(autouse=True)
def _compat_env():
    """Pin the reason backend to compat with a deterministic thinking budget,
    a pinned model (no discovery), and a fresh discovery cache."""
    import tools.reasoning as R
    with patch.object(R, "REASON_BACKEND", "openai-compat"), \
         patch.object(R, "REASON_URL", "http://qwen.test:8002"), \
         patch.object(R, "REASON_MODEL", "Qwen/Qwen3-8B"), \
         patch.object(R, "COMPAT_THINKING_BUDGET", 8192), \
         patch.object(R, "COMPAT_MAX_TOKENS_CEILING", 32768), \
         patch.object(R, "COMPAT_EXTRA_BODY_RAW", ""), \
         patch.object(R, "COMPAT_NO_THINK_TOOLS", frozenset()), \
         patch.object(R, "COMPAT_NO_THINK_MODE", "both"), \
         patch.dict(R._compat_model_cache, {}, clear=True):
        yield


@pytest.fixture
def trace_log():
    """Stub the execution-log methods the client writes to."""
    from core.execution_log import log
    with patch.object(log, "record_call_initiated", return_value=1) as initiated, \
         patch.object(log, "record_call_abandoned", return_value=2) as abandoned, \
         patch.object(log, "record_reason_call", return_value=3) as reason_call, \
         patch.object(log, "record_dair_call", return_value=4) as dair_call:
        yield {"initiated": initiated, "abandoned": abandoned,
               "reason_call": reason_call, "dair_call": dair_call}


def _sent_max_tokens(http_mock, call_index=0):
    return http_mock.call_args_list[call_index][1]["json"]["max_tokens"]


# ── _split_thinking ───────────────────────────────────────────────────────────

class TestSplitThinking:
    def test_terminated_block_is_stripped(self):
        from tools.reasoning import _split_thinking
        answer, thinking = _split_thinking("<think>hmm\nplan</think>\nReal answer.")
        assert answer == "Real answer."
        assert "plan" in thinking

    def test_unterminated_block_means_no_answer(self):
        from tools.reasoning import _split_thinking
        answer, thinking = _split_thinking("<think>still going and the budget ran out")
        assert answer == ""
        assert "budget ran out" in thinking

    def test_plain_text_untouched(self):
        from tools.reasoning import _split_thinking
        assert _split_thinking("no tags here") == ("no tags here", "")

    def test_alternate_tags_handled_by_default(self):
        from tools.reasoning import _split_thinking
        a, t = _split_thinking("<reasoning>step 1\nstep 2</reasoning>\nVERDICT: SUPPORTED")
        assert a == "VERDICT: SUPPORTED" and "step 2" in t
        a, t = _split_thinking("<thought>hmm</thought>Answer.")
        assert a == "Answer." and t == "<thought>hmm</thought>"

    def test_unterminated_alternate_tag(self):
        from tools.reasoning import _split_thinking
        a, t = _split_thinking("<reasoning>still going")
        assert a == "" and "still going" in t

    def test_mismatched_close_tag_is_not_a_block(self):
        from tools.reasoning import _split_thinking
        # <think> … </reasoning> must not pair up; treated as unterminated <think>
        a, t = _split_thinking("<think>x</reasoning>answer")
        assert a == "" and t.startswith("<think>")

    def test_custom_tag_list(self):
        from tools.reasoning import _split_thinking, _resolve_think_tags
        tags = _resolve_think_tags(" <scratchpad>, Think ")
        assert tags == (("<scratchpad>", "</scratchpad>"), ("<think>", "</think>"))
        a, t = _split_thinking("<scratchpad>notes</scratchpad>Final.", tags=tags)
        assert a == "Final." and "notes" in t
        # a tag outside the list is left alone
        a, t = _split_thinking("<reasoning>r</reasoning>Final.", tags=tags)
        assert a.startswith("<reasoning>") and t == ""

    def test_primus_reserved_token_pair_by_default(self):
        """Llama-Primus-Reasoning: <|reserved_special_token_0|>{reasoning}
        <|reserved_special_token_1|>{answer} — an open/separator pair, not a
        matching close tag. Requires llama-server --special to be visible."""
        from tools.reasoning import _split_thinking
        text = ("<|reserved_special_token_0|>Step 1: the UA is not an identity.\n"
                "Reflection: check cookies.<|reserved_special_token_1|>"
                "VERDICT: CHALLENGED\n" + _DIRECTIVES_JSON)
        a, t = _split_thinking(text)
        assert a.startswith("VERDICT: CHALLENGED")
        assert "DIRECTIVES" in a
        assert "Step 1" in t and "VERDICT" not in t

    def test_primus_unterminated_reasoning(self):
        from tools.reasoning import _split_thinking
        a, t = _split_thinking("<|reserved_special_token_0|>Step 1… budget gone")
        assert a == "" and "budget gone" in t

    def test_special_token_litter_stripped_from_answer(self, trace_log):
        """llama-server --special renders <|python_tag|> / <|eot_id|> into the
        text (observed on Llama-Primus-Reasoning). They must not reach the
        conclusion; the reasoning pair itself is consumed by the split."""
        from tools.reasoning import reason_hypothesize
        content = ("<|python_tag|><|reserved_special_token_0|>think think"
                   "<|reserved_special_token_1|>" + _ANSWER + "<|eot_id|>")
        http = MagicMock(return_value=_resp(content=content))
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is True
        assert "<|" not in r["conclusion"]
        assert r["conclusion"].startswith("Hypothesis H1")
        assert r["directives"]["priority_tools"] == ["net.http_session_inventory"]
        assert "think think" in r["backend_meta"]["reasoning_excerpt"]

    def test_literal_pair_env_spec(self):
        from tools.reasoning import _resolve_think_tags, _split_thinking
        tags = _resolve_think_tags("[[R]]:[[/R]],think")
        assert tags == (("[[R]]", "[[/R]]"), ("<think>", "</think>"))
        a, t = _split_thinking("[[R]]deliberate[[/R]]Answer", tags=tags)
        assert a == "Answer" and t == "[[R]]deliberate[[/R]]"

    @pytest.mark.parametrize("raw,expected", [
        (None, "DEFAULT"), ("", "DEFAULT"), (" , ", "DEFAULT"),
        ("think", (("<think>", "</think>"),)),
        ("<reasoning>,think,think", (("<reasoning>", "</reasoning>"), ("<think>", "</think>"))),
        ("a:b", (("a", "b"),)),
        ("a:", "DEFAULT"),
    ])
    def test_tag_env_resolution(self, raw, expected):
        from tools.reasoning import _resolve_think_tags, _DEFAULT_THINK_TAGS
        default = _resolve_think_tags(_DEFAULT_THINK_TAGS)
        assert ("<|reserved_special_token_0|>", "<|reserved_special_token_1|>") in default
        assert ("<think>", "</think>") in default
        want = default if expected == "DEFAULT" else expected
        assert _resolve_think_tags(raw) == want

    def test_empty(self):
        from tools.reasoning import _split_thinking
        assert _split_thinking("") == ("", "")
        assert _split_thinking(None) == ("", "")


# ── Budget + retry ────────────────────────────────────────────────────────────

class TestThinkingBudget:
    def test_request_budget_includes_thinking_allowance(self, trace_log):
        from tools.reasoning import reason_hypothesize, MAX_TOKENS_HYPOTHESIZE
        http = MagicMock(return_value=_resp(content=_ANSWER))
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is True
        assert _sent_max_tokens(http) == MAX_TOKENS_HYPOTHESIZE + 8192
        assert r["backend_meta"]["attempts"] == 1
        assert r["backend_meta"]["finish_reason"] == "stop"

    def test_exhausted_then_success_retries_with_doubled_budget(self, trace_log):
        from tools.reasoning import reason_hypothesize, MAX_TOKENS_HYPOTHESIZE
        second = _resp(content=_ANSWER, reasoning_content="thought…",
                       completion_tokens=6000, reasoning_tokens=4500)
        http = MagicMock(side_effect=[_exhausted(), second])
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is True
        assert r["output_tokens"] == 6000
        assert r["directives"]["priority_tools"] == ["net.http_session_inventory"]
        assert "DIRECTIVES" not in r["conclusion"]
        first = MAX_TOKENS_HYPOTHESIZE + 8192
        assert _sent_max_tokens(http, 0) == first
        assert _sent_max_tokens(http, 1) == first * 2
        meta = r["backend_meta"]
        assert meta["attempts"] == 2
        assert meta["reasoning_tokens"] == 4500
        assert meta["reasoning_excerpt"] == "thought…"
        # the retry is visible in the trace as a second call_initiated
        assert trace_log["initiated"].call_count == 2
        retry_inputs = trace_log["initiated"].call_args_list[1][0][2]
        assert retry_inputs["attempt"] == 2
        assert retry_inputs["max_tokens"] == first * 2
        trace_log["abandoned"].assert_not_called()

    def test_both_attempts_exhausted_fails_with_cause(self, trace_log):
        from tools.reasoning import reason_hypothesize
        http = MagicMock(side_effect=[_exhausted(), _exhausted()])
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is False
        assert r["conclusion"] == ""
        assert "finish_reason=length" in r["error"]
        assert "TRUDI_COMPAT_THINKING_BUDGET" in r["error"]
        assert http.call_count == 2
        # token usage of the failed attempt is no longer reported as 0/0
        assert r["output_tokens"] == 2048
        # the cause reaches the trace twice: call_abandoned + reason_call.error
        trace_log["abandoned"].assert_called_once()
        assert "finish_reason=length" in trace_log["abandoned"].call_args[0][1]
        logged = trace_log["reason_call"].call_args[1]
        assert logged["success"] is False
        assert "finish_reason=length" in logged["error"]
        assert logged["backend_meta"]["attempts"] == 2
        assert "Let me think" in logged["backend_meta"]["reasoning_excerpt"]

    def test_truncated_reasoning_is_never_promoted_to_answer(self, trace_log):
        """finish_reason=length: an incomplete thought is not a conclusion —
        the stop-only salvage (TestReasoningSalvage) must NOT engage here."""
        from tools.reasoning import reason_hypothesize
        http = MagicMock(side_effect=[_exhausted(), _exhausted()])
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is False
        assert "Let me think" not in r["conclusion"]
        assert r["directives"] == {}
        assert r["backend_meta"].get("answer_source") is None

    def test_empty_answer_without_length_does_not_retry(self, trace_log):
        from tools.reasoning import reason_hypothesize
        http = MagicMock(return_value=_resp(content="", finish_reason="stop"))
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is False
        assert http.call_count == 1
        assert "empty response" in r["error"]
        assert "finish_reason=stop" in r["error"]

    def test_retry_respects_ceiling(self, trace_log):
        import tools.reasoning as R
        from tools.reasoning import reason_hypothesize, MAX_TOKENS_HYPOTHESIZE
        first = MAX_TOKENS_HYPOTHESIZE + 8192
        http = MagicMock(side_effect=[_exhausted(), _resp(content=_ANSWER)])
        with patch.object(R, "COMPAT_MAX_TOKENS_CEILING", first + 1000), \
             patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is True
        assert _sent_max_tokens(http, 1) == first + 1000

    def test_ceiling_already_reached_means_no_retry(self, trace_log):
        import tools.reasoning as R
        from tools.reasoning import reason_hypothesize, MAX_TOKENS_HYPOTHESIZE
        http = MagicMock(side_effect=[_exhausted(), _exhausted()])
        with patch.object(R, "COMPAT_MAX_TOKENS_CEILING", MAX_TOKENS_HYPOTHESIZE + 8192), \
             patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is False
        assert http.call_count == 1

    def test_zero_budget_is_legacy_single_attempt(self, trace_log):
        """Foundation-Sec / GPT regression guard: budget unchanged, no retry."""
        import tools.reasoning as R
        from tools.reasoning import reason_hypothesize, MAX_TOKENS_HYPOTHESIZE
        http = MagicMock(side_effect=[_exhausted(), _exhausted()])
        with patch.object(R, "COMPAT_THINKING_BUDGET", 0), \
             patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is False
        assert http.call_count == 1
        assert _sent_max_tokens(http) == MAX_TOKENS_HYPOTHESIZE

    def test_truncated_answer_is_flagged_not_failed(self, trace_log):
        from tools.reasoning import reason_hypothesize
        http = MagicMock(return_value=_resp(content="Partial answer that hit the cap",
                                            finish_reason="length"))
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is True
        assert r["truncated"] is True
        assert http.call_count == 1


# ── Inline <think> (server without a reasoning parser) ───────────────────────

class TestInlineThink:
    def test_inline_think_stripped_before_directive_parse(self, trace_log):
        from tools.reasoning import reason_hypothesize
        content = "<think>DIRECTIVES: {\"priority_tools\": [\"wrong.tool\"]}</think>\n" + _ANSWER
        http = MagicMock(return_value=_resp(content=content))
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is True
        assert r["directives"]["priority_tools"] == ["net.http_session_inventory"]
        assert "<think>" not in r["conclusion"]
        assert "wrong.tool" in r["backend_meta"]["reasoning_excerpt"]

    def test_unterminated_inline_think_retries_like_empty(self, trace_log):
        from tools.reasoning import reason_hypothesize
        http = MagicMock(side_effect=[
            _resp(content="<think>ran out of budget mid-think", finish_reason="length"),
            _resp(content=_ANSWER),
        ])
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is True
        assert http.call_count == 2


# ── Transport errors still go through the abandoned path ─────────────────────

class TestTransportErrors:
    def test_http_exception_recorded(self, trace_log):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", side_effect=Exception("connection refused")):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is False
        assert "connection refused" in r["error"]
        trace_log["abandoned"].assert_called_once()
        assert trace_log["reason_call"].call_args[1]["error"] == "connection refused"


# ── Model discovery + extra body ──────────────────────────────────────────────

class TestModelDiscovery:
    def test_unpinned_model_discovered_from_v1_models(self, trace_log):
        import tools.reasoning as R
        from tools.reasoning import reason_hypothesize
        models = MagicMock()
        models.raise_for_status = MagicMock()
        models.json.return_value = {"data": [{"id": "Qwen/Qwen3-8B"}]}
        http = MagicMock(return_value=_resp(content=_ANSWER))
        with patch.object(R, "REASON_MODEL", ""), \
             patch("httpx.get", return_value=models) as get, \
             patch("httpx.post", http):
            reason_hypothesize("who sent the mail?")
            reason_hypothesize("second call")
        assert get.call_count == 1  # cached per URL
        assert get.call_args[0][0] == "http://qwen.test:8002/v1/models"
        assert http.call_args[1]["json"]["model"] == "Qwen/Qwen3-8B"

    def test_discovery_refreshes_after_ttl(self, trace_log):
        """Swapping the model behind llama-server (which ignores `model`) must
        not leave the trace stamped with the old name for the process lifetime."""
        import tools.reasoning as R
        from tools.reasoning import reason_hypothesize
        first = MagicMock(); first.raise_for_status = MagicMock()
        first.json.return_value = {"data": [{"id": "old-model"}]}
        second = MagicMock(); second.raise_for_status = MagicMock()
        second.json.return_value = {"data": [{"id": "new-model"}]}
        http = MagicMock(return_value=_resp(content=_ANSWER))
        clock = [1000.0]
        with patch.object(R, "REASON_MODEL", ""), \
             patch.object(R, "COMPAT_MODEL_DISCOVERY_TTL", 60.0), \
             patch("time.monotonic", side_effect=lambda: clock[0]), \
             patch("httpx.get", side_effect=[first, second]) as get, \
             patch("httpx.post", http):
            reason_hypothesize("q1")
            clock[0] += 30                       # inside TTL → cached
            reason_hypothesize("q2")
            assert get.call_count == 1
            assert http.call_args[1]["json"]["model"] == "old-model"
            clock[0] += 31                       # past TTL → re-discover
            reason_hypothesize("q3")
            assert get.call_count == 2
            assert http.call_args[1]["json"]["model"] == "new-model"

    def test_discovery_failure_falls_back_to_default(self, trace_log):
        import tools.reasoning as R
        from tools.reasoning import reason_hypothesize, _DEFAULT_COMPAT_MODEL
        http = MagicMock(return_value=_resp(content=_ANSWER))
        with patch.object(R, "REASON_MODEL", ""), \
             patch("httpx.get", side_effect=Exception("refused")), \
             patch("httpx.post", http):
            reason_hypothesize("who sent the mail?")
        assert http.call_args[1]["json"]["model"] == _DEFAULT_COMPAT_MODEL

    def test_pinned_model_skips_discovery(self, trace_log):
        from tools.reasoning import reason_hypothesize
        http = MagicMock(return_value=_resp(content=_ANSWER))
        with patch("httpx.get") as get, patch("httpx.post", http):
            reason_hypothesize("who sent the mail?")
        get.assert_not_called()

    def test_extra_body_merged_into_request(self, trace_log):
        import tools.reasoning as R
        from tools.reasoning import reason_hypothesize
        http = MagicMock(return_value=_resp(content=_ANSWER))
        extra = json.dumps({"chat_template_kwargs": {"enable_thinking": True}, "temperature": 0.6})
        with patch.object(R, "COMPAT_EXTRA_BODY_RAW", extra), patch("httpx.post", http):
            reason_hypothesize("who sent the mail?")
        body = http.call_args[1]["json"]
        assert body["chat_template_kwargs"] == {"enable_thinking": True}
        assert body["temperature"] == 0.6
        assert body["model"] == "Qwen/Qwen3-8B"  # core fields win over extra_body

    def test_malformed_extra_body_ignored(self, trace_log):
        import tools.reasoning as R
        from tools.reasoning import reason_hypothesize
        http = MagicMock(return_value=_resp(content=_ANSWER))
        with patch.object(R, "COMPAT_EXTRA_BODY_RAW", "{not json"), patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is True


# ── Thinking-length guidance on the system prompt ────────────────────────────

class TestThinkingGuidance:
    def test_default_guidance_appended_to_compat_system_prompt(self, trace_log):
        from tools.reasoning import reason_hypothesize, _HYPOTHESIZE_SYS, _DEFAULT_THINKING_GUIDANCE
        http = MagicMock(return_value=_resp(content=_ANSWER))
        with patch("httpx.post", http):
            reason_hypothesize("who sent the mail?")
        system = http.call_args[1]["json"]["messages"][0]["content"]
        assert system.startswith(_HYPOTHESIZE_SYS.rstrip())
        assert system.endswith(_DEFAULT_THINKING_GUIDANCE)
        assert "REASONING BUDGET" in system
        # user message is untouched
        assert "REASONING BUDGET" not in http.call_args[1]["json"]["messages"][1]["content"]
        initiated = trace_log["initiated"].call_args[0][2]
        assert initiated["thinking_guidance"] is True

    def test_guidance_disabled(self, trace_log):
        import tools.reasoning as R
        from tools.reasoning import reason_hypothesize, _HYPOTHESIZE_SYS
        http = MagicMock(return_value=_resp(content=_ANSWER))
        with patch.object(R, "COMPAT_THINKING_GUIDANCE", ""), patch("httpx.post", http):
            reason_hypothesize("who sent the mail?")
        system = http.call_args[1]["json"]["messages"][0]["content"]
        assert system == _HYPOTHESIZE_SYS
        assert trace_log["initiated"].call_args[0][2]["thinking_guidance"] is False

    def test_custom_guidance_text(self, trace_log):
        import tools.reasoning as R
        from tools.reasoning import reason_hypothesize
        http = MagicMock(return_value=_resp(content=_ANSWER))
        with patch.object(R, "COMPAT_THINKING_GUIDANCE", "Think for at most 500 tokens."), \
             patch("httpx.post", http):
            reason_hypothesize("who sent the mail?")
        system = http.call_args[1]["json"]["messages"][0]["content"]
        assert system.endswith("Think for at most 500 tokens.")
        assert "REASONING BUDGET" not in system

    def test_guidance_reaches_dair_prompt(self, trace_log):
        import tools.dair as D
        from tools.dair import dair_assess, _DAIR_SYS
        http = MagicMock(return_value=_resp(content=_ASSESSMENT_STAY))
        with patch.object(D, "DAIR_BACKEND", "openai-compat"), \
             patch.object(D, "DAIR_URL", "http://qwen.test:8002"), \
             patch.object(D, "DAIR_MODEL", "Qwen/Qwen3-8B"), \
             patch("httpx.post", http):
            dair_assess("findings")
        system = http.call_args[1]["json"]["messages"][0]["content"]
        assert system.startswith(_DAIR_SYS.rstrip())
        assert "REASONING BUDGET" in system

    def test_claude_backend_never_sees_guidance(self):
        from tools.reasoning import reason_hypothesize, _HYPOTHESIZE_SYS
        resp = MagicMock(); resp.content = [MagicMock(text=_ANSWER)]
        client = MagicMock(); client.messages.create.return_value = resp
        with patch("anthropic.Anthropic", MagicMock(return_value=client)), \
             patch("tools.reasoning.ANTHROPIC_API_KEY", "sk-test"), \
             patch("tools.reasoning.REASON_BACKEND", "claude"):
            reason_hypothesize("who sent the mail?")
        system_blocks = client.messages.create.call_args[1]["system"]
        assert system_blocks[0]["text"] == _HYPOTHESIZE_SYS
        assert "REASONING BUDGET" not in system_blocks[0]["text"]

    @pytest.mark.parametrize("raw,expected", [
        (None, "DEFAULT"), ("", "DEFAULT"), ("   ", "DEFAULT"),
        ("off", ""), ("0", ""), ("NONE", ""), ("False", ""),
        ("custom text", "custom text"), ("  padded  ", "padded"),
    ])
    def test_env_resolution(self, raw, expected):
        from tools.reasoning import _resolve_thinking_guidance, _DEFAULT_THINKING_GUIDANCE
        want = _DEFAULT_THINKING_GUIDANCE if expected == "DEFAULT" else expected
        assert _resolve_thinking_guidance(raw) == want


# ── Per-surface thinking control ──────────────────────────────────────────────

class TestPerToolThinking:
    """Default set: DAIR + the mechanical checks run without thinking; the
    adversarial surfaces keep it."""

    @pytest.fixture(autouse=True)
    def _default_set(self):
        import tools.reasoning as R
        with patch.object(R, "COMPAT_NO_THINK_TOOLS",
                          R._resolve_no_think_tools(None)):
            yield

    def test_default_set_contents(self):
        from tools.reasoning import COMPAT_NO_THINK_TOOLS
        assert COMPAT_NO_THINK_TOOLS == frozenset({
            "dair_assess", "reason_cite_check", "reason_confidence_score",
            "reason_audit_findings"})

    @pytest.mark.parametrize("raw,expected", [
        (None, "DEFAULT"), ("", "DEFAULT"),
        ("none", frozenset()), ("OFF", frozenset()), ("0", frozenset()),
        ("dair_assess", frozenset({"dair_assess"})),
        (" dair_assess , reason_plan ", frozenset({"dair_assess", "reason_plan"})),
    ])
    def test_env_resolution(self, raw, expected):
        from tools.reasoning import _resolve_no_think_tools, _DEFAULT_NO_THINK_TOOLS
        want = (frozenset(_DEFAULT_NO_THINK_TOOLS.split(","))
                if expected == "DEFAULT" else expected)
        assert _resolve_no_think_tools(raw) == want

    def test_hypothesize_still_thinks(self, trace_log):
        from tools.reasoning import reason_hypothesize, MAX_TOKENS_HYPOTHESIZE
        http = MagicMock(return_value=_resp(content=_ANSWER))
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        body = http.call_args[1]["json"]
        assert body["max_tokens"] == MAX_TOKENS_HYPOTHESIZE + 8192
        assert "chat_template_kwargs" not in body
        assert not body["messages"][1]["content"].endswith("/no_think")
        assert "REASONING BUDGET" in body["messages"][0]["content"]
        assert r["backend_meta"]["thinking"] is True

    def test_cite_check_runs_without_thinking(self, trace_log):
        from tools.reasoning import reason_cite_check, MAX_TOKENS_CITE_CHECK
        http = MagicMock(return_value=_resp(content="ALL_CITED\n" + _DIRECTIVES_JSON))
        with patch("httpx.post", http):
            r = reason_cite_check("finding text", "evidence text")
        body = http.call_args[1]["json"]
        assert body["max_tokens"] == MAX_TOKENS_CITE_CHECK          # no think allowance
        assert body["chat_template_kwargs"] == {"enable_thinking": False}
        assert body["messages"][1]["content"].endswith("/no_think")
        assert "REASONING BUDGET" not in body["messages"][0]["content"]
        assert r["backend_meta"]["thinking"] is False
        initiated = trace_log["initiated"].call_args[0][2]
        assert initiated["thinking"] is False
        assert initiated["thinking_guidance"] is False

    def test_no_think_never_retries(self, trace_log):
        from tools.reasoning import reason_cite_check
        http = MagicMock(side_effect=[_exhausted(), _exhausted()])
        with patch("httpx.post", http):
            r = reason_cite_check("finding text", "evidence text")
        assert r["success"] is False
        assert http.call_count == 1

    def test_mode_kwargs_only(self, trace_log):
        import tools.reasoning as R
        from tools.reasoning import reason_cite_check
        http = MagicMock(return_value=_resp(content="ALL_CITED"))
        with patch.object(R, "COMPAT_NO_THINK_MODE", "kwargs"), patch("httpx.post", http):
            reason_cite_check("finding text", "evidence text")
        body = http.call_args[1]["json"]
        assert body["chat_template_kwargs"] == {"enable_thinking": False}
        assert not body["messages"][1]["content"].endswith("/no_think")

    def test_mode_soft_only(self, trace_log):
        import tools.reasoning as R
        from tools.reasoning import reason_cite_check
        http = MagicMock(return_value=_resp(content="ALL_CITED"))
        with patch.object(R, "COMPAT_NO_THINK_MODE", "soft"), patch("httpx.post", http):
            reason_cite_check("finding text", "evidence text")
        body = http.call_args[1]["json"]
        assert "chat_template_kwargs" not in body
        assert body["messages"][1]["content"].endswith("/no_think")

    def test_kwargs_merge_with_extra_body(self, trace_log):
        import tools.reasoning as R
        from tools.reasoning import reason_cite_check
        http = MagicMock(return_value=_resp(content="ALL_CITED"))
        extra = json.dumps({"chat_template_kwargs": {"foo": 1}, "temperature": 0.2})
        with patch.object(R, "COMPAT_EXTRA_BODY_RAW", extra), patch("httpx.post", http):
            reason_cite_check("finding text", "evidence text")
        body = http.call_args[1]["json"]
        assert body["chat_template_kwargs"] == {"foo": 1, "enable_thinking": False}
        assert body["temperature"] == 0.2

    def test_dair_runs_without_thinking_by_default(self, trace_log):
        import tools.dair as D
        from tools.dair import dair_assess, MAX_TOKENS_DAIR
        http = MagicMock(return_value=_resp(content=_ASSESSMENT_STAY))
        with patch.object(D, "DAIR_BACKEND", "openai-compat"), \
             patch.object(D, "DAIR_URL", "http://qwen.test:8002"), \
             patch.object(D, "DAIR_MODEL", "Qwen/Qwen3-8B"), \
             patch("httpx.post", http):
            r = dair_assess("findings")
        assert r["success"] is True
        body = http.call_args[1]["json"]
        assert body["max_tokens"] == MAX_TOKENS_DAIR
        assert body["chat_template_kwargs"] == {"enable_thinking": False}
        assert "REASONING BUDGET" not in body["messages"][0]["content"]
        assert trace_log["dair_call"].call_args[1]["backend_meta"]["thinking"] is False


# ── DAIR shares the client ────────────────────────────────────────────────────

class TestDairCompat:
    @pytest.fixture(autouse=True)
    def _dair_env(self):
        import tools.dair as D
        with patch.object(D, "DAIR_BACKEND", "openai-compat"), \
             patch.object(D, "DAIR_URL", "http://qwen.test:8002"), \
             patch.object(D, "DAIR_MODEL", "Qwen/Qwen3-8B"):
            yield

    def test_dair_passes_its_max_tokens_plus_budget(self, trace_log):
        from tools.dair import dair_assess, MAX_TOKENS_DAIR
        http = MagicMock(return_value=_resp(content=_ASSESSMENT_STAY))
        with patch("httpx.post", http):
            r = dair_assess("findings")
        assert r["success"] is True
        assert _sent_max_tokens(http) == MAX_TOKENS_DAIR + 8192
        assert http.call_args[1]["json"]["model"] == "Qwen/Qwen3-8B"
        assert trace_log["dair_call"].call_args[1]["backend_meta"]["attempts"] == 1

    def test_dair_retries_on_exhausted_thinking(self, trace_log):
        from tools.dair import dair_assess
        http = MagicMock(side_effect=[_exhausted(), _resp(content=_ASSESSMENT_STAY)])
        with patch("httpx.post", http):
            r = dair_assess("findings")
        assert r["success"] is True
        assert http.call_count == 2

    def test_dair_failure_records_cause(self, trace_log):
        from tools.dair import dair_assess
        http = MagicMock(side_effect=[_exhausted(), _exhausted()])
        with patch("httpx.post", http):
            r = dair_assess("findings")
        assert r["success"] is False
        assert "finish_reason=length" in r["error"]
        trace_log["abandoned"].assert_called_once()
        logged = trace_log["dair_call"].call_args[1]
        assert "finish_reason=length" in logged["error"]
        assert logged["backend_meta"]["attempts"] == 2
        assert logged["output_tokens"] == 2048


# ── Execution log persists the new fields ─────────────────────────────────────

class TestExecutionLogFields:
    def test_reason_and_dair_entries_carry_error_and_meta(self, tmp_path):
        from core.execution_log import ExecutionLog
        log = ExecutionLog()
        log.configure("T-1", str(tmp_path / "t.json"), save_session=False)
        cid = log.record_reason_call(
            tool="reason_hypothesize", success=False, conclusion="", directives={},
            error="thinking consumed output budget (finish_reason=length)",
            backend_meta={"attempts": 2, "finish_reason": "length"},
        )
        entry = next(e for e in log._entries if e.get("call_id") == cid)
        assert entry["error"].startswith("thinking consumed")
        assert entry["backend_meta"]["attempts"] == 2
        ok = log.record_reason_call(tool="reason_plan", success=True,
                                    conclusion="x", directives={})
        ok_entry = next(e for e in log._entries if e.get("call_id") == ok)
        assert "error" not in ok_entry and "backend_meta" not in ok_entry
        dcid = log.record_dair_call(
            current_phase="Triage", phase_rationale="", transition_recommended=False,
            next_phase="", transition_rationale="", stack_action="stay",
            investigation_focus="", error="boom", backend_meta={"attempts": 1},
        )
        dentry = next(e for e in log._entries if e.get("call_id") == dcid)
        assert dentry["error"] == "boom"
        assert dentry["backend_meta"] == {"attempts": 1}


# ── Salvage-on-stop: completed answer misclassified as thinking ──────────────
# Observed live (Titus, base-Qwen template): finish_reason=stop with empty
# `content` and a COMPLETE conclusive analysis in think-classified text — the
# template pre-opens <think> and the model never closes it. A finished
# generation is a committed conclusion; only length-truncation is not.

_SALVAGE_ANSWER = (
    "The evidence points toward deliberate harassment from the dorm device; "
    "attribution requires correlating the AIM identity with the class roster.\n"
    + _DIRECTIVES_JSON
)


class TestReasoningSalvage:
    def test_stop_with_unterminated_inline_think_is_salvaged(self, trace_log):
        from tools.reasoning import reason_hypothesize
        http = MagicMock(return_value=_resp(
            content="<think>" + _SALVAGE_ANSWER, finish_reason="stop"))
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is True
        assert http.call_count == 1
        assert "<think>" not in r["conclusion"]
        assert "deliberate harassment" in r["conclusion"]
        assert r["directives"]["priority_tools"] == ["net.http_session_inventory"]
        assert r["backend_meta"]["answer_source"] == "reasoning_salvage"

    def test_stop_with_server_side_reasoning_content_is_salvaged(self, trace_log):
        from tools.reasoning import reason_hypothesize
        http = MagicMock(return_value=_resp(
            content=None, reasoning_content=_SALVAGE_ANSWER,
            finish_reason="stop"))
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is True
        assert "deliberate harassment" in r["conclusion"]
        assert r["backend_meta"]["answer_source"] == "reasoning_salvage"

    def test_empty_think_block_is_not_salvaged(self, trace_log):
        from tools.reasoning import reason_hypothesize
        http = MagicMock(return_value=_resp(
            content="<think>\n\n</think>", finish_reason="stop"))
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is False
        assert "empty response" in r["error"]

    def test_below_substance_floor_is_not_salvaged(self, trace_log):
        from tools.reasoning import reason_hypothesize
        http = MagicMock(return_value=_resp(
            content="<think>ok", finish_reason="stop"))
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is False

    def test_length_truncation_is_never_salvaged(self, trace_log):
        """Both attempts exhausted mid-think: salvage must not fire on length."""
        from tools.reasoning import reason_hypothesize
        http = MagicMock(side_effect=[
            _resp(content="<think>" + _SALVAGE_ANSWER, finish_reason="length"),
            _resp(content="<think>" + _SALVAGE_ANSWER, finish_reason="length"),
        ])
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is False
        assert r["backend_meta"].get("answer_source") is None

    def test_salvage_strips_special_token_litter(self, trace_log):
        from tools.reasoning import reason_hypothesize
        http = MagicMock(return_value=_resp(
            content="<think><|eot_id|>" + _SALVAGE_ANSWER + "<|eom_id|>",
            finish_reason="stop"))
        with patch("httpx.post", http):
            r = reason_hypothesize("who sent the mail?")
        assert r["success"] is True
        assert "<|eot_id|>" not in r["conclusion"] and "<|eom_id|>" not in r["conclusion"]
