"""Tests for tools/reasoning.py — mocks the Foundation-Sec HTTP call."""
import pytest
from unittest.mock import patch, MagicMock


BASE_URL = "http://localhost:8000"
HTTP_PATCH = "httpx.post"
HEALTH_PATCH = "tools.reasoning._health_check"


@pytest.fixture(autouse=True)
def _server_healthy():
    """Assume server passes health check for all tests unless explicitly overridden."""
    with patch(HEALTH_PATCH, return_value=True):
        yield

_DIRECTIVES_JSON = (
    'DIRECTIVES:\n'
    '{"priority_tools": ["vol.psscan", "vol.cmdline"], '
    '"skip_tools": [], "focus_pids": [5024], '
    '"focus_paths": ["C:\\\\ProgramData\\\\staging\\\\"], '
    '"max_depth": "targeted", "next_hypothesis_triggers": []}'
)


def _resp(content, reasoning="<think>chain of thought</think>"):
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json.return_value = {
        "choices": [{
            "message": {
                "content": content,
                "reasoning": reasoning,
            }
        }]
    }
    return m


def _resp_with_directives(content="ok"):
    return _resp(content, reasoning=f"analysis here\n{_DIRECTIVES_JSON}")


class TestReasonPlan:
    def test_returns_success(self):
        from tools.reasoning import reason_plan
        with patch(HTTP_PATCH, return_value=_resp_with_directives("1. Check memory first.")):
            r = reason_plan("Suspected keylogger on wkstn-01", "memory.img, c-drive.E01")
        assert r["success"] is True

    def test_directives_present(self):
        from tools.reasoning import reason_plan
        with patch(HTTP_PATCH, return_value=_resp_with_directives()):
            r = reason_plan("case", "evidence")
        assert "directives" in r
        assert isinstance(r["directives"], dict)

    def test_directives_priority_tools_parsed(self):
        from tools.reasoning import reason_plan
        with patch(HTTP_PATCH, return_value=_resp_with_directives()):
            r = reason_plan("case", "evidence")
        assert r["directives"].get("priority_tools") == ["vol.psscan", "vol.cmdline"]

    def test_evidence_capped_at_300_lines(self):
        from tools.reasoning import reason_plan
        big_evidence = "\n".join(f"line{i}" for i in range(400))
        with patch(HTTP_PATCH, return_value=_resp_with_directives()) as m:
            reason_plan("case", big_evidence)
        body = m.call_args[1]["json"]
        user_msg = body["messages"][1]["content"]
        assert "line399" not in user_msg
        assert "omitted for brevity" in user_msg

    def test_case_and_evidence_in_request(self):
        from tools.reasoning import reason_plan
        with patch(HTTP_PATCH, return_value=_resp("ok")) as m:
            reason_plan("Suspected C2 beacon", "memory.img mounted at /mnt")
        body = m.call_args[1]["json"]
        user_msg = body["messages"][1]["content"]
        assert "Suspected C2 beacon" in user_msg
        assert "memory.img" in user_msg

    def test_server_error_has_directives_key(self):
        from tools.reasoning import reason_plan
        with patch(HTTP_PATCH, side_effect=Exception("refused")):
            r = reason_plan("case", "evidence")
        assert r["success"] is False
        assert "directives" in r


class TestReasonHypothesize:
    def test_returns_success(self):
        from tools.reasoning import reason_hypothesize
        with patch(HTTP_PATCH, return_value=_resp_with_directives("Hypothesis A: malicious.")):
            r = reason_hypothesize("cmd.exe from orphaned PPID 2748 in Session 0")
        assert r["success"] is True

    def test_directives_present(self):
        from tools.reasoning import reason_hypothesize
        with patch(HTTP_PATCH, return_value=_resp_with_directives()):
            r = reason_hypothesize("observation")
        assert "directives" in r
        assert isinstance(r["directives"], dict)

    def test_conclusion_present(self):
        from tools.reasoning import reason_hypothesize
        with patch(HTTP_PATCH, return_value=_resp("Hypothesis A: malicious.")):
            r = reason_hypothesize("cmd.exe from orphaned PPID 2748")
        assert "Hypothesis" in r["conclusion"]

    def test_conclusion_strips_directives_block(self):
        from tools.reasoning import reason_hypothesize
        content = "Hypothesis: malicious.\nDIRECTIVES:\n{\"priority_tools\": [\"vol.psscan\"]}"
        with patch(HTTP_PATCH, return_value=_resp(content)):
            r = reason_hypothesize("cmd.exe from orphaned PPID")
        assert "DIRECTIVES" not in r["conclusion"]
        assert "Hypothesis: malicious." in r["conclusion"]

    def test_conclusion_capped_at_1200_chars(self):
        from tools.reasoning import reason_hypothesize
        long_content = "A" * 2000
        with patch(HTTP_PATCH, return_value=_resp(long_content)):
            r = reason_hypothesize("observation")
        assert len(r["conclusion"]) <= 1200

    def test_context_included_in_request(self):
        from tools.reasoning import reason_hypothesize
        with patch(HTTP_PATCH, return_value=_resp("ok")) as m:
            reason_hypothesize("observation", context="Windows 10, CRIMSON OSPREY")
        body = m.call_args[1]["json"]
        user_msg = body["messages"][1]["content"]
        assert "CRIMSON OSPREY" in user_msg

    def test_server_unreachable_returns_error(self):
        from tools.reasoning import reason_hypothesize
        with patch(HTTP_PATCH, side_effect=Exception("connection refused")):
            r = reason_hypothesize("observation")
        assert r["success"] is False
        assert "connection refused" in r["error"]

    def test_server_unreachable_has_directives_key(self):
        from tools.reasoning import reason_hypothesize
        with patch(HTTP_PATCH, side_effect=Exception("refused")):
            r = reason_hypothesize("observation")
        assert "directives" in r


class TestReasonEvaluateFinding:
    def test_supported_verdict(self):
        from tools.reasoning import reason_evaluate_finding
        with patch(HTTP_PATCH, return_value=_resp_with_directives("VERDICT: SUPPORTED.")):
            r = reason_evaluate_finding(
                finding="BlazingTools keylogger installed by attacker",
                supporting_evidence="Amcache entry, 48/77 VT detections, MFT ctime",
            )
        assert r["success"] is True
        assert "SUPPORTED" in r["conclusion"]

    def test_directives_present(self):
        from tools.reasoning import reason_evaluate_finding
        with patch(HTTP_PATCH, return_value=_resp_with_directives()):
            r = reason_evaluate_finding("finding", "evidence")
        assert "directives" in r

    def test_challenged_verdict(self):
        from tools.reasoning import reason_evaluate_finding
        with patch(HTTP_PATCH, return_value=_resp("VERDICT: CHALLENGED. No direct attribution.")):
            r = reason_evaluate_finding(
                finding="gpupdate.exe run by attacker",
                supporting_evidence="Process in memory, spawned from svchost",
            )
        assert "CHALLENGED" in r["conclusion"]

    def test_case_context_included(self):
        from tools.reasoning import reason_evaluate_finding
        with patch(HTTP_PATCH, return_value=_resp("ok")) as m:
            reason_evaluate_finding("finding", "evidence", case_context="FOR508 dataset")
        body = m.call_args[1]["json"]
        user_msg = body["messages"][1]["content"]
        assert "FOR508" in user_msg

    def test_server_error_has_directives_key(self):
        from tools.reasoning import reason_evaluate_finding
        with patch(HTTP_PATCH, side_effect=Exception("timeout")):
            r = reason_evaluate_finding("finding", "evidence")
        assert r["success"] is False
        assert "directives" in r


class TestReasonSynthesize:
    def test_returns_success(self):
        from tools.reasoning import reason_synthesize
        findings = "1. Keylogger installed 2018-08-31\n2. BITS exfiltration 2018-09-05"
        with patch(HTTP_PATCH, return_value=_resp_with_directives("Gap: initial access unknown.")):
            r = reason_synthesize(findings)
        assert r["success"] is True

    def test_directives_present(self):
        from tools.reasoning import reason_synthesize
        with patch(HTTP_PATCH, return_value=_resp_with_directives()):
            r = reason_synthesize("finding 1\nfinding 2")
        assert "directives" in r

    def test_investigation_summary_included(self):
        from tools.reasoning import reason_synthesize
        with patch(HTTP_PATCH, return_value=_resp("ok")) as m:
            reason_synthesize("finding 1\nfinding 2", investigation_summary="ran psscan, netscan, amcache")
        body = m.call_args[1]["json"]
        user_msg = body["messages"][1]["content"]
        assert "psscan" in user_msg

    def test_model_and_url_in_request(self):
        from tools.reasoning import reason_synthesize, MODEL, FOUNDATION_SEC_URL
        with patch(HTTP_PATCH, return_value=_resp("ok")) as m:
            reason_synthesize("findings")
        call_url = m.call_args[0][0]
        body = m.call_args[1]["json"]
        assert "v1/chat/completions" in call_url
        assert body["model"] == MODEL

    def test_server_error_has_directives_key(self):
        from tools.reasoning import reason_synthesize
        with patch(HTTP_PATCH, side_effect=Exception("refused")):
            r = reason_synthesize("findings")
        assert r["success"] is False
        assert "directives" in r


class TestNoUrlConfigured:
    def test_missing_url_returns_error(self, monkeypatch):
        monkeypatch.setattr("tools.reasoning.FOUNDATION_SEC_URL", "")
        from tools.reasoning import reason_hypothesize
        r = reason_hypothesize("observation")
        assert r["success"] is False
        assert "FOUNDATION_SEC_URL" in r["error"]

    def test_missing_url_has_directives_key(self, monkeypatch):
        monkeypatch.setattr("tools.reasoning.FOUNDATION_SEC_URL", "")
        from tools.reasoning import reason_hypothesize
        r = reason_hypothesize("observation")
        assert "directives" in r


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
        text = 'DIRECTIVES:\n{"priority_tools": ["vol.psscan"], "focus_pids": [1234] // check this pid\n}'
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


class TestHealthCheck:
    def test_server_down_returns_failure(self):
        from tools.reasoning import reason_hypothesize
        with patch(HEALTH_PATCH, return_value=False):
            r = reason_hypothesize("observation")
        assert r["success"] is False
        assert "unreachable" in r["error"]

    def test_server_down_has_directives_key(self):
        from tools.reasoning import reason_hypothesize
        with patch(HEALTH_PATCH, return_value=False):
            r = reason_hypothesize("observation")
        assert "directives" in r

    def test_server_down_does_not_call_completions(self):
        from tools.reasoning import reason_hypothesize
        with patch(HEALTH_PATCH, return_value=False):
            with patch(HTTP_PATCH) as m:
                reason_hypothesize("observation")
        m.assert_not_called()

    def test_server_up_proceeds_to_completions(self):
        from tools.reasoning import reason_hypothesize
        # autouse fixture already sets health=True; verify completions is called
        with patch(HTTP_PATCH, return_value=_resp_with_directives()) as m:
            r = reason_hypothesize("observation")
        assert r["success"] is True
        assert m.called


class TestTokenBudgetCap:
    def test_falls_back_to_line_cap_when_tokenize_unavailable(self):
        from tools.reasoning import reason_plan
        big = "\n".join(f"line{i}" for i in range(400))
        with patch(HTTP_PATCH, return_value=_resp_with_directives()) as m:
            reason_plan("case", big)
        # Last POST is the completions call; user message should be line-capped at 300
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "line399" not in user_msg
        assert "omitted for brevity" in user_msg

    def test_token_aware_trims_further_when_over_budget(self):
        from tools.reasoning import reason_plan, _INPUT_BUDGET
        big = "\n".join(f"line{i}" for i in range(400))

        def fake_token_count(msgs):
            # Over budget for 300 lines, under budget for 100 lines
            user = msgs[1]["content"]
            return _INPUT_BUDGET + 100 if "line299" in user else _INPUT_BUDGET - 100

        with patch("tools.reasoning._token_count", side_effect=fake_token_count):
            with patch(HTTP_PATCH, return_value=_resp_with_directives()) as m:
                reason_plan("case", big)
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "line299" not in user_msg
        assert "omitted for brevity" in user_msg

    def test_token_count_returns_neg1_on_bad_response(self):
        from tools.reasoning import _token_count
        # Mock returns response without "count" key
        m = MagicMock()
        m.status_code = 200
        m.json.return_value = {"choices": []}
        with patch(HTTP_PATCH, return_value=m):
            result = _token_count([{"role": "user", "content": "hello"}])
        assert result == -1

    def test_token_count_returns_neg1_on_exception(self):
        from tools.reasoning import _token_count
        with patch(HTTP_PATCH, side_effect=Exception("refused")):
            result = _token_count([{"role": "user", "content": "hello"}])
        assert result == -1

    def test_short_evidence_not_trimmed(self):
        from tools.reasoning import reason_plan
        short = "line1\nline2\nline3"
        with patch(HTTP_PATCH, return_value=_resp_with_directives()) as m:
            reason_plan("case", short)
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "line1" in user_msg
        assert "omitted for brevity" not in user_msg
