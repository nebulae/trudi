"""Live-response UX changes (operator feedback, 2026-10-05):
1. respond.suggest_containment works off an alert with finding_id omitted.
2. AskUserQuestion answers are captured as a user_message by the PostToolUse
   hook so the operator_text_required gate accepts a POPUP approval — without
   letting the agent self-approve (only the hook writes the entry).
"""
import importlib.util
import json
from pathlib import Path

import pytest

_HOOK = Path(__file__).resolve().parents[2] / "claude" / "hooks" / "log_narration.py"


def _load_hook():
    spec = importlib.util.spec_from_file_location("ln_test", _HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestPopupCapture:
    def test_askuserquestion_answer_becomes_user_message(self):
        ln = _load_hook()
        payload = {"tool_name": "AskUserQuestion", "tool_use_id": "t1",
                   "tool_response": {"answers": {"Approve destructive action?": "Approve ACT-2"}}}
        e = ln._extract_popup_user_message(payload)
        assert e["type"] == "user_message"
        assert e["role"] == "user"
        assert e["source"] == "claude_code_popup_answer"
        assert e["content"] == "Approve ACT-2"          # carries the ACT-N id
        assert e["_source_tool_use_id"] == "t1"

    def test_decline_option_has_no_actid(self):
        ln = _load_hook()
        e = ln._extract_popup_user_message(
            {"tool_name": "AskUserQuestion", "tool_response": {"answers": {"q": "Skip"}}})
        assert "ACT-" not in e["content"]               # gate will not match → stays queued

    def test_non_popup_tool_ignored(self):
        ln = _load_hook()
        assert ln._extract_popup_user_message({"tool_name": "Bash"}) is None
        assert ln._extract_popup_user_message({"tool_name": "Read"}) is None

    def test_dict_valued_answer(self):
        ln = _load_hook()
        e = ln._extract_popup_user_message(
            {"tool_name": "AskUserQuestion",
             "tool_response": {"answers": {"q": {"label": "Approve ACT-7"}}}})
        assert e and "ACT-7" in e["content"]


class TestGateAcceptsPopup:
    def test_popup_user_message_satisfies_operator_text_gate(self, tmp_path, monkeypatch):
        import response.gates as gates
        import core.execution_log as el
        case = "POPUP-UX"
        monkeypatch.setattr(gates, "CASES_ROOT", tmp_path)
        (tmp_path / case / "monitoring" / "baselines").mkdir(parents=True)
        sug = tmp_path / case / "monitoring" / "response" / "suggestions"
        sug.mkdir(parents=True)
        (sug / "ACT-2.json").write_text(json.dumps({"action_id": "ACT-2"}))
        analysis = tmp_path / case / "analysis"
        analysis.mkdir(parents=True)
        trace = analysis / f"{case}_trace.json"
        trace.write_text(json.dumps({"entries": []}))
        el.log.configure(case, str(trace), save_session=False)
        # hook (separate process) appends the popup answer to the file
        data = json.loads(trace.read_text())
        data["entries"].append({"call_id": 1, "type": "user_message",
                                "content": "Approve ACT-2",
                                "source": "claude_code_popup_answer", "role": "user"})
        trace.write_text(json.dumps(data))
        with el.log.transaction():          # the refresh an MCP call performs
            pass
        # exact selected label as operator_text → accepted
        assert gates.check_operator_text(case, "ACT-2", "Approve ACT-2") is None
        # agent cannot self-approve an action with no operator entry
        (sug / "ACT-9.json").write_text(json.dumps({"action_id": "ACT-9"}))
        assert gates.check_operator_text(case, "ACT-9", "Approve ACT-9") is not None
