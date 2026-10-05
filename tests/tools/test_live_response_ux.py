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


class TestKillByImageSweep:
    def test_argv_and_irreversible(self):
        from core import ssh_exec
        argv = ssh_exec.build_argv("kill_by_image", {"image_path": "/usr/local/sbin/.trudi-rootsvc"})
        assert argv == ["/usr/bin/pkill", "-9", "-f", "/usr/local/sbin/.trudi-rootsvc"]
        assert ssh_exec.revert_template_for("kill_by_image") is None

    def test_rejects_shell_metachars(self):
        from core import ssh_exec
        import pytest as _pt
        for bad in ("/x; rm -rf /", "/x && id", "/x`id`", "../etc/passwd"):
            with _pt.raises(ssh_exec.ParamValidationError):
                ssh_exec.build_argv("kill_by_image", {"image_path": bad})

    def test_in_recipes_and_needs_approval(self):
        import yaml
        from response import policy
        for rp in ("Custom.TRUDI.NewProcess", "Custom.TRUDI.PrivilegeEscalation"):
            doc = yaml.safe_load(open(f"response/recipes/{rp}.yaml"))
            kbi = [a for a in doc["actions"] if a["action_template"] == "kill_by_image"]
            assert kbi, f"{rp} missing kill_by_image"
            assert policy.classify(kbi[0]) == policy.NEEDS_APPROVAL


class TestSnapshotEvidence:
    def _scope(self, tmp_path, monkeypatch):
        import tools.respond as respond
        case = "SNAP"
        monkeypatch.setattr(respond, "CASES_ROOT", tmp_path)
        import response.gates as gates
        monkeypatch.setattr(gates, "CASES_ROOT", tmp_path)
        bl = tmp_path / case / "monitoring" / "baselines"; bl.mkdir(parents=True)
        (bl / "C.x.json").write_text("{}")
        monkeypatch.setattr(respond, "_resolve_host_for_case", lambda c: "trudi-victim-b")
        return respond, case

    def _fake_live(self, monkeypatch):
        import tools.live as live
        calls = {"n": 1000}

        def mk(name):
            def f(*a, **k):
                calls["n"] += 1
                return {"success": True, "_trudi_call_id": calls["n"], "tool": name}
            return f
        for n in ("live_process_details", "live_read_file",
                  "live_network_connections", "live_processes"):
            monkeypatch.setattr(live, n, mk(n))

    def test_privesc_snapshots_proc_and_table(self, tmp_path, monkeypatch):
        respond, case = self._scope(tmp_path, monkeypatch)
        self._fake_live(monkeypatch)
        r = respond.snapshot_evidence(
            case, detector="Custom.TRUDI.PrivilegeEscalation",
            evidence={"pid": "612", "image_path": "/usr/local/sbin/.trudi-rootsvc"})
        assert r["success"] is True
        assert len(r["snapshot_call_ids"]) >= 2          # process_details + process_table
        caps = {c["capture"] for c in r["captured"]}
        assert "process_details" in caps and "process_table" in caps

    def test_persistence_snapshots_file(self, tmp_path, monkeypatch):
        respond, case = self._scope(tmp_path, monkeypatch)
        self._fake_live(monkeypatch)
        r = respond.snapshot_evidence(
            case, detector="Custom.TRUDI.NewPersistence",
            evidence={"path": "/etc/cron.d/trudi-pivot"})
        caps = {c["capture"] for c in r["captured"]}
        assert "persistence_file" in caps and r["snapshot_call_ids"]

    def test_logon_snapshots_netstat(self, tmp_path, monkeypatch):
        respond, case = self._scope(tmp_path, monkeypatch)
        self._fake_live(monkeypatch)
        r = respond.snapshot_evidence(
            case, detector="Custom.TRUDI.NewLogon",
            evidence={"remote_ip": "10.73.0.3", "pid": 616})
        caps = {c["capture"] for c in r["captured"]}
        assert "network_connections" in caps and "session_proc" in caps

    def test_off_scope_refused(self, tmp_path, monkeypatch):
        import tools.respond as respond
        monkeypatch.setattr(respond, "CASES_ROOT", tmp_path)
        import response.gates as gates
        monkeypatch.setattr(gates, "CASES_ROOT", tmp_path)
        r = respond.snapshot_evidence("NOCASE", detector="Custom.TRUDI.NewProcess",
                                         evidence={"pid": "1"})
        assert r.get("success") is False
