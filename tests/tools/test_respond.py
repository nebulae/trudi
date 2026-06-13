"""Tests for the containment-recommendation path.

TRUDI does NOT execute remediation (Velociraptor's client build ships without
`execve()`, and keeping execution out of the agent's hands is the safer
posture). `respond.suggest_containment` renders operator-runnable commands from
the detector recipe; `monitor.end_investigation` writes them into the report.
These tests cover the rendering + the report fallback section.
"""
import json
import pytest

from tools import respond as respond_mod
from response import gates as gates_mod
from response import policy as policy_mod
from core import ssh_exec as ssh_exec_mod


@pytest.fixture
def live_case(tmp_path, monkeypatch):
    """A tmp cases root holding a baselined (live-monitoring) case so the
    `live_monitoring_scope` gate is satisfied."""
    monkeypatch.setattr(respond_mod, "CASES_ROOT", tmp_path)
    monkeypatch.setattr(gates_mod, "CASES_ROOT", tmp_path)
    monkeypatch.setattr(policy_mod, "CASES_ROOT", tmp_path)
    case_id = "DEMO-TEST"
    baselines = tmp_path / case_id / "monitoring" / "baselines"
    baselines.mkdir(parents=True)
    (baselines / "C.deadbeef.json").write_text("{}")
    return case_id, tmp_path


@pytest.fixture
def exec_case(live_case, monkeypatch):
    """live_case + a stubbed write-SSH runner (records calls, never shells out)
    + a config.json that pins the host so _resolve_host_for_case is
    deterministic."""
    case_id, root = live_case
    calls = []

    def _fake_write(case, host, action_template, raw_params, **kw):
        calls.append({"case": case, "host": host, "action_template": action_template,
                      "raw_params": dict(raw_params)})
        return {"success": True, "stdout": "", "stderr": "", "exit_code": 0,
                "elapsed_seconds": 0.1, "truncated": False, "cmd": f"ssh -- {action_template}",
                "host": host, "source": "ssh_writer", "_trudi_call_id": 99}

    monkeypatch.setattr(respond_mod.ssh_exec, "ssh_run_write", _fake_write)
    cfg = root / case_id / "monitoring" / "config.json"
    cfg.write_text(json.dumps({"auto_protect": {"enabled": True}, "host": "trudi-victim"}))
    return case_id, root, calls


def _suggest_newprocess(case_id):
    """Create ACT-1 pause_pid (AUTO), ACT-2 kill_pid (destructive),
    ACT-3 quarantine_image (AUTO) from the NewProcess recipe."""
    return respond_mod.suggest_containment(
        case_id, finding_id=0, detector="Custom.TRUDI.NewProcess",
        evidence={"pid": 4242, "image_path": "/tmp/evil"},
    )


class TestSuggestContainment:
    def test_substitutes_evidence_into_command_and_description(self, live_case):
        case_id, _root = live_case
        r = respond_mod.suggest_containment(
            case_id,
            finding_id=0,
            detector="Custom.TRUDI.NewNetwork",
            evidence={"remote_ip": "203.0.113.10", "remote_port": 8080, "pid": 4242},
        )
        assert r["success"] is True
        sugg = r["suggestions"]
        assert sugg, "expected at least one suggestion from the NewNetwork recipe"

        block = next(s for s in sugg if "iptables" in s["manual_command"])
        assert "203.0.113.10" in block["manual_command"]
        assert "8080" in block["manual_command"]
        assert "<remote_ip>" not in block["manual_command"]
        assert "<remote_port>" not in block["manual_command"]
        assert "203.0.113.10:8080" in block["description"]
        assert block["unresolved_placeholders"] == []

        kill = next(s for s in sugg if s["manual_command"].startswith("kill -9"))
        assert kill["manual_command"] == "kill -9 4242"

    def test_case_insensitive_evidence_keys(self, live_case):
        # Detector alerts are inconsistent about case (`Pid` vs `pid`); the
        # placeholder `<pid>` must resolve against a lowercased key map.
        case_id, _root = live_case
        r = respond_mod.suggest_containment(
            case_id, finding_id=0,
            detector="Custom.TRUDI.NewNetwork",
            evidence={"Remote_IP": "10.0.0.5", "Remote_Port": 9, "Pid": 77},
        )
        kill = next(s for s in r["suggestions"] if s["manual_command"].startswith("kill -9"))
        assert kill["manual_command"] == "kill -9 77"

    def test_missing_evidence_flagged_unresolved(self, live_case):
        case_id, _root = live_case
        r = respond_mod.suggest_containment(
            case_id, finding_id=0,
            detector="Custom.TRUDI.NewNetwork",
            evidence={"remote_ip": "203.0.113.10", "remote_port": 8080},  # no pid
        )
        kill = next(s for s in r["suggestions"] if "kill -9" in s["manual_command"])
        assert "pid" in kill["unresolved_placeholders"]

    def test_writes_one_act_json_per_suggestion(self, live_case):
        case_id, root = live_case
        r = respond_mod.suggest_containment(
            case_id, finding_id=0,
            detector="Custom.TRUDI.NewNetwork",
            evidence={"remote_ip": "1.2.3.4", "remote_port": 5, "pid": 6},
        )
        sug_dir = root / case_id / "monitoring" / "response" / "suggestions"
        files = list(sug_dir.glob("ACT-*.json"))
        assert len(files) == len(r["suggestions"])
        rec = json.loads((sug_dir / "ACT-1.json").read_text())
        assert rec["manual_command"]
        assert rec["action_id"] == "ACT-1"

    def test_refuses_non_live_case(self, tmp_path, monkeypatch):
        monkeypatch.setattr(respond_mod, "CASES_ROOT", tmp_path)
        monkeypatch.setattr(gates_mod, "CASES_ROOT", tmp_path)
        r = respond_mod.suggest_containment(
            "NO-SUCH", finding_id=0,
            detector="Custom.TRUDI.NewNetwork", evidence={"pid": 1},
        )
        assert r["success"] is False
        assert r["gate"] == "live_monitoring_scope"

    def test_unknown_detector_errors(self, live_case):
        case_id, _root = live_case
        r = respond_mod.suggest_containment(
            case_id, finding_id=0,
            detector="Custom.TRUDI.Nonexistent", evidence={"pid": 1},
        )
        assert r["success"] is False
        assert "recipe" in r["error"].lower()


class TestReportContainmentSection:
    def test_appends_section_with_commands(self, tmp_path, monkeypatch):
        from tools import monitor as monitor_mod
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        case_id = "DEMO-TEST"
        sug_dir = tmp_path / case_id / "monitoring" / "response" / "suggestions"
        sug_dir.mkdir(parents=True)
        (sug_dir / "ACT-1.json").write_text(json.dumps({
            "action_id": "ACT-1",
            "description": "iptables REJECT outbound to 203.0.113.10:8080",
            "detector": "Custom.TRUDI.NewNetwork",
            "manual_command": "iptables -I OUTPUT -d 203.0.113.10 -p tcp --dport 8080 -j REJECT",
            "risk": "low", "reversible": True,
            "unresolved_placeholders": [],
        }))
        reports = tmp_path / case_id / "reports"
        reports.mkdir(parents=True)
        report_base = reports / "DEMO-TEST_INV-001"
        (reports / "DEMO-TEST_INV-001.md").write_text("# Report\n")
        (reports / "DEMO-TEST_INV-001.json").write_text(json.dumps({"entries": []}))

        n = monitor_mod._append_containment_section(case_id, report_base)
        assert n == 1
        md = (reports / "DEMO-TEST_INV-001.md").read_text()
        assert "Recommended Containment Commands (run manually)" in md
        assert "ACT-1" in md
        assert "iptables -I OUTPUT -d 203.0.113.10" in md
        doc = json.loads((reports / "DEMO-TEST_INV-001.json").read_text())
        assert doc["recommended_containment_commands"][0]["action_id"] == "ACT-1"
        # The pre-existing report content is preserved (append, not overwrite).
        assert md.startswith("# Report")

    def test_unresolved_placeholder_warned_in_report(self, tmp_path, monkeypatch):
        from tools import monitor as monitor_mod
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        case_id = "DEMO-TEST"
        sug_dir = tmp_path / case_id / "monitoring" / "response" / "suggestions"
        sug_dir.mkdir(parents=True)
        (sug_dir / "ACT-1.json").write_text(json.dumps({
            "action_id": "ACT-1", "description": "Terminate owning process",
            "detector": "Custom.TRUDI.NewNetwork", "manual_command": "kill -9 <pid>",
            "risk": "medium", "reversible": False,
            "unresolved_placeholders": ["pid"],
        }))
        reports = tmp_path / case_id / "reports"
        reports.mkdir(parents=True)
        report_base = reports / "DEMO-TEST_INV-001"
        (reports / "DEMO-TEST_INV-001.md").write_text("# Report\n")
        monitor_mod._append_containment_section(case_id, report_base)
        md = (reports / "DEMO-TEST_INV-001.md").read_text()
        assert "Unresolved placeholders" in md
        assert "pid" in md

    def test_no_suggestions_no_section(self, tmp_path, monkeypatch):
        from tools import monitor as monitor_mod
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        case_id = "DEMO-TEST"
        reports = tmp_path / case_id / "reports"
        reports.mkdir(parents=True)
        report_base = reports / "DEMO-TEST_INV-002"
        (reports / "DEMO-TEST_INV-002.md").write_text("# Report\n")
        n = monitor_mod._append_containment_section(case_id, report_base)
        assert n == 0
        assert "Containment" not in (reports / "DEMO-TEST_INV-002.md").read_text()


# ── Auto-protect policy + config ──────────────────────────────────────────────

class TestPolicy:
    def test_classify_auto_only_for_reversible_low(self):
        assert policy_mod.classify({"reversible": True, "risk": "low"}) == policy_mod.AUTO

    @pytest.mark.parametrize("sugg", [
        {"reversible": True, "risk": "medium"},
        {"reversible": True, "risk": "high"},
        {"reversible": False, "risk": "low"},
        {},                       # missing fields → fail-closed
        "not a dict",             # garbage → fail-closed
    ])
    def test_classify_needs_approval(self, sugg):
        assert policy_mod.classify(sugg) == policy_mod.NEEDS_APPROVAL


class TestConfigDefaultTrue:
    def test_enabled_when_file_absent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(policy_mod, "CASES_ROOT", tmp_path)
        assert policy_mod.auto_protect_enabled("X") is True
        assert policy_mod.demo_response_enabled("X") is False

    def test_disabled_when_configured(self, tmp_path, monkeypatch):
        monkeypatch.setattr(policy_mod, "CASES_ROOT", tmp_path)
        d = tmp_path / "X" / "monitoring"
        d.mkdir(parents=True)
        (d / "config.json").write_text(json.dumps({"auto_protect": {"enabled": False}}))
        assert policy_mod.auto_protect_enabled("X") is False

    def test_corrupt_json_defaults_true(self, tmp_path, monkeypatch):
        monkeypatch.setattr(policy_mod, "CASES_ROOT", tmp_path)
        d = tmp_path / "X" / "monitoring"
        d.mkdir(parents=True)
        (d / "config.json").write_text("{ not json")
        assert policy_mod.auto_protect_enabled("X") is True
        assert policy_mod.demo_response_enabled("X") is False

    def test_demo_response_opt_in(self, tmp_path, monkeypatch):
        monkeypatch.setattr(policy_mod, "CASES_ROOT", tmp_path)
        d = tmp_path / "X" / "monitoring"
        d.mkdir(parents=True)
        (d / "config.json").write_text(json.dumps({
            "demo_response": {"enabled": True, "respond_to_synthetic": True},
        }))
        cfg = policy_mod.load_config("X")
        assert cfg["demo_response"]["enabled"] is True
        assert cfg["demo_response"]["respond_to_synthetic"] is True
        assert policy_mod.demo_response_enabled("X") is True

    def test_demo_response_enabled_alone_implies_respond(self, tmp_path, monkeypatch):
        monkeypatch.setattr(policy_mod, "CASES_ROOT", tmp_path)
        d = tmp_path / "X" / "monitoring"
        d.mkdir(parents=True)
        (d / "config.json").write_text(json.dumps({
            "demo_response": {"enabled": True},
        }))
        assert policy_mod.demo_response_enabled("X") is True


# ── execute_action gate composition ───────────────────────────────────────────

class TestExecuteGate:
    def test_auto_action_executes_when_enabled(self, exec_case):
        case_id, root, calls = exec_case
        _suggest_newprocess(case_id)
        r = respond_mod.execute_action(case_id, "ACT-1", mode="auto")  # pause_pid (AUTO)
        assert r["success"] is True
        assert r["classification"] == "AUTO"
        assert r["rollback_command"] == "/bin/kill -CONT 4242"
        assert len(calls) == 1 and calls[0]["action_template"] == "pause_pid"
        rec = json.loads((root / case_id / "monitoring" / "response" / "executions"
                          / "ACT-1.json").read_text())
        assert rec["classification"] == "AUTO" and rec["success"] is True

    def test_auto_action_refused_when_disabled(self, exec_case):
        case_id, root, calls = exec_case
        (root / case_id / "monitoring" / "config.json").write_text(
            json.dumps({"auto_protect": {"enabled": False}, "host": "trudi-victim"}))
        _suggest_newprocess(case_id)
        r = respond_mod.execute_action(case_id, "ACT-1", mode="auto")
        assert r["success"] is False and r["gate"] == "approval_required"
        assert calls == []  # never shelled out

    def test_destructive_refused_without_approval(self, exec_case):
        case_id, _root, calls = exec_case
        _suggest_newprocess(case_id)
        r = respond_mod.execute_action(case_id, "ACT-2", mode="auto")  # kill_pid (destructive)
        assert r["success"] is False and r["gate"] == "approval_required"
        assert calls == []

    def test_mode_auto_does_not_bypass_destructive(self, exec_case):
        # The agent cannot self-execute a destructive action by claiming mode=auto.
        case_id, _root, calls = exec_case
        _suggest_newprocess(case_id)
        r = respond_mod.execute_action(case_id, "ACT-2", mode="auto")
        assert r["success"] is False and r["gate"] == "approval_required"
        assert calls == []

    def test_destructive_executes_with_token(self, exec_case):
        case_id, _root, calls = exec_case
        _suggest_newprocess(case_id)
        gates_mod.issue_approval(case_id, "ACT-2", "approve ACT-2")
        r = respond_mod.execute_action(case_id, "ACT-2", mode="operator")
        assert r["success"] is True
        assert calls and calls[0]["action_template"] == "kill_pid"

    def test_unresolved_placeholders_block_execution(self, exec_case):
        case_id, _root, calls = exec_case
        respond_mod.suggest_containment(  # no pid → kill_pid has unresolved <pid>
            case_id, finding_id=0, detector="Custom.TRUDI.NewProcess",
            evidence={"image_path": "/tmp/evil"})
        r = respond_mod.execute_action(case_id, "ACT-2", mode="auto")
        assert r["success"] is False and "unresolved" in r["error"].lower()
        assert calls == []


class TestApproveDualKey:
    def _seed_user_msg(self, case_id, root, text):
        analysis = root / case_id / "analysis"
        analysis.mkdir(parents=True, exist_ok=True)
        trace = analysis / f"{case_id}_INV-001_trace.json"
        trace.write_text(json.dumps({
            "schema_version": "2.0", "case_id": case_id, "entry_count": 1,
            "entries": [{"call_id": 1, "type": "user_message", "ts": "2026-01-01T00:00:00Z",
                         "content": text, "source": "claude_code_user_prompt", "role": "user"}],
        }))
        from core.execution_log import log
        log.configure(case_id, str(trace), save_session=False)

    def test_refuses_without_action_id_in_text(self, live_case):
        case_id, _root = live_case
        _suggest_newprocess(case_id)
        r = respond_mod.approve_action(case_id, "ACT-2", operator_text="approve something else")
        assert r["success"] is False and r["gate"] == "operator_text_required"

    def test_refuses_without_user_message(self, live_case):
        case_id, root = live_case
        _suggest_newprocess(case_id)
        analysis = root / case_id / "analysis"
        analysis.mkdir(parents=True, exist_ok=True)
        trace = analysis / "empty_trace.json"
        trace.write_text(json.dumps({"schema_version": "2.0", "case_id": case_id,
                                     "entry_count": 0, "entries": []}))
        from core.execution_log import log
        log.configure(case_id, str(trace), save_session=False)
        r = respond_mod.approve_action(case_id, "ACT-2", "approve ACT-2")
        assert r["success"] is False and r["gate"] == "operator_text_required"

    def test_succeeds_with_both_keys(self, live_case):
        case_id, root = live_case
        _suggest_newprocess(case_id)
        self._seed_user_msg(case_id, root, "approve ACT-2")
        r = respond_mod.approve_action(case_id, "ACT-2", "approve ACT-2")
        assert r["success"] is True
        appr = root / case_id / "monitoring" / "response" / "approvals" / "ACT-2.json"
        assert appr.exists()


class TestRevert:
    def test_revert_runs_inverse(self, exec_case):
        case_id, root, calls = exec_case
        _suggest_newprocess(case_id)
        respond_mod.execute_action(case_id, "ACT-1", mode="auto")  # pause_pid
        calls.clear()
        r = respond_mod.revert_action(case_id, "ACT-1")
        assert r["success"] is True and r["reverted"] is True
        assert calls and calls[0]["action_template"] == "resume_pid"
        rec = json.loads((root / case_id / "monitoring" / "response" / "executions"
                          / "ACT-1.json").read_text())
        assert rec["reverted"] is True

    def test_revert_irreversible_refused(self, exec_case):
        case_id, _root, calls = exec_case
        _suggest_newprocess(case_id)
        gates_mod.issue_approval(case_id, "ACT-2", "approve ACT-2")
        respond_mod.execute_action(case_id, "ACT-2", mode="operator")  # kill_pid
        r = respond_mod.revert_action(case_id, "ACT-2")
        assert r["success"] is False and "irreversible" in r["error"].lower()


class TestResponseReportAndPause:
    def _monitor(self, tmp_path, monkeypatch):
        from tools import monitor as monitor_mod
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        return monitor_mod

    def test_response_section_renders_rollback(self, tmp_path, monkeypatch):
        m = self._monitor(tmp_path, monkeypatch)
        case_id = "DEMO-TEST"
        resp = tmp_path / case_id / "monitoring" / "response"
        (resp / "suggestions").mkdir(parents=True)
        (resp / "executions").mkdir(parents=True)
        (resp / "suggestions" / "ACT-1.json").write_text(json.dumps({
            "action_id": "ACT-1", "detector": "Custom.TRUDI.NewProcess",
            "manual_command": "kill -STOP 4242", "risk": "low", "reversible": True}))
        (resp / "executions" / "ACT-1.json").write_text(json.dumps({
            "action_id": "ACT-1", "classification": "AUTO", "mode": "auto", "success": True,
            "exit_code": 0, "command_str": "/bin/kill -STOP 4242",
            "rollback_command": "/bin/kill -CONT 4242"}))
        reports = tmp_path / case_id / "reports"
        reports.mkdir(parents=True)
        base = reports / f"{case_id}_INV-001"
        (reports / f"{case_id}_INV-001.md").write_text("# Report\n")
        (reports / f"{case_id}_INV-001.json").write_text(json.dumps({"entries": []}))
        n = m._append_response_section(case_id, base)
        assert n == 1
        md = (reports / f"{case_id}_INV-001.md").read_text()
        assert "Autonomous Response Actions" in md
        assert "/bin/kill -CONT 4242" in md
        doc = json.loads((reports / f"{case_id}_INV-001.json").read_text())
        assert doc["autonomous_response_actions"][0]["rollback_command"] == "/bin/kill -CONT 4242"

    def test_pause_state_roundtrip(self, tmp_path, monkeypatch):
        m = self._monitor(tmp_path, monkeypatch)
        case_id = "DEMO-TEST"
        mon = tmp_path / case_id / "monitoring"
        mon.mkdir(parents=True)
        (mon / "config.json").write_text(json.dumps({
            "demo_response": {"enabled": True, "respond_to_synthetic": True},
        }))
        (mon / "_open_investigation.json").write_text(json.dumps(
            {"investigation_id": "INV-001", "alert_ids": ["a"]}))
        st0 = m.get_response_state(case_id)
        assert st0["paused"] is False
        assert st0["demo_response"]["respond_to_synthetic"] is True
        m.set_awaiting_approval(case_id, ["ACT-2"])
        st = m.get_response_state(case_id)
        assert st["paused"] is True and "ACT-2" in st["awaiting_approval"]
        m.clear_awaiting_approval(case_id, "ACT-2")
        assert m.get_response_state(case_id)["paused"] is False

    def test_end_investigation_skips_close_when_paused(self, tmp_path, monkeypatch):
        m = self._monitor(tmp_path, monkeypatch)
        case_id = "DEMO-TEST"
        mon = tmp_path / case_id / "monitoring"
        mon.mkdir(parents=True)
        (mon / "_open_investigation.json").write_text(json.dumps(
            {"investigation_id": "INV-001", "alert_ids": ["a"], "awaiting_approval": ["ACT-2"]}))
        r = m.end_investigation(case_id, "INV-001")
        assert r.get("closed") is False and r.get("paused") is True
        assert (mon / "_open_investigation.json").exists()  # tracker preserved
