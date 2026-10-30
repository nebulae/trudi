"""Tests for the containment path.

`respond.suggest_containment` renders operator-runnable commands from the
detector recipe (stamped with the open investigation, superseding its own
earlier placeholder drafts); `respond.execute_action` is the gated write path
(AUTO tier runs under auto-protect, everything else needs an operator token);
`monitor.end_investigation` writes the investigation's own suggestions and
executions into its report. These tests cover rendering, gating, scoping and
the report sections.
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

    def test_end_investigation_report_is_findings_not_trace(self, tmp_path, monkeypatch):
        """The live report must be a findings report, distinct from the raw
        execution trace (which lands in the `_trace` files). Regression for the
        INV-002 bug where report == trace."""
        m = self._monitor(tmp_path, monkeypatch)
        case_id = "DEMO-TEST"
        mon = tmp_path / case_id / "monitoring"
        (mon / "baselines").mkdir(parents=True)
        (mon / "_open_investigation.json").write_text(json.dumps(
            {"investigation_id": "INV-001", "alert_ids": ["a1", "a2"]}))
        analysis = tmp_path / case_id / "analysis"
        analysis.mkdir(parents=True)
        inv_trace = analysis / f"{case_id}_INV-001_trace.json"
        inv_trace.write_text(json.dumps({
            "schema_version": "2.0", "case_id": case_id, "entry_count": 2,
            "entries": [
                {"call_id": 10, "type": "finding", "confidence": "CONFIRMED",
                 "finding_id": "F0001", "linked_call_id": 7, "input_call_ids": [5, 6],
                 "description": "Lateral movement victim-a to victim-b over SSH.",
                 "validated_techniques": ["T1021.004"],
                 "claim": {"kind": "positive", "category": "logon_auth",
                           "act": "lateral_movement", "answers_case_question": True}},
                {"call_id": 11, "type": "finding", "confidence": "LIKELY",
                 "finding_id": "F0002", "linked_call_id": 9, "input_call_ids": [],
                 "description": "Root cron persistence installed on victim-b.",
                 "validated_techniques": ["T1053.003"],
                 "claim": {"kind": "positive", "category": "persistence",
                           "act": "persistence_install"}},
            ],
        }))
        from core.execution_log import log
        log.configure(case_id, str(inv_trace), save_session=False)

        r = m.end_investigation(case_id, "INV-001")
        assert r["success"] is True and r["closed"] is True
        assert r["findings_written"] == 2

        reports = tmp_path / case_id / "reports"
        report_md = (reports / f"{case_id}_INV-001.md").read_text()
        trace_md = (reports / f"{case_id}_INV-001_trace.md").read_text()

        # Report is a findings report; trace is the execution trace. Distinct.
        assert report_md.startswith("# Investigation Report")
        assert trace_md.startswith("# Execution Trace")
        assert report_md != trace_md
        assert "Lateral movement" in report_md and "T1021.004" in report_md
        assert "## Verdict" in report_md

        doc = json.loads((reports / f"{case_id}_INV-001.json").read_text())
        assert doc["report_kind"] == "investigation_findings"
        assert len(doc["findings"]) == 2
        assert doc["verdict"]["confidence"] == "CONFIRMED"
        assert "T1053.003" in doc["attack_chain"]
        # Trace files exist and are returned.
        assert (reports / f"{case_id}_INV-001_trace.json").exists()
        assert r["trace_md_path"].endswith("_INV-001_trace.md")
        # Nothing was suggested or executed: the report says so explicitly
        # instead of silently omitting the containment sections.
        assert "No containment actions were suggested or executed" in report_md
        assert doc["containment_note"] == "none suggested or executed"


# ── Per-investigation scoping + supersession of containment actions ──────────
#
# Regression for the DECOY-DEMO reports: the response store is per case, so
# every investigation's report reprinted every ACT the case ever suggested —
# stale dry-run leftovers aimed at a TEST-NET address included — and each
# re-suggestion after evidence enrichment minted a twin ACT.

def _open_inv(root, case_id, inv, opened_at="2026-10-08T17:36:14Z"):
    mon = root / case_id / "monitoring"
    mon.mkdir(parents=True, exist_ok=True)
    (mon / "_open_investigation.json").write_text(json.dumps(
        {"investigation_id": inv, "alert_ids": ["a"], "opened_at_utc": opened_at}))


def _suggest_decoy(case_id, evidence, **kw):
    return respond_mod.suggest_containment(
        case_id, finding_id=0, detector="Custom.TRUDI.DecoyTouch", evidence=evidence, **kw)


class TestInvestigationScoping:
    def test_suggestion_stamped_with_open_investigation(self, live_case):
        case_id, root = live_case
        _open_inv(root, case_id, "INV-004")
        r = _suggest_decoy(case_id, {"remote_ip": "10.73.0.50", "remote_port": 3389})
        assert r["investigation_id"] == "INV-004"
        assert all(s["investigation_id"] == "INV-004" for s in r["suggestions"])
        on_disk = json.loads((root / case_id / "monitoring" / "response" / "suggestions"
                              / f"{r['suggestions'][0]['action_id']}.json").read_text())
        assert on_disk["investigation_id"] == "INV-004"

    def test_explicit_investigation_id_wins(self, live_case):
        case_id, root = live_case
        _open_inv(root, case_id, "INV-004")
        r = _suggest_decoy(case_id, {"remote_ip": "10.73.0.50", "remote_port": 3389},
                           investigation_id="INV-009")
        assert r["investigation_id"] == "INV-009"

    def test_no_open_investigation_leaves_stamp_empty(self, live_case):
        case_id, _root = live_case
        r = _suggest_decoy(case_id, {"remote_ip": "10.73.0.50", "remote_port": 3389})
        assert r["investigation_id"] is None
        assert all(s["investigation_id"] is None for s in r["suggestions"])

    def test_enriched_resuggest_supersedes_placeholder_draft(self, live_case):
        case_id, root = live_case
        _open_inv(root, case_id, "INV-001")
        first = _suggest_decoy(case_id, {"remote_ip": "10.73.0.50", "remote_port": 3389})
        by_tpl = {s["action_template"]: s for s in first["suggestions"]}
        assert by_tpl["kill_owning_pid"]["unresolved_placeholders"] == ["pid"]
        block_id = by_tpl["block_egress_to_endpoint"]["action_id"]

        second = _suggest_decoy(case_id, {"remote_ip": "10.73.0.50", "remote_port": 3389,
                                          "pid": "120", "image_path": "/tmp/.rdp-probe"})
        by_tpl2 = {s["action_template"]: s for s in second["suggestions"]}
        # Identical block command: reused, not re-minted.
        assert by_tpl2["block_egress_to_endpoint"]["action_id"] == block_id
        assert block_id in second["reused_action_ids"]
        # Filled kill/pkill: new ids that supersede the placeholder drafts.
        new_kill = by_tpl2["kill_owning_pid"]
        assert new_kill["manual_command"] == "kill -9 120"
        assert new_kill["supersedes"] == by_tpl["kill_owning_pid"]["action_id"]
        old_kill = json.loads((root / case_id / "monitoring" / "response" / "suggestions"
                               / f"{by_tpl['kill_owning_pid']['action_id']}.json").read_text())
        assert old_kill["superseded_by"] == new_kill["action_id"]
        assert {d["action_id"] for d in second["superseded"]} == {
            by_tpl["kill_owning_pid"]["action_id"], by_tpl["kill_by_image"]["action_id"]}
        # Only three ACT ids were ever minted for a fresh action: 3 drafts + 2 refills.
        files = list((root / case_id / "monitoring" / "response" / "suggestions").glob("ACT-*.json"))
        assert len(files) == 5

    def test_list_actions_hides_superseded_by_default(self, live_case):
        case_id, root = live_case
        _open_inv(root, case_id, "INV-001")
        _suggest_decoy(case_id, {"remote_ip": "10.73.0.50", "remote_port": 3389})
        _suggest_decoy(case_id, {"remote_ip": "10.73.0.50", "remote_port": 3389, "pid": "120",
                                 "image_path": "/tmp/.rdp-probe"})
        live = respond_mod.list_actions(case_id, investigation_id="INV-001")["actions"]
        assert len(live) == 3 and not any(a.get("superseded_by") for a in live)
        everything = respond_mod.list_actions(case_id, include_superseded=True)["actions"]
        assert len(everything) == 5
        assert respond_mod.list_actions(case_id, investigation_id="INV-002")["actions"] == []

    def test_different_target_is_not_superseded(self, live_case):
        """Two NewProcess alerts (two pids) in one investigation are two kills."""
        case_id, root = live_case
        _open_inv(root, case_id, "INV-001")
        a = respond_mod.suggest_containment(case_id, detector="Custom.TRUDI.NewProcess",
                                            evidence={"pid": 111, "image_path": "/tmp/a"})
        b = respond_mod.suggest_containment(case_id, detector="Custom.TRUDI.NewProcess",
                                            evidence={"pid": 222, "image_path": "/tmp/b"})
        ids_a = {s["action_id"] for s in a["suggestions"]}
        ids_b = {s["action_id"] for s in b["suggestions"]}
        assert ids_a.isdisjoint(ids_b)
        assert b["superseded"] == [] and b["reused_action_ids"] == []

    def test_execute_refuses_superseded_draft(self, exec_case):
        case_id, root, _calls = exec_case
        _open_inv(root, case_id, "INV-001")
        first = _suggest_decoy(case_id, {"remote_ip": "10.73.0.50", "remote_port": 3389,
                                         "pid": "<pid>"})
        # Force a draft with an unresolved pid, then refill it.
        draft = next(s for s in first["suggestions"] if s["action_template"] == "kill_owning_pid")
        second = _suggest_decoy(case_id, {"remote_ip": "10.73.0.50", "remote_port": 3389,
                                          "pid": "120"})
        refill = next(s for s in second["suggestions"] if s["action_template"] == "kill_owning_pid")
        assert refill["supersedes"] == draft["action_id"]
        r = respond_mod.execute_action(case_id, draft["action_id"], mode="operator")
        assert r["success"] is False and "superseded by" in r["error"]

    def test_execution_record_carries_investigation_id(self, exec_case):
        case_id, root, _calls = exec_case
        _open_inv(root, case_id, "INV-003")
        r = respond_mod.suggest_containment(case_id, detector="Custom.TRUDI.NewNetwork",
            evidence={"remote_ip": "10.73.0.50", "remote_port": 3389})
        block = next(s for s in r["suggestions"] if s["action_template"] == "block_egress_to_endpoint")
        ex = respond_mod.execute_action(case_id, block["action_id"], mode="auto")
        assert ex["success"] is True
        rec = json.loads((root / case_id / "monitoring" / "response" / "executions"
                          / f"{block['action_id']}.json").read_text())
        assert rec["investigation_id"] == "INV-003"


class TestReportScoping:
    """The report sections list only the closing investigation's actions."""

    def _monitor(self, tmp_path, monkeypatch):
        from tools import monitor as monitor_mod
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        return monitor_mod

    def _store(self, tmp_path, case_id):
        resp = tmp_path / case_id / "monitoring" / "response"
        (resp / "suggestions").mkdir(parents=True)
        (resp / "executions").mkdir(parents=True)

        def sug(n, inv, created, cmd, **extra):
            rec = {"action_id": f"ACT-{n}", "detector": "Custom.TRUDI.DecoyTouch",
                   "description": f"act {n}", "manual_command": cmd, "risk": "low",
                   "reversible": True, "unresolved_placeholders": [],
                   "created_at_utc": created, "investigation_id": inv, **extra}
            (resp / "suggestions" / f"ACT-{n}.json").write_text(json.dumps(rec))

        def ex(n, inv, when):
            rec = {"action_id": f"ACT-{n}", "classification": "AUTO", "mode": "auto",
                   "success": True, "exit_code": 0, "command_str": f"/sbin/iptables run {n}",
                   "rollback_command": f"/sbin/iptables undo {n}", "executed_at_utc": when,
                   "investigation_id": inv}
            (resp / "executions" / f"ACT-{n}.json").write_text(json.dumps(rec))

        # Stale dry-run leftovers: unstamped, created BEFORE INV-001 opened.
        sug(1, None, "2026-10-08T16:17:16Z", "iptables -I OUTPUT -d 192.0.2.59 -j REJECT")
        sug(2, None, "2026-10-08T16:17:16Z", "kill -9 4242")
        # INV-001: unstamped legacy record written after it opened (time fallback)
        # plus a stamped superseded draft and its refill.
        sug(7, None, "2026-10-08T17:36:28Z", "iptables -I OUTPUT -d 10.73.0.50 -j REJECT")
        sug(8, "INV-001", "2026-10-08T17:36:28Z", "kill -9 <pid>",
            unresolved_placeholders=["pid"], superseded_by="ACT-11")
        sug(11, "INV-001", "2026-10-08T17:38:22Z", "kill -9 120", supersedes="ACT-8")
        ex(7, None, "2026-10-08T17:37:16Z")
        # INV-002: stamped, its own.
        sug(13, "INV-002", "2026-10-09T06:27:00Z", "kill -9 746")
        return resp

    def _report(self, tmp_path, case_id, inv):
        reports = tmp_path / case_id / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        base = reports / f"{case_id}_{inv}"
        (reports / f"{case_id}_{inv}.md").write_text("# Report\n")
        (reports / f"{case_id}_{inv}.json").write_text(json.dumps({"entries": []}))
        return base

    def test_inv001_report_lists_only_its_live_actions(self, tmp_path, monkeypatch):
        m = self._monitor(tmp_path, monkeypatch)
        case_id = "DEMO-TEST"
        self._store(tmp_path, case_id)
        base = self._report(tmp_path, case_id, "INV-001")
        n = m._append_containment_section(case_id, base, "INV-001", "2026-10-08T17:36:14Z")
        md = (tmp_path / case_id / "reports" / f"{case_id}_INV-001.md").read_text()
        assert n == 2                       # ACT-7 (legacy, in window) + ACT-11
        assert "ACT-7" in md and "ACT-11" in md
        assert "192.0.2.59" not in md and "4242" not in md   # stale dry-run leftovers
        assert "ACT-8" not in md            # superseded draft
        assert "ACT-13" not in md           # another investigation's
        assert "does **not** execute" not in md
        doc = json.loads((tmp_path / case_id / "reports" / f"{case_id}_INV-001.json").read_text())
        assert [s["action_id"] for s in doc["recommended_containment_commands"]] == ["ACT-7", "ACT-11"]

    def test_inv002_report_has_no_inv001_actions(self, tmp_path, monkeypatch):
        m = self._monitor(tmp_path, monkeypatch)
        case_id = "DEMO-TEST"
        self._store(tmp_path, case_id)
        base = self._report(tmp_path, case_id, "INV-002")
        n = m._append_containment_section(case_id, base, "INV-002", "2026-10-09T06:26:58Z")
        assert n == 1
        md = (tmp_path / case_id / "reports" / f"{case_id}_INV-002.md").read_text()
        assert "ACT-13" in md and "kill -9 746" in md
        for stale in ("ACT-1 ", "ACT-2 ", "ACT-7", "ACT-8", "ACT-11", "192.0.2.59", "10.73.0.50"):
            assert stale not in md
        # And the executed-actions ledger does not credit INV-002 with INV-001's block.
        n2 = m._append_response_section(case_id, base, "INV-002", "2026-10-09T06:26:58Z")
        assert n2 == 0
        assert "## Autonomous Response Actions" not in \
            (tmp_path / case_id / "reports" / f"{case_id}_INV-002.md").read_text()

    def test_inv001_ledger_keeps_its_execution(self, tmp_path, monkeypatch):
        m = self._monitor(tmp_path, monkeypatch)
        case_id = "DEMO-TEST"
        self._store(tmp_path, case_id)
        base = self._report(tmp_path, case_id, "INV-001")
        n = m._append_response_section(case_id, base, "INV-001", "2026-10-08T17:36:14Z")
        assert n == 1
        md = (tmp_path / case_id / "reports" / f"{case_id}_INV-001.md").read_text()
        assert "ACT-7" in md and "/sbin/iptables undo 7" in md

    def test_unscoped_call_keeps_case_wide_behaviour(self, tmp_path, monkeypatch):
        """Back-compat: with no investigation_id the loaders list everything live."""
        m = self._monitor(tmp_path, monkeypatch)
        case_id = "DEMO-TEST"
        self._store(tmp_path, case_id)
        ids = [s["action_id"] for s in m._load_suggestions(case_id)]
        assert ids == ["ACT-1", "ACT-2", "ACT-7", "ACT-11", "ACT-13"]   # numeric order, no superseded
        assert len(m._load_suggestions(case_id, include_superseded=True)) == 6
