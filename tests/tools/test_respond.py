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


@pytest.fixture
def live_case(tmp_path, monkeypatch):
    """A tmp cases root holding a baselined (live-monitoring) case so the
    `live_monitoring_scope` gate is satisfied."""
    monkeypatch.setattr(respond_mod, "CASES_ROOT", tmp_path)
    monkeypatch.setattr(gates_mod, "CASES_ROOT", tmp_path)
    case_id = "DEMO-TEST"
    baselines = tmp_path / case_id / "monitoring" / "baselines"
    baselines.mkdir(parents=True)
    (baselines / "C.deadbeef.json").write_text("{}")
    return case_id, tmp_path


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
