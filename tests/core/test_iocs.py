"""Typed IOCs, their ATT&CK detection coverage, and how coverage surfaces
(DAIR leads, readiness warnings) without ever blocking."""
import json
from unittest.mock import patch

import pytest

import tools.mitre as M
from core import iocs as I
from core.execution_log import ExecutionLog


@pytest.fixture
def case(tmp_path, monkeypatch):
    det = {"detection": {
        "T1200": {"name": "Hardware Additions", "strategies": [{"id": "DET0069", "name": "x"}],
                  "related": [],
                  "analytics": [{"id": "AN0185", "platforms": ["Windows"], "description": "",
                                 "log_sources": [{"component": "Drive Creation", "source": "", "channel": ""},
                                                 {"component": "Process Creation", "source": "", "channel": ""}]},
                                {"id": "AN0186", "platforms": ["Linux"], "description": "",
                                 "log_sources": [{"component": "Network Traffic Flow", "source": "", "channel": ""}]}]},
        "T1136": {"name": "Create Account", "strategies": [], "related": ["T1021.001"],
                  "analytics": [{"id": "AN1", "platforms": ["Windows"], "description": "",
                                 "log_sources": [{"component": "User Account Creation", "source": "", "channel": ""},
                                                 {"component": "Active Directory Object Creation", "source": "", "channel": ""}]}]},
    }}
    p = tmp_path / "mitre_detection.json"
    p.write_text(json.dumps(det))
    monkeypatch.setattr(M, "DEFAULT_DETECTION_PATH", str(p))
    tech = tmp_path / "mitre_techniques.json"
    tech.write_text(json.dumps({"techniques": {
        "T1200": {"name": "Hardware Additions", "tactic": "Initial Access"},
        "T1136": {"name": "Create Account", "tactic": "Persistence"},
        "T1136.001": {"name": "Local Account", "tactic": "Persistence"}}}))
    monkeypatch.setattr(M, "DEFAULT_TECHNIQUES_PATH", str(tech))
    log = ExecutionLog()
    log.configure("IOC", str(tmp_path / "trace.json"), save_session=False)
    log.record_dair_call("Scan", "", False, "", "", "stay", "")
    return log


def _tool(log, cmd, mcp_tool, out="rows"):
    cid = log.record_tool_call(cmd, True, False, 0, 0, stdout_excerpt=out)
    log.index().by_call_id[cid]["mcp_tool"] = mcp_tool
    return cid


def test_normalize_by_type():
    assert I.normalize("device", "VID_03EB&PID_2422") == "03EB:2422"
    assert I.normalize("device", "03eb:2422") == "03EB:2422"
    assert I.normalize("ipv4", " 173.73.166.249 ") == "173.73.166.249"
    assert I.normalize("sid", "s-1-5-21-1-2-3-1006") == "S-1-5-21-1-2-3-1006"
    assert I.normalize("scheduled_task", "\\Windows\\System32\\Tasks\\FileTree") == "\\windows\\system32\\tasks\\filetree"
    assert I.normalize("email", "Nina_Kwai@QQ.com") == "nina_kwai@qq.com"
    for t, v in (("ipv4", "not-an-ip"), ("sha256", "abc"), ("device", "ducky"), ("nope", "x")):
        with pytest.raises(ValueError):
            I.normalize(t, v)


def test_records_merge_and_coverage_follows_examination(case):
    ev = _tool(case, "setupapi read", "misc_device_install_inventory",
               out="USBSTOR vendor ATMEL product Ducky_Storage VID_03EB&PID_2422")
    case.record_ioc("device", "03EB:2422", "03EB:2422", "observed", ["T1200"], [ev])
    case.record_ioc("device", "VID_03EB&PID_2422", "03EB:2422", "malicious", [], [ev])
    state = I.ioc_state(case._entries)
    assert list(state) == ["device:03EB:2422"] and state["device:03EB:2422"]["status"] == "malicious"

    cov = I.coverage(case._entries)
    by = {(i["technique"], i["component"]): i["status"] for i in cov["items"] if i["component"]}
    assert by[("T1200", "Drive Creation")] == "covered"          # its own output names the device
    assert by[("T1200", "Process Creation")] == "open"           # nothing examined for it yet
    assert ("T1200", "Network Traffic Flow") not in by           # Linux-only analytic


def test_a_tool_that_merely_ran_does_not_cover_an_ioc(case):
    ev = _tool(case, "setupapi read", "misc_device_install_inventory", out="VID_03EB&PID_2422")
    case.record_ioc("device", "03EB:2422", "03EB:2422", "malicious", ["T1200"], [ev],
                    aliases=["Ducky_Storage"])
    _tool(case, "dotnet PECmd.dll -d /img/Windows/Prefetch --csv /case/exports/pf", "ez_pecmd")
    st = lambda: {i["component"]: i["status"] for i in I.coverage(case._entries)["items"] if i["component"]}
    assert st()["Process Creation"] == "open"                   # Prefetch parsed, never asked about the device
    # A traced read over that tool's output that queries for the IOC (by alias) examines it.
    _tool(case, "read.output --output /case/exports/pf/prefetch.csv query=Ducky_Storage 2016-06-18",
          "read_output")
    assert st()["Process Creation"] == "covered"


def test_unmapped_components_are_never_open_and_dispositions_settle(case):
    dev = _tool(case, "setupapi read", "misc_device_install_inventory", out="VID_03EB&PID_2422")
    case.record_ioc("device", "03EB:2422", "03EB:2422", "observed", ["T1200"], [dev])
    case.record_disposition("coverage", "T1200:Process Creation", "absent_from_evidence")
    st = {(i["technique"], i["component"]): i["status"] for i in I.coverage(case._entries)["items"] if i["component"]}
    assert st[("T1200", "Process Creation")] == "dispositioned"

    sam = _tool(case, "sam", "ez_recmd_hive", out="Users\\Names\\defaultprinter RID 1006")
    case.record_ioc("account", "defaultprinter", "defaultprinter", "malicious", ["T1136"], [sam])
    cov = I.coverage(case._entries)
    st = {i["component"]: i["status"] for i in cov["items"] if i["component"]}
    assert st["Active Directory Object Creation"] == "unmapped"
    assert st["User Account Creation"] == "covered"
    assert any(i["status"] == "advisory" and i["related_techniques"] == ["T1021.001"] for i in cov["items"])


def test_record_ioc_tool_requires_grounding_and_known_techniques(case):
    import tools.misc as TM
    with patch("core.execution_log.log", case):
        r = TM.record_ioc("ipv4", "173.73.166.249", evidence_call_ids=[])
        assert not r["success"] and r["gate"] == "typed_ioc"
        ev = _tool(case, "EvtxECmd -d winevt/Logs", "ez_evtxecmd")
        r = TM.record_ioc("ipv4", "173.73.166.249", evidence_call_ids=[ev], techniques=["T9999"])
        assert not r["success"] and r["gate"] == "mitre_technique_validation"
        r = TM.record_ioc("device", "vid_03eb&pid_2422", evidence_call_ids=[ev], techniques=["t1200"])
        assert r["success"] and r["key"] == "device:03EB:2422" and r["techniques"] == ["T1200"]
        listed = TM.list_iocs(technique="T1200")
        assert listed["count"] == 1 and listed["coverage"]
        assert TM.list_iocs(tactic="initial access")["count"] == 1
        assert TM.list_iocs(ioc_type="ipv4")["count"] == 0


def test_open_coverage_warns_and_leads_dair_but_never_blocks(case):
    from tools._readiness import assess_readiness
    from tools.dair import _ioc_coverage_block
    ev = _tool(case, "setupapi read", "misc_device_install_inventory", out="VID_03EB&PID_2422")
    case.record_ioc("device", "03EB:2422", "03EB:2422", "malicious", ["T1200"], [ev])
    r = assess_readiness(case)
    assert any("ATT&CK coverage item" in w for w in r["warnings"])
    assert not any("ATT&CK coverage" in b for b in r["blocking_issues"])
    assert r["ioc_inventory"]["iocs"] and r["ioc_inventory"]["open"]
    with patch("core.execution_log.log", case):
        assert "T1200 Hardware Additions / Process Creation" in _ioc_coverage_block("Scan")
        assert _ioc_coverage_block("Collect") == ""
