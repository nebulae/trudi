"""Tests for tools/antiforensics.py."""
import csv
import pytest


@pytest.fixture
def log(tmp_path):
    from core.execution_log import log as _log
    _log.configure("AF-TEST", str(tmp_path / "trace.json"))
    return _log


def _seed_tool_call(log, cmd, stdout):
    log._entries.append({
        "call_id": log._next_id(),
        "type": "tool_call",
        "ts": "2026-05-23T00:00:00+00:00",
        "cmd": cmd,
        "stdout_excerpt": stdout,
        "success": True,
    })
    log._index_version += 1


def test_timestomp_drift_detects_divergence(tmp_path):
    from tools.antiforensics import af_timestomp_drift
    csv_path = tmp_path / "mft.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "ParentPath", "FileName", "EntryNumber",
            "LastModified0x10", "LastModified0x30",
        ])
        w.writeheader()
        # Timestomp: SI is 2020, FN is 2024 → 4-year drift
        w.writerow({
            "ParentPath": "C:\\Windows\\System32",
            "FileName": "evil.exe",
            "EntryNumber": "42",
            "LastModified0x10": "2020-01-01T00:00:00",
            "LastModified0x30": "2024-09-15T14:32:00",
        })
        # Clean row
        w.writerow({
            "ParentPath": "C:\\Users",
            "FileName": "report.docx",
            "EntryNumber": "43",
            "LastModified0x10": "2024-09-15T14:32:00",
            "LastModified0x30": "2024-09-15T14:32:00",
        })
    r = af_timestomp_drift(str(csv_path))
    assert r["success"] is True
    assert r["drift_count"] == 1
    assert r["drift_records"][0]["mft_record"] == 42
    assert r["suggested_finding"]["confidence"] == "LIKELY"


def test_event_log_clear_finds_eid_1102(log):
    from tools.antiforensics import af_event_log_clear
    _seed_tool_call(
        log,
        "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f Security.evtx",
        "Record 1: EventID=1102 User=DOMAIN\\admin Time=2024-09-15T14:00:00 — "
        "Security log cleared\n"
        "Record 2: EventID=4624 User=user Time=2024-09-15T14:01:00 — Logon\n",
    )
    log._flush()
    r = af_event_log_clear()
    assert r["success"] is True
    assert r["clear_events_found"] >= 1
    assert any(e["eid"] == 1102 for e in r["events"])
    assert r["suggested_finding"]["confidence"] == "CONFIRMED"


def test_event_log_clear_no_evtxecmd(log):
    from tools.antiforensics import af_event_log_clear
    r = af_event_log_clear()
    assert r["success"] is False
    assert "ez.evtxecmd" in r["error"]


def test_usn_gaps_detects_pruning(tmp_path):
    from tools.antiforensics import af_usn_gaps
    csv_path = tmp_path / "usn.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Usn", "Reason", "FileName"])
        w.writeheader()
        # Contiguous block, then a big jump (pruning), then more contiguous
        for u in range(1000, 1010):
            w.writerow({"Usn": u, "Reason": "test", "FileName": "x"})
        # Gap of 5000 USNs
        for u in range(6010, 6020):
            w.writerow({"Usn": u, "Reason": "test", "FileName": "y"})
    r = af_usn_gaps(str(csv_path), gap_threshold=100)
    assert r["success"] is True
    assert r["gap_count"] == 1
    assert r["gap_records"][0]["delta"] == 5001  # 6010 - 1009
    assert r["suggested_finding"]["confidence"] == "SUSPECTED"
