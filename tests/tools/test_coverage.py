"""Tests for tools/coverage.py."""
import pytest


@pytest.fixture
def log(tmp_path):
    from core.execution_log import log as _log
    _log.configure("COV-TEST", str(tmp_path / "trace.json"))
    return _log


def _seed_finding(log, description, confidence="CONFIRMED"):
    log._entries.append({
        "call_id": log._next_id(),
        "type": "finding",
        "ts": "2026-05-23T00:00:00+00:00",
        "description": description,
        "confidence": confidence,
        "source": "test",
    })
    log._index_version += 1


def test_coverage_empty_trace(log):
    from tools.coverage import coverage_report
    r = coverage_report()
    assert r["success"] is True
    assert r["checked"] == []
    assert r["found"] == []


def test_coverage_categorises_tiers(log):
    from tools.coverage import coverage_report
    _seed_finding(log, "Used T1003.001 to dump LSASS")
    _seed_finding(log, "Saw T1059.001 powershell usage", confidence="LIKELY")
    _seed_finding(log, "Possibly T1027 obfuscation", confidence="SUSPECTED")
    log._flush()
    r = coverage_report()
    assert "T1003.001" in r["checked"]
    assert "T1003.001" in r["found"]
    assert "T1027" in r["checked"]
    assert "T1027" not in r["found"]  # SUSPECTED tier doesn't count as "found"


def test_coverage_markdown_includes_summary(log):
    from tools.coverage import coverage_report
    _seed_finding(log, "T1003 credential dumping")
    log._flush()
    r = coverage_report()
    assert "Detection Coverage Report" in r["markdown"]
    assert "T1003" in r["markdown"]
