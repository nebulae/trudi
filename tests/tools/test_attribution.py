"""Tests for tools/attribution.py — verify the F1-based ranking surfaces the
expected group from a synthetic finding trace."""
import json
import pytest
from unittest.mock import patch


@pytest.fixture
def log(tmp_path, monkeypatch):
    from core.execution_log import log as _log
    _log.configure("ATTR-TEST", str(tmp_path / "trace.json"))
    return _log


@pytest.fixture
def fake_mitre_tables(tmp_path, monkeypatch):
    """Point tools.mitre to small synthetic tables for deterministic scoring."""
    techniques = {
        "_meta": {"source": "fake", "version": "test"},
        "techniques": {
            "T1059.001": {"name": "PowerShell", "tactic": "Execution",
                          "description": "", "keywords": []},
            "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access",
                          "description": "", "keywords": []},
            "T1021.002": {"name": "SMB", "tactic": "Lateral Movement",
                          "description": "", "keywords": []},
            "T1027": {"name": "Obfuscated Files", "tactic": "Defense Evasion",
                      "description": "", "keywords": []},
            "T1071.001": {"name": "Web Protocols", "tactic": "Command And Control",
                          "description": "", "keywords": []},
            "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery",
                      "description": "", "keywords": []},
        },
    }
    groups = {
        "_meta": {"source": "fake", "version": "test"},
        "groups": {
            "G0001": {
                "name": "TestActor",
                "aliases": ["Phantom Crab"],
                "description": "",
                "technique_ids": ["T1059.001", "T1003.001", "T1021.002",
                                  "T1027", "T1071.001"],
            },
            "G0002": {
                "name": "OtherActor",
                "aliases": [],
                "description": "",
                "technique_ids": ["T1071.001", "T1083"],
            },
        },
    }
    t_path = tmp_path / "tech.json"
    g_path = tmp_path / "groups.json"
    t_path.write_text(json.dumps(techniques))
    g_path.write_text(json.dumps(groups))
    # Bust the lru_cache between tests
    from tools.mitre import _load_json
    _load_json.cache_clear()
    monkeypatch.setenv("TRUDI_MITRE_TABLE", str(t_path))
    monkeypatch.setenv("TRUDI_MITRE_GROUPS", str(g_path))
    monkeypatch.setattr("tools.mitre.DEFAULT_TECHNIQUES_PATH", str(t_path))
    monkeypatch.setattr("tools.mitre.DEFAULT_GROUPS_PATH", str(g_path))


def _seed_findings(log, tids):
    """Inject CONFIRMED findings citing each tid (bypass gates by writing entries directly)."""
    for tid in tids:
        log._entries.append({
            "call_id": log._next_id(),
            "type": "finding",
            "ts": "2026-05-23T00:00:00+00:00",
            "description": f"Confirmed observation of {tid}",
            "confidence": "CONFIRMED",
            "source": "test",
        })
    log._index_version += 1
    log._flush()


def test_attribute_actors_empty_trace(log, fake_mitre_tables):
    from tools.attribution import attribute_actors
    r = attribute_actors()
    assert r["success"] is True
    assert r["observed_tid_count"] == 0
    assert r["candidates"] == []


def test_attribute_actors_high_match(log, fake_mitre_tables):
    from tools.attribution import attribute_actors
    # Seed 5 findings → all 5 of TestActor's techniques covered → HIGH band
    _seed_findings(log, ["T1059.001", "T1003.001", "T1021.002", "T1027", "T1071.001"])
    r = attribute_actors()
    assert r["success"] is True
    assert r["candidates"], f"no candidates returned: {r}"
    top = r["candidates"][0]
    assert top["group_id"] == "G0001"
    assert top["confidence_band"] == "HIGH"
    assert top["overlap_count"] == 5
    # Suggested finding emitted at LIKELY tier
    assert r["suggested_finding"] is not None
    assert r["suggested_finding"]["primary_group_id"] == "G0001"


def test_attribute_actors_below_min_overlap(log, fake_mitre_tables):
    from tools.attribution import attribute_actors
    # Only 1 overlap with each group — under default min_overlap=2
    _seed_findings(log, ["T1083"])
    r = attribute_actors(min_overlap=2)
    assert r["candidates"] == []  # nothing meets threshold
