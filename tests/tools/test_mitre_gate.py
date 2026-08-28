"""H-3: mitre_technique_validation must not hard-refuse a well-formed id on an
incomplete local table; the shipped cache rejected T1027 for months because
the build filter had dropped it."""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tools._gates import GateContext, mitre_technique_validation as MT


def _ctx(desc, techniques=None):
    return GateContext(
        description=desc, confidence="Suspected", tier="SUSPECTED", source="t",
        linked_call_id=0, tested_hypothesis_id="", log=MagicMock(),
        idx=SimpleNamespace(by_call_id={}, by_type={}), window=[], input_call_ids=[],
        supporting_evidence="ev", claim={"techniques": techniques or []},
        validated_techniques=[],
    )


def test_unknown_id_on_small_table_is_recorded_unvalidated_not_refused():
    def fake_validate(tid):
        return {"exists": False, "technique_id": tid, "available_count": 486}
    with patch("tools.correlate.mitre_validate", fake_validate):
        ctx = _ctx("VeraCrypt + SDelete usage (T1027) on the host")
        assert MT.check(ctx) is None
    rec = ctx.validated_techniques[0]
    assert rec["technique_id"] == "T1027" and rec["unvalidated"] and rec["reason"] == "table_incomplete"


def test_unknown_id_on_full_table_still_refuses():
    def fake_validate(tid):
        return {"exists": False, "technique_id": tid, "available_count": 700}
    with patch("tools.correlate.mitre_validate", fake_validate):
        out = MT.check(_ctx("something (T9999)"))
    assert out and out["gate"] == "mitre_technique_validation" and out["unknown_technique_ids"] == ["T9999"]


def test_build_tables_keeps_every_live_technique():
    # The CTI bundle uses phase names outside the old DFIR_TACTICS allowlist
    # ('stealth', 'defense-impairment'); they must not drop techniques.
    from tools.mitre.build_mitre_cache import build_tables
    stix = {"objects": [
        {"type": "attack-pattern", "id": "ap-1", "name": "Obfuscated Files",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1027"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "stealth"}],
         "description": "x"},
        {"type": "attack-pattern", "id": "ap-2", "name": "Old", "revoked": True,
         "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]},
    ]}
    techniques, _groups = build_tables(stix, {})
    assert "T1027" in techniques and "T0001" not in techniques
