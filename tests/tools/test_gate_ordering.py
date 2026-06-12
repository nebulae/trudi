"""Verify gate registry ordering is stable and gates run in the documented order."""
import pytest
from tools._gates import GATES, GateContext, run_gates


EXPECTED_ORDER = [
    "mcp_routing",
    "dair_required",
    "lineage_required",
    "evidence_strength",
    "completeness",
    "attribution",
    "transfer",
]


def test_gate_registry_order():
    """The order is load-bearing — mcp_routing first so its message wins
    over dair_required when both fire. CONFIRMED-tier checks come last so
    infra problems (DAIR not started, missing linked_call_id) refuse before
    we burn cycles on adversarial-review lookups."""
    assert [name for name, _ in GATES] == EXPECTED_ORDER


def test_all_gates_return_none_or_dict():
    """Each gate must return None (pass) or a dict (refusal). Confirm via
    inspection — actual behaviour is exercised by tests/tools/test_misc.py."""
    from unittest.mock import MagicMock
    fake_log = MagicMock()
    fake_log.index.return_value = MagicMock(by_call_id={}, by_type={}, by_tool={})
    ctx = GateContext(
        description="benign test",
        confidence="UNCONFIRMED",
        tier="UNCONFIRMED",
        source="test",
        linked_call_id=0,
        tested_hypothesis_id="",
        log=fake_log,
        idx=MagicMock(by_call_id={}, by_type={}, by_tool={}, findings_by_linked={}, hypotheses_by_id={}),
        window=[{"type": "dair_call"}],
    )
    # UNCONFIRMED tier + dair_call in window → all gates should pass
    failure = run_gates(ctx)
    assert failure is None


def test_dair_required_fires_before_tier_checks():
    """If no dair_call exists, dair_required must fire even for CONFIRMED
    findings (so the agent gets the underlying-cause error, not 'missing eval')."""
    from unittest.mock import MagicMock
    fake_log = MagicMock()
    ctx = GateContext(
        description="CONFIRMED malicious process",
        confidence="CONFIRMED",
        tier="CONFIRMED",
        source="vol",
        linked_call_id=0,
        tested_hypothesis_id="",
        log=fake_log,
        idx=MagicMock(by_call_id={}, by_type={}, by_tool={}, findings_by_linked={}, hypotheses_by_id={}),
        window=[],  # NO dair_call
    )
    failure = run_gates(ctx)
    assert failure is not None
    assert failure["gate"] == "dair_required"


def test_evidence_strength_fires_after_dair_passes():
    """With dair_call present but linked_call_id=0, evidence_strength fires."""
    from unittest.mock import MagicMock
    fake_log = MagicMock()
    ctx = GateContext(
        description="CONFIRMED malicious process",
        confidence="CONFIRMED",
        tier="CONFIRMED",
        source="vol",
        linked_call_id=0,
        tested_hypothesis_id="",
        log=fake_log,
        idx=MagicMock(by_call_id={}, by_type={}, by_tool={}, findings_by_linked={}, hypotheses_by_id={}),
        window=[{"type": "dair_call"}],
    )
    failure = run_gates(ctx)
    assert failure is not None
    assert failure["gate"] == "evidence_strength"
    assert failure["detail_gate"] == "confirmed_requires_linked_call_id"


def test_broad_contracts_preserve_detail_gate(monkeypatch):
    """Broad gates keep the public gate simple while preserving exact cause."""
    from tools._gates import contracts
    from tools._gates import negative_from_truncated
    from tools._gates import principal_attribution_grounding
    from tools._gates import exfil_channel_grounding

    monkeypatch.setattr(
        negative_from_truncated,
        "check",
        lambda ctx: {"gate": "negative_from_truncated", "error": "truncated"},
    )
    monkeypatch.setattr(
        principal_attribution_grounding,
        "check",
        lambda ctx: {"gate": "principal_attribution_grounding", "error": "ungrounded"},
    )
    monkeypatch.setattr(
        exfil_channel_grounding,
        "check",
        lambda ctx: {"gate": "exfil_channel_grounding", "error": "no transfer"},
    )

    assert contracts.completeness(object()) == {
        "gate": "completeness",
        "detail_gate": "negative_from_truncated",
        "error": "truncated",
    }
    assert contracts.attribution(object()) == {
        "gate": "attribution",
        "detail_gate": "principal_attribution_grounding",
        "error": "ungrounded",
    }
    assert contracts.transfer(object()) == {
        "gate": "transfer",
        "detail_gate": "exfil_channel_grounding",
        "error": "no transfer",
    }
