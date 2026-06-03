"""Verify gate registry ordering is stable and gates run in the documented order."""
import pytest
from tools._gates import GATES, GateContext, run_gates


EXPECTED_ORDER = [
    "mcp_routing",
    "dair_required",
    "lineage_required",
    "confirmed_requires_linked_call_id",
    "linked_call_id_must_exist",
    "negative_from_truncated",
    "mitre_technique_validation",
    "confirmed_requires_supported_evaluate",
    "confidence_and_citation",
    "hypothesize_required",
    "attribution_required",
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


def test_confirmed_requires_linked_call_id_fires_after_dair_passes():
    """With dair_call present but linked_call_id=0, confirmed_requires_linked_call_id fires."""
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
    assert failure["gate"] == "confirmed_requires_linked_call_id"
