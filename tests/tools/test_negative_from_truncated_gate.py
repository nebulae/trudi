"""Tests for the negative_from_truncated gate.

This gate enforces the CLAUDE.md truncated-output rule: an UNCONFIRMED
finding cannot be linked to a tool_call whose output was truncated. The
regression motivating the gate is NITROBA-2008, where the agent recorded
"no roster match in PCAP" against an ngrep call whose stdout was 600
chars of '#' progress markers (truncated=True) and so missed 116 cleartext
matches of `jcoachj@gmail.com`.
"""
from unittest.mock import MagicMock

from tools._gates import GateContext
from tools._gates.negative_from_truncated import check


def _ctx(*, tier: str, linked_call_id: int, by_call_id: dict) -> GateContext:
    fake_log = MagicMock()
    fake_idx = MagicMock(by_call_id=by_call_id)
    return GateContext(
        description="No roster match in PCAP",
        confidence=tier,
        tier=tier.upper(),
        source="net.ngrep_search",
        linked_call_id=linked_call_id,
        tested_hypothesis_id="",
        log=fake_log,
        idx=fake_idx,
        window=[],
    )


def test_unconfirmed_linked_to_truncated_call_refused():
    """The original NITROBA-2008 failure mode: UNCONFIRMED negative finding
    whose linked tool_call returned truncated output. Must refuse."""
    by_call_id = {
        49: {
            "type": "tool_call",
            "cmd": "sudo ngrep -I /tmp/x.pcap -i 'jcoach|burtgreedom' tcp",
            "truncated": True,
            "success": True,
        }
    }
    ctx = _ctx(tier="UNCONFIRMED", linked_call_id=49, by_call_id=by_call_id)
    failure = check(ctx)
    assert failure is not None
    assert failure["gate"] == "negative_from_truncated"
    assert "truncated" in failure["error"].lower()
    assert "49" in failure["error"]


def test_unconfirmed_linked_to_clean_call_passes():
    """UNCONFIRMED is fine when the linked call ran to completion."""
    by_call_id = {
        49: {
            "type": "tool_call",
            "cmd": "sudo ngrep -q -I /tmp/x.pcap -i jcoach",
            "truncated": False,
            "success": True,
        }
    }
    ctx = _ctx(tier="UNCONFIRMED", linked_call_id=49, by_call_id=by_call_id)
    assert check(ctx) is None


def test_unconfirmed_with_no_linked_call_passes():
    """linked_call_id=0 is allowed for negative findings (genesis grace)."""
    ctx = _ctx(tier="UNCONFIRMED", linked_call_id=0, by_call_id={})
    assert check(ctx) is None


def test_confirmed_linked_to_truncated_call_passes():
    """The gate is scoped to UNCONFIRMED. Higher tiers may legitimately cite
    a truncated call (the visible output already proves the positive)."""
    by_call_id = {
        49: {
            "type": "tool_call",
            "cmd": "ngrep ...",
            "truncated": True,
            "success": True,
        }
    }
    for tier in ("CONFIRMED", "LIKELY", "SUSPECTED"):
        ctx = _ctx(tier=tier, linked_call_id=49, by_call_id=by_call_id)
        assert check(ctx) is None, f"gate should not fire on {tier}"


def test_unknown_linked_call_id_passes():
    """Out-of-trace linked_call_id is the linked_call_id_must_exist gate's
    job, not ours — pass through cleanly."""
    ctx = _ctx(tier="UNCONFIRMED", linked_call_id=9999, by_call_id={})
    assert check(ctx) is None
