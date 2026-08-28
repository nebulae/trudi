"""Behaviour tests for offhost_delivery_grounding.

A CONFIRMED/LIKELY finding whose typed claim asserts act="delivery"|"possession"
needs a destination-side receipt artifact — a host image alone cannot prove
off-host state. Keyed on the claim, never the wording.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

from tools._gates import GateContext
from tools._gates import offhost_delivery_grounding as odg
from tools._gates._claims import normalize_claim


def _ctx(description, *, tier="CONFIRMED", supporting_evidence="",
         linked_call_id=0, input_call_ids=None, by_call_id=None, claim=None):
    return GateContext(
        description=description,
        confidence=tier.capitalize(),
        tier=tier,
        source="test",
        linked_call_id=linked_call_id,
        tested_hypothesis_id="",
        log=MagicMock(),
        idx=SimpleNamespace(by_call_id=by_call_id or {}, by_type={}),
        window=[],
        input_call_ids=input_call_ids or [],
        supporting_evidence=supporting_evidence,
        claim=claim or {},
    )


def _delivery(act="delivery", **kw):
    return normalize_claim(claim_kind="positive", category="delivery", act=act,
                           recipients=["buyer@x.org"], **kw)


_PCAP = {"type": "tool_call", "call_id": 55, "success": True, "cmd": "net.tcpdump_read x.pcap",
         "stdout_excerpt": "response code: 201 Created — upload accepted by server"}


class TestFiresOnDestinationClaims:
    def test_delivery_without_receipt_refused(self):
        out = odg.check(_ctx("The archive was received by the recipient", claim=_delivery()))
        assert out is not None and out["gate"] == "offhost_delivery_grounding"
        assert out["missing"] == ["receipt_call_ids"]

    def test_possession_without_receipt_refused(self):
        assert odg.check(_ctx("x", claim=_delivery(act="possession"))) is not None

    def test_wording_alone_does_not_fire(self):
        assert odg.check(_ctx("The stolen data was delivered to the buyer")) is None
        assert odg.check(_ctx("The stolen data was delivered to the buyer", claim=normalize_claim(
            claim_kind="positive", category="exfil", act="egress", channel="email"))) is None


class TestSatisfiedByReceiptArtifact:
    def test_receipt_call_ids_pass(self):
        ctx = _ctx("x", claim=_delivery(receipt_call_ids=[55]), by_call_id={55: _PCAP})
        assert odg.check(ctx) is None

    def test_http_2xx_in_supporting_evidence_passes(self):
        ctx = _ctx("x", claim=_delivery(),
                   supporting_evidence="PCAP shows PUT /upload HTTP/1.1 200 OK from server")
        assert odg.check(ctx) is None

    def test_ftp_226_complete_passes(self):
        ctx = _ctx("x", claim=_delivery(), supporting_evidence="transfers.log: 226 Transfer complete")
        assert odg.check(ctx) is None

    def test_smtp_250_delivered_passes(self):
        ctx = _ctx("x", claim=_delivery(),
                   supporting_evidence="SMTP 250 2.0.0 message accepted for delivery")
        assert odg.check(ctx) is None

    def test_receipt_via_linked_entry_passes(self):
        ctx = _ctx("x", claim=_delivery(), input_call_ids=[55], by_call_id={55: _PCAP})
        assert odg.check(ctx) is None


class TestDoesNotOverfire:
    def test_suspected_tier_not_gated(self):
        assert odg.check(_ctx("x", tier="SUSPECTED", claim=_delivery())) is None
