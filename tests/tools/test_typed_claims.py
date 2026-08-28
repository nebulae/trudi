"""typed_claims gate — declared claim structure instead of wording regexes.

The root-cause fix for wording-evadable triggers: CONFIRMED/LIKELY findings and
classified UNCONFIRMED negatives must DECLARE claim_kind + category; downstream
gates key on the declared structure first.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tools._gates import GateContext, typed_claims


def _ctx(description="x", tier="LIKELY", claim=None, supporting_evidence="ev"):
    return GateContext(
        description=description, confidence=tier.capitalize(), tier=tier,
        source="t", linked_call_id=0, tested_hypothesis_id="",
        log=MagicMock(), idx=SimpleNamespace(by_call_id={}, by_type={}),
        window=[], input_call_ids=[], supporting_evidence=supporting_evidence,
        claim=claim or {},
    )


@pytest.fixture(autouse=True)
def _enforce(monkeypatch):
    # conftest defaults enforcement OFF for the legacy corpus; this suite is
    # about the enforcement itself.
    monkeypatch.setenv("TRUDI_REQUIRE_TYPED_CLAIMS", "1")


class TestTypedClaims:
    def test_likely_without_claim_refused(self):
        out = typed_claims.check(_ctx(tier="LIKELY"))
        assert out is not None and out["gate"] == "typed_claims"
        assert "claim_kind" in out["error"] and "category" in out["error"]

    def test_confirmed_with_claim_passes(self):
        out = typed_claims.check(_ctx(
            tier="CONFIRMED",
            claim={"kind": "positive", "category": "exfil", "act": "egress",
                   "entities": ["a@b.c"], "channel": "usb", "window": {}}))
        assert out is None

    def test_unconfirmed_requires_claim_structurally(self):
        # No wording classifier: EVERY UNCONFIRMED finding declares its shape.
        out = typed_claims.check(_ctx(
            description="No exfiltration off the host could be established",
            tier="UNCONFIRMED"))
        assert out is not None and out["gate"] == "typed_claims"
        out = typed_claims.check(_ctx(
            description="Possibly a benign scheduled backup", tier="UNCONFIRMED"))
        assert out is not None and set(out["missing"]) == {"claim_kind", "category", "act"}

    def test_act_required_and_conditionals(self):
        from tools._gates._claims import normalize_claim
        base = dict(claim_kind="positive", category="exfil")
        out = typed_claims.check(_ctx(tier="LIKELY", claim=normalize_claim(**base)))
        assert out["missing"] == ["act"] and "act=" in out["error"]
        out = typed_claims.check(_ctx(tier="LIKELY", claim=normalize_claim(**base, act="egress")))
        assert out["missing"] == ["channel"]
        out = typed_claims.check(_ctx(tier="LIKELY", claim=normalize_claim(
            claim_kind="positive", category="delivery", act="delivery")))
        assert out["missing"] == ["recipients"]
        out = typed_claims.check(_ctx(tier="UNCONFIRMED", claim=normalize_claim(
            claim_kind="negative", category="logon_auth", act="logon")))
        assert out["missing"] == ["window"]
        out = typed_claims.check(_ctx(tier="LIKELY", claim=normalize_claim(
            claim_kind="positive", category="identity", act="attribution", actor_kind="human")))
        assert out["missing"] == ["actor"]
        out = typed_claims.check(_ctx(tier="LIKELY", claim=normalize_claim(
            claim_kind="positive", category="identity", act="attribution",
            actor_kind="human", actor="J Doe", principal="jdoe",
            session_binding_call_ids=[3])))
        assert out is None

    def test_channel_alias_and_norm_keys(self):
        from tools._gates._claims import normalize_claim
        c = normalize_claim(claim_kind="positive", category="exfil", act="egress",
                            channel="USB", entities=["CORP\\J.Doe", "usb"],
                            recipients=["buyer@x.org"], principal="J.Doe")
        assert c["channel"] == "removable" and c["claim_version"] == 2
        assert c["entities_norm"] == ["jdoe", "usb"] and c["principal_norm"] == "jdoe"
        assert c["recipients_norm"] == ["buyer@xorg"]   # canonical key, not display form
        assert typed_claims.check(_ctx(tier="LIKELY", claim=c)) is None

    def test_suspected_not_gated(self):
        assert typed_claims.check(_ctx(tier="SUSPECTED")) is None

    def test_invalid_enum_refused_even_when_disabled(self, monkeypatch):
        monkeypatch.setenv("TRUDI_REQUIRE_TYPED_CLAIMS", "0")
        out = typed_claims.check(_ctx(claim={"kind": "definitely"}))
        assert out is not None and "Invalid" in out["error"]
        out = typed_claims.check(_ctx(claim={"kind": "positive", "act": "flying"}))
        assert out is not None and "act=" in out["error"]

    def test_env_off_disables_requirement(self, monkeypatch):
        monkeypatch.setenv("TRUDI_REQUIRE_TYPED_CLAIMS", "0")
        assert typed_claims.check(_ctx(tier="CONFIRMED")) is None

    def test_declared_category_drives_negative_completeness(self):
        # Wording classify() would MISS is still gated when the category is
        # declared — the wording-independent path.
        from tools._gates import negative_completeness as nc
        ctx = _ctx(
            description="The material never left via the alternate route",
            tier="UNCONFIRMED",
            claim={"kind": "negative", "category": "exfil", "entities": [],
                   "channel": "", "window": {}})
        ctx.idx = SimpleNamespace(by_call_id={}, by_type={"tool_call": []})
        out = nc.check(ctx)
        assert out is not None and out["gate"] == "negative_completeness"


class TestRecordFindingClaimFlow:
    def test_claim_persisted_on_entry(self, monkeypatch):
        monkeypatch.setenv("TRUDI_REQUIRE_TYPED_CLAIMS", "1")
        from core.execution_log import log
        from tools.misc import record_finding
        log.record_dair_call("Collect", "", False, "", "", "stay", "")
        cidt = log.record_tool_call(
            "misc.chat_db_export /x/main.db", True, False, 0, 0,
            stdout_excerpt="1 messages, 1 transfers")
        fn = getattr(record_finding, "fn", record_finding)
        r = fn(f"Contact ext.a received research_bundle.7z (call {cidt})",
               "SUSPECTED", source="misc.chat_db_export", linked_call_id=cidt,
               input_call_ids=[cidt],
               claim_kind="positive", category="exfil",
               entities=["ext.contact.a"], channel="chat")
        assert r["success"], r
        entry = [e for e in log._entries if e.get("type") == "finding"][-1]
        assert entry["claim"]["category"] == "exfil"
        assert entry["claim"]["entities"] == ["ext.contact.a"]
        assert entry["claim"]["channel"] == "chat"
        assert entry["claim"]["claim_version"] == 2

    def test_v2_fields_persist_and_batched_findings_forward_them(self, monkeypatch):
        monkeypatch.setenv("TRUDI_REQUIRE_TYPED_CLAIMS", "1")
        from core.execution_log import log
        from tools.misc import record_agent_message
        log.record_dair_call("Collect", "", False, "", "", "stay", "")
        cidt = log.record_tool_call("misc.chat_db_export /x/main.db", True, False, 0, 0,
                                    stdout_excerpt="1 messages")
        fn = getattr(record_agent_message, "fn", record_agent_message)
        r = fn("narration", input_call_ids=[cidt], findings=[{
            "description": "bundle sent", "confidence": "SUSPECTED",
            "linked_call_id": cidt, "input_call_ids": [cidt],
            "claim_kind": "positive", "category": "delivery", "act": "delivery",
            "recipients": ["Buyer@X.org"], "receipt_call_ids": [cidt],
            "actor_kind": "account", "actor": "jdoe", "resolves": "confirmed"}])
        assert r["findings"][0]["success"], r
        entry = [e for e in log._entries if e.get("type") == "finding"][-1]
        c = entry["claim"]
        assert c["act"] == "delivery" and c["recipients_norm"] == ["buyer@xorg"]
        assert c["receipt_call_ids"] == [cidt] and c["resolves"] == "confirmed"

    def test_likely_without_claim_refused_end_to_end(self, monkeypatch):
        monkeypatch.setenv("TRUDI_REQUIRE_TYPED_CLAIMS", "1")
        from core.execution_log import log
        from tools.misc import record_finding
        log.record_dair_call("Collect", "", False, "", "", "stay", "")
        cidt = log.record_tool_call("t.x", True, False, 0, 0, stdout_excerpt="d")
        fn = getattr(record_finding, "fn", record_finding)
        r = fn("something happened (d)", "LIKELY", linked_call_id=cidt,
               input_call_ids=[cidt], supporting_evidence="d")
        assert r["success"] is False
        assert r["gate"] == "evidence_strength"
        assert r["detail_gate"] == "typed_claims"
        # The refusal ledger keeps what the agent was told (dashboard + audit).
        led = [e for e in log._entries if e.get("type") == "finding_refused"][-1]
        assert led["error"] == r["error"][:800]
        assert led["extra"]["missing"]

    def test_principal_actor_kind_conflict_is_named_not_missing(self):
        # actor_kind='account' with a principal was
        # refused as "missing actor_kind" three times.
        from tools._gates._claims import normalize_claim, conflicts
        c = normalize_claim(claim_kind="positive", category="identity", act="attribution",
                            actor_kind="account", actor="defaultprinter", principal="defaultprinter")
        assert conflicts(c) == []                       # the account itself acted — allowed
        c = normalize_claim(claim_kind="positive", category="identity", act="attribution",
                            actor_kind="process", actor="svchost.exe", principal="defaultprinter")
        msg = conflicts(c)
        assert msg and "cannot bind principal='defaultprinter'" in msg[0] and "actor_kind='unknown'" in msg[0]
        out = typed_claims.check(_ctx(tier="LIKELY", claim=c))
        assert out["gate"] == "typed_claims" and out.get("conflict") and "missing" not in out
        assert "Typed-claim conflict" in out["error"]
        # A DEVICE creating an account is a valid
        # shape — principal is the created account, not a binding target.
        c = normalize_claim(claim_kind="positive", category="device_initial_access",
                            act="account_creation", actor_kind="device",
                            actor="ATMEL Ducky_Storage", principal="defaultprinter")
        assert conflicts(c) == [] and typed_claims.check(_ctx(tier="LIKELY", claim=c)) is None

    def test_attribution_without_actor_kind_is_missing(self):
        # The bypass shape: act=attribution answering the case
        # question with actor_kind/principal blanked, which skipped every
        # human-binding gate. Declare actor_kind — "unknown" is allowed.
        from tools._gates._claims import normalize_claim, missing_fields
        c = normalize_claim(claim_kind="positive", category="identity", act="attribution",
                            entities=["Greg Schardt", "Mr. Evil"])
        assert "actor_kind" in missing_fields("LIKELY", c)
        c = normalize_claim(claim_kind="positive", category="identity", act="attribution",
                            entities=["Greg Schardt"], actor_kind="unknown")
        assert "actor_kind" not in missing_fields("LIKELY", c)