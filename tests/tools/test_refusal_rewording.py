"""Refusal ledger + refusal_rewording gate."""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.execution_log import ExecutionLog
from tools._gates import GateContext, refusal_rewording as rw


def _ctx(desc, tier="LIKELY", claim=None, by_type=None, input_call_ids=None, linked=0):
    return GateContext(description=desc, confidence=tier.capitalize(), tier=tier, source="t",
                       linked_call_id=linked, tested_hypothesis_id="", log=MagicMock(),
                       idx=SimpleNamespace(by_type=by_type if by_type is not None else {}),
                       window=[], input_call_ids=input_call_ids or [],
                       supporting_evidence="x", claim=claim or {})


def _refusal(cid, desc, tier="LIKELY", detail="named_actor_attribution_grounding",
             claim=None, cited=None, extra=None):
    e = {"type": "finding_refused", "call_id": cid, "description": desc, "tier": tier,
         "gate": "attribution", "detail_gate": detail}
    if claim:
        e["claim"] = claim
    if cited:
        e["cited_call_ids"] = cited
    if extra:
        e["extra"] = extra
    return e


def _tool(cid, cmd="dotnet EvtxECmd.dll -f x", success=True):
    return {"type": "tool_call", "call_id": cid, "cmd": cmd, "success": success}


DESC = "Alice Example copied the classified archive to a removable USB drive on 2016-06-30"
REWORD = "The classified archive was copied to a removable USB drive on 2016-06-30"
CLAIM = {"kind": "positive", "category": "exfil", "act": "egress",
         "entities": ["Alice Example", "usb"], "channel": "removable"}


class TestGateUnit:
    def test_description_overlap_alone_no_longer_matches(self):
        # Wording is not compared: a near-identical description with no declared
        # claim on either side is not a rewording match.
        bt = {"finding_refused": [_refusal(10, DESC, cited=[3])], "tool_call": [_tool(3)]}
        assert rw.check(_ctx(REWORD, by_type=bt, input_call_ids=[3])) is None

    def test_reworded_same_claim_refused(self):
        bt = {"finding_refused": [_refusal(10, DESC, claim=CLAIM, cited=[3])], "tool_call": [_tool(3)]}
        out = rw.check(_ctx(REWORD, claim=CLAIM, by_type=bt, input_call_ids=[3]))
        assert out is not None and out["gate"] == "refusal_rewording"
        assert out["prior_refusal_call_id"] == 10 and out["matched_by"] == "claim"

    def test_same_hypothesis_id_matches(self):
        r = _refusal(10, DESC, cited=[3]); r["tested_hypothesis_id"] = "H0002"
        bt = {"finding_refused": [r], "tool_call": [_tool(3)]}
        c = _ctx("entirely different words", by_type=bt, input_call_ids=[3])
        c.tested_hypothesis_id = "H0002"
        out = rw.check(c)
        assert out is not None and out["matched_by"] == "hypothesis"

    def test_entities_normalized_across_spellings(self):
        c2 = dict(CLAIM, entities=["alice.example", "USB"])
        bt = {"finding_refused": [_refusal(10, DESC, claim=CLAIM, cited=[3])], "tool_call": [_tool(3)]}
        assert rw.check(_ctx("x", claim=c2, by_type=bt, input_call_ids=[3])) is not None

    def test_different_act_is_a_different_claim(self):
        c2 = dict(CLAIM, act="presence")
        bt = {"finding_refused": [_refusal(10, DESC, claim=CLAIM, cited=[3])], "tool_call": [_tool(3)]}
        assert rw.check(_ctx("x", claim=c2, by_type=bt, input_call_ids=[3])) is None

    def test_claim_match_survives_total_rewrite(self):
        bt = {"finding_refused": [_refusal(10, DESC, claim=CLAIM, cited=[3])], "tool_call": [_tool(3)]}
        out = rw.check(_ctx("Data left the host through external media.", claim=CLAIM,
                            by_type=bt, input_call_ids=[3]))
        assert out is not None and out["matched_by"] == "claim"

    def test_new_evidence_since_refusal_allows(self):
        bt = {"finding_refused": [_refusal(10, DESC, claim=CLAIM, cited=[3])],
              "tool_call": [_tool(3), _tool(12, "dotnet EvtxECmd.dll --inc 4624")]}
        assert rw.check(_ctx(REWORD, claim=CLAIM, by_type=bt, input_call_ids=[3, 12])) is None

    def test_meta_tool_call_does_not_clear(self):
        bt = {"finding_refused": [_refusal(10, DESC, claim=CLAIM, cited=[3])],
              "tool_call": [_tool(3), _tool(12, "<py>:misc_record_agent_message")]}
        assert rw.check(_ctx(REWORD, claim=CLAIM, by_type=bt, input_call_ids=[3])) is not None

    def test_honest_downgrade_allowed(self):
        bt = {"finding_refused": [_refusal(10, DESC, tier="CONFIRMED", claim=CLAIM, cited=[3])], "tool_call": [_tool(3)]}
        assert rw.check(_ctx(DESC, tier="SUSPECTED", claim=CLAIM, by_type=bt, input_call_ids=[3])) is None
        # LIKELY is not an honest downgrade of CONFIRMED for this purpose.
        assert rw.check(_ctx(DESC, tier="LIKELY", claim=CLAIM, by_type=bt, input_call_ids=[3])) is not None

    def test_newly_cited_call_allowed(self):
        bt = {"finding_refused": [_refusal(10, DESC, claim=CLAIM, cited=[3])], "tool_call": [_tool(3), _tool(4)]}
        # call 4 existed before the refusal but was not cited by it — the
        # grounding gate's own remediation ("cite the 4624 call") stays open.
        assert rw.check(_ctx(REWORD, claim=CLAIM, by_type=bt, input_call_ids=[3, 4])) is None

    def test_structural_refusal_does_not_arm(self):
        bt = {"finding_refused": [_refusal(10, DESC, detail="lineage_required", claim=CLAIM, cited=[3])],
              "tool_call": [_tool(3)]}
        assert rw.check(_ctx(DESC, claim=CLAIM, by_type=bt, input_call_ids=[3])) is None
        # confirmed_requires_supported_evaluate is remediated by a per-finding
        # reason.evaluate_finding (a reason call, not a tool run) — never arms.
        # A genuine challenge is challenge_sticky's job.
        for extra in (None, {"evaluate_verdict": "UNCERTAIN"},
                      {"evaluate_verdict": "UNCERTAIN", "evaluate_match": "fallback"},
                      {"evaluate_match": "claim"}):
            bt2 = {"finding_refused": [_refusal(10, DESC, detail="confirmed_requires_supported_evaluate",
                                                claim=CLAIM, cited=[3], extra=extra)], "tool_call": [_tool(3)]}
            assert rw.check(_ctx(DESC, claim=CLAIM, by_type=bt2, input_call_ids=[3])) is None
        # …but a MATCHED evaluate that challenged this claim is a genuine
        # challenge — it arms.
        bt2 = {"finding_refused": [_refusal(10, DESC, detail="confirmed_requires_supported_evaluate",
                                            claim=CLAIM, cited=[3],
                                            extra={"evaluate_verdict": "CHALLENGED",
                                                   "evaluate_match": "claim"})],
               "tool_call": [_tool(3)]}
        assert rw.check(_ctx(DESC, claim=CLAIM, by_type=bt2, input_call_ids=[3])) is not None
        bt3 = {"finding_refused": [_refusal(10, DESC, detail="challenge_sticky", claim=CLAIM, cited=[3])],
               "tool_call": [_tool(3)]}
        assert rw.check(_ctx(DESC, claim=CLAIM, by_type=bt3, input_call_ids=[3])) is not None

    def test_unrelated_finding_allowed(self):
        bt = {"finding_refused": [_refusal(10, DESC, cited=[3])], "tool_call": [_tool(3)]}
        assert rw.check(_ctx("SDelete was executed on 2016-06-30 01:23", by_type=bt,
                             input_call_ids=[3])) is None

    def test_tolerates_magicmock(self):
        c = _ctx(DESC)
        c.idx = MagicMock()
        assert rw.check(c) is None


class TestLedgerEndToEnd:
    def _log(self, tmp_path):
        l = ExecutionLog()
        l.configure("LEDGER", str(tmp_path / "trace.json"), save_session=False)
        l.record_dair_call("Analyze", "", False, "", "", "stay", "")
        tid = l.record_tool_call("dotnet EvtxECmd.dll -f Security.evtx", True, False, 0, 0)
        return l, tid

    def test_refusal_is_ledgered_and_reword_refused(self, tmp_path):
        from tools.misc import record_finding
        l, tid = self._log(tmp_path)
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: CHALLENGED — no.", {},
                             inputs={"user_message": f"FINDING:\n{DESC}"})
        with patch("core.execution_log.log", l):
            r1 = record_finding(DESC, "LIKELY", "ez.evtxecmd", linked_call_id=tid,
                                input_call_ids=[tid], supporting_evidence="x",
                                claim_kind="positive", category="exfil", act="egress",
                                entities=["Alice Example", "usb"], channel="usb")
            assert r1["success"] is False
            assert r1["detail_gate"] == "confirmed_requires_supported_evaluate"
            assert r1["evaluate_match"] == "description"
            ledger = [e for e in l._entries if e.get("type") == "finding_refused"]
            assert len(ledger) == 1
            assert ledger[0]["extra"]["evaluate_verdict"] == "CHALLENGED"
            assert ledger[0]["claim"]["category"] == "exfil" and tid in ledger[0]["cited_call_ids"]
            # Reworded, same claim, same evidence → rewording gate, before any deep gate.
            r2 = record_finding("Data left the host through external media.", "LIKELY",
                                "ez.evtxecmd", linked_call_id=tid, input_call_ids=[tid],
                                supporting_evidence="x", claim_kind="positive",
                                category="exfil", act="egress", entities=["Alice Example", "usb"], channel="usb")
            assert r2["success"] is False and r2["gate"] == "refusal_rewording"
            assert r2["prior_refusal_call_id"] == ledger[0]["call_id"]
            # …and that refusal is ledgered too.
            assert len([e for e in l._entries if e.get("type") == "finding_refused"]) == 2

    def test_batched_findings_one_ledger_entry_each(self, tmp_path):
        from tools.misc import record_agent_message
        l, tid = self._log(tmp_path)
        with patch("core.execution_log.log", l):
            r = record_agent_message("narration", input_call_ids=[tid], findings=[
                {"description": "finding one", "confidence": "CONFIRMED", "linked_call_id": 0},
                {"description": "finding two", "confidence": "CONFIRMED", "linked_call_id": 0},
            ])
        assert r["any_finding_refused"] is True
        assert len([e for e in l._entries if e.get("type") == "finding_refused"]) == 2

    def test_ledger_before_configure_is_silent(self):
        assert ExecutionLog().record_finding_refused("d", "LIKELY", "g") == 0
