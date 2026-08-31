"""challenge_sticky gate — a CHALLENGED/UNCERTAIN evaluate blocks CONFIRMED and
LIKELY until new evidence AND a SUPPORTED re-evaluate; SUSPECTED is the honest
downgrade and passes."""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.execution_log import ExecutionLog
from tools._gates import GateContext, challenge_sticky

DESC = "helpsvc account created 4720 on the host"


def _log(tmp_path):
    l = ExecutionLog()
    l.configure("STICKY", str(tmp_path / "trace.json"), save_session=False)
    l.record_dair_call("Analyze", "", False, "", "", "stay", "")
    tid = l.record_tool_call("dotnet EvtxECmd.dll -f Security.evtx", True, False, 0, 0)
    # a logon-session artifact: under the J-1 tier contract an attribution
    # claim citing it reaches LIKELY, so the evaluate/sticky gates are what
    # these tests exercise (tier_contract runs first and would refuse
    # SUSPECTED-shape evidence asked at LIKELY).
    l.annotate_tool_call(tid, session_artifact=True, session_event_ids=[4624])
    return l, tid


def _evaluate(l, verdict, desc=DESC, with_verdict_line=True):
    concl = "analysis." + (f"\nVERDICT: {verdict} — because." if with_verdict_line else "")
    return l.record_reason_call("reason_evaluate_finding", True, concl, {},
                                inputs={"user_message": f"FINDING:\n{desc}\n\nSUPPORTING EVIDENCE:\nx"})


def _record(l, tid, tier="LIKELY", desc=DESC):
    from tools.misc import record_finding
    with patch("core.execution_log.log", l):
        return record_finding(desc, tier, "ez.evtxecmd", linked_call_id=tid,
                              input_call_ids=[tid], supporting_evidence="Security.evtx 4720 helpsvc")


class TestSticky:
    # A LIKELY whose matched evaluate is CHALLENGED/UNCERTAIN is refused by the
    # evaluate gate first (Phase E: LIKELY needs SUPPORTED); challenge_sticky is
    # the backstop for the re-ask-without-evidence and beyond-window cases.
    _BAD_VERDICT_GATES = {"confirmed_requires_supported_evaluate", "challenge_sticky"}

    def test_likely_after_challenged_refused(self, tmp_path):
        l, tid = _log(tmp_path)
        _evaluate(l, "CHALLENGED")
        r = _record(l, tid)
        assert r["success"] is False
        assert r["gate"] == "evidence_strength" and r["detail_gate"] in self._BAD_VERDICT_GATES
        assert r["evaluate_verdict"] == "CHALLENGED"

    def test_uncertain_is_sticky_too(self, tmp_path):
        l, tid = _log(tmp_path)
        _evaluate(l, "UNCERTAIN")
        assert _record(l, tid)["detail_gate"] in self._BAD_VERDICT_GATES

    def test_suspected_downgrade_allowed(self, tmp_path):
        l, tid = _log(tmp_path)
        _evaluate(l, "CHALLENGED")
        assert _record(l, tid, tier="SUSPECTED")["success"] is True

    def test_new_evidence_then_supported_clears(self, tmp_path):
        l, tid = _log(tmp_path)
        _evaluate(l, "CHALLENGED")
        l.record_tool_call("dotnet EvtxECmd.dll -f Security.evtx --inc 4720", True, False, 0, 0)
        _evaluate(l, "SUPPORTED")
        assert _record(l, tid)["success"] is True

    def test_supported_reask_without_evidence_still_refused(self, tmp_path):
        # The re-ask changed nothing — the challenge stands.
        l, tid = _log(tmp_path)
        _evaluate(l, "CHALLENGED")
        _evaluate(l, "SUPPORTED")
        r = _record(l, tid)
        assert r["success"] is False and r["detail_gate"] == "challenge_sticky"
        assert "re-ask" in r["error"]

    def test_meta_tool_call_does_not_count_as_evidence(self, tmp_path):
        l, tid = _log(tmp_path)
        _evaluate(l, "CHALLENGED")
        l.record_tool_call("<py>:misc_record_agent_message", True, False, 0, 0)
        _evaluate(l, "SUPPORTED")
        assert _record(l, tid)["detail_gate"] == "challenge_sticky"

    def test_read_call_counts_as_evidence(self, tmp_path):
        l, tid = _log(tmp_path)
        _evaluate(l, "CHALLENGED")
        l.record_tool_call("read.output --output /c/exports/evtx/x.csv", True, False, 0, 0)
        _evaluate(l, "SUPPORTED")
        assert _record(l, tid)["success"] is True

    def test_challenge_on_other_finding_does_not_stick(self, tmp_path):
        l, tid = _log(tmp_path)
        _evaluate(l, "SUPPORTED")                                   # this finding's own verdict
        _evaluate(l, "CHALLENGED", desc="an unrelated finding about prefetch")
        assert _record(l, tid)["success"] is True

    def test_verdict_field_honoured_without_conclusion_line(self, tmp_path):
        l, tid = _log(tmp_path)
        cid = _evaluate(l, "CHALLENGED", with_verdict_line=False)
        l.update_reason_call(cid, verdict="CHALLENGED",
                             evidence_requests=[{"query": "4720 helpsvc", "rows_returned": 0}])
        r = _record(l, tid)
        assert r["detail_gate"] in self._BAD_VERDICT_GATES and r["evaluate_verdict"] == "CHALLENGED"
        # The sticky gate's own report still carries the empty discriminators.
        from tools._gates import challenge_sticky as cs
        ctx = GateContext(description=DESC, confidence="Likely", tier="LIKELY", source="t",
                          linked_call_id=tid, tested_hypothesis_id="", log=l, idx=l.index(),
                          window=l.last_n_window(30), input_call_ids=[tid], supporting_evidence="x")
        out = cs.check(ctx)
        assert out["empty_evidence_requests"] == ["4720 helpsvc"] and "4720 helpsvc" in out["error"]

    def test_tolerates_magicmock_index(self):
        ctx = GateContext(description=DESC, confidence="Likely", tier="LIKELY", source="t",
                          linked_call_id=0, tested_hypothesis_id="", log=MagicMock(),
                          idx=MagicMock(), window=[], input_call_ids=[],
                          supporting_evidence="x")
        assert challenge_sticky.check(ctx) is None
        ctx2 = GateContext(description=DESC, confidence="Likely", tier="LIKELY", source="t",
                           linked_call_id=0, tested_hypothesis_id="", log=MagicMock(),
                           idx=SimpleNamespace(by_type={}), window=[], input_call_ids=[],
                           supporting_evidence="x")
        assert challenge_sticky.check(ctx2) is None


def test_partial_source_challenge_does_not_stick():
    """A CHALLENGED verdict whose only basis was misses over PARTIAL sources is
    not an earned challenge — the reviewer never saw the rows."""
    from types import SimpleNamespace
    from tools._gates import challenge_sticky as cs
    desc = "Clamscan flagged three hacktools in COMMANDS"
    ev = {"type": "reason_call", "call_id": 5, "tool": "reason_evaluate_finding",
          "verdict": "CHALLENGED", "verdict_basis": "partial_source",
          "inputs": {"user_message": f"FINDING:\n{desc}"}}
    ctx = SimpleNamespace(tier="LIKELY", confidence="Likely", description=desc,
                          idx=SimpleNamespace(by_type={"reason_call": [ev], "tool_call": []}))
    assert cs.check(ctx) is None
    ev2 = dict(ev, verdict_basis="")
    ctx.idx = SimpleNamespace(by_type={"reason_call": [ev2], "tool_call": []})
    assert cs.check(ctx) is not None


def test_reworded_likely_inherits_challenge_by_claim_key(tmp_path):
    """The Phase-E hatch: a challenged claim re-authored with different wording
    is matched by its typed claim (key + entities) and stays refused."""
    from tools._gates._claims import normalize_claim
    from tools.misc import record_finding
    l, tid = _log(tmp_path)
    claim = normalize_claim(claim_kind="positive", category="identity", act="attribution",
                            entities=["Greg Schardt", "Mr. Evil"])
    l.record_reason_call("reason_evaluate_finding", True, "VERDICT: UNCERTAIN — overclaims", {},
                         inputs={"user_message": "FINDING:\nMultiple artifacts establish the laptop was operated by Greg Schardt"},
                         extra={"claim": claim, "verdict": "UNCERTAIN"})
    with patch("core.execution_log.log", l):
        r = record_finding("Identity linkage (NIST Q12): irunin.ini LANUSER Mr. Evil", "LIKELY",
                           "ez.recmd", linked_call_id=tid, input_call_ids=[tid],
                           supporting_evidence="irunin.ini LANUSER Mr. Evil",
                           claim_kind="positive", category="identity", act="attribution",
                           entities=["mr.evil", "greg.schardt"])
    assert r["success"] is False
    assert r["detail_gate"] in ("confirmed_requires_supported_evaluate", "challenge_sticky")
    assert r.get("evaluate_verdict") == "UNCERTAIN"


def test_reviewer_tier_opinion_does_not_cap_the_record(tmp_path):
    """Phase J-1: the reviewer fact-checks; the tier is arithmetic over the
    cited artifact classes (tier_contract). A stale `supported_tier=LIKELY` on
    the evaluate entry no longer caps a CONFIRMED record — only the classes do."""
    from tools.misc import record_finding
    from tools._gates import confirmed_requires_supported_evaluate as g
    assert not hasattr(g, "evaluate_tier_cap")
    l, tid = _log(tmp_path)
    # session artifact (tid) + an independent documentary binding (RECmd
    # SOFTWARE RegisteredOwner) = the attribution CONFIRMED contract.
    sess = l.record_tool_call("dotnet RECmd.dll -f SOFTWARE --bn BatchMostPlugins.reb --csv /out",
                              True, False, 0, 0, stdout_excerpt="RegisteredOwner Greg Schardt")
    claim = {"kind": "positive", "category": "identity", "act": "attribution",
             "entities": ["Greg Schardt"], "entities_norm": ["gregschardt"]}
    l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED — at LIKELY", {},
                         inputs={"user_message": "FINDING:\nlaptop registered to Greg Schardt"},
                         extra={"claim": claim, "verdict": "SUPPORTED",
                                "intended_tier": "LIKELY", "supported_tier": "LIKELY"})
    kw = dict(linked_call_id=tid, input_call_ids=[tid, sess], supporting_evidence="RegisteredOwner Greg Schardt",
              claim_kind="positive", category="identity", act="attribution",
              entities=["Greg Schardt"], actor_kind="unknown", tested_hypothesis_id="H0001")
    with patch("core.execution_log.log", l):
        r = record_finding("laptop registered to Greg Schardt", "CONFIRMED", "ez.recmd", **kw)
    assert r["success"] is True, r
    assert r["tier_achievable"] == "CONFIRMED" and "evaluate_tier" not in r


def test_claim_matched_evaluate_found_beyond_the_window(tmp_path):
    """The SUPPORTED evaluate with the IDENTICAL
    typed claim sat 38 entries back; the 30-entry window fell to an unrelated
    fallback evaluate and refused claim_mismatch."""
    from tools.misc import record_finding
    l, tid = _log(tmp_path)
    claim = {"kind": "positive", "category": "identity", "act": "attribution",
             "entities": ["PC User", "Anthony Vanko"], "entities_norm": ["pcuser", "anthonyvanko"],
             "principal": "PC User", "principal_norm": "pcuser"}
    good = l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED — bound.", {},
                                inputs={"user_message": "FINDING:\nPC User is operated by Anthony Vanko"},
                                extra={"claim": claim, "verdict": "SUPPORTED", "supported_tier": "LIKELY"})
    for i in range(40):                                   # push it well outside the window
        l.record_tool_call(f"strings -a x{i}", True, False, 0, 0, stdout_excerpt="x")
    other = {"kind": "positive", "category": "exfil", "act": "execution", "entities": ["vacation photos.7z"],
             "entities_norm": ["vacationphotos7z"]}
    l.record_reason_call("reason_evaluate_finding", True, "VERDICT: CHALLENGED — thin.", {},
                         inputs={"user_message": "FINDING:\narchive staged"},
                         extra={"claim": other, "verdict": "CHALLENGED"})
    l.record_dair_call("Analyze", "", False, "", "", "stay", "")
    with patch("core.execution_log.log", l):
        r = record_finding("PC User is operated by Anthony Vanko", "LIKELY", "ez.evtxecmd",
                           linked_call_id=tid, input_call_ids=[tid, good], supporting_evidence="4624 rows",
                           claim_kind="positive", category="identity", act="attribution",
                           entities=["PC User", "Anthony Vanko"], principal="PC User",
                           actor_kind="human", actor="Anthony Vanko", session_binding_call_ids=[tid])
    # Whatever later gate fires, the evaluate gate must have matched cid `good`.
    assert r.get("detail_gate") != "confirmed_requires_supported_evaluate", r
    assert r.get("claim_mismatch") is None
