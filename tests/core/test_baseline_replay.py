"""Baseline-replay harness + the attribution-grounding hole regression.

`replay_finding` reconstructs a GateContext from trace-shaped entries and runs a
gate against it — the primitive that lets us assert a recorded finding still
gets the same verdict after a gate change (the "don't degrade the compliant
path" guard) and that a known-bad finding now refuses (the fix landed).

Item 2 (2026-08-29): `session_bound`'s legacy evidence-TEXT fallback matched a
bare IPv4 (and generic "source ip"), so on any network/PCAP case a human
attribution with EMPTY session_binding_call_ids was falsely "bound" — an IP in
the prose counted as binding a PERSON. Observed live: an empty-binding
"Amy Smith, CONFIRMED" passed principal_attribution_grounding. Fix: an
address/identity string is not an authenticated session; person-binding needs
the cited `session_artifact` marker, the logon-tool cmd, or a genuine
logon/session keyword — never a bare IP.
"""
from core.execution_log import ExecutionLog
from tools._gates import GateContext
from tools._gates import _session as S
from tools._gates import principal_attribution_grounding as PAG


def replay_finding(entries, finding, gate):
    """Rebuild a GateContext from trace entries and run `gate`. Returns the
    refusal dict, or None on pass."""
    log = ExecutionLog()
    log._entries = list(entries)
    claim = finding.get("claim") or {}
    ctx = GateContext(
        description=finding.get("description", ""),
        confidence=finding.get("confidence", ""),
        tier=(finding.get("confidence") or "").upper(),
        source=finding.get("source", ""),
        linked_call_id=finding.get("linked_call_id", 0),
        tested_hypothesis_id="",
        log=log, idx=log.index(), window=log.last_n_window(30),
        input_call_ids=finding.get("input_call_ids") or [],
        claim=claim,
    )
    return gate(ctx)


def _finding(confidence, actor, binding, cid=900):
    return {
        "type": "finding", "call_id": cid, "confidence": confidence,
        "description": f"{actor} attribution",
        "input_call_ids": list(binding),
        "claim": {"kind": "positive", "category": "identity", "act": "logon",
                  "actor_kind": "human", "actor": actor, "principal": actor,
                  "session_binding_call_ids": list(binding)},
    }


# A trace with a genuine session artifact (net.pcap_identity_timeline stamps the
# marker) at cid 68, and an ngrep whose evidence text merely contains an IP.
def _trace(evidence_text="Device 192.168.15.4 accessed willselfdestruct.com"):
    return [
        {"type": "dair_call", "call_id": 1, "current_phase": "Analyze"},
        {"type": "tool_call", "call_id": 68, "cmd": "<py>:net_pcap_identity_timeline",
         "success": True, "session_artifact": True,
         "stdout_excerpt": "identity timeline for 192.168.15.4"},
        {"type": "tool_call", "call_id": 34, "cmd": "sudo ngrep -q -I x.pcap -i jcoachj",
         "success": True, "stdout_excerpt": evidence_text},
    ]


class TestSessionRegex:
    def test_bare_ipv4_is_not_a_session(self):
        assert not S.SESSION_RE.search("device 192.168.15.4 sent the email")

    def test_generic_source_ip_is_not_a_session(self):
        assert not S.SESSION_RE.search("x-originating-ip: 10.0.0.5")

    def test_real_logon_markers_still_match(self):
        for txt in ("Security 4624 logon type 10", "an interactive session",
                    "RDP connection", "sshd accepted", "kerberos ticket",
                    "source network address 10.0.0.5"):
            assert S.SESSION_RE.search(txt), txt


class TestAttributionGroundingHole:
    def test_empty_binding_network_person_refuses(self):
        """The bug: a human attribution citing no session artifact, whose only
        'binding' was an IP in the prose. Must refuse after the fix."""
        e = _trace()
        f = _finding("CONFIRMED", "Amy Smith", binding=[])
        r = replay_finding(e, f, PAG.check)
        assert r is not None and r["gate"] == "principal_attribution_grounding"

    def test_marker_cited_binding_passes(self):
        """A finding that cites the real session_artifact-marked extractor
        (cid 68) is genuinely bound — must pass. This is the compliant path;
        the fix must not touch it."""
        e = _trace()
        f = _finding("LIKELY", "Johnny Coach", binding=[68])
        assert replay_finding(e, f, PAG.check) is None

    def test_genuine_logon_text_still_binds(self):
        """Legacy disk path: no cited marker, but the evidence text carries a
        real logon signal (4624). The text fallback must still accept it."""
        e = _trace(evidence_text="Security 4624 logon type 10 source 10.0.0.5")
        f = _finding("CONFIRMED", "DOMAIN\\admin", binding=[34])
        assert replay_finding(e, f, PAG.check) is None

    def test_suspected_is_exempt(self):
        """SUSPECTED never requires grounding — the gate only guards
        CONFIRMED/LIKELY."""
        e = _trace()
        f = _finding("SUSPECTED", "Amy Smith", binding=[])
        assert replay_finding(e, f, PAG.check) is None


class TestDistinctPrincipalAlreadyBlocks:
    """Gap (A) is ALREADY enforced (verified 2026-08-29): a DECLARED
    distinct_principal never driven to a verdict blocks pre_report_check. This
    locks that invariant so it cannot silently regress. The residual weak-driver
    failure (not declaring the competitor at all) is a discovery problem, not an
    enforcement one — no gate change here."""

    def _log_with(self, extra):
        from core.execution_log import ExecutionLog
        log = ExecutionLog()
        log._entries = [
            {"type": "tool_call", "call_id": 1, "cmd": "<py>:misc_start_execution_log", "success": True},
            {"type": "dair_call", "call_id": 2, "current_phase": "Analyze"},
            {"type": "reason_call", "call_id": 3, "tool": "reason_plan", "success": True},
            {"type": "reason_call", "call_id": 4, "tool": "reason_hypothesize", "success": True,
             "hypothesis_id": "H1", "hypothesis_kind": "distinct_principal",
             "contested_principals": ["jcoachj"], "contested_principals_norm": ["jcoachj"],
             "sub_hypotheses": [{"likelihood_tier": "HIGH", "label": "jcoachj controls the session"}]},
            {"type": "reason_call", "call_id": 5, "tool": "reason_synthesize", "success": True},
            {"type": "finding", "call_id": 6, "confidence": "LIKELY", "description": "answer",
             "claim": {"actor_kind": "human", "actor": "Amy Smith", "principal": "Amy Smith",
                       "answers_case_question": True, "session_binding_call_ids": [2]}},
        ] + extra
        return log

    def test_undispositioned_distinct_principal_blocks(self):
        from unittest.mock import patch
        import core.execution_log as EL
        import tools.reasoning as R
        log = self._log_with([])
        with patch.object(EL, "log", log), patch.object(R, "log", log, create=True):
            r = R.reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("jcoachj" in str(b).lower() for b in r["blocking_issues"])
