"""Behaviour tests for the grounding gates that close two generic
reasoning-failure classes:

  principal_attribution_grounding / named_actor_attribution_grounding —
    attributing an account's or a person's act requires an authentication /
    session artifact, not assumption.
  exfil_channel_grounding — asserting data left the host over a channel
    requires a transfer artifact, not tool/folder presence.

The gates key on the TYPED CLAIM (never the description) and inspect the
evidence (session_binding_call_ids / transfer_call_ids, then the legacy
evidence-text validators), so a synthetic ctx exercises the real logic.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

from tools._gates import GateContext
from tools._gates import principal_attribution_grounding as pag
from tools._gates import named_actor_attribution_grounding as nag
from tools._gates import exfil_channel_grounding as ecg
from tools._gates import attribution_required as ar
from tools._gates._claims import normalize_claim
from tools._gates._session import session_bound, has_logon_enumeration


def _ctx(description, *, tier="CONFIRMED", supporting_evidence="",
         linked_call_id=0, input_call_ids=None, by_call_id=None, by_type=None,
         claim=None, window=None):
    return GateContext(
        description=description,
        confidence=tier.capitalize(),
        tier=tier,
        source="test",
        linked_call_id=linked_call_id,
        tested_hypothesis_id="",
        log=MagicMock(),
        idx=SimpleNamespace(by_call_id=by_call_id or {}, by_type=by_type or {}),
        window=window or [],
        input_call_ids=input_call_ids or [],
        supporting_evidence=supporting_evidence,
        claim=claim or {},
    )


_EVTX_SESSION = {"type": "tool_call", "call_id": 61, "success": True,
                 "cmd": "dotnet EvtxECmd.dll -f Security.evtx --csv /out",
                 "session_artifact": True, "session_event_ids": [4624]}
_EVTX_NO_MARKER = {"type": "tool_call", "call_id": 62, "success": True,
                   "cmd": "dotnet EvtxECmd.dll -f Security.evtx --csv /out"}
_SAM = {"type": "tool_call", "call_id": 63, "success": True, "cmd": "rip.pl -r SAM -p samparse",
        "stdout_excerpt": "Username: jdoe"}


def _human_act(act="egress", actor="Dana Doe", **kw):
    return normalize_claim(claim_kind="positive", category="exfil", act=act,
                           actor_kind="human", actor=actor, channel="removable", **kw)


def _binding(**kw):
    return normalize_claim(claim_kind="positive", category="identity", act="attribution",
                           actor_kind="human", actor="Jane Doe", principal="svc_backup", **kw)


class TestNamedActorAttributionGrounding:
    def test_human_core_act_without_session_refused(self):
        out = nag.check(_ctx("the data was exfiltrated", claim=_human_act()))
        assert out is not None
        assert out["gate"] == "named_actor_attribution_grounding"
        assert out["missing"] == ["session_binding_call_ids"]

    def test_wording_not_read(self):
        out = nag.check(_ctx("Dana exfiltrated the classified data",
                             claim=normalize_claim(claim_kind="positive", category="exfil",
                                                   act="egress", channel="removable")))
        assert out is None

    def test_satisfied_by_session_artifact_marker(self):
        ctx = _ctx("x", claim=_human_act(session_binding_call_ids=[61]),
                   by_call_id={61: _EVTX_SESSION})
        assert nag.check(ctx) is None

    def test_satisfied_by_logon_tool_command(self):
        ctx = _ctx("x", claim=_human_act(session_binding_call_ids=[62]),
                   by_call_id={62: _EVTX_NO_MARKER})
        assert nag.check(ctx) is None

    def test_cited_non_session_call_does_not_bind(self):
        ctx = _ctx("x", claim=_human_act(session_binding_call_ids=[63]),
                   by_call_id={63: _SAM})
        assert nag.check(ctx) is not None

    def test_legacy_evidence_text_validator(self):
        ctx = _ctx("x", claim=_human_act(),
                   supporting_evidence="Security 4778 RDP session for Dana from 10.0.0.5")
        assert nag.check(ctx) is None

    def test_account_principal_defers_to_sibling(self):
        ctx = _ctx("x", claim=_binding())
        assert nag.check(ctx) is None
        assert pag.check(ctx) is not None

    def test_non_core_act_does_not_fire(self):
        assert nag.check(_ctx("x", claim=_human_act(act="presence"))) is None

    def test_suspected_tier_not_gated(self):
        assert nag.check(_ctx("x", tier="SUSPECTED", claim=_human_act())) is None

    def test_process_actor_not_gated(self):
        c = normalize_claim(claim_kind="positive", category="exfil", act="egress",
                            actor_kind="process", actor="Dropbox.exe", channel="cloud")
        assert nag.check(_ctx("Dropbox.exe uploaded the archive", claim=c)) is None


class TestPrincipalAttributionGrounding:
    def test_account_to_person_without_session_refused(self):
        out = pag.check(_ctx("svc_backup is operated by Jane Doe", claim=_binding()))
        assert out is not None
        assert out["gate"] == "principal_attribution_grounding"
        assert "session_binding_call_ids" in out["error"]

    def test_satisfied_by_marker(self):
        ctx = _ctx("x", claim=_binding(session_binding_call_ids=[61]),
                   by_call_id={61: _EVTX_SESSION})
        assert pag.check(ctx) is None

    def test_satisfied_by_session_marker_in_supporting_evidence(self):
        ctx = _ctx("x", claim=_binding(),
                   supporting_evidence="Security 4624 LogonType 10 SourceNetworkAddress 10.0.0.42")
        assert pag.check(ctx) is None

    def test_principal_bound_to_unknown_actor_not_gated(self):
        c = normalize_claim(claim_kind="positive", category="identity", act="attribution",
                            actor_kind="unknown", principal="svc_backup")
        assert pag.check(_ctx("x", claim=c)) is None

    def test_prose_binding_without_claim_not_gated(self):
        assert pag.check(_ctx("Local admin account svc_backup is operated by Jane Doe")) is None

    def test_suspected_tier_not_gated(self):
        assert pag.check(_ctx("x", tier="SUSPECTED", claim=_binding())) is None

    def test_likely_tier_is_gated(self):
        out = pag.check(_ctx("x", tier="LIKELY", claim=_binding()))
        assert out is not None and out["gate"] == "principal_attribution_grounding"


class TestSessionHelpers:
    def test_session_bound_paths(self):
        ctx = _ctx("x", claim=_binding(session_binding_call_ids=[61]), by_call_id={61: _EVTX_SESSION})
        assert session_bound(ctx) == (True, "session_artifact")
        ctx = _ctx("x", claim=_binding(session_binding_call_ids=[62]), by_call_id={62: _EVTX_NO_MARKER})
        assert session_bound(ctx) == (True, "logon_tool_cmd")
        ctx = _ctx("x", claim=_binding(), supporting_evidence="rdp from 10.0.0.1")
        assert session_bound(ctx) == (True, "evidence_text")
        assert session_bound(_ctx("x", claim=_binding())) == (False, "")

    def test_has_logon_enumeration(self):
        assert has_logon_enumeration([_EVTX_SESSION])
        assert has_logon_enumeration([_EVTX_NO_MARKER])
        assert not has_logon_enumeration([_SAM])


class TestAttributionRequired:
    def test_prose_group_without_declared_field_refused(self):
        out = ar.check(_ctx("Tooling consistent with APT29", claim=normalize_claim(
            claim_kind="positive", category="attribution", act="attribution")))
        assert out is not None and out["missing"] == ["threat_actor"]

    def test_declared_without_attribute_actors_refused(self):
        out = ar.check(_ctx("x", claim=normalize_claim(
            claim_kind="positive", category="attribution", act="attribution",
            threat_actor="G0016")))
        assert out is not None and "attribute_actors" in out["error"]

    def test_declared_with_attribute_actors_passes(self):
        win = [{"type": "tool_call", "cmd": "<py>:attribution_attribute_actors"}]
        assert ar.check(_ctx("x", window=win, claim=normalize_claim(
            claim_kind="positive", category="attribution", act="attribution",
            threat_actor="G0016"))) is None


def _egress(channel="cloud", **kw):
    return normalize_claim(claim_kind="positive", category="exfil", act="egress",
                           channel=channel, **kw)


_USN = {"type": "tool_call", "call_id": 77, "success": True,
        "cmd": "misc_usnparser_parse $J",
        "stdout_excerpt": "USN rename + DataExtend of payload.bin on USBSTOR volume"}
_META = {"type": "tool_call", "call_id": 78, "success": True, "cmd": "<py>:misc_record_agent_message"}


class TestExfilChannelGrounding:
    def test_presence_only_cloud_claim_refused(self):
        ctx = _ctx("Classified data exfiltrated to cloud via Dropbox", claim=_egress(),
                   supporting_evidence="archive present in the Dropbox sync folder with a "
                                       ":com.dropbox.attributes ADS")
        out = ecg.check(ctx)
        assert out is not None and out["gate"] == "exfil_channel_grounding"
        assert out["missing"] == ["transfer_call_ids"]

    def test_satisfied_by_transfer_call_ids(self):
        ctx = _ctx("x", claim=_egress(transfer_call_ids=[77]), by_call_id={77: _USN})
        assert ecg.check(ctx) is None

    def test_meta_call_is_not_a_transfer_artifact(self):
        ctx = _ctx("x", claim=_egress(transfer_call_ids=[78]), by_call_id={78: _META})
        assert ecg.check(ctx) is not None

    def test_legacy_evidence_text_validator(self):
        ctx = _ctx("x", claim=_egress(channel="ftp"),
                   supporting_evidence="transfers.log records 36864 bytes written to 203.0.113.249")
        assert ecg.check(ctx) is None

    def test_wording_not_read(self):
        ctx = _ctx("Classified data exfiltrated to cloud via Dropbox",
                   claim=normalize_claim(claim_kind="positive", category="exfil", act="presence"))
        assert ecg.check(ctx) is None

    def test_suspected_tier_not_gated(self):
        assert ecg.check(_ctx("x", tier="SUSPECTED", claim=_egress(),
                              supporting_evidence="file in sync folder")) is None


def test_lineage_evidence_text_reads_the_stdout_sidecar(tmp_path):
    from tools._gates._match import lineage_evidence_text
    side = tmp_path / "9.txt"
    side.write_text("x" * 700 + "\nEventId 4624 logon type 10 source ip 10.0.0.7\n")
    entry = {"type": "tool_call", "call_id": 9, "cmd": "dotnet EvtxECmd.dll",
             "stdout_excerpt": "x" * 600, "stdout_path": str(side)}
    ctx = SimpleNamespace(supporting_evidence="", input_call_ids=[9], linked_call_id=0,
                          idx=SimpleNamespace(by_call_id={9: entry}))
    assert "logon type 10" in lineage_evidence_text(ctx)
