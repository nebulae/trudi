"""Behaviour tests for the grounding gates that close two generic
reasoning-failure classes:

  principal_attribution_grounding — attributing an account's actions to a
    named person requires an authentication/session artifact, not assumption.
  exfil_channel_grounding — asserting data left the host over a channel
    requires a transfer artifact, not tool/folder presence.

These are synthetic (no scenario fixtures): the gates key on generic prose
patterns and inspect the evidence (supporting_evidence + linked/input_call_ids
entries), so a synthetic ctx exercises the real logic.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

from tools._gates import GateContext
from tools._gates import principal_attribution_grounding as pag
from tools._gates import named_actor_attribution_grounding as nag
from tools._gates import exfil_channel_grounding as ecg


def _ctx(description, *, tier="CONFIRMED", supporting_evidence="",
         linked_call_id=0, input_call_ids=None, by_call_id=None, by_type=None):
    return GateContext(
        description=description,
        confidence=tier.capitalize(),
        tier=tier,
        source="test",
        linked_call_id=linked_call_id,
        tested_hypothesis_id="",
        log=MagicMock(),
        idx=SimpleNamespace(by_call_id=by_call_id or {}, by_type=by_type or {}),
        window=[],
        input_call_ids=input_call_ids or [],
        supporting_evidence=supporting_evidence,
    )


# ── named_actor_attribution_grounding ────────────────────────────────────────

class TestNamedActorAttributionGrounding:
    """FIX 3a — closing the direct-naming dodge: a person named directly as the
    actor of the core act (no account token, no copula) still needs a session
    artifact."""

    def test_direct_name_core_act_without_session_refused(self):
        out = nag.check(_ctx("Dana exfiltrated the classified data"))
        assert out is not None
        assert out["gate"] == "named_actor_attribution_grounding"

    def test_satisfied_by_session_in_supporting_evidence(self):
        ctx = _ctx(
            "Dana exfiltrated the classified data",
            supporting_evidence="Security 4778 RDP session for Dana from 10.0.0.5",
        )
        assert nag.check(ctx) is None

    def test_satisfied_by_ip_literal(self):
        ctx = _ctx(
            "Dana exfiltrated the classified data",
            supporting_evidence="RDP session from 203.0.113.249",
        )
        assert nag.check(ctx) is None

    def test_satisfied_by_session_in_lineage_entry(self):
        by_id = {61: {"cmd": "ez_evtxecmd Security.evtx",
                      "stdout_excerpt": "EventId 4624 logon type 10 source ip 10.0.0.7"}}
        ctx = _ctx("Mallory copied the classified research", input_call_ids=[61],
                   by_call_id=by_id)
        assert nag.check(ctx) is None

    def test_known_subject_named_generically_still_fires(self):
        # Actor name only resolvable via the trace subject, after the verb (so
        # not a prefix candidate) — the _case_subject_names path must catch it.
        by_type = {"dair_call": [
            {"inputs": {"case_context": "Subject Sam on host rd-01"},
             "investigation_focus": ""}]}
        out = nag.check(_ctx(
            "The data was copied; the timeline places Sam at the host",
            by_type=by_type))
        assert out is not None
        assert out["gate"] == "named_actor_attribution_grounding"

    def test_account_plus_copula_defers_to_sibling(self):
        ctx = _ctx("account svc_x is operated by Dana who exfiltrated data")
        # Sibling owns the account+copula binding — this gate must not double-fire.
        assert nag.check(ctx) is None
        assert pag.check(ctx) is not None

    def test_no_core_act_does_not_fire(self):
        assert nag.check(_ctx("Dana logged into the workstation")) is None

    def test_suspected_tier_not_gated(self):
        assert nag.check(_ctx("Dana exfiltrated the data", tier="SUSPECTED")) is None

    def test_tool_name_not_human_no_fire(self):
        assert nag.check(_ctx("Dropbox.exe uploaded the archive")) is None

    def test_destination_after_verb_not_actor_no_fire(self):
        # 'China' is a destination after the verb, not an actor — excluded by
        # the subject-position (pre-verb) slice.
        assert nag.check(_ctx("Classified data was exfiltrated to China")) is None


# ── principal_attribution_grounding ──────────────────────────────────────────

class TestPrincipalAttributionGrounding:
    def test_account_to_person_without_session_refused(self):
        ctx = _ctx("Local admin account svc_backup is operated by Jane Doe")
        out = pag.check(ctx)
        assert out is not None
        assert out["gate"] == "principal_attribution_grounding"

    def test_satisfied_by_session_marker_in_supporting_evidence(self):
        ctx = _ctx(
            "Local admin account svc_backup is operated by Jane Doe",
            supporting_evidence=(
                "Security 4624 LogonType 10 SourceNetworkAddress 10.0.0.42 "
                "for svc_backup (ez.evtxecmd)"
            ),
        )
        assert pag.check(ctx) is None

    def test_satisfied_by_session_marker_in_lineage_entry(self):
        by_id = {50: {"cmd": "ez_evtxecmd Security.evtx",
                      "stdout_excerpt": "EventId 4624 logon type 3 source ip 192.168.1.9"}}
        ctx = _ctx(
            "account printer_svc belongs to Bob Smith",
            input_call_ids=[50], by_call_id=by_id,
        )
        assert pag.check(ctx) is None

    def test_satisfied_by_ip_literal_evidence(self):
        ctx = _ctx(
            "account x_admin was used by Carol",
            supporting_evidence="RDP session from 203.0.113.249",
        )
        assert pag.check(ctx) is None

    def test_no_account_token_does_not_fire(self):
        # 'created by process' is an attribution copula but there is no
        # account/identity subject — must not fire.
        ctx = _ctx("temp.zip was created by process explorer.exe")
        assert pag.check(ctx) is None

    def test_suspected_tier_not_gated(self):
        ctx = _ctx("account svc_backup is operated by Jane Doe", tier="SUSPECTED")
        assert pag.check(ctx) is None

    def test_likely_tier_is_gated(self):
        ctx = _ctx("account svc_backup operated by Jane Doe", tier="LIKELY")
        out = pag.check(ctx)
        assert out is not None
        assert out["gate"] == "principal_attribution_grounding"


# ── exfil_channel_grounding ──────────────────────────────────────────────────

class TestExfilChannelGrounding:
    def test_presence_only_cloud_claim_refused(self):
        ctx = _ctx(
            "Classified data exfiltrated to cloud via Dropbox",
            supporting_evidence=(
                "archive present in the Dropbox sync folder with a "
                ":com.dropbox.attributes ADS"
            ),
        )
        out = ecg.check(ctx)
        assert out is not None
        assert out["gate"] == "exfil_channel_grounding"

    def test_satisfied_by_ftp_transfer_log(self):
        ctx = _ctx(
            "Data exfiltrated over FTP to the staging host",
            supporting_evidence="transfers.log records 36864 bytes written to 203.0.113.249",
        )
        assert ecg.check(ctx) is None

    def test_satisfied_by_removable_volume_binding(self):
        ctx = _ctx(
            "vacation.7z was copied to a USB removable drive for handoff",
            supporting_evidence="LNK shows the file resided on removable volume; MountedDevices binding present",
        )
        assert ecg.check(ctx) is None

    def test_satisfied_by_usn_write_in_lineage(self):
        by_id = {77: {"cmd": "misc_usnparser_parse $J",
                      "stdout_excerpt": "USN rename + DataExtend of payload.bin on USBSTOR volume"}}
        ctx = _ctx("payload transferred to USB", input_call_ids=[77], by_call_id=by_id)
        assert ecg.check(ctx) is None

    def test_tool_execution_alone_refused(self):
        ctx = _ctx(
            "Research uploaded to cloud storage",
            supporting_evidence="Dropbox.exe present in Program Files; VeraCrypt executed",
        )
        out = ecg.check(ctx)
        assert out is not None
        assert out["gate"] == "exfil_channel_grounding"

    def test_no_channel_does_not_fire(self):
        ctx = _ctx("VeraCrypt executed to encrypt the staged archive")
        assert ecg.check(ctx) is None

    def test_no_egress_verb_does_not_fire(self):
        ctx = _ctx("A Dropbox client is installed on the host")
        assert ecg.check(ctx) is None

    def test_suspected_tier_not_gated(self):
        ctx = _ctx("data exfiltrated to cloud via Dropbox", tier="SUSPECTED",
                   supporting_evidence="file in sync folder")
        assert ecg.check(ctx) is None
