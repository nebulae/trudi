"""Tests for the interactive_injection_grounding gate (and the DEVICE_INITIAL_ACCESS
negative_completeness manifest).

An interactive/console session does not prove human authorship while a HID-capable
removable device is in evidence — a keystroke injector produces input that looks
identical. Grounding is an ENUMERATION, not a search: a CONFIRMED/LIKELY "X created
it interactively" finding, or a "no BadUSB" negative, requires that
`misc.device_install_inventory` actually ran (parsing the WHOLE setupapi.dev.log
into a complete device table) with coverage spanning the claim window — and that it
flagged no keystroke-injector. A keyword grep / strings dump no longer satisfies.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

from tools._gates import GateContext
from tools._gates import interactive_injection_grounding as iig
from tools._gates import negative_completeness as nc


# A successful structured inventory, nothing flagged. The markers (set by the MCP
# tool via annotate_tool_call, not fakeable in prose) are what the gates read.
_INVENTORY_CLEAN = {
    "type": "tool_call", "call_id": 4242, "success": True,
    "cmd": "misc.device_install_inventory /mnt/Windows/INF/setupapi.dev.log",
    "device_install_inventory": True,
    "coverage_window": {"start": "2021-01-02 07:08:52", "end": "2021-12-31 06:05:50"},
    "device_count": 80, "flagged_count": 0,
}
# Same inventory, but it flagged a keystroke-injector (a composite HID+storage device).
_INVENTORY_FLAGGED = {**_INVENTORY_CLEAN, "call_id": 4243, "flagged_count": 1}
_TASK_ENUM = {
    "type": "tool_call", "call_id": 4244, "success": True,
    "cmd": "misc.parse_scheduled_tasks /mnt/x/Windows/System32/Tasks",
}
# A keyword grep / strings dump — the RETIRED path; carries no inventory marker.
from tools._gates._claims import normalize_claim
_NEG_DEVICE = normalize_claim(claim_kind="negative", category="device_initial_access",
                              act="other", window={"start": "2021-05-01", "end": "2021-05-31"})
_STRINGS_GREP = {
    "type": "tool_call", "call_id": 99, "success": True,
    "cmd": "strings -a /mnt/Windows/INF/setupapi.dev.log",
    "stdout_excerpt": ">>>  [Device Install - USB\\VID_BEEF&PID_1234]\nHID\\VID_BEEF&PID_1234&MI_01",
}


def _ctx(description, cmds=None, *, tier="CONFIRMED", supporting_evidence="",
         tool_calls=None, by_call_id=None, input_call_ids=None, claim=None):
    entries = [{"type": "tool_call", "cmd": c} for c in (cmds or [])]
    entries += list(tool_calls or [])
    by_type = {"tool_call": entries, "dair_call": [], "investigation_narration": []}
    return GateContext(claim=claim or {},
        description=description,
        confidence=tier.capitalize(),
        tier=tier,
        source="test",
        linked_call_id=0,
        tested_hypothesis_id="",
        log=MagicMock(),
        idx=SimpleNamespace(by_call_id=(by_call_id or {}), by_type=by_type),
        window=[],
        input_call_ids=(input_call_ids or []),
        supporting_evidence=supporting_evidence,
    )


def _interactive(act="account_creation", actor_kind="human", actor="Quinn Avery",
                 window=None, **kw):
    return normalize_claim(claim_kind="positive", category="persistence", act=act,
                           actor_kind=actor_kind, actor=actor, session_type="interactive",
                           window=window or {"start": "2021-05-01", "end": "2021-05-31"}, **kw)


_EVIDENCE = {"type": "tool_call", "call_id": 500, "success": True,
             "cmd": "misc.usbdeviceforensics SYSTEM", "stdout_excerpt": "…"}
_USB_CMD = {"type": "tool_call", "cmd": "rip.pl -p usbstor"}


class TestA4SessionTypeBypass:
    """A4: omitting session_type must not dodge the gate — console keystroke
    injection is possible for interactive, unspecified, and unknown sessions."""

    def _claim(self, st):
        return normalize_claim(claim_kind="positive", category="persistence",
                               act="account_creation", actor_kind="account",
                               actor="svc_x", principal="svc_x", session_type=st,
                               window={"start": "2021-05-01", "end": "2021-05-31"})

    def test_empty_session_type_still_blocks_with_flagged_injector(self):
        for st in ("", "unknown"):
            out = iig.check(_ctx("svc_x was created", ["rip.pl -r SYSTEM -p usbstor"],
                                 tool_calls=[_INVENTORY_FLAGGED], claim=self._claim(st)))
            assert out is not None and out["gate"] == "interactive_injection_grounding"

    def test_explicitly_non_interactive_does_not_trigger(self):
        # a network/service logon has no console keyboard — BadUSB cannot inject.
        for st in ("network", "service", "remote_interactive"):
            out = iig.check(_ctx("svc_x was created", ["rip.pl -r SYSTEM -p usbstor"],
                                 tool_calls=[_INVENTORY_FLAGGED], claim=self._claim(st)))
            assert out is None

    def test_empty_session_type_cleared_by_ruleout_with_task_look(self):
        ctx = _ctx("svc_x was created", ["rip.pl -r SYSTEM -p usbstor"],
                   tool_calls=[_INVENTORY_FLAGGED, _TASK_ENUM], by_call_id={500: _EVIDENCE},
                   claim=normalize_claim(claim_kind="positive", category="persistence",
                                         act="account_creation", actor_kind="account",
                                         actor="svc_x", principal="svc_x", session_type="",
                                         window={"start": "2021-05-01", "end": "2021-05-31"},
                                         rule_outs=[{"what": "injector", "call_ids": [500]}]))
        assert iig.check(ctx) is None


class TestInteractiveInjectionGate:
    def test_interactive_account_creation_refused(self):
        out = iig.check(_ctx("Quinn Avery created the covert helpsvc account",
                             ["rip.pl -r SYSTEM -p usbstor"], claim=_interactive()))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"
        assert "device_install_inventory" in out["error"]

    def test_wording_not_read(self):
        # The TYPED session_type decides, not the prose: an explicitly
        # non-interactive (network) logon does not trigger even though the
        # description says "interactive console session".
        out = iig.check(_ctx(
            "Quinn Avery, in a local interactive console session (LogonType 11), "
            "created the covert helpsvc account", ["rip.pl -r SYSTEM -p usbstor"],
            claim=normalize_claim(claim_kind="positive", category="persistence",
                                  act="account_creation", actor_kind="human",
                                  actor="Quinn Avery", session_type="network")))
        assert out is None

    def test_account_actor_softened_phrasing_still_gated(self):
        out = iig.check(_ctx("svc-helper was created from the operator session",
                             ["rip.pl -r SYSTEM -p usbstor"], tier="LIKELY",
                             claim=_interactive(actor_kind="account", actor="operator")))
        assert out is not None and out["gate"] == "interactive_injection_grounding"

    def test_process_actor_out_of_scope(self):
        assert iig.check(_ctx("explorer.exe created the Run key", ["rip.pl -p usbstor"],
                              claim=_interactive(act="persistence_install", actor_kind="process",
                                                 actor="explorer.exe"))) is None

    def test_clean_inventory_clears(self):
        assert iig.check(_ctx("x", tool_calls=[_INVENTORY_CLEAN, _USB_CMD], claim=_interactive())) is None

    def test_flagged_inventory_refuses_human_authorship(self):
        out = iig.check(_ctx("x", tool_calls=[_INVENTORY_FLAGGED, _USB_CMD], claim=_interactive()))
        assert out is not None and "FLAGGED" in out["error"] and out["missing"] == ["rule_outs"]

    def test_flagged_injector_prose_ruleout_no_longer_clears(self):
        out = iig.check(_ctx("the keystroke injector was not connected during that window",
                             ["rip.pl -r SYSTEM -p usbstor"], tool_calls=[_INVENTORY_FLAGGED],
                             supporting_evidence="The BadUSB device was ruled out for this window",
                             claim=_interactive()))
        assert out is not None

    def test_flagged_injector_typed_ruleout_clears(self):
        # N-2: ruling out a flagged injector also requires the scheduled-task look.
        ctx = _ctx("x", ["rip.pl -r SYSTEM -p usbstor"],
                   tool_calls=[_INVENTORY_FLAGGED, _TASK_ENUM], by_call_id={500: _EVIDENCE},
                   claim=_interactive(rule_outs=[{"what": "injector", "call_ids": [500]}]))
        assert iig.check(ctx) is None

    def test_flagged_injector_typed_ruleout_without_task_look_refused(self):
        # N-2: same rule-out but no task enumeration → still refused.
        ctx = _ctx("x", ["rip.pl -r SYSTEM -p usbstor"], tool_calls=[_INVENTORY_FLAGGED],
                   by_call_id={500: _EVIDENCE},
                   claim=_interactive(rule_outs=[{"what": "injector", "call_ids": [500]}]))
        assert iig.check(ctx) is not None

    def test_flagged_injector_ruleout_needs_evidence_calls(self):
        ctx = _ctx("x", ["rip.pl -r SYSTEM -p usbstor"], tool_calls=[_INVENTORY_FLAGGED],
                   claim=_interactive(rule_outs=[{"what": "injector", "call_ids": [999]}]))
        assert iig.check(ctx) is not None

    def test_flagged_injector_device_disposition_clears(self):
        ctx = _ctx("x", ["rip.pl -r SYSTEM -p usbstor"],
                   tool_calls=[_INVENTORY_FLAGGED, _TASK_ENUM], claim=_interactive())
        ctx.idx.dispositions = {("device", "vid_beef&pid_1234"): [
            {"type": "disposition", "call_id": 9, "target_kind": "device", "reason": "ruled_out",
             "window": {"start": "2021-05-01", "end": "2021-05-31"}}]}
        assert iig.check(ctx) is None
        ctx.idx.dispositions[("device", "vid_beef&pid_1234")][0]["window"] = {
            "start": "2021-06-01", "end": "2021-06-30"}
        assert iig.check(ctx) is not None

    def test_strings_grep_does_not_satisfy(self):
        out = iig.check(_ctx("x", ["rip.pl -p usbstor"], tool_calls=[_STRINGS_GREP],
                             claim=_interactive()))
        assert out is not None and out["gate"] == "interactive_injection_grounding"

    def test_input_call_id_to_inventory_clears(self):
        out = iig.check(_ctx("x", ["rip.pl -p usbstor"],
                             by_call_id={4242: _INVENTORY_CLEAN}, input_call_ids=[4242],
                             claim=_interactive()))
        assert out is None

    def test_inventory_must_span_claim_window(self):
        out = iig.check(_ctx("x", tool_calls=[_INVENTORY_CLEAN, _USB_CMD],
                             claim=_interactive(window={"start": "2024-09-01", "end": "2024-09-01"})))
        assert out is not None and out["gate"] == "interactive_injection_grounding"

    def test_no_removable_media_out_of_scope(self):
        assert iig.check(_ctx("x", ["vol.pslist"], claim=_interactive())) is None

    def test_non_creation_act_passes(self):
        assert iig.check(_ctx("x", ["rip.pl -p usbstor"],
                              claim=_interactive(act="egress", channel="cloud"))) is None

    def test_suspected_tier_not_gated(self):
        assert iig.check(_ctx("x", ["rip.pl -p usbstor"], tier="SUSPECTED", claim=_interactive())) is None


class TestDeviceInitialAccessManifest:
    def test_no_badusb_negative_without_inventory_refused(self):
        out = nc.check(_ctx("No malicious USB or HID injection was found",
                            ["rip.pl -p usbstor"], tier="UNCONFIRMED", claim=_NEG_DEVICE))
        assert out is not None and out["gate"] == "negative_completeness"
        assert "device_install_inventory" in out["error"]

    def test_no_badusb_negative_with_clean_inventory_passes(self):
        out = nc.check(_ctx(
            "No HID injection / BadUSB: the device inventory shows no keystroke injector",
            tier="UNCONFIRMED", tool_calls=[_INVENTORY_CLEAN], claim=_NEG_DEVICE))
        assert out is None

    def test_no_badusb_negative_with_flagged_inventory_refused(self):
        # "no BadUSB" while the inventory flagged an injector must be refused.
        out = nc.check(_ctx(
            "No BadUSB present in the 2021-05 window",
            tier="UNCONFIRMED", tool_calls=[_INVENTORY_FLAGGED], claim=_NEG_DEVICE))
        assert out is not None and out["gate"] == "negative_completeness"
        assert "flagged" in out["error"].lower()

    def test_no_badusb_negative_strings_grep_refused(self):
        # The retired keyword path: a strings/grep over setupapi no longer grounds it.
        out = nc.check(_ctx(
            "No HID injection / BadUSB: setupapi.dev.log shows only mass-storage",
            ["strings -a setupapi.dev.log", "usbdeviceforensics SYSTEM"],
            tier="UNCONFIRMED", tool_calls=[_STRINGS_GREP], claim=_NEG_DEVICE))
        assert out is not None and out["gate"] == "negative_completeness"

    def test_no_badusb_negative_absent_escape_is_a_typed_disposition(self):
        # Prose "absent from evidence" no longer waives; a typed disposition does.
        out = nc.check(_ctx(
            "No BadUSB assessment possible: setupapi.dev.log absent from evidence (not collected)",
            ["rip.pl -p usbstor"], tier="UNCONFIRMED", claim=_NEG_DEVICE))
        assert out is not None
        ctx = _ctx("No BadUSB assessment possible", ["rip.pl -p usbstor"],
                   tier="UNCONFIRMED", claim=_NEG_DEVICE)
        ctx.idx.dispositions = {("source", "device_inventory"): [
            {"type": "disposition", "call_id": 7, "target_kind": "source",
             "target_id": "device_inventory", "reason": "absent_from_evidence"}]}
        assert nc.check(ctx) is None
