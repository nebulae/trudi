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
# A keyword grep / strings dump — the RETIRED path; carries no inventory marker.
_STRINGS_GREP = {
    "type": "tool_call", "call_id": 99, "success": True,
    "cmd": "strings -a /mnt/Windows/INF/setupapi.dev.log",
    "stdout_excerpt": ">>>  [Device Install - USB\\VID_BEEF&PID_1234]\nHID\\VID_BEEF&PID_1234&MI_01",
}


def _ctx(description, cmds=None, *, tier="CONFIRMED", supporting_evidence="",
         tool_calls=None, by_call_id=None, input_call_ids=None):
    entries = [{"type": "tool_call", "cmd": c} for c in (cmds or [])]
    entries += list(tool_calls or [])
    by_type = {"tool_call": entries, "dair_call": [], "investigation_narration": []}
    return GateContext(
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


class TestInteractiveInjectionGate:
    def test_interactive_account_creation_refused(self):
        out = iig.check(_ctx(
            "Quinn Avery, in a local interactive console session (LogonType 11), "
            "created the covert helpsvc account",
            ["rip.pl -r SYSTEM -p usbstor"]))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"
        assert "device_install_inventory" in out["error"]

    def test_clean_inventory_clears(self):
        # The complete inventory ran, nothing flagged → grounded.
        out = iig.check(_ctx(
            "Quinn created the covert account in an interactive console session (type 11)",
            tool_calls=[_INVENTORY_CLEAN]))
        assert out is None

    def test_flagged_inventory_refuses_human_authorship(self):
        # The inventory RAN, but it flagged a keystroke-injector — "human-authored,
        # not injected" cannot stand over a flagged injector.
        out = iig.check(_ctx(
            "Quinn created the svc-backdoor account in an interactive Type-11 console "
            "session on 2021-05-03 — human-authored, not injected",
            tool_calls=[_INVENTORY_FLAGGED]))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"
        assert "flagged" in out["error"].lower()

    def test_strings_grep_does_not_satisfy(self):
        # The RETIRED keyword path: a strings/grep that surfaced device records is no
        # longer grounding — only the structured inventory marker is.
        out = iig.check(_ctx(
            "Quinn created the covert account in an interactive console session",
            ["rip.pl -p usbstor"], tool_calls=[_STRINGS_GREP]))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"

    def test_prose_claim_without_inventory_refused(self):
        out = iig.check(_ctx(
            "Quinn created the account in an interactive session",
            ["rip.pl -p usbstor"],
            supporting_evidence="setupapi.dev.log shows only mass-storage USB, no HID device"))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"

    def test_input_call_id_to_inventory_clears(self):
        out = iig.check(_ctx(
            "Quinn created the covert account in an interactive console session",
            ["rip.pl -p usbstor"],
            by_call_id={4242: _INVENTORY_CLEAN}, input_call_ids=[4242]))
        assert out is None

    def test_inventory_must_span_claim_window(self):
        # Inventory ran, but its coverage does not span the finding's date → not
        # grounded (a log silent about the window can't clear a window claim).
        out = iig.check(_ctx(
            "Quinn created the covert account in an interactive console session on 2024-09-01",
            tool_calls=[_INVENTORY_CLEAN]))  # coverage ends 2021
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"

    def test_softened_session_attribution_refused(self):
        # The softened-attribution evasion: no "interactive" keyword, no human name —
        # covert admin account creation attributed to a host-local logon session.
        out = iig.check(_ctx(
            "A local administrator account 'svc-helper' was created from the operator "
            "session (SubjectLogonId 0x4F1A2) and added to the Builtin\\Administrators group",
            ["rip.pl -r SYSTEM -p usbstor"], tier="LIKELY"))
        assert out is not None
        assert out["gate"] == "interactive_injection_grounding"

    def test_softened_session_attribution_clears_with_inventory(self):
        out = iig.check(_ctx(
            "A local administrator account 'svc-helper' was created from the operator "
            "session (SubjectLogonId 0x4F1A2) and added to Builtin\\Administrators",
            tier="LIKELY", tool_calls=[_INVENTORY_CLEAN]))
        assert out is None

    def test_system_process_session_creation_passes(self):
        # A service/system-principal session creating a service is not a human-at-
        # keyboard scenario → out of scope even with the softened phrasing.
        assert iig.check(_ctx(
            "services.exe created the service from the SYSTEM logon session",
            ["rip.pl -p usbstor"])) is None

    def test_no_removable_media_out_of_scope(self):
        # No USB anywhere in the case → keystroke-injection not in scope → pass.
        assert iig.check(_ctx("Quinn created the account in an interactive console session",
                              ["vol.pslist"])) is None

    def test_non_interactive_action_passes(self):
        assert iig.check(_ctx("Quinn exfiltrated data to Dropbox",
                              ["rip.pl -p usbstor"])) is None

    def test_process_not_human_passes(self):
        assert iig.check(_ctx("explorer.exe created the Run key in an interactive session",
                              ["rip.pl -p usbstor"])) is None

    def test_suspected_tier_not_gated(self):
        assert iig.check(_ctx("Quinn created the account interactively",
                              ["rip.pl -p usbstor"], tier="SUSPECTED")) is None

    def test_known_subject_via_trace_fires(self):
        # Name only resolvable as the case subject, in an interactive-action finding.
        by_type = {
            "tool_call": [{"type": "tool_call", "cmd": "rip.pl -p usbstor"}],
            "dair_call": [{"inputs": {"case_context": "Subject Sam on host host-01"},
                           "investigation_focus": ""}],
            "investigation_narration": [],
        }
        ctx = GateContext(
            description="Sam created the service in an interactive console session",
            confidence="Confirmed", tier="CONFIRMED", source="test", linked_call_id=0,
            tested_hypothesis_id="", log=MagicMock(),
            idx=SimpleNamespace(by_call_id={}, by_type=by_type), window=[],
            input_call_ids=[], supporting_evidence="")
        out = iig.check(ctx)
        assert out is not None and out["gate"] == "interactive_injection_grounding"


class TestDeviceInitialAccessManifest:
    def test_no_badusb_negative_without_inventory_refused(self):
        out = nc.check(_ctx("No malicious USB or HID injection was found",
                            ["rip.pl -p usbstor"], tier="UNCONFIRMED"))
        assert out is not None and out["gate"] == "negative_completeness"
        assert "device_install_inventory" in out["error"]

    def test_no_badusb_negative_with_clean_inventory_passes(self):
        out = nc.check(_ctx(
            "No HID injection / BadUSB: the device inventory shows no keystroke injector",
            tier="UNCONFIRMED", tool_calls=[_INVENTORY_CLEAN]))
        assert out is None

    def test_no_badusb_negative_with_flagged_inventory_refused(self):
        # "no BadUSB" while the inventory flagged an injector must be refused.
        out = nc.check(_ctx(
            "No BadUSB present in the 2021-05 window",
            tier="UNCONFIRMED", tool_calls=[_INVENTORY_FLAGGED]))
        assert out is not None and out["gate"] == "negative_completeness"
        assert "flagged" in out["error"].lower()

    def test_no_badusb_negative_strings_grep_refused(self):
        # The retired keyword path: a strings/grep over setupapi no longer grounds it.
        out = nc.check(_ctx(
            "No HID injection / BadUSB: setupapi.dev.log shows only mass-storage",
            ["strings -a setupapi.dev.log", "usbdeviceforensics SYSTEM"],
            tier="UNCONFIRMED", tool_calls=[_STRINGS_GREP]))
        assert out is not None and out["gate"] == "negative_completeness"

    def test_no_badusb_negative_absent_escape_passes(self):
        # Explicit "absent from evidence" escape still works.
        out = nc.check(_ctx(
            "No BadUSB assessment possible: setupapi.dev.log absent from evidence (not collected)",
            ["rip.pl -p usbstor"], tier="UNCONFIRMED"))
        assert out is None
