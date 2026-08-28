"""Gate: an interactive/console session does NOT prove human authorship while a
HID-capable removable device is in evidence.

Trigger (typed claim, never wording):
  tier ∈ {CONFIRMED, LIKELY}
  AND claim.session_type == "interactive"
  AND claim.act ∈ {account_creation, persistence_install}
  AND claim.actor_kind ∈ {human, account, unknown}   (a process/system actor is
      out of scope — keystroke injection targets an interactive USER session)
Scope: only when removable media is in evidence (a regex over tool COMMANDS).

The gate clears only when a COMPLETE structured device-install inventory was
produced over the claim's window (misc.device_install_inventory, coverage
spanning claim.window) with no keystroke-injector flagged. A flagged injector
must be ruled out with evidence: claim.rule_outs=[{"what": "injector",
"call_ids": [...]}] naming evidence tool calls, or a typed disposition
misc.record_disposition(target_kind="device", target_id=<VID:PID>,
reason="ruled_out", evidence_call_ids=[...], window={start,end}) spanning the
claim window. Prose ("the injector was not connected") is not read.
"""
import re
from typing import Optional

from ._claims import FIELD_HELP
from ._device_install import flagged_count, inventory_for
from ._dispositions import any_disposition, disposition_call
from ._evidence_calls import is_evidence_tool_call

# Removable media is in the case (so a BadUSB is in scope at all). Over tool
# COMMANDS — classifies what ran, not what the agent wrote.
_REMOVABLE_IN_EVIDENCE_RE = re.compile(
    r"usbstor|mounteddevices|usbdevice|\bremovable\b|\blnk\b|lecmd|setupapi"
    r"|\bUSB\b|usb serial|volume label",
    re.IGNORECASE,
)

_INJECTOR_WHATS = frozenset({"injector", "badusb", "hid", "keystroke_injector", "hid_injector"})


def _claim_days(claim: dict) -> list:
    w = (claim or {}).get("window") or {}
    return [str(w[k])[:10] for k in ("start", "end") if w.get(k)]


def _injector_ruled_out(ctx, claim: dict) -> bool:
    # A rule-out is valid only if the injection's downstream traces were
    # looked at — the scheduled-task / autorun enumeration. Symmetric: the look
    # supports the rule-out or refutes it.
    from ._scheduled_tasks import tasks_examined
    entries = []
    idx = getattr(ctx, "idx", None)
    by_type = getattr(idx, "by_type", {}) or {}
    for lst in by_type.values():
        entries.extend(lst)
    if not tasks_examined(entries, idx):
        return False
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    for ro in claim.get("rule_outs") or []:
        if str(ro.get("what") or "").lower() not in _INJECTOR_WHATS:
            continue
        cids = [int(c) for c in (ro.get("call_ids") or []) if c]
        if cids and all(is_evidence_tool_call(by_id.get(c) or {}) for c in cids):
            return True
    win = claim.get("window") or None
    return any_disposition(ctx.idx, "device", reasons=["ruled_out"], window=win) is not None


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    claim = getattr(ctx, "claim", None) or {}
    # A4: fire on any session type that is NOT explicitly non-interactive —
    # interactive, unspecified (""), or unknown. Console keystroke injection is
    # possible in all three; a BadUSB cannot inject over a network/service logon.
    # Keying on the literal "interactive" let an agent dodge the gate by simply
    # omitting session_type on an account created at the console.
    if (claim.get("session_type") or "") not in ("interactive", "", "unknown"):
        return None
    if claim.get("act") not in ("account_creation", "persistence_install"):
        return None
    if claim.get("actor_kind") not in ("human", "account", "unknown", ""):
        return None

    by_type = getattr(ctx.idx, "by_type", {}) or {}
    cmds = [e.get("cmd", "") for e in by_type.get("tool_call", [])
            if isinstance(e.get("cmd"), str)]
    if not any(_REMOVABLE_IN_EVIDENCE_RE.search(c) for c in cmds):
        return None

    who = claim.get("actor") or claim.get("principal") or "the host-local session"
    inv = inventory_for(ctx, _claim_days(claim))
    if inv is None:
        return {
            "success": False,
            "error": (
                f"{ctx.tier} finding credits {who} with {claim.get('act')} at the "
                f"console, but a local session is NOT proof of human "
                f"authorship while a HID-capable removable device is in evidence — a "
                f"BadUSB injects keystrokes indistinguishable from human typing. No "
                f"COMPLETE device-install inventory covering the claim window "
                f"({', '.join(_claim_days(claim)) or 'no window declared — pass window='}) "
                f"exists in the trace. Run misc.device_install_inventory over "
                f"setupapi.dev.log (it enumerates every device), confirm no "
                f"keystroke-injector is present in the window, then re-record — or "
                f"downgrade to SUSPECTED."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "interactive_injection_grounding",
        }
    flagged = flagged_count(inv)
    if flagged > 0 and not _injector_ruled_out(ctx, claim):
        return {
            "success": False,
            "error": (
                f"{ctx.tier} finding attributes console HUMAN authorship to {who}, "
                f"but the structured device-install inventory FLAGGED {flagged} "
                f"keystroke-injection-capable device(s) in the window. A flagged "
                f"injector means an interactive session cannot establish a human typed "
                f"this. Rule the device out WITH EVIDENCE — pass "
                f"{FIELD_HELP['rule_outs']} or record "
                f"{disposition_call('device', '<VID:PID>', 'ruled_out', evidence=True)} "
                f"with a window spanning the claim — or downgrade to SUSPECTED and frame "
                f"the keystroke-injection alternative."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "interactive_injection_grounding",
            "missing": ["rule_outs"],
        }
    return None
