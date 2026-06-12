"""Gate: an interactive/console session does NOT prove human authorship while a
HID-capable removable device is in evidence.

Two ways a finding trips this gate:
  (1) it credits a NAMED human with an action in an interactive/console session
      (LogonType 2/11, "console", "at the keyboard"); or
  (2) it attributes covert-account / persistence CREATION to a host-local logon
      session under softened phrasing ("created … from the PC User session",
      "SubjectLogonId 0x…") — a softened phrasing that drops the word
      "interactive" and the actor's name to slip past trigger (1).

Either way, the gate clears only when a COMPLETE structured device-install
inventory was produced over the claim's window (misc.device_install_inventory)
with no keystroke-injector flagged — NOT when the finding merely *says* the log
was checked. A BadUSB injects keystrokes indistinguishable from human typing, so
an interactive session alone cannot establish a human authored the activity.
"""
import re
from typing import Optional

from ._device_install import claim_dates, flagged_count, inventory_for
from .named_actor_attribution_grounding import _NAME_RE, _NAME_STOPS, _case_subject_names

# Interactive / console / physical-presence session markers.
_INTERACTIVE_RE = re.compile(
    r"\binteractive(?:ly)?\b|\bconsole\b|\bat the keyboard\b"
    r"|\bphysically (?:present|at)\b|logon ?type ?(?:2|11)\b|\btype ?(?:2|11)\b",
    re.IGNORECASE,
)

# An action credited to the person (broad surface — per operator choice).
_ACTION_RE = re.compile(
    r"\b(?:creat\w+|ran|executed?|launched?|installed?|configured?|set ?up|"
    r"enabled?|added?|copied?|archived?|staged?|deleted?|typed?|entered?|"
    r"performed?|accessed?|opened?|mapped?|downloaded?)\b",
    re.IGNORECASE,
)

# (1b) Softened account/logon-session attribution — "created … from the <X>
# session", the raw EVTX SubjectLogonId field, "logged on as", etc. Narrow on
# purpose: the generic "in an interactive session" is owned by trigger (1) (which
# carries the named-human guard), so a bare process there still passes.
_SESSION_ATTRIB_RE = re.compile(
    r"from the [^.\n]{0,40}? session"
    r"|\bSubjectLogonId\b"
    r"|\blogon session\b"
    r"|under the [^.\n]{0,40}? (?:account|session)"
    r"|within the [^.\n]{0,40}? session"
    r"|(?:logged on|signed in|authenticated) as\b",
    re.IGNORECASE,
)

# Creation / setup of a covert account or persistence (the act this gate guards).
_CREATION_VERB_RE = re.compile(
    r"\b(?:creat\w+|added?|enabled?|installed?|set ?up|configured?|established?)\b",
    re.IGNORECASE,
)
_COVERT_NOUN_RE = re.compile(
    r"\b(?:account|admin(?:istrator)?|backdoor|persist\w*|service|scheduled task|"
    r"\btask\b|run ?key|autostart|implant|foothold)\b",
    re.IGNORECASE,
)

# A bare process executable or a non-human system principal as the creating
# subject — BadUSB keystroke injection targets an interactive *user* session, so
# these are out of scope (keeps "explorer.exe created the Run key" passing).
_NON_HUMAN_SUBJECT_RE = re.compile(
    r"\b[\w-]+\.exe\b|\b(?:SYSTEM|LocalSystem|LOCAL SERVICE|NETWORK SERVICE)\b",
    re.IGNORECASE,
)

# Removable media is in the case (so a BadUSB is in scope at all).
_REMOVABLE_IN_EVIDENCE_RE = re.compile(
    r"usbstor|mounteddevices|usbdevice|\bremovable\b|\blnk\b|lecmd|setupapi"
    r"|\bUSB\b|usb serial|volume label",
    re.IGNORECASE,
)


def _named_human(desc: str, ctx) -> bool:
    subjects = _case_subject_names(ctx)
    if any(re.search(rf"\b{re.escape(s)}\b", desc) for s in subjects):
        return True
    return bool(set(_NAME_RE.findall(desc)) - _NAME_STOPS)


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    desc = ctx.description or ""

    # (1) named human credited with an interactive-session action.
    interactive_action = bool(
        _INTERACTIVE_RE.search(desc) and _ACTION_RE.search(desc) and _named_human(desc, ctx)
    )
    # (1b) covert-account / persistence creation attributed to a host-local logon
    # session under softened phrasing — no "interactive" keyword, no name needed.
    covert_session_creation = bool(
        _SESSION_ATTRIB_RE.search(desc)
        and _CREATION_VERB_RE.search(desc)
        and _COVERT_NOUN_RE.search(desc)
        and not _NON_HUMAN_SUBJECT_RE.search(desc)
    )
    if not (interactive_action or covert_session_creation):
        return None

    by_type = getattr(ctx.idx, "by_type", {}) or {}
    cmds = [e.get("cmd", "") for e in by_type.get("tool_call", [])
            if isinstance(e.get("cmd"), str)]

    # Scope: only when removable media is actually in evidence.
    if not any(_REMOVABLE_IN_EVIDENCE_RE.search(c) for c in cmds):
        return None

    names = sorted(set(_NAME_RE.findall(desc)) - _NAME_STOPS) or ["the named person"]
    who = ", ".join(names) if interactive_action else "the host-local session"

    # Satisfaction is grounded on a COMPLETE structured device-install inventory
    # (misc.device_install_inventory parses the whole setupapi.dev.log), not a
    # keyword grep over a truncated/windowed dump. Two ways to fail:
    inv = inventory_for(ctx, claim_dates(desc))
    if inv is None:
        return {
            "success": False,
            "error": (
                f"{ctx.tier} finding credits {who} with covert-account/persistence "
                f"creation in an interactive/host-local session, but an interactive "
                f"session is NOT proof of human authorship while a HID-capable "
                f"removable device is in evidence — a BadUSB injects keystrokes "
                f"indistinguishable from human typing. No COMPLETE device-install "
                f"inventory covering the window exists in the trace. Run "
                f"misc.device_install_inventory over setupapi.dev.log (it enumerates "
                f"every device — you cannot miss a row by grepping the wrong string), "
                f"confirm no keystroke-injector is present in the window, then "
                f"re-record — or downgrade to SUSPECTED."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "interactive_injection_grounding",
        }
    flagged = flagged_count(inv)
    if flagged > 0:
        return {
            "success": False,
            "error": (
                f"{ctx.tier} finding attributes interactive HUMAN authorship to "
                f"{who}, but the structured device-install inventory FLAGGED "
                f"{flagged} keystroke-injection-capable device(s) in the window "
                f"(a device exposing both HID/keyboard and mass-storage interfaces). "
                f"A flagged injector means an interactive session cannot establish a "
                f"human typed this. Rule the flagged device(s) out with evidence — or "
                f"downgrade to SUSPECTED and frame the keystroke-injection alternative."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "interactive_injection_grounding",
        }
    return None
