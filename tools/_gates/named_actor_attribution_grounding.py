"""Gate: a CONFIRMED/LIKELY finding that attributes the CORE ACT (exfiltration /
copy / theft / dissemination) to a NAMED HUMAN must be grounded in a logon /
session artifact.

Failure mode this closes: the sibling gate principal_attribution_grounding only
fires when the description binds an *account/identity* to a person via a copula
("account X is operated by Y"). A verdict phrased as a person acting directly —
"<Name> exfiltrated the data" — has no account token and no copula, so it would
otherwise ship with no session requirement, attributing a sole-actor verdict
without ruling out a second principal who operated the same host.
"""
import re
from typing import Optional

from ._match import lineage_evidence_text
from .principal_attribution_grounding import _SESSION_RE, _ACCOUNT_RE, _ATTRIB_RE

# The core act a sole-actor verdict turns on.
_CORE_ACT_RE = re.compile(
    r"\b(?:exfiltrat\w+|copied|stole|stol\w+|disseminat\w+|uploaded|upload\b"
    r"|transferred|transmit\w+|leaked|sent\b|smuggled|removed|staged)\b",
    re.IGNORECASE,
)

# A capitalized given-name-like token.
_NAME_RE = re.compile(r"\b([A-Z][a-z]{2,20})\b")

# General-purpose denylist of capitalized tokens that are NOT human actors, so a
# capitalized non-name in subject position can't be mistaken for a person. This
# is ordinary English / DFIR / brand vocabulary, not tied to any case — it keeps
# "Classified data was exfiltrated", "Dropbox uploaded…", "Monday's copy" from
# firing. Broad on purpose; add common tokens freely, they only suppress noise.
_NAME_STOPS = frozenset({
    # Sentence openers / determiners / tier words.
    "The", "This", "That", "These", "Those", "Confirmed", "Likely",
    "Suspected", "Unconfirmed", "Subject", "User", "Account",
    # OS / forensic artifact category nouns.
    "Security", "Windows", "System", "Event", "Registry", "Prefetch",
    "Source", "Network", "Remote", "Local", "Host", "Server", "Workstation",
    "Run", "Runonce", "Startup", "Task", "Tasks", "Service", "Services",
    "Key", "Value", "Desktop", "Downloads", "Recycle", "Temp", "Drive",
    "Volume", "Disk", "Session", "Logon", "Console", "Interactive", "Type",
    "Rdp", "Smb", "Ssh", "Usb", "Hid",
    # Generic data / object nouns common in finding prose.
    "Data", "Research", "Classified", "Stolen", "Files", "File", "Archive",
    "Folder", "Document", "Documents", "Payload", "Image", "Backup",
    # Common application / vendor brand names (broad, not case-specific) — cloud
    # storage, comms, archive/crypto, browsers, transfer clients.
    "Dropbox", "Onedrive", "Googledrive", "Gdrive", "Sharepoint", "Box",
    "Icloud", "Mega", "Wetransfer", "Pcloud", "Sync",
    "Skype", "Whatsapp", "Telegram", "Signal", "Discord", "Slack", "Teams",
    "Zoom", "Messenger", "Wechat", "Viber",
    "Veracrypt", "Truecrypt", "Bitlocker", "Winrar", "Winzip", "Peazip",
    "Chrome", "Firefox", "Edge", "Safari", "Opera", "Brave", "Outlook",
    "Thunderbird", "Filezilla", "Winscp", "Putty", "Rclone",
    # Calendar words.
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
    "Sunday", "January", "February", "March", "April", "June", "July",
    "August", "September", "October", "November", "December",
})

_SUBJECT_RE = re.compile(r"\bsubject(?:\s+is)?\s*:?\s+([A-Z][a-z]{2,20})\b",
                         re.IGNORECASE)
_BY_ACTOR_RE = re.compile(r"\bby\s+([A-Z][a-z]{2,20})\b")


def _case_subject_names(ctx) -> set[str]:
    """Learn the case subject's name from the trace (case_context is not plumbed
    into GateContext). Scan dair_call inputs.case_context / investigation_focus
    and agent_message content for 'Subject <Name>' / 'subject is <Name>'."""
    names: set[str] = set()
    by_type = getattr(ctx.idx, "by_type", {}) or {}
    blobs: list[str] = []
    for e in by_type.get("dair_call", []):
        inp = e.get("inputs") or {}
        blobs.append(inp.get("case_context") or "")
        blobs.append(e.get("investigation_focus") or "")
    for e in by_type.get("investigation_narration", []):
        blobs.append(e.get("content") or "")
    for b in blobs:
        for m in _SUBJECT_RE.finditer(b):
            names.add(m.group(1))
    return names


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None

    desc = ctx.description or ""
    m = _CORE_ACT_RE.search(desc)
    if not m:
        return None

    # If the description is already an account+copula binding, the sibling gate
    # principal_attribution_grounding owns it — don't double-fire.
    if _ACCOUNT_RE.search(desc) and _ATTRIB_RE.search(desc):
        return None

    # Candidate actors: capitalized names in subject position (before the verb)
    # or "by <Name>", minus noise; PLUS the case subject (always in scope even
    # if its name looks generic). Names AFTER the verb ("exfiltrated to China")
    # are destinations, not actors — excluded by the prefix slice.
    prefix = desc[:m.start()]
    candidates = (set(_NAME_RE.findall(prefix)) | set(_BY_ACTOR_RE.findall(desc)))
    candidates -= _NAME_STOPS
    subjects = _case_subject_names(ctx)
    subject_in_desc = {s for s in subjects if re.search(rf"\b{re.escape(s)}\b", desc)}
    named = candidates | subject_in_desc
    if not named:
        return None

    evidence = lineage_evidence_text(ctx)
    if _SESSION_RE.search(evidence):
        return None

    who = ", ".join(sorted(named))
    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding attributes the core act (exfiltration / copy / "
            f"transfer / dissemination) to a named person ({who}) but cites no "
            f"logon/RDP session artifact. Naming a person directly does not "
            f"establish that they — and not a second principal operating the "
            f"same host — performed the act. Pull the logon-session binding "
            f"(Security 4624/4625 logon type + source address, or RDP 4778/4779 "
            f"— ez.evtxecmd / misc.chainsaw_hunt) placing this person at the host "
            f"during the act and cite it (input_call_ids), or downgrade to "
            f"SUSPECTED."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "named_actor_attribution_grounding",
    }
