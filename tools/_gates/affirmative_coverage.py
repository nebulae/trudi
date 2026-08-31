"""Affirmative coverage completeness — block-late at reason.pre_report_check.

The negative_completeness gate enforces "you can't claim ABSENCE without
searching the complete source set." This is its mirror for POSITIVE verdicts:
a CONFIRMED/LIKELY conclusion that data LEFT the host (claim.act="egress"), or
that a named party received it (claim.recipients / act delivery|possession),
must rest on a COMPLETE enumeration of the relevant sources — not on the one
channel the investigation happened to look at first. A destruction finding
(claim.act="destruction", any tier) must be followed by a destruction-impact
pass or an explicit typed disposition of the wiped scope.

Everything keys on the TYPED CLAIM and on TOOL COMMANDS; nothing reads the
wording of a finding or a narration. Source waivers are typed dispositions:
  misc.record_disposition(target_kind="source", target_id=<EXFIL source id>,
                          reason="absent_from_evidence"|"inapplicable"|"out_of_scope")
  misc.record_disposition(target_kind="destruction_scope", target_id=<finding cid>,
                          reason="undetermined")
"""
from __future__ import annotations

import re

from ._dispositions import (SOURCE_WAIVER_REASONS_ALL, any_disposition, disposition_call,
                            find_disposition, index_from_entries)
from ._manifests import MANIFESTS

# Mail/chat correspondent enumeration (recipient exhaustion) — over COMMANDS.
_COMMS_RE = re.compile(
    r"readpst|pff_export|\.ost\b|\.pst\b|outlook|main\.db|skype|whatsapp|telegram"
    r"|msgstore|chat_db_export|read[._]mail",
    re.IGNORECASE)

# A destruction-impact pass — enumerating/recovering what was destroyed — over
# COMMANDS only (narrating the word "carving" no longer satisfies it).
_IMPACT_RE = re.compile(
    r"(?:af_usn_gaps|usn_?gaps|usnparser|usnjrnl|\$usnjrnl|\$j\b|usn journal"
    r"|\$logfile|\blogfile\b"
    r"|vshadow|volume shadow|shadow ?cop\w*|\bvss\b"
    r"|bulk_extractor|foremost|scalpel|photorec|tsk_recover|carv\w*)",
    re.IGNORECASE,
)


def _cmds(entries) -> list:
    return [e.get("cmd", "") for e in (entries or [])
            if e.get("type") == "tool_call" and e.get("cmd")]


def _findings(entries, tiers=("CONFIRMED", "LIKELY")) -> list:
    return [e for e in (entries or []) if e.get("type") == "finding"
            and (e.get("confidence") or "").upper() in tiers]


def coverage_gaps(entries) -> list:
    """Block-late issue strings for affirmative verdicts with incomplete source
    coverage. `entries` is log._entries."""
    issues: list = []
    cmds = _cmds(entries)
    didx = index_from_entries(entries)
    verdicts = _findings(entries)

    # (1) EXFIL channel enumeration — STRICT: every EXFIL manifest source
    #     touched (by command) or settled by a typed source disposition.
    if any((f.get("claim") or {}).get("act") == "egress" for f in verdicts):
        missing, calls = [], []
        for sid, rx, hint in MANIFESTS["EXFIL"]["required"]:
            touched = any(rx.search(c) for c in cmds)
            waived = find_disposition(didx, "source", sid, reasons=SOURCE_WAIVER_REASONS_ALL) is not None
            if not touched and not waived:
                missing.append(f"{sid} ({hint})")
                calls.append(disposition_call("source", sid, "absent_from_evidence"))
        if missing:
            issues.append(
                "Exfiltration/dissemination verdict recorded but the egress-channel "
                "enumeration is incomplete — untouched, undispositioned channel(s): "
                + "; ".join(missing)
                + ". Enumerate ALL candidate channels and rank them by evidence "
                "strength before the verdict (Exfil-Channel Enumeration); only a "
                "source genuinely not in evidence may be settled with "
                + "; ".join(calls[:3]) + "."
            )

    # (2) Recipient/correspondent exhaustion — a named-recipient verdict needs a
    #     full mail/chat sender-recipient inventory (by command).
    if any((f.get("claim") or {}).get("recipients")
           or (f.get("claim") or {}).get("act") in ("delivery", "possession")
           for f in verdicts):
        if not any(_COMMS_RE.search(c) for c in cmds):
            issues.append(
                "A recipient is declared in a CONFIRMED/LIKELY finding but no mail/chat "
                "correspondent enumeration ran (readpst / pff_export / chat_db_export / "
                "read.mail over the OST/PST/chat stores). Extract and enumerate ALL "
                "senders and recipients, cross-referenced against the case roster, before "
                "naming the recipient (Recipient/Correspondent Exhaustion)."
            )

    # (3) Destruction-impact — a wiping/destruction action was identified but
    #     the investigation never characterized WHAT was destroyed, nor
    #     dispositioned the wiped scope as undetermined.
    destruction = [f for f in _findings(entries, ("CONFIRMED", "LIKELY", "SUSPECTED", "UNCONFIRMED"))
                   if (f.get("claim") or {}).get("act") == "destruction"]
    if destruction:
        impact_ran = any(_IMPACT_RE.search(c) for c in cmds)
        dispositioned = any_disposition(didx, "destruction_scope", reasons=["undetermined"]) is not None
        if not impact_ran and not dispositioned:
            cid = destruction[0].get("call_id") or "<finding call_id>"
            issues.append(
                "A data-destruction / anti-forensic wiping action was identified "
                "on the host, but no destruction-impact assessment was performed. "
                "'A wiper ran' is not a conclusion — the wiped material may be the "
                "very evidence under investigation. Characterize what was destroyed "
                "via USN $J gap analysis (af.usn_gaps), $LogFile, VSS/shadow "
                "copies, or file carving; OR record "
                + disposition_call("destruction_scope", str(cid), "undetermined")
                + " before the report."
            )
    return issues
