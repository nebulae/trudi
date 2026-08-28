"""Atomicity advisory (W3) — warn-early, never blocks.

Audit-trail quality depends on one finding mapping to one claim mapping to one
piece of evidence (linked_call_id). A description that bundles several distinct
claims ("X was created AND executed AND connected to C2") can carry only a single
linked_call_id, so the individual claims lose their per-artifact traceability and
the tier gates evaluate the bundle as a whole rather than each claim.

This is a non-blocking nudge surfaced on the record_finding success path (like
the FK corroboration note): it suggests splitting into per-claim findings while
the evidence is still at hand. Deterministic; fail-open at the call site.

Signals of a multi-claim bundle:
  - two or more distinct ATT&CK technique IDs, or
  - two or more distinct claim-bearing action verbs joined by a connector
    (and / ; / then / ", and").
"""
from __future__ import annotations

import re
from typing import Optional

# Action verbs that each constitute a distinct forensic claim.
_CLAIM_VERB_RE = re.compile(
    r"\b(?:execut\w+|ran\b|creat\w+|install\w+|persist\w+|establish\w+"
    r"|connect\w+|beacon\w+|exfiltrat\w+|copied|transferr\w+|uploaded|downloaded"
    r"|delet\w+|wip\w+|modif\w+|disabl\w+|clear\w+|inject\w+|dump\w+|harvest\w+"
    r"|stag\w+|encrypt\w+|schedul\w+|authenticat\w+|escalat\w+|exfil\w+"
    r"|logged in|moved lateral\w*)\b",
    re.IGNORECASE,
)

# A clause connector — presence signals two claims were joined rather than one
# claim with modifiers.
_CONNECTOR_RE = re.compile(r"(?:\band\b|;|\bthen\b|, and\b)", re.IGNORECASE)

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def atomicity_note(description: str) -> Optional[str]:
    d = description or ""
    tids = set(m.upper() for m in _TID_RE.findall(d))
    verbs = {v.lower() for v in _CLAIM_VERB_RE.findall(d)}

    reason = None
    if len(tids) >= 2:
        reason = f"{len(tids)} ATT&CK techniques ({', '.join(sorted(tids))})"
    elif _CONNECTOR_RE.search(d) and len(verbs) >= 2:
        reason = f"multiple actions ({', '.join(sorted(verbs))})"

    if not reason:
        return None

    return (
        f"This finding's description appears to bundle multiple claims — {reason}. "
        f"For audit traceability, prefer one finding per claim so each links to its "
        f"own evidence (linked_call_id) and is tiered on its own merits. Consider "
        f"splitting it into separate record_finding calls."
    )
