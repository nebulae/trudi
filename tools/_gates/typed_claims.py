"""Gate: typed-claim declaration on findings (detail gate of evidence_strength).

The control plane must not classify findings by regexing their prose — the
finding's author chooses the wording, so wording-keyed triggers can be slipped
by accident or on purpose. The agent DECLARES the claim's shape instead
(tools/_gates/_claims.py): kind, category and act are required for every
CONFIRMED / LIKELY / UNCONFIRMED finding — a STRUCTURAL trigger, no wording
classifier — plus the conditional fields the declared shape implies (an egress
needs a channel, a delivery needs recipients, a human actor needs a name, a
logon/device negative needs a window). Downstream gates key on the declared
structure only.

Enforcement of PRESENCE: TRUDI_REQUIRE_TYPED_CLAIMS (default ON; "0" disables —
test suites and legacy flows). Enum validation always runs.
"""
from __future__ import annotations

import os
from typing import Optional

from . import _claims as C

VALID_KINDS = C.KINDS
VALID_CATEGORIES = C.CATEGORIES


def _enabled() -> bool:
    return (os.environ.get("TRUDI_REQUIRE_TYPED_CLAIMS") or "1").strip() != "0"


def check(ctx) -> Optional[dict]:
    claim = getattr(ctx, "claim", None) or {}

    # Validate declared values even when enforcement is off — a bad enum is
    # always an error; silence would hide it.
    bad = C.enum_errors(claim)
    if bad:
        return {
            "success": False,
            "error": "Invalid typed-claim value(s): " + "; ".join(bad),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "typed_claims",
        }

    conflict = C.conflicts(claim)
    if conflict:
        return {
            "success": False,
            "error": "Typed-claim conflict: " + "; ".join(conflict),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "typed_claims",
            "conflict": conflict,
        }

    if not _enabled():
        return None
    missing = C.missing_fields(ctx.tier, claim)
    if missing:
        return {
            "success": False,
            "error": (
                f"{ctx.tier} findings must declare a typed claim — missing "
                f"{', '.join(missing)}. Pass: {C.help_lines(missing)}. Gates key on the "
                f"declared structure instead of regexing your wording; SUSPECTED needs "
                f"no claim."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "typed_claims",
            "missing": missing,
        }
    return None
