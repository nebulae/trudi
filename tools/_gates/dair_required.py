"""Gate: DAIR must have been engaged before findings are recorded.

Findings only make sense inside a DAIR-directed investigation. Checks that a
dair_call exists anywhere in the trace (DAIR has established phase), not within
a fixed window — a long collection batch must not age it out.
"""
from typing import Optional


def check(ctx) -> Optional[dict]:
    by_type = getattr(ctx.idx, "by_type", {}) or {}
    if by_type.get("dair_call"):
        return None
    return {
        "success": False,
        "error": (
            "Findings can only be recorded inside an active DAIR investigation "
            "(no dair_assess call found in the trace). Call dair_assess to "
            "establish current phase before recording findings."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "dair_required",
    }
