"""Gate: a recent dair_assess must exist in the last 30 trace entries.

Findings only make sense inside an active DAIR-directed investigation. This
gate forces the agent to call dair_assess to establish phase before recording.
"""
from typing import Optional


def check(ctx) -> Optional[dict]:
    has_recent_dair = any(e.get("type") == "dair_call" for e in ctx.window)
    if has_recent_dair:
        return None
    return {
        "success": False,
        "error": (
            "Findings can only be recorded inside an active DAIR investigation "
            "(no dair_assess call found in last 30 trace entries). Call "
            "dair_assess to establish current phase before recording findings."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "dair_required",
    }
