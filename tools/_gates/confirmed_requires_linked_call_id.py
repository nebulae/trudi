"""Gate: CONFIRMED tier requires a non-zero linked_call_id.

Every CONFIRMED finding must trace back to the tool execution that produced
it — this is the primary audit-log link the hackathon judges grade against.
"""
from typing import Optional


def check(ctx) -> Optional[dict]:
    if ctx.tier != "CONFIRMED":
        return None
    if ctx.linked_call_id != 0:
        return None
    return {
        "success": False,
        "error": (
            "CONFIRMED finding requires linked_call_id pointing to the tool "
            "result that produced it. Pass linked_call_id=<_trudi_call_id> "
            "from the source tool result."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "confirmed_requires_linked_call_id",
    }
