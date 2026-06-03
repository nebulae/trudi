"""Gate: linked_call_id (if non-zero) must point at a known trace entry."""
from typing import Optional


def check(ctx) -> Optional[dict]:
    if ctx.linked_call_id == 0:
        return None
    if ctx.linked_call_id in ctx.idx.by_call_id:
        return None
    return {
        "success": False,
        "error": (
            f"linked_call_id={ctx.linked_call_id} not found in execution trace. "
            "Use the _trudi_call_id from a recorded tool result."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "linked_call_id_must_exist",
    }
