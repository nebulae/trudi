"""Gate: CONFIRMED/LIKELY findings about specific behaviour kinds require a
recent reason.hypothesize call OR an explicit tested_hypothesis_id.

The keyword list (process, service, persistence, C2, lateral, ...) keys on
the things the agent is most likely to claim without first hypothesising.
A spurious hit on a pure file-existence finding is satisfied by a thin
reason.hypothesize call describing the observation.
"""
from typing import Optional

_HYPOTHESIZE_KEYWORDS = (
    "process", "service", "scheduled task", "task ",
    "persist", "c2", "beacon", "exfil", "lateral",
    "ghost", "orphan", "detached", "null cmdline",
    "unsigned", "credential", "implant", "stager",
)


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    if (ctx.tested_hypothesis_id or "").strip():
        return None

    desc_l = (ctx.description or "").lower()
    if not any(kw in desc_l for kw in _HYPOTHESIZE_KEYWORDS):
        return None

    # Find the most recent hypothesize call so the finding can carry its id
    # as an explicit foreign key.
    matched_hyp = None
    for e in reversed(ctx.window):
        if e.get("type") == "reason_call" and e.get("tool") == "reason_hypothesize":
            matched_hyp = e
            break
    if matched_hyp is not None:
        ctx.gated_by_hypothesize_call_id = int(matched_hyp.get("call_id") or 0)
        return None

    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding mentions process / service / persistence / "
            f"C2 / lateral-movement behaviour but no recent "
            f"reason.hypothesize call exists in the last 30 trace entries. "
            f"Call reason.hypothesize(observation=..., evidence=..., context=...) "
            f"and capture the returned hypothesis_id, then pass it as "
            f"tested_hypothesis_id when recording this finding."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "hypothesize_required",
    }
