"""Gate: CONFIRMED tier requires a recent reason.evaluate_finding with SUPPORTED verdict.

If the most recent evaluate_finding within the look-back window returned
CHALLENGED, refuse and emit a self_correction trace entry — this surfaces
the adversarial-review moment in the dashboard.
"""
import re
from typing import Optional


def check(ctx) -> Optional[dict]:
    if ctx.tier != "CONFIRMED":
        return None

    most_recent_eval = None
    for e in reversed(ctx.window):
        if e.get("type") == "reason_call" and e.get("tool") == "reason_evaluate_finding":
            most_recent_eval = e
            break

    if most_recent_eval is None:
        return {
            "success": False,
            "error": (
                "CONFIRMED tier requires a preceding reason.evaluate_finding "
                "call (none found in last 30 trace entries). Call "
                "reason.evaluate_finding(finding=..., supporting_evidence=...) "
                "first, then re-record this finding."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "confirmed_requires_supported_evaluate",
        }

    conclusion = most_recent_eval.get("conclusion", "") or ""
    verdict_match = re.search(
        r"VERDICT:\s*(SUPPORTED|CHALLENGED|UNCERTAIN)",
        conclusion,
        re.IGNORECASE,
    )
    verdict = verdict_match.group(1).upper() if verdict_match else ""

    if verdict == "SUPPORTED":
        # Explicit SUPPORTED verdict — gate passes. Stamp the matched eval
        # call_id so record_finding carries it as an explicit foreign key.
        ctx.gated_by_evaluate_call_id = int(most_recent_eval.get("call_id") or 0)
        return None

    # CHALLENGED or UNCERTAIN both block CONFIRMED. CLAUDE.md requires
    # an explicit SUPPORTED verdict; UNCERTAIN is insufficient — it means
    # the reviewer could not confirm the claim, which is not the same as
    # supporting it. Previously the gate only blocked CHALLENGED, allowing
    # UNCERTAIN through.
    trigger = "evaluate_challenged_gate_refused"
    if verdict == "UNCERTAIN":
        trigger = "evaluate_uncertain_gate_refused"

    ctx.log.record_self_correction(
        trigger=trigger,
        prior_belief=f"Attempted to record CONFIRMED: {ctx.description[:200]}",
        new_belief=(
            f"Refused — evaluate_finding returned VERDICT: {verdict or 'unparseable'}. "
            f"Awaiting re-evaluation with stronger evidence or tier downgrade."
        ),
        evidence=(most_recent_eval.get("conclusion", "") or "")[:300],
        linked_call_id=most_recent_eval.get("call_id", 0),
    )
    return {
        "success": False,
        "error": (
            f"CONFIRMED tier refused: most recent reason.evaluate_finding "
            f"returned VERDICT: {verdict or 'UNPARSEABLE'} — an explicit "
            f"SUPPORTED verdict is required. Re-evaluate with stronger "
            f"evidence or downgrade this finding to SUSPECTED/LIKELY."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "confirmed_requires_supported_evaluate",
        "evaluate_verdict": verdict or "UNPARSEABLE",
    }
