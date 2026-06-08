"""Gate: CONFIRMED tier requires a reason.evaluate_finding with SUPPORTED verdict
for THIS finding.

Matches the evaluate_finding whose user_message echoes this finding's
description (so a *different* finding's CHALLENGED verdict reviewed in the same
batch cannot block this one — the cross-contamination bug). Only when no
description-matched evaluate exists does it fall back to the most-recent
evaluate_finding (legacy behaviour, and what older traces that did not echo the
description rely on). A CHALLENGED/UNCERTAIN verdict refuses and emits a
self_correction trace entry so the adversarial-review moment is auditable.
"""
import re
from typing import Optional

from ._match import normalize_desc, find_reason_call, most_recent_reason_call


def check(ctx) -> Optional[dict]:
    if ctx.tier != "CONFIRMED":
        return None

    norm = normalize_desc(ctx.description)
    # Prefer the evaluate_finding that actually reviewed THIS finding.
    matched = find_reason_call(ctx.window, "reason_evaluate_finding", norm)
    eval_entry = matched or most_recent_reason_call(ctx.window, "reason_evaluate_finding")

    if eval_entry is None:
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

    conclusion = eval_entry.get("conclusion", "") or ""
    verdict_match = re.search(
        r"VERDICT:\s*(SUPPORTED|CHALLENGED|UNCERTAIN)",
        conclusion,
        re.IGNORECASE,
    )
    verdict = verdict_match.group(1).upper() if verdict_match else ""

    if verdict == "SUPPORTED":
        # Explicit SUPPORTED verdict — gate passes. Stamp the matched eval
        # call_id so record_finding carries it as an explicit foreign key.
        ctx.gated_by_evaluate_call_id = int(eval_entry.get("call_id") or 0)
        return None

    # CHALLENGED or UNCERTAIN both block CONFIRMED. CLAUDE.md requires
    # an explicit SUPPORTED verdict; UNCERTAIN is insufficient — it means
    # the reviewer could not confirm the claim, which is not the same as
    # supporting it.
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
        evidence=(eval_entry.get("conclusion", "") or "")[:300],
        linked_call_id=eval_entry.get("call_id", 0),
    )
    return {
        "success": False,
        "error": (
            f"CONFIRMED tier refused: the reason.evaluate_finding for this "
            f"finding returned VERDICT: {verdict or 'UNPARSEABLE'} — an explicit "
            f"SUPPORTED verdict is required. Re-evaluate with stronger "
            f"evidence or downgrade this finding to SUSPECTED/LIKELY."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "confirmed_requires_supported_evaluate",
        "evaluate_verdict": verdict or "UNPARSEABLE",
    }
