"""Gate: CONFIRMED/LIKELY findings whose typed claim asserts a behaviour that
deserves an adversarial hypothesis pass require a reason.hypothesize call
ANYWHERE in the investigation OR an explicit tested_hypothesis_id — never a
tool-call-inflated recency window.

Trigger (typed claim, never wording): tier ∈ {CONFIRMED, LIKELY} AND no
tested_hypothesis_id AND (claim.category not in {"", "other"} OR claim.act ∈
HYPOTHESIS_ACTS). A finding with an undeclared claim (enforcement off) is not
gated here.
"""
from typing import Optional

HYPOTHESIS_ACTS = frozenset({"execution", "persistence_install", "account_creation",
                             "egress", "c2", "lateral_movement", "credential_access"})


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    if (ctx.tested_hypothesis_id or "").strip():
        return None
    claim = getattr(ctx, "claim", None) or {}
    cat = str(claim.get("category") or "").lower()
    act = str(claim.get("act") or "").lower()
    if not ((cat and cat != "other") or act in HYPOTHESIS_ACTS):
        return None

    # Existence over the WHOLE trace, not a 30-ENTRY window: a hypothesize→collect
    # (many tool calls)→record flow blows a raw-entry window out every time, so a
    # 30-entry recency check just churns the agent into re-running the same
    # hypothesize. The gate is a backstop — "you asserted a conclusion with NO
    # hypothesis pass anywhere" — so it fires only when the investigation never
    # hypothesized; per-artifact contemporaneity is carried by tested_hypothesis_id
    # (the strong form above) and driven by the DAIR loop, not a tool-call count.
    by_type = getattr(getattr(ctx, "idx", None), "by_type", {}) or {}
    hyps = [e for e in by_type.get("reason_call", [])
            if e.get("tool") == "reason_hypothesize" and e.get("success") is not False]
    if hyps:
        ctx.gated_by_hypothesize_call_id = int(hyps[-1].get("call_id") or 0)
        return None

    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding declares category={cat or 'n/a'} / act={act or 'n/a'} "
            f"but the investigation has NO reason.hypothesize call at all. Call "
            f"reason.hypothesize(observation=..., evidence=..., context=...) and capture "
            f"the returned hypothesis_id, then pass it as tested_hypothesis_id when "
            f"recording this finding (per-artifact hypotheses build the strongest lineage)."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "hypothesize_required",
    }
