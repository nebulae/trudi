"""Gate: the tier a CONFIRMED / LIKELY finding asks for must be reachable
from the artifact classes its cited calls carry (data/fk/tiering.yaml).

Refuses ONLY when the agent asks HIGHER than the cited evidence reaches — and
then names the missing classes and the tools that produce them (the path to
the tier, not a wording request). Asking lower is accepted; the reachable
tier is stamped on the context so record_finding can surface the headroom.
Negative claims and SUSPECTED / UNCONFIRMED are not tiered here.
"""
from typing import Optional

from ._tiering import _RANK, artifact_classes, tier_for, tier_path


def cited_cids(ctx) -> list[int]:
    claim = getattr(ctx, "claim", None) or {}
    cids: list[int] = list(ctx.input_call_ids or [])
    if ctx.linked_call_id:
        cids.append(int(ctx.linked_call_id))
    for k in ("transfer_call_ids", "receipt_call_ids", "session_binding_call_ids"):
        cids.extend(int(c) for c in (claim.get(k) or []) if c)
    for ro in claim.get("rule_outs") or []:
        if isinstance(ro, dict):
            cids.extend(int(c) for c in (ro.get("call_ids") or []) if c)
    out, seen = [], set()
    for c in cids:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    claim = getattr(ctx, "claim", None) or {}
    if str(claim.get("claim_kind") or claim.get("kind") or "").lower() == "negative":
        return None
    if not claim.get("act"):
        return None                       # typed_claims will name the missing field
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    classes, origins = artifact_classes(by_id, cited_cids(ctx), with_origins=True)
    res = tier_for(claim, classes, origins)
    if not res.tier:
        return None                       # act without a contract — not tiered
    ctx.tier_achievable = res.tier
    ctx.artifact_classes = {k: sorted(v) for k, v in res.classes.items()}
    ctx.tier_rule = res.rule_key
    if _RANK.get(ctx.tier, 0) <= _RANK.get(res.tier, 0):
        return None
    path = tier_path(res, ctx.tier)
    return {
        "success": False,
        "error": (
            f"{ctx.tier} refused: the cited calls reach {res.tier} for this claim "
            f"(rule {res.rule_key}). {path} Cite the calls that carry the missing "
            f"class(es) in input_call_ids / transfer_call_ids / session_binding_call_ids "
            f"— run the named tools if they have not run — or record at {res.tier}."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "tier_contract",
        "tier_achievable": res.tier,
        "tier_rule": res.rule_key,
        "artifact_classes": ctx.artifact_classes,
        "missing": res.missing,
        "tier_path": path,
    }
