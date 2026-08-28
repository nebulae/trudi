"""Gate: a refused finding cannot be re-recorded by rewording it.

The workaround this closes (observed): a grounding gate refuses a finding; the
agent edits the description — removes the actor's name, "re-scopes" the claim —
and records it again with the same evidence. Refusals are now ledgered
(`finding_refused` entries) and a re-record that matches a recent refusal — by
declared claim (same kind|category|act key and overlapping entities /
principal / recipients) or by the same tested_hypothesis_id — with NO new
evidence tool call since, is itself refused. Wording is never compared.

Only EVIDENCE-DEMANDING refusals arm this gate: ones whose remediation is a
tool run. Structural refusals (lineage, typed_claims, MITRE ids, linked_call_id
must exist, dair_required) are remediated by fixing the record call;
`confidence_and_citation` by reason calls — none of these produces an
evidence tool_call, so counting them would deadlock legitimate fixes.
`confirmed_requires_supported_evaluate` arms ONLY when a claim/description-
matched evaluate returned CHALLENGED/UNCERTAIN (a genuine challenge of this
claim); `challenge_sticky` refusals always arm.

Exemptions: an honest downgrade (new tier lower than the refused tier and at
most SUSPECTED), and an attempt that cites a call_id the refused attempt did
not (the grounding gates' own remediation is "cite the existing 4624 call";
that gate still validates the marker).
"""
from __future__ import annotations

from typing import Optional

from ._evidence_calls import last_evidence_call_id
from ._entities import claim_key, entity_overlap, norm_entity as _norm_entity_shared

_EVIDENCE_DEMANDING = frozenset({
    "challenge_sticky",
    "negative_completeness",
    "principal_attribution_grounding",
    "named_actor_attribution_grounding",
    "interactive_injection_grounding",
    "exfil_channel_grounding",
    "offhost_delivery_grounding",
})
_TIER_RANK = {"CONFIRMED": 3, "LIKELY": 2, "SUSPECTED": 1, "UNCONFIRMED": 0}

ENTITY_JACCARD = 0.5


def _norm_entity(v) -> str:
    return _norm_entity_shared(v)


def _claim_entities(c: dict) -> list:
    c = c or {}
    out = list(c.get("entities") or [])
    if c.get("principal"):
        out.append(c["principal"])
    out += list(c.get("recipients") or [])
    return out


def check(ctx) -> Optional[dict]:
    by_type = getattr(ctx.idx, "by_type", None)
    if not isinstance(by_type, dict):
        return None
    refusals = [r for r in (by_type.get("finding_refused", []) or []) if isinstance(r, dict)]
    if not refusals:
        return None
    last_ev = last_evidence_call_id(by_type)
    my_tier = (ctx.tier or "").upper()
    my_claim = getattr(ctx, "claim", None) or {}
    my_key = claim_key(my_claim)
    my_ents = _claim_entities(my_claim)
    my_hyp = str(getattr(ctx, "tested_hypothesis_id", "") or "").strip()
    my_cids = {int(c) for c in (ctx.input_call_ids or []) if c}
    if getattr(ctx, "linked_call_id", 0):
        my_cids.add(int(ctx.linked_call_id))

    for r in reversed(refusals):
        if int(r.get("call_id") or 0) <= last_ev:
            continue                                   # evidence has run since
        dg = str(r.get("detail_gate") or r.get("gate") or "")
        if dg == "confirmed_requires_supported_evaluate":
            # Evidence-demanding only when a MATCHED (claim/description)
            # evaluate challenged this very claim — an absent evaluate or a
            # spent fallback is remediated by a reason call, not a tool run.
            ex = r.get("extra") or {}
            if not (str(ex.get("evaluate_verdict") or "").upper() in {"CHALLENGED", "UNCERTAIN"}
                    and str(ex.get("evaluate_match") or "") in {"claim", "description"}):
                continue
        elif dg not in _EVIDENCE_DEMANDING:
            continue
        r_tier = str(r.get("tier") or "").upper()
        if _TIER_RANK.get(my_tier, 0) < _TIER_RANK.get(r_tier, 0) and _TIER_RANK.get(my_tier, 0) <= 1:
            continue                                   # honest downgrade
        rc = r.get("claim") or {}
        by_claim = bool(my_key.strip("|") and my_key == claim_key(rc)
                        and entity_overlap(my_ents, _claim_entities(rc)) >= ENTITY_JACCARD)
        r_hyp = str(r.get("tested_hypothesis_id") or "").strip()
        by_hyp = bool(my_hyp and r_hyp and my_hyp == r_hyp)
        if not (by_claim or by_hyp):
            continue
        if my_cids - set(int(c) for c in (r.get("cited_call_ids") or [])):
            continue                                   # cites something new
        return {
            "success": False,
            "error": (
                f"Refused as a rewording: this finding matches a recent refusal "
                f"(call {r.get('call_id')}, gate {dg}) and no new evidence tool has run "
                f"since. That refusal asked for evidence, not wording — run the "
                f"discriminators it named, cite the new evidence (input_call_ids), or "
                f"downgrade to SUSPECTED."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "refusal_rewording",
            "prior_refusal_call_id": int(r.get("call_id") or 0),
            "prior_detail_gate": dg,
            "matched_by": "claim" if by_claim else "hypothesis",
        }
    return None
