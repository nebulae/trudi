"""Gate: CONFIRMED and LIKELY tiers require a reason.evaluate_finding with a
SUPPORTED verdict for THIS finding.

Matching, strongest first:
  1. by TYPED CLAIM — an evaluate that declared the same claim key
     (kind|category|act) with overlapping entities/principal/recipients;
  2. by description — the evaluate whose user_message echoes this finding's
     description (legacy);
  3. single-use fallback — the most-recent un-matched evaluate, spent as soon
     as any finding is recorded after it (one SUPPORTED verdict cannot wave
     through an unbounded run of findings).

A matched evaluate whose declared claim DIFFERS from the finding's (a different
kind/category/act) is refused naming the field: the reviewer must have judged
the claim actually being recorded. A CHALLENGED/UNCERTAIN verdict refuses and
emits a self_correction trace entry so the adversarial-review moment is
auditable; challenge_sticky then keeps it refused until new evidence.

LIKELY is gated like CONFIRMED (operator decision): the reviewer can
pull evidence itself, so there is no longer a "citation-only" tier above
SUSPECTED — the tier a re-authored challenged claim used to slip into.

The reviewer does NOT set the tier: a SUPPORTED verdict means the
cited rows hold the finding's facts; the tier itself is arithmetic over the
cited artifact classes (tier_contract gate, data/fk/tiering.yaml).
"""
from typing import Optional

from ._claims import FIELD_HELP
from ._entities import claim_key, entity_overlap
from ._match import normalize_desc, find_reason_call, most_recent_reason_call
from tools.verdict import parse_verdict

_KEY_FIELDS = (("claim_kind", "kind"), ("category", "category"), ("act", "act"))
ENTITY_OVERLAP = 0.5


def _fallback_spent(ctx, fb) -> bool:
    """True if a finding was already recorded after this un-matched evaluate,
    making it single-use-spent. Prefers the full-trace finding index; falls
    back to the window."""
    fb_id = int(fb.get("call_id") or 0)
    findings = None
    idx = getattr(ctx, "idx", None)
    if idx is not None:
        findings = (getattr(idx, "by_type", {}) or {}).get("finding")
    if findings is None:
        findings = [e for e in ctx.window if e.get("type") == "finding"]
    return any(int(e.get("call_id") or 0) > fb_id for e in findings)


def _claim_ents(c: dict) -> list:
    c = c or {}
    out = list(c.get("entities") or [])
    if c.get("principal"):
        out.append(c["principal"])
    return out + list(c.get("recipients") or [])


def claim_matches(finding_claim: dict, eval_claim: dict) -> bool:
    """Same claim key; entities overlap when either side declared any."""
    fk, ek = claim_key(finding_claim), claim_key(eval_claim)
    if not fk.strip("|") or fk != ek:
        return False
    fe, ee = _claim_ents(finding_claim), _claim_ents(eval_claim)
    if not fe and not ee:
        return True
    return entity_overlap(fe, ee) >= ENTITY_OVERLAP


def find_by_claim(window, tool_name: str, claim: dict, used: set | None = None) -> Optional[dict]:
    """Most-recent evaluate declaring the same typed claim. `window` may be
    the FULL evaluate list (see `_evaluates_full`): a claim match is precise,
    so it is not limited to the last-30 window — one evaluate spawns
    fetch/self-correction entries, so the matching SUPPORTED verdict can sit
    far back while the window falls to an unrelated fallback. `used` =
    evaluate cids already spent on a recorded finding (single-use)."""
    if not claim or not claim_key(claim).strip("|"):
        return None
    for entry in reversed(window):
        if entry.get("type") != "reason_call" or entry.get("tool") != tool_name:
            continue
        if used and int(entry.get("call_id") or 0) in used:
            continue
        ec = entry.get("claim")
        if isinstance(ec, dict) and claim_matches(claim, ec):
            return entry
    return None


def _evaluates_full(ctx) -> list:
    """Every reason_evaluate_finding entry in the trace (index-backed), else
    the window. Ordered by call_id."""
    idx = getattr(ctx, "idx", None)
    calls = None
    if idx is not None:
        calls = (getattr(idx, "by_type", {}) or {}).get("reason_call")
    if not isinstance(calls, list):
        return list(ctx.window)
    return sorted((e for e in calls if isinstance(e, dict)
                   and e.get("tool") == "reason_evaluate_finding"),
                  key=lambda e: int(e.get("call_id") or 0))


def _spent_evaluates(ctx) -> set:
    idx = getattr(ctx, "idx", None)
    findings = None
    if idx is not None:
        findings = (getattr(idx, "by_type", {}) or {}).get("finding")
    if not isinstance(findings, list):
        findings = [e for e in ctx.window if e.get("type") == "finding"]
    return {int(e.get("gated_by_evaluate_call_id") or 0) for e in findings
            if e.get("gated_by_evaluate_call_id")}


def claim_mismatch(finding_claim: dict, eval_claim: dict) -> list:
    """Key fields declared on BOTH sides that differ."""
    out = []
    for name, k in _KEY_FIELDS:
        a = str((finding_claim or {}).get(k) or "").lower()
        b = str((eval_claim or {}).get(k) or "").lower()
        if a and b and a != b:
            out.append(name)
    return out


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    claim = getattr(ctx, "claim", None) or {}

    match = "claim"
    eval_entry = find_by_claim(_evaluates_full(ctx), "reason_evaluate_finding", claim,
                               used=_spent_evaluates(ctx))
    if eval_entry is None:
        match = "description"
        eval_entry = find_reason_call(ctx.window, "reason_evaluate_finding",
                                      normalize_desc(ctx.description))
    if eval_entry is None:
        match = "fallback"
        fb = most_recent_reason_call(ctx.window, "reason_evaluate_finding")
        if fb is not None and not _fallback_spent(ctx, fb):
            eval_entry = fb

    if eval_entry is None:
        return {
            "success": False,
            "error": (
                f"{ctx.tier} tier requires a reason.evaluate_finding for THIS "
                f"finding — none declares the same typed claim or echoes its "
                f"description, and any prior evaluate was already spent on an earlier "
                f"finding (a single SUPPORTED verdict cannot cover multiple findings). "
                f"Call reason.evaluate_finding(finding=<this finding's text>, "
                f"supporting_evidence=..., claim_kind=..., category=..., act=..., "
                f"entities=[...]) first, then re-record — or downgrade to SUSPECTED."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "confirmed_requires_supported_evaluate",
            "evaluate_match": "none",
        }

    # The reviewer must have judged the claim actually being recorded.
    mismatch = claim_mismatch(claim, eval_entry.get("claim") or {})
    if mismatch:
        return {
            "success": False,
            "error": (
                f"{ctx.tier} refused: the matched reason.evaluate_finding (call "
                f"{eval_entry.get('call_id')}) reviewed a different typed claim — "
                f"{', '.join(mismatch)} differ. Re-run reason.evaluate_finding with the "
                f"same {', '.join(mismatch)} you are recording "
                f"({'; '.join(FIELD_HELP[m] for m in mismatch)})."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "confirmed_requires_supported_evaluate",
            "evaluate_match": match,
            "claim_mismatch": mismatch,
            "evaluate_call_id": int(eval_entry.get("call_id") or 0),
        }

    conclusion = eval_entry.get("conclusion", "") or ""
    verdict = str(eval_entry.get("verdict") or "").upper() or parse_verdict(conclusion)

    if verdict == "SUPPORTED":
        # The reviewer is a fact-checker: SUPPORTED means the
        # cited rows hold the stated facts. The TIER is not its call — the
        # tier_contract gate computed it from the cited artifact classes.
        ctx.gated_by_evaluate_call_id = int(eval_entry.get("call_id") or 0)
        return None

    trigger = "evaluate_challenged_gate_refused"
    if verdict == "UNCERTAIN":
        trigger = "evaluate_uncertain_gate_refused"

    ctx.log.record_self_correction(
        trigger=trigger,
        prior_belief=f"Attempted to record {ctx.tier}: {ctx.description[:200]}",
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
            f"{ctx.tier} tier refused: the reason.evaluate_finding for this "
            f"finding returned VERDICT: {verdict or 'UNPARSEABLE'} — an explicit "
            f"SUPPORTED verdict is required. Collect the discriminators it asked for, "
            f"re-evaluate, or downgrade this finding to SUSPECTED."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "confirmed_requires_supported_evaluate",
        "evaluate_verdict": verdict or "UNPARSEABLE",
        "evaluate_match": match,
        "evaluate_call_id": int(eval_entry.get("call_id") or 0),
    }
