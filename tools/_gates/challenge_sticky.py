"""Gate: a CHALLENGED / UNCERTAIN reviewer verdict is STICKY
(detail gate of evidence_strength).

The workaround this closes: the reviewer challenges a finding; the agent
records it anyway at LIKELY (which had no evaluate requirement) or re-asks with
the same evidence until a SUPPORTED comes back. Now, for CONFIRMED and LIKELY:

  - the most recent evaluate for this finding is CHALLENGED/UNCERTAIN → refuse;
  - it is SUPPORTED, but an earlier one was CHALLENGED/UNCERTAIN and no
    evidence tool call sits between them → refuse (the re-ask changed nothing).

SUSPECTED / UNCONFIRMED are the honest downgrade and pass. The evaluate is
matched by normalized description over the WHOLE trace (idx.by_type), not the
30-entry window, so a challenge cannot age out.
"""
from __future__ import annotations

from typing import Optional

from ._evidence_calls import is_evidence_tool_call
from ._match import normalize_desc
from .confirmed_requires_supported_evaluate import claim_matches

_BAD = {"CHALLENGED", "UNCERTAIN"}


def _verdict_of(entry: dict) -> str:
    v = str(entry.get("verdict") or "").upper()
    if v:
        return v
    from tools.verdict import parse_verdict
    return (parse_verdict(entry.get("conclusion") or "") or "").upper()


def _evaluates_for(ctx, norm: str) -> list[dict]:
    """Evaluates of THIS finding: by typed claim (same key + overlapping
    entities — so a re-worded finding inherits its challenge) or by the legacy
    description echo."""
    by_type = getattr(ctx.idx, "by_type", None)
    if not isinstance(by_type, dict):
        return []
    claim = getattr(ctx, "claim", None) or {}
    out = []
    for e in by_type.get("reason_call", []) or []:
        if not isinstance(e, dict) or e.get("tool") != "reason_evaluate_finding":
            continue
        um = str(((e.get("inputs") or {}).get("user_message")) or "").lower()
        by_desc = bool(norm) and norm in um
        ec = e.get("claim")
        by_claim = isinstance(ec, dict) and claim_matches(claim, ec)
        if not (by_desc or by_claim):
            continue
        # A challenge that rests only on misses over PARTIAL sources (the
        # stdout was never retained) is not an earned challenge — the reviewer
        # could not have seen the rows. It does not stick.
        if str(e.get("verdict_basis") or "") == "partial_source":
            continue
        out.append(e)
    out.sort(key=lambda e: int(e.get("call_id") or 0))
    return out


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    evals = _evaluates_for(ctx, normalize_desc(ctx.description))
    if not evals:
        return None
    by_type = ctx.idx.by_type
    calls = [e for e in (by_type.get("tool_call", []) or []) if is_evidence_tool_call(e)]

    def _evidence_between(a: int, b: int) -> bool:
        return any(a < int(e.get("call_id") or 0) < b for e in calls)

    latest = evals[-1]
    lv = _verdict_of(latest)
    offending = None
    if lv in _BAD:
        offending = latest
    elif lv == "SUPPORTED":
        for prior in reversed(evals[:-1]):
            if _verdict_of(prior) in _BAD:
                if not _evidence_between(int(prior.get("call_id") or 0),
                                         int(latest.get("call_id") or 0)):
                    offending = prior
                break
    if offending is None:
        return None

    ov = _verdict_of(offending)
    ocid = int(offending.get("call_id") or 0)
    empties = [str(r.get("query")) for r in (offending.get("evidence_requests") or [])
               if isinstance(r, dict) and not int(r.get("rows_returned") or 0)]
    if offending is latest:
        why = (f"the most recent reason.evaluate_finding for this finding (call {ocid}) "
               f"returned {ov} and no evidence tool has run since")
    else:
        why = (f"reason.evaluate_finding call {ocid} returned {ov}; the later SUPPORTED "
               f"verdict was obtained without any evidence tool call in between — a "
               f"re-ask on the same evidence does not overturn a challenge")
    hint = ""
    if empties:
        hint = (" The reviewer looked for these discriminators and found NO rows: "
                + "; ".join(empties[:4]) + " — collect that evidence first.")
    return {
        "success": False,
        "error": (
            f"{ctx.tier} refused: {why}. A challenge is sticky — run the discriminators "
            f"the reviewer asked for (new evidence tool calls), re-evaluate to SUPPORTED, "
            f"or downgrade to SUSPECTED.{hint}"
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "challenge_sticky",
        "evaluate_verdict": ov,
        "evaluate_call_id": ocid,
        "empty_evidence_requests": empties,
    }
