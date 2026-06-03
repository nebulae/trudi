"""Gate: CONFIRMED/LIKELY tiers require recent confidence_score + cite_check whose
inputs reference this finding's text. Anti-reuse — each finding gets a fresh check.
"""
import re
from typing import Optional

_WHITESPACE_RE = re.compile(r"\s+")
_RANK = {"CONFIRMED": 3, "LIKELY": 2, "SUSPECTED": 1, "UNCONFIRMED": 0}


def _normalize(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", (text or "").lower()).strip()[:60]


def _find_matching(ctx, tool_name: str, norm_desc: str, prior_dup_call_id: int) -> Optional[dict]:
    for entry in reversed(ctx.window):
        if entry.get("type") != "reason_call":
            continue
        if entry.get("tool") != tool_name:
            continue
        if int(entry.get("call_id") or 0) <= prior_dup_call_id:
            continue
        ins = entry.get("inputs") or {}
        user_msg = (ins.get("user_message") or "").lower()
        if norm_desc and norm_desc in user_msg:
            return entry
    return None


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None

    norm_desc = _normalize(ctx.description)
    # Anti-reuse: the matching reason_call must come AFTER any prior finding
    # with the same normalized description. Otherwise one confidence_score
    # call could satisfy the gate for unbounded duplicate findings.
    prior_dup_call_id = 0
    for e in ctx.idx.by_type.get("finding", []):
        if _normalize(e.get("description", "")) == norm_desc:
            prior_dup_call_id = max(prior_dup_call_id, int(e.get("call_id") or 0))

    cs_entry = _find_matching(ctx, "reason_confidence_score", norm_desc, prior_dup_call_id)
    if cs_entry is None:
        return {
            "success": False,
            "error": (
                f"{ctx.tier} tier requires a preceding reason.confidence_score "
                f"call that referenced this finding's text. None found in the "
                f"last 30 trace entries that (a) matched the description and "
                f"(b) was fresh (not reused from an earlier identical finding). "
                f"Call reason.confidence_score(finding=..., supporting_evidence=..., "
                f"intended_tier='{ctx.tier}') first, then re-record."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "confidence_and_citation",
            "missing_check": "reason_confidence_score",
        }

    # Parse the tier the reviewer assigned; refuse if it's lower than requested.
    cs_conclusion = (cs_entry.get("conclusion") or "")
    cs_tier_match = re.search(
        r'"tier"\s*:\s*"(CONFIRMED|LIKELY|SUSPECTED|UNCONFIRMED)"',
        cs_conclusion,
        re.IGNORECASE,
    )
    if not cs_tier_match:
        cs_tier_match = re.search(
            r"\bTIER\s*[:=]\s*(CONFIRMED|LIKELY|SUSPECTED|UNCONFIRMED)\b",
            cs_conclusion,
            re.IGNORECASE,
        )
    if cs_tier_match:
        assigned = cs_tier_match.group(1).upper()
        if _RANK.get(assigned, 0) < _RANK.get(ctx.tier, 0):
            return {
                "success": False,
                "error": (
                    f"reason.confidence_score assigned tier {assigned!r} but "
                    f"this record_finding requested {ctx.tier!r}. Downgrade the "
                    f"finding to {assigned!r} (or lower) before recording."
                ),
                "description": ctx.description,
                "confidence": ctx.confidence,
                "gate": "confidence_and_citation",
                "missing_check": "reason_confidence_score",
                "confidence_score_tier": assigned,
            }

    cc_entry = _find_matching(ctx, "reason_cite_check", norm_desc, prior_dup_call_id)
    if cc_entry is None:
        return {
            "success": False,
            "error": (
                f"{ctx.tier} tier requires a preceding reason.cite_check call that "
                f"referenced this finding's text. None found in the last 30 "
                f"trace entries. Call reason.cite_check(finding=..., "
                f"supporting_evidence=...) and resolve any uncited claims."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "confidence_and_citation",
            "missing_check": "reason_cite_check",
        }

    cc_conclusion = (cc_entry.get("conclusion") or "").upper()
    if "UNCITED_CLAIMS_PRESENT" in cc_conclusion or "INSUFFICIENT_EVIDENCE" in cc_conclusion:
        return {
            "success": False,
            "error": (
                "reason.cite_check returned UNCITED_CLAIMS_PRESENT or "
                "INSUFFICIENT_EVIDENCE for this finding. Add citations for "
                "every concrete claim (paths, IPs, hashes, technique IDs) "
                "and re-run cite_check before recording."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "confidence_and_citation",
            "missing_check": "reason_cite_check",
        }

    # Gate passed — stamp matched call_ids onto ctx so record_finding can
    # write them onto the finding entry as explicit foreign keys.
    ctx.gated_by_confidence_call_id = int(cs_entry.get("call_id") or 0)
    ctx.gated_by_cite_check_call_id = int(cc_entry.get("call_id") or 0)
    return None
