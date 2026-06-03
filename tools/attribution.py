"""Adversary attribution pipeline.

Given the accumulated CONFIRMED/LIKELY findings in the trace, extract MITRE
ATT&CK technique IDs, look them up against the local groups table, and rank
candidate threat-actor profiles by F1 + tactic diversity. Most autonomous IR
agents stop at "we saw T1059.001"; this closes the loop to
"this matches G0016 (APT29) with HIGH confidence."
"""
from __future__ import annotations
import re
from fastmcp import FastMCP

from core import output_safe
from tools.mitre import load_groups, load_techniques

mcp = FastMCP("attribution")

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _collect_observed_tids() -> tuple[set[str], int]:
    """Pull T-IDs from every finding in the trace. Returns (tids, finding_count)."""
    from core.execution_log import log
    idx = log.index()
    tids: set[str] = set()
    findings = idx.by_type.get("finding", [])
    for f in findings:
        # Only weight CONFIRMED/LIKELY for attribution scoring — SUSPECTED
        # and UNCONFIRMED tiers introduce too much noise.
        if (f.get("confidence") or "").upper() in {"CONFIRMED", "LIKELY"}:
            tids.update(_TID_RE.findall(f.get("description", "") or ""))
    return tids, len(findings)


def _tactic_count(tids: set[str], techniques: dict) -> int:
    """How many distinct tactics are covered by the observed T-IDs?"""
    tactics: set[str] = set()
    for tid in tids:
        info = techniques.get(tid)
        if not info:
            continue
        for t in (info.get("tactic") or "").split():
            tactics.add(t)
    return len(tactics)


def _classify_confidence(overlap: int, tactic_count: int) -> str:
    """Confidence band: HIGH / MEDIUM / LOW based on overlap + tactic diversity."""
    if overlap >= 5 and tactic_count >= 3:
        return "HIGH"
    if overlap >= 3 and tactic_count >= 2:
        return "MEDIUM"
    if overlap >= 2:
        return "LOW"
    return "INSUFFICIENT"


@mcp.tool()
@output_safe
def attribute_actors(
    top_n: int = 5,
    min_overlap: int = 2,
) -> dict:
    """
    Rank MITRE ATT&CK Groups by overlap with observed techniques in the trace.

    Walks all CONFIRMED/LIKELY findings, extracts T-IDs, computes per-group
    F1 (precision/recall over the group's known techniques) + tactic-diversity
    bonus, assigns a HIGH/MEDIUM/LOW confidence band per group.

    top_n: number of candidates to return (default 5).
    min_overlap: minimum overlap to consider (default 2; lower = noisier).

    Returns ranked candidate list with matched_techniques, missing_techniques,
    score, confidence_band, caveat. Use this BEFORE recording any finding that
    names a threat actor — the `attribution_required` gate refuses such
    findings without a backing attribute_actors call.
    """
    observed, finding_count = _collect_observed_tids()
    if not observed:
        return {
            "success": True,
            "observed_tid_count": 0,
            "finding_count": finding_count,
            "candidates": [],
            "table_size": 0,
            "note": "No T-IDs in CONFIRMED/LIKELY findings — record findings "
                    "with ATT&CK technique citations first.",
        }

    groups_table = load_groups().get("groups", {}) or {}
    techniques_table = load_techniques().get("techniques", {}) or {}
    if not groups_table:
        return {
            "success": False,
            "error": "MITRE groups table empty. Run "
                     "`python -m tools.mitre.build_mitre_cache` to populate.",
        }

    observed_tactic_count = _tactic_count(observed, techniques_table)
    candidates: list[dict] = []
    for gid, info in groups_table.items():
        gtids = set(info.get("technique_ids") or [])
        if not gtids:
            continue
        overlap_set = observed & gtids
        overlap = len(overlap_set)
        if overlap < min_overlap:
            continue
        precision = overlap / max(len(gtids), 1)
        recall = overlap / max(len(observed), 1)
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        # Tactic diversity bonus: 0.1 per distinct tactic represented in overlap
        overlap_tactic_count = _tactic_count(overlap_set, techniques_table)
        score = round(f1 + 0.1 * overlap_tactic_count, 4)
        band = _classify_confidence(overlap, overlap_tactic_count)
        if band == "INSUFFICIENT":
            continue
        caveat = (
            "Profile partially matches; consider broader collection."
            if band != "HIGH" else
            "Strong technique + tactic overlap with this profile."
        )
        candidates.append({
            "group_id": gid,
            "group_name": info.get("name", ""),
            "aliases": (info.get("aliases") or [])[:5],
            "score": score,
            "confidence_band": band,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "overlap_count": overlap,
            "matched_techniques": sorted(overlap_set),
            "missing_techniques": sorted(gtids - observed)[:10],
            "total_group_techniques": len(gtids),
            "caveat": caveat,
        })

    candidates.sort(key=lambda c: (-c["score"], -c["overlap_count"], c["group_id"]))
    top = candidates[:top_n]

    suggested_finding = None
    if top and top[0]["confidence_band"] in {"HIGH", "MEDIUM"}:
        primary = top[0]
        tier = "LIKELY" if primary["confidence_band"] == "HIGH" else "SUSPECTED"
        suggested_finding = {
            "description": (
                f"Adversary attribution: profile matches "
                f"{primary['group_name']} ({primary['group_id']}) — "
                f"{primary['overlap_count']} overlapping techniques across "
                f"{observed_tactic_count} tactics ({primary['confidence_band']} band)"
            ),
            "confidence": tier,
            "source": "attribution.attribute_actors",
            "primary_group_id": primary["group_id"],
        }

    return {
        "success": True,
        "observed_tid_count": len(observed),
        "observed_tactic_count": observed_tactic_count,
        "finding_count": finding_count,
        "candidates": top,
        "total_candidates_above_threshold": len(candidates),
        "table_size": len(groups_table),
        "suggested_finding": suggested_finding,
    }
