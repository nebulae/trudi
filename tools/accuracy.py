"""Accuracy framework: compare trace findings against a case ground truth.

Produces a confusion matrix (TP/FP/FN), precision/recall/F1, and a list of
confidence downgrades — findings recorded below the ground truth's minimum tier.
Used to populate hackathon submission Component #6 (Accuracy Report).
"""
import json
import os
import re
from fastmcp import FastMCP
from core.paths import assert_output_safe
from core import output_safe

mcp = FastMCP("accuracy")


_TIER_RANK = {
    "CONFIRMED": 4,
    "LIKELY": 3,
    "SUSPECTED": 2,
    "UNCONFIRMED": 1,
}


def _tokens(text: str) -> set[str]:
    """Lowercase alphanumeric tokens ≥3 chars from a description.

    Used as the matching primitive between trace findings and ground-truth
    items. We deliberately avoid heavyweight NLP — simple token-set overlap is
    enough for hackathon validation against a curated ground truth.
    """
    return {t for t in re.findall(r"[A-Za-z0-9_.\\:-]{3,}", text.lower())}


def _match_score(a: str, b: str) -> float:
    """Jaccard similarity of token sets."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _meets_min_tier(actual: str, minimum: str) -> bool:
    """True if actual confidence tier is at or above minimum."""
    return _TIER_RANK.get(actual.upper(), 0) >= _TIER_RANK.get(minimum.upper(), 0)


@mcp.tool()
@output_safe
def accuracy_compare(ground_truth_path: str, match_threshold: float = 0.30) -> dict:
    """Compare current execution-log findings against a ground-truth manifest.

    ground_truth_path: JSON file matching the schema:
        {
          "case_id": "...",
          "expected_findings": [
            {"id": "F1", "description": "...", "confidence_min": "CONFIRMED",
             "category": "implant"},
            ...
          ],
          "negative_assertions": ["..."]
        }

    Returns:
      true_positives:        [{trace_finding, ground_truth_id, score}]
      false_positives:       [trace_finding]   (in trace, no GT match)
      false_negatives:       [{id, description, confidence_min}]  (in GT, no match)
      confidence_downgrades: [{ground_truth_id, expected_tier, actual_tier}]
      summary: precision, recall, f1, true_positive_count, false_positive_count,
               false_negative_count.
    """
    if not os.path.exists(ground_truth_path):
        return {"success": False, "error": f"ground_truth not found: {ground_truth_path}"}

    try:
        with open(ground_truth_path) as f:
            gt = json.load(f)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        return {"success": False, "error": f"ground_truth read failed: {e}"}

    expected = gt.get("expected_findings", []) or []

    from core.execution_log import log
    trace_findings = [e for e in log._entries if e.get("type") == "finding"]

    # Greedy matching: for each ground-truth item, take the highest-scoring
    # unmatched trace finding above threshold. This is deterministic and easy
    # to defend in the accuracy report.
    matched_trace_idxs: set[int] = set()
    true_positives = []
    false_negatives = []
    confidence_downgrades = []

    for gt_item in expected:
        best_idx = -1
        best_score = match_threshold  # must exceed threshold to count
        for i, tf in enumerate(trace_findings):
            if i in matched_trace_idxs:
                continue
            score = _match_score(gt_item.get("description", ""), tf.get("description", ""))
            if score > best_score:
                best_score = score
                best_idx = i
        if best_idx == -1:
            false_negatives.append({
                "id": gt_item.get("id", ""),
                "description": gt_item.get("description", ""),
                "confidence_min": gt_item.get("confidence_min", ""),
            })
            continue
        matched_trace_idxs.add(best_idx)
        tf = trace_findings[best_idx]
        true_positives.append({
            "ground_truth_id": gt_item.get("id", ""),
            "trace_finding": tf.get("description", ""),
            "trace_call_id": tf.get("call_id", 0),
            "score": round(best_score, 3),
        })
        actual = tf.get("confidence", "")
        expected_tier = gt_item.get("confidence_min", "")
        if expected_tier and not _meets_min_tier(actual, expected_tier):
            confidence_downgrades.append({
                "ground_truth_id": gt_item.get("id", ""),
                "expected_tier": expected_tier,
                "actual_tier": actual,
            })

    false_positives = [
        {"description": tf.get("description", ""),
         "confidence": tf.get("confidence", ""),
         "call_id": tf.get("call_id", 0)}
        for i, tf in enumerate(trace_findings)
        if i not in matched_trace_idxs
    ]

    # Negative-assertion scoring: each negative_assertion in ground truth is
    # "supported" if an UNCONFIRMED finding addresses it, "unaddressed" otherwise.
    negative_assertions = gt.get("negative_assertions", []) or []
    unconfirmed_findings = [
        tf for tf in trace_findings
        if tf.get("confidence", "").upper() == "UNCONFIRMED"
    ]
    negative_results = []
    for na in negative_assertions:
        best_score = match_threshold
        best_finding = None
        for uf in unconfirmed_findings:
            score = _match_score(na, uf.get("description", ""))
            if score > best_score:
                best_score = score
                best_finding = uf
        negative_results.append({
            "assertion": na,
            "addressed": best_finding is not None,
            "matched_call_id": best_finding.get("call_id", 0) if best_finding else 0,
            "score": round(best_score, 3) if best_finding else 0.0,
        })

    tp = len(true_positives)
    fp = len(false_positives)
    fn = len(false_negatives)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    addressed = sum(1 for r in negative_results if r["addressed"])
    negative_coverage = (
        addressed / len(negative_results) if negative_results else 1.0
    )

    return {
        "success": True,
        "case_id": gt.get("case_id", ""),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "confidence_downgrades": confidence_downgrades,
        "negative_assertions": negative_results,
        "summary": {
            "true_positive_count": tp,
            "false_positive_count": fp,
            "false_negative_count": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "negative_assertion_total": len(negative_results),
            "negative_assertion_addressed": addressed,
            "negative_coverage": round(negative_coverage, 3),
        },
    }


@mcp.tool()
@output_safe
def accuracy_export_report(ground_truth_path: str, output_path: str) -> dict:
    """Run accuracy_compare and write a Markdown report to output_path.

    output_path must be inside analysis/, exports/, or reports/.
    """
    cmp = accuracy_compare(ground_truth_path)
    if not cmp.get("success"):
        return cmp

    s = cmp["summary"]
    lines = [
        f"# Accuracy Report — {cmp.get('case_id', 'unknown')}",
        "",
        "## Summary",
        f"- True positives: **{s['true_positive_count']}**",
        f"- False positives: **{s['false_positive_count']}**",
        f"- False negatives: **{s['false_negative_count']}**",
        f"- Precision: **{s['precision']}**",
        f"- Recall: **{s['recall']}**",
        f"- F1: **{s['f1']}**",
        "",
        "## True Positives",
    ]
    for tp in cmp["true_positives"]:
        lines.append(
            f"- `{tp['ground_truth_id']}` ↔ call #{tp['trace_call_id']} (score "
            f"{tp['score']}): {tp['trace_finding']}"
        )
    lines.append("")
    lines.append("## False Negatives (expected, not found)")
    for fn in cmp["false_negatives"]:
        lines.append(f"- `{fn['id']}` (expected ≥{fn['confidence_min']}): {fn['description']}")
    lines.append("")
    lines.append("## False Positives (found, not in ground truth)")
    for fp in cmp["false_positives"]:
        lines.append(f"- call #{fp['call_id']} [{fp['confidence']}]: {fp['description']}")
    lines.append("")
    lines.append("## Confidence Downgrades")
    for cd in cmp["confidence_downgrades"]:
        lines.append(
            f"- `{cd['ground_truth_id']}`: expected {cd['expected_tier']}, "
            f"recorded as {cd['actual_tier']}"
        )

    try:
        with open(output_path, "w") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        return {"success": False, "error": f"write failed: {e}"}
    return {
        "success": True,
        "output_path": output_path,
        "summary": cmp["summary"],
    }
