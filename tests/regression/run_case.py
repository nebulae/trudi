"""Score a TRUDI case run against a ground-truth manifest.

Usage:
    python -m tests.regression.run_case \\
        --case-dir /home/trin/cases/<case> \\
        --ground-truth /home/trin/cases/<case>/ground_truth.json \\
        [--min-recall 0.8 --max-false-positives 2]

Reuses tools/accuracy.py:accuracy_compare so the scoring logic stays
in one place. Exits non-zero on regression.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path


def _load_trace(case_dir: Path) -> list[dict]:
    """Find and load the trace JSON for a case directory."""
    candidates = sorted(case_dir.glob("analysis/*_trace.json"))
    if not candidates:
        candidates = sorted(case_dir.glob("reports/*_trace.json"))
    if not candidates:
        raise FileNotFoundError(
            f"No *_trace.json found in {case_dir}/analysis or {case_dir}/reports"
        )
    # Take most recently modified
    trace_path = max(candidates, key=lambda p: p.stat().st_mtime)
    with trace_path.open() as f:
        data = json.load(f)
    return data.get("entries", []) if isinstance(data, dict) else data


def _score_against_ground_truth(
    trace_entries: list[dict],
    ground_truth: dict,
    match_threshold: float = 0.30,
) -> dict:
    """Standalone scorer — same logic shape as tools/accuracy.accuracy_compare
    but operates on a trace file instead of the live execution log so the
    harness can run without TRUDI being live."""
    expected = ground_truth.get("expected_findings", []) or []
    trace_findings = [e for e in trace_entries if e.get("type") == "finding"]

    def _norm(s: str) -> set[str]:
        import re
        toks = re.findall(r"[A-Za-z0-9_]+", (s or "").lower())
        stop = {"the", "and", "for", "with", "from", "this", "that"}
        return {t for t in toks if len(t) >= 3 and t not in stop}

    def _score(a: str, b: str) -> float:
        ta, tb = _norm(a), _norm(b)
        if not ta or not tb:
            return 0.0
        return len(ta & tb) / len(ta | tb)

    matched: set[int] = set()
    true_positives, false_negatives, downgrades = [], [], []

    for gt in expected:
        best_i, best_score = -1, match_threshold
        for i, tf in enumerate(trace_findings):
            if i in matched:
                continue
            s = _score(gt.get("description", ""), tf.get("description", ""))
            if s > best_score:
                best_score = s
                best_i = i
        if best_i == -1:
            false_negatives.append(gt)
            continue
        matched.add(best_i)
        tf = trace_findings[best_i]
        true_positives.append({
            "ground_truth_id": gt.get("id"),
            "trace_call_id": tf.get("call_id"),
            "score": round(best_score, 3),
            "trace_description": tf.get("description"),
        })
        tier_order = {"UNCONFIRMED": 0, "SUSPECTED": 1, "LIKELY": 2, "CONFIRMED": 3}
        expected_tier = gt.get("confidence_min", "")
        actual_tier = (tf.get("confidence") or "").upper()
        if expected_tier and tier_order.get(actual_tier, -1) < tier_order.get(expected_tier, 99):
            downgrades.append({
                "id": gt.get("id"),
                "expected": expected_tier,
                "actual": actual_tier,
            })

    false_positives = [
        trace_findings[i] for i in range(len(trace_findings)) if i not in matched
    ]

    tp, fp, fn = len(true_positives), len(false_positives), len(false_negatives)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "confidence_downgrades": downgrades,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score a TRUDI case against ground truth.")
    p.add_argument("--case-dir", required=True, type=Path)
    p.add_argument("--ground-truth", required=True, type=Path)
    p.add_argument("--min-recall", type=float, default=0.8)
    p.add_argument("--max-false-positives", type=int, default=10)
    p.add_argument("--max-downgrades", type=int, default=0)
    args = p.parse_args(argv)

    if not args.case_dir.exists():
        print(f"ERROR: case dir not found: {args.case_dir}", file=sys.stderr)
        return 2
    if not args.ground_truth.exists():
        print(f"ERROR: ground truth not found: {args.ground_truth}", file=sys.stderr)
        return 2

    try:
        entries = _load_trace(args.case_dir)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    with args.ground_truth.open() as f:
        gt = json.load(f)

    result = _score_against_ground_truth(entries, gt)

    print(f"Case: {gt.get('case_id', '?')}")
    print(f"Precision: {result['precision']}  Recall: {result['recall']}  F1: {result['f1']}")
    print(f"  True positives:  {len(result['true_positives'])}")
    print(f"  False positives: {len(result['false_positives'])}")
    print(f"  False negatives: {len(result['false_negatives'])}")
    print(f"  Confidence downgrades: {len(result['confidence_downgrades'])}")

    if result["false_negatives"]:
        print("\nFalse negatives (expected findings not present in trace):")
        for fn in result["false_negatives"]:
            print(f"  - {fn.get('id')}: {fn.get('description')[:120]}")

    if result["confidence_downgrades"]:
        print("\nConfidence downgrades (found but at lower tier than expected):")
        for d in result["confidence_downgrades"]:
            print(f"  - {d['id']}: expected {d['expected']}, got {d['actual']}")

    # Check thresholds
    failures = []
    if result["recall"] < args.min_recall:
        failures.append(f"recall {result['recall']} < min {args.min_recall}")
    if len(result["false_positives"]) > args.max_false_positives:
        failures.append(
            f"false positives {len(result['false_positives'])} > max {args.max_false_positives}"
        )
    if len(result["confidence_downgrades"]) > args.max_downgrades:
        failures.append(
            f"downgrades {len(result['confidence_downgrades'])} > max {args.max_downgrades}"
        )

    if failures:
        print("\nREGRESSION:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("\nPASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
