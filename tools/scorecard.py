"""Read-only run scorecard.

Measures ONE investigation's execution trace against operational targets and a
ground-truth answer key — the metric for the local-backend viability goal. It
never writes to the trace, the evidence, or any cache file.

    python -m tools.scorecard <trace.json> [ground_truth.json]

Operational metrics (from the trace alone):
  minutes                wall-clock first→last entry
  evidence_calls         is_evidence_tool_call (real forensic / read.* work)
  control_plane          reason_call + dair_call + disposition + finding_refused
                         + self_correction (the overhead the rabbit hole grew)
  control_to_evidence    control_plane / evidence_calls  (target ≤ 1.0)
  dispositions           typed misc.record_disposition entries  (target ≤ 20)
  refusals               finding_refused entries               (target ≤ 5)
  evaluate_rounds        mean reason_evaluate_finding evidence rounds
  findings_by_tier       CONFIRMED / LIKELY / SUSPECTED / UNCONFIRMED counts
  reached_report         a successful misc_write_final_report entry exists

Tier accuracy (when a ground_truth.json is given): each expected finding is
matched to the best trace finding by typed claim (category+act) and entity /
token overlap; the pair's tier is compared to confidence_min. under = recorded
below the evidence (a miss); over = recorded above it (an over-claim). Both are
failures. The pairing is PRINTED so it can be adjudicated by hand — the Jaccard
matcher in accuracy.py is known to mis-pair, so this stays transparent.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime

from tools._gates._evidence_calls import is_evidence_tool_call
from tools._gates._entities import norm_entity, entity_variants

_TIER_RANK = {"CONFIRMED": 3, "LIKELY": 2, "SUSPECTED": 1, "UNCONFIRMED": 0, "": 0}
_CONTROL_TYPES = {"reason_call", "dair_call", "disposition", "finding_refused", "self_correction"}
_TARGETS = {"minutes": 60.0, "control_to_evidence": 1.0, "dispositions": 20,
            "refusals": 5, "under_tiered": 0, "over_tiered": 0}
_STOP = frozenset("the a an of to and or is was were be been being in on at for with "
                  "by from as that this it its into onto account created via using "
                  "user data file drive over after before during within".split())


def _load(path: str) -> list[dict]:
    with open(path) as fh:
        d = json.load(fh)
    return d.get("entries", d) if isinstance(d, dict) else d


def _parse_ts(s: str) -> float | None:
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9.@]+", (text or "").lower())
            if len(t) > 2 and t not in _STOP}


def _finding_terms(e: dict) -> tuple[set, set]:
    c = e.get("claim") or {}
    ents = set()
    for v in list(c.get("entities") or []) + list(c.get("recipients") or []) + \
            ([c.get("principal")] if c.get("principal") else []):
        ents |= entity_variants(v)
    return ents, _tokens(e.get("description", ""))


def _gt_terms(g: dict) -> tuple[set, set]:
    ents = set()
    for v in g.get("entities") or []:
        ents |= entity_variants(v)
    return ents, _tokens(g.get("description", ""))


def _match_score(gt: dict, fe: dict) -> float:
    ge, gt_tok = _gt_terms(gt)
    feE, fe_tok = _finding_terms(fe)
    fc = fe.get("claim") or {}
    # typed-claim agreement is worth more than word overlap
    cat_ok = bool(gt.get("category")) and gt.get("category") == fc.get("category")
    act_ok = bool(gt.get("act")) and gt.get("act") == fc.get("act")
    ent_ov = len(ge & feE) / len(ge | feE) if (ge or feE) else 0.0
    tok_ov = len(gt_tok & fe_tok) / len(gt_tok | fe_tok) if (gt_tok or fe_tok) else 0.0
    return 0.4 * cat_ok + 0.2 * act_ok + 0.25 * ent_ov + 0.15 * tok_ov


def score(trace_path: str, gt_path: str | None = None) -> dict:
    entries = _load(trace_path)
    ev = [e for e in entries if e.get("type") == "tool_call" and is_evidence_tool_call(e)]
    control = [e for e in entries if e.get("type") in _CONTROL_TYPES]
    disp = [e for e in entries if e.get("type") == "disposition"]
    refus = [e for e in entries if e.get("type") == "finding_refused"]
    findings = [e for e in entries if e.get("type") == "finding"]
    evals = [e for e in entries if e.get("type") == "reason_call"
             and e.get("tool") == "reason_evaluate_finding"]
    rounds = [int(e.get("evidence_rounds") or 0) for e in evals]
    ts = [t for e in entries if (t := _parse_ts(e.get("ts"))) is not None]
    reached = any(e.get("type") == "tool_call" and e.get("success")
                  and "misc_write_final_report" in str(e.get("cmd") or "") for e in entries)
    by_tier = {t: sum(1 for f in findings if (f.get("confidence") or "").upper() == t)
               for t in ("CONFIRMED", "LIKELY", "SUSPECTED", "UNCONFIRMED")}

    m = {
        "minutes": round((max(ts) - min(ts)) / 60, 1) if len(ts) >= 2 else 0.0,
        "entries": len(entries),
        "evidence_calls": len(ev),
        "control_plane": len(control),
        "control_to_evidence": round(len(control) / len(ev), 2) if ev else 0.0,
        "dispositions": len(disp),
        "refusals": len(refus),
        "evaluate_calls": len(evals),
        "evaluate_rounds_mean": round(sum(rounds) / len(rounds), 2) if rounds else 0.0,
        "findings_by_tier": by_tier,
        "reached_report": reached,
    }

    result = {"trace": trace_path, "metrics": m, "targets": {}, "tier_accuracy": None}
    for k, tgt in _TARGETS.items():
        if k in ("under_tiered", "over_tiered"):
            continue
        val = m.get(k)
        if val is not None:
            result["targets"][k] = {"value": val, "target": tgt, "pass": val <= tgt}

    if gt_path:
        with open(gt_path) as fh:
            gt = json.load(fh)
        gts = gt.get("expected_findings", [])
        # Global assignment: score every (gt, finding) pair, then take pairs in
        # descending score, skipping GT/findings already claimed. This avoids
        # the per-GT greedy failure where the first GT eats a later GT's best
        # finding (the Jaccard matcher in accuracy.py mis-pairs exactly here).
        cand = sorted(
            ((_match_score(g, fe), gi, fi) for gi, g in enumerate(gts) for fi, fe in enumerate(findings)),
            key=lambda x: -x[0])
        g_used, f_used, best_for = set(), set(), {}
        for sc, gi, fi in cand:
            if sc < 0.35 or gi in g_used or fi in f_used:
                continue
            g_used.add(gi); f_used.add(fi); best_for[gi] = (fi, sc)
        pairs, under, over = [], 0, 0
        for gi, g in enumerate(gts):
            exp = (g.get("confidence_min") or "").upper()
            if gi in best_for:
                fi, sc = best_for[gi]
                best = findings[fi]
                act = (best.get("confidence") or "").upper()
                rel = ("met" if _TIER_RANK[act] == _TIER_RANK[exp]
                       else "over" if _TIER_RANK[act] > _TIER_RANK[exp] else "under")
                under += rel == "under"
                over += rel == "over"
                pairs.append({"id": g["id"], "expected": exp, "actual": act,
                              "verdict": rel, "score": round(sc, 2),
                              "finding": (best.get("description") or "")[:90]})
            else:
                under += 1
                pairs.append({"id": g["id"], "expected": exp, "actual": "MISSING",
                              "verdict": "missing", "score": 0.0, "finding": ""})
        matched = sum(1 for p in pairs if p["verdict"] != "missing")
        result["tier_accuracy"] = {
            "expected": len(gt.get("expected_findings", [])),
            "matched": matched, "met": sum(1 for p in pairs if p["verdict"] == "met"),
            "under_tiered": under, "over_tiered": over, "pairs": pairs,
            "recall": round(matched / len(gt["expected_findings"]), 2) if gt.get("expected_findings") else 0.0,
        }
        result["targets"]["under_tiered"] = {"value": under, "target": 0, "pass": under == 0}
        result["targets"]["over_tiered"] = {"value": over, "target": 0, "pass": over == 0}
    return result


def _render(r: dict) -> str:
    m, out = r["metrics"], []
    out.append(f"SCORECARD  {r['trace']}")
    out.append(f"  {m['entries']} entries · {m['minutes']} min · report written: "
               f"{'yes' if m['reached_report'] else 'NO'}")
    bt = m["findings_by_tier"]
    out.append(f"  findings: {bt['CONFIRMED']}C {bt['LIKELY']}L {bt['SUSPECTED']}S "
               f"{bt['UNCONFIRMED']}U   evaluates: {m['evaluate_calls']} "
               f"(mean {m['evaluate_rounds_mean']} rounds)")
    out.append("  operational targets:")
    for k, t in r["targets"].items():
        out.append(f"    [{'PASS' if t['pass'] else 'FAIL'}] {k}: {t['value']} (≤ {t['target']})")
    ta = r.get("tier_accuracy")
    if ta:
        out.append(f"  tier accuracy: {ta['met']}/{ta['expected']} met, "
                   f"{ta['under_tiered']} under, {ta['over_tiered']} over, "
                   f"recall {ta['recall']}")
        for p in ta["pairs"]:
            mark = {"met": "✓", "over": "▲", "under": "▽", "missing": "✗"}[p["verdict"]]
            out.append(f"    {mark} {p['id']}: expected {p['expected']} → "
                       f"{p['actual']} (match {p['score']})  {p['finding']}")
    passed = all(t["pass"] for t in r["targets"].values())
    out.append(f"  OVERALL: {'PASS' if passed else 'REVIEW'}")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.strip().splitlines()[3].strip())
        return 2
    r = score(argv[0], argv[1] if len(argv) > 1 else None)
    print(_render(r))
    print("\n" + json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
