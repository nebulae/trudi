"""Replay a recorded investigation trace against the CURRENT control-plane code.

A full investigation takes ~2 hours; almost everything that stops one from
reaching its report is deterministic code (readiness checks, work-order and
failed-tool closure, path resolution, evidence packets, review-issue tracking,
disposition rules). This runs all of it over a saved trace in seconds, with no
model calls and nothing written outside a temp directory.

    python -m tools.replay_check <trace.json | case dir | .trace-backups/<ts> dir> [--json]

A trace saved under <case>/.trace-backups/<ts>/ refers to outputs under
<case>/exports and <case>/analysis that were moved into the backup; those
paths are remapped to the backup copy automatically.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile

# Isolate the TRUDI cache BEFORE any core/tools import: replay must never touch
# a live investigation's session beacon, counter or hook state.
_TMP = tempfile.mkdtemp(prefix="trudi-replay-")
os.environ["TRUDI_CACHE_DIR"] = os.path.join(_TMP, "cache")


def _find_trace(arg: str) -> tuple[str, dict]:
    """(trace path, {old path prefix: new path prefix}) for a trace file, a case
    dir, or a backup dir."""
    p = os.path.abspath(arg)
    if os.path.isdir(p):
        cands = [os.path.join(p, "analysis", f) for f in sorted(os.listdir(os.path.join(p, "analysis")))
                 if f.endswith("_trace.json")] if os.path.isdir(os.path.join(p, "analysis")) else []
        if not cands:
            raise SystemExit(f"no analysis/*_trace.json under {p}")
        p = cands[0]
    remap = {}
    m = re.match(r"^(.*)/\.trace-backups/([^/]+)/analysis/[^/]+$", p)
    if m:
        case, bdir = m.group(1), os.path.dirname(os.path.dirname(p))
        for sub in ("exports", "analysis"):
            remap[f"{case}/{sub}"] = f"{bdir}/{sub}"
    return p, remap


def _load(trace: str, remap: dict):
    from core.execution_log import ExecutionLog
    text = open(trace, encoding="utf-8").read()
    for old, new in remap.items():
        text = text.replace(old, new)
    d = json.loads(text)
    case_id = (d.get("case_id") if isinstance(d, dict) else None) or "REPLAY"
    work = os.path.join(_TMP, "analysis")
    os.makedirs(work, exist_ok=True)
    copy = os.path.join(work, os.path.basename(trace))
    with open(copy, "w", encoding="utf-8") as fh:
        fh.write(text)
    log = ExecutionLog()
    log.configure(case_id, copy, save_session=False)
    return log


def _paths(log) -> dict:
    """Every read.* call's target must resolve to an existing FILE."""
    from tools._output_reader import _cmd_output_paths
    bad = []
    for e in log._entries:
        cmd = str(e.get("cmd") or "")
        if e.get("type") != "tool_call" or not cmd.startswith(("read.output", "read.mail")):
            continue
        ps = _cmd_output_paths(cmd)
        if not ps:
            bad.append({"call_id": e.get("call_id"), "problem": "no path parsed", "cmd": cmd[:160]})
        elif not os.path.exists(ps[0]):
            bad.append({"call_id": e.get("call_id"), "problem": "missing", "path": ps[0]})
        elif cmd.startswith("read.output") and os.path.isdir(ps[0]):
            bad.append({"call_id": e.get("call_id"), "problem": "resolves to a directory", "path": ps[0]})
    return {"checked": sum(1 for e in log._entries if str(e.get("cmd") or "").startswith("read.")),
            "problems": bad}


def _packets(log) -> list:
    """Rebuild the review packet for every active finding with cited inputs."""
    from core.findings import active_findings
    from core.finding_submission import make_request
    from core.evidence_packets import build_packet, PacketError
    out = []
    for f in active_findings(log._entries):
        cids = [c for c in (f.get("input_call_ids") or []) if c]
        if not cids:
            continue
        row = {"finding": f.get("call_id"), "confidence": f.get("confidence")}
        # The stored claim carries server-normalised fields; submit the declared ones.
        claim = {k: v for k, v in (f.get("claim") or {}).items()
                 if not k.endswith("_norm") and k != "claim_version"}
        try:
            req = make_request(f.get("description") or "x", f.get("confidence") or "SUSPECTED", cids,
                               claim, linked_call_id=f.get("linked_call_id") or 0)
            pk = build_packet(log, req)
            row["sources"] = len(pk.get("evidence") or [])
            row["incomplete"] = [e["call_id"] for e in pk.get("evidence") or []
                                 if not e.get("retained_output_complete")]
        except (PacketError, ValueError) as exc:
            row["error"] = str(exc)[:200]
        out.append(row)
    return out


def _reviews(log) -> list:
    """Per synthesis round: objections raised vs objections tracked. A round
    whose blockers never became tracked issues silently loses them."""
    from core.review_issues import normalize_review
    out = []
    for i, e in enumerate(log._entries):
        if e.get("type") != "reason_call" or e.get("tool") != "reason_synthesize":
            continue
        rb = e.get("result_block") or {}
        raw = rb.get("issues")
        row = {"call_id": e.get("call_id"), "success": e.get("success"),
               "blockers": len(e.get("blockers") or []),
               "raw_issues": len(raw) if isinstance(raw, list) else None,
               "advisories": len(rb.get("advisories") or []),
               "tracked": len(e.get("review_issues") or []),
               "rejected": [r.get("reason") for r in e.get("review_items_rejected") or []]}
        # What the CURRENT code would track for the same reviewer answer.
        if e.get("success") and rb:
            try:
                now, _res, rej = normalize_review({"result_block": rb, "blockers": e.get("blockers")},
                                                  log._entries[:i])
                row["tracked_now"], row["rejected_now"] = len(now), [r.get("reason") for r in rej]
            except ValueError as exc:
                row["tracked_now"], row["rejected_now"] = None, [str(exc)[:80]]
        out.append(row)
    return out


def _dispositions(log) -> list:
    from tools._gates._disposition_review import dispositions_to_review
    return dispositions_to_review(log._entries)


def replay(arg: str) -> dict:
    trace, remap = _find_trace(arg)
    log = _load(trace, remap)
    from tools._readiness import assess_readiness
    from tools._gates.work_order import unrun_priority_tools, unretried_blocks
    r = assess_readiness(log)
    phases = []
    for e in log._entries:
        p = e.get("dair_phase")
        if p and (not phases or phases[-1][1] != p):
            phases.append((str(e.get("ts", ""))[11:19], p))
    return {
        "trace": trace, "remapped": remap, "entries": len(log._entries),
        "recorded_phase": log._current_phase,
        "dair_calls": sum(1 for e in log._entries if e.get("type") == "dair_call"),
        "phases": phases,
        "ready_to_report": r.get("ready_to_report"),
        "blocking_issues": r.get("blocking_issues") or [],
        "warnings": r.get("warnings") or [],
        "unrun_prescribed": unrun_priority_tools(log._entries),
        "failed_tools_open": unretried_blocks(log._entries),
        "read_paths": _paths(log),
        "packets": _packets(log),
        "synthesis_rounds": _reviews(log),
        "disposition_audit": _dispositions(log),
    }


def _print(rep: dict) -> None:
    short = lambda s, n=170: " ".join(str(s).split())[:n]
    print(f"trace     {rep['trace']}  ({rep['entries']} entries, {rep['dair_calls']} dair calls, "
          f"recorded phase {rep['recorded_phase']})")
    print("phases    " + " > ".join(f"{p}@{t}" for t, p in rep["phases"]))
    print(f"\nREADY TO REPORT: {rep['ready_to_report']}   blockers {len(rep['blocking_issues'])}, "
          f"warnings {len(rep['warnings'])}")
    for b in rep["blocking_issues"]:
        print("  BLOCK   " + short(b))
    print(f"\nwork order unrun: {rep['unrun_prescribed'] or 'none'}")
    for b in rep["failed_tools_open"]:
        print("  FAILED  " + short(b))
    rp = rep["read_paths"]
    print(f"\nread.* paths: {rp['checked']} checked, {len(rp['problems'])} problems")
    for p in rp["problems"][:15]:
        print("  PATH    " + short(p))
    bad = [p for p in rep["packets"] if p.get("error")]
    print(f"\nevidence packets: {len(rep['packets'])} findings, {len(bad)} fail to build")
    for p in bad:
        print(f"  PACKET  F-{p['finding']}: {short(p['error'])}")
    print("\nsynthesis rounds (raw issues / tracked then / tracked with current code / advisories):")
    for s in rep["synthesis_rounds"]:
        raw = s["raw_issues"] if s["raw_issues"] is not None else s["blockers"]
        lost = (s.get("tracked_now", s["tracked"]) or 0) < raw
        print(f"  #{s['call_id']}: {raw} / {s['tracked']} / {s.get('tracked_now', '-')} / {s['advisories']}"
              + ("   <-- objections not tracked" if lost else "")
              + (f"  rejected: {s['rejected']}" if s["rejected"] else ""))
    print(f"\ndispositions to review: {len(rep['disposition_audit'])}")
    for d in rep["disposition_audit"]:
        print(f"  DISP    #{d['call_id']} {d['target_kind']} {d.get('reason')}: {short(d['target_id'], 80)} — {short(d['why'], 90)}")


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    if not args:
        print(__doc__)
        return 2
    rep = replay(args[0])
    if as_json:
        print(json.dumps(rep, indent=2, default=str))
    else:
        _print(rep)
    return 0 if rep["ready_to_report"] else 1


if __name__ == "__main__":
    sys.exit(main())
