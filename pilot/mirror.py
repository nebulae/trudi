"""trace→vera mirror: convert a TRUDI trace into a browsable .vera case.

One record pipeline for everything (docs/pilot.md Phase 1): batch mode
exports any past run; follow mode tails a live trace. Both are the same
idempotent pass — every mirrored row carries its originating
`_trudi_call_id`, so re-running skips what already landed.

    python -m pilot.mirror <trace.json> <case.vera> [--investigator NAME] [--follow]

Mapping (verified against vera schema 19):
  tool_call        -> Action method="command" (cid marker in notes; full
                      stdout stays in TRUDI's .tool_output sidecar)
  finding          -> Finding, ftype from the typed claim's category,
                      action_id via linked_call_id, whole claim in attrs
  hash.verify_evidence_hash tool_call -> Evidence row (label + sha256)
  dair_call        -> Lead finding + one lead_item per priority tool
  narration / self_correction / agent_message -> note findings
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time

from vera.db import Case

# typed claim category -> vera ftype (docs/pilot.md field-mapping table)
FTYPE_MAP = {
    "exfil": "netindicator",
    "c2": "netindicator",
    "delivery": "netindicator",
    "persistence": "hostindicator",
    "execution": "hostindicator",
    "device_initial_access": "hostindicator",
    "destruction": "hostindicator",
    "privilege_escalation": "hostindicator",
    "lateral_movement": "lateral",
    "account_creation": "account",
    "logon_auth": "account",
    "identity": "account",
    "attribution": "account",
    "timeline": "event",
}

CID_MARK = re.compile(r"\[trudi:cid (\d+)\]")
_SHA256 = re.compile(r"\b[0-9a-f]{64}\b")

# trace entry types mirrored as note findings
_NOTE_TYPES = {
    "investigation_narration": "narration",
    "agent_message": "narration",
    "self_correction": "self-correction",
    "system_error": "system error",
}

# claim fields that ride into finding attrs verbatim when present
_CLAIM_FIELDS = (
    "claim_kind", "category", "act", "channel", "entities", "principal",
    "actor_kind", "actor", "recipients", "scope", "window", "session_type",
    "techniques", "resolves", "answers_case_question", "tested_hypothesis_id",
    "transfer_call_ids", "receipt_call_ids", "session_binding_call_ids",
)


def load_trace(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        trace = json.load(fh)
    if not isinstance(trace, dict) or "entries" not in trace:
        raise ValueError(f"{path}: not a TRUDI trace (no 'entries')")
    return trace


def _existing_cids(case: Case) -> tuple[dict[int, int], set[int]]:
    """(tool cid -> action id) from notes markers; mirrored finding cids
    from attrs. The scan is what makes every pass idempotent."""
    actions: dict[int, int] = {}
    for row in case.conn.execute("SELECT id, notes FROM actions"):
        m = CID_MARK.search(row["notes"] or "")
        if m:
            actions[int(m.group(1))] = row["id"]
    finding_cids: set[int] = set()
    for f in case.findings():
        cid = (f.get("attrs") or {}).get("trudi_call_id")
        if cid is not None:
            finding_cids.add(int(cid))
    return actions, finding_cids


def _finding_attrs(entry: dict) -> dict:
    attrs = {"trudi_call_id": entry.get("call_id"),
             "confidence": entry.get("confidence", ""),
             "source": entry.get("source", "")}
    for k in _CLAIM_FIELDS:
        if entry.get(k) not in (None, "", [], {}):
            attrs[k] = entry[k]
    lineage = entry.get("input_call_ids") or []
    if lineage:
        attrs["lineage"] = lineage
    return attrs


def _mirror_evidence(case: Case, entry: dict, known_labels: set[str]) -> bool:
    """A verify_evidence_hash call is the custody record: one Evidence row."""
    cmd = entry.get("cmd", "")
    parts = cmd.split()
    label = next((p for p in parts[1:] if not p.startswith("-")), "")
    if not label or label in known_labels:
        return False
    sha = _SHA256.search(entry.get("stdout_excerpt", "") or "")
    case.add_evidence(label=label, kind="image",
                      source="TRUDI hash.verify_evidence_hash",
                      sha256=sha.group(0) if sha else "",
                      notes=f"[trudi:cid {entry.get('call_id')}]")
    known_labels.add(label)
    return True


def mirror_trace(trace_path: str, case_path: str, investigator: str = "") -> dict:
    """One idempotent pass; returns counts of rows written this pass."""
    import os
    trace = load_trace(trace_path)
    case = Case(case_path, create=not os.path.exists(case_path),
                actor=investigator, origin_label="TRUDI trace mirror")
    # The .vera mirror is a DERIVED artifact — always rebuildable from the
    # trace, which is the authoritative record. Vera's per-row fsync is the
    # right posture for a live evidence file and the wrong one for bulk
    # mirroring (~0.2s per row on WSL); relax durability on this connection
    # only. A crash mid-pass at worst costs a re-run.
    case.conn.execute("PRAGMA synchronous=OFF")
    counts = {"actions": 0, "findings": 0, "evidence": 0, "leads": 0, "notes": 0}
    try:
        if not case.meta().get("name"):
            case.set_meta(name=trace.get("case_id", ""))
        actions, finding_cids = _existing_cids(case)
        known_evidence = {e["label"] for e in case.evidence()}

        for entry in trace["entries"]:
            etype = entry.get("type")
            cid = entry.get("call_id")

            if etype == "tool_call":
                if cid in actions:
                    continue
                cmd = entry.get("cmd", "") or "<unknown>"
                notes = f"[trudi:cid {cid}]"
                if not entry.get("success", True):
                    stderr = (entry.get("stderr") or "")[:400]
                    notes += f" FAILED. {stderr}".rstrip()
                aid = case.add_action(
                    command=cmd,
                    output=entry.get("stdout_excerpt", "") or "",
                    exit_code=entry.get("exit_code"),
                    performed_at=entry.get("ts", ""),
                    notes=notes)
                actions[cid] = aid
                counts["actions"] += 1
                if "verify_evidence_hash" in cmd:
                    counts["evidence"] += _mirror_evidence(case, entry,
                                                           known_evidence)

            elif etype == "finding":
                if cid in finding_cids:
                    continue
                desc = entry.get("description", "") or "(no description)"
                ftype = "note" if entry.get("claim_kind") == "negative" else \
                    FTYPE_MAP.get(entry.get("category", ""), "note")
                case.add_finding(
                    title=f"[{entry.get('confidence', '?')}] {desc[:120]}",
                    ftype=ftype,
                    action_id=actions.get(entry.get("linked_call_id")),
                    detail=desc,
                    attrs=_finding_attrs(entry),
                    starred=entry.get("confidence") == "CONFIRMED")
                finding_cids.add(cid)
                counts["findings"] += 1

            elif etype == "dair_call":
                if cid in finding_cids:
                    continue
                tools = (entry.get("directives") or {}).get("priority_tools") or []
                if not tools:
                    continue
                phase = entry.get("next_phase") or entry.get("current_phase") or "?"
                lid = case.add_finding(
                    title=f"DAIR work order — {phase}",
                    ftype="lead",
                    detail=entry.get("transition_rationale", "") or "",
                    attrs={"trudi_call_id": cid, "source": "dair_assess"})
                for tool in tools:
                    case.add_lead_item(lid, label=str(tool)[:200])
                finding_cids.add(cid)
                counts["leads"] += 1

            elif etype in _NOTE_TYPES:
                if cid is None or cid in finding_cids:
                    continue
                text = (entry.get("message") or entry.get("description")
                        or entry.get("narration") or "")
                if not text.strip():
                    continue
                case.add_finding(
                    title=f"{_NOTE_TYPES[etype]}: {text[:100]}",
                    ftype="note",
                    detail=text,
                    attrs={"trudi_call_id": cid, "kind": _NOTE_TYPES[etype]})
                finding_cids.add(cid)
                counts["notes"] += 1
    finally:
        case.close()
    return counts


def follow(trace_path: str, case_path: str, investigator: str = "",
           interval: float = 2.0) -> None:  # pragma: no cover - loop shell
    """Tail the trace: re-run the idempotent pass when it grows."""
    last = None
    print(f"following {trace_path} -> {case_path} (^C to stop)")
    while True:
        try:
            trace = load_trace(trace_path)
        except (OSError, ValueError, json.JSONDecodeError):
            time.sleep(interval)
            continue
        marker = (trace.get("entry_count"), len(trace.get("entries", [])))
        if marker != last:
            counts = mirror_trace(trace_path, case_path, investigator)
            written = {k: v for k, v in counts.items() if v}
            if written:
                print(f"mirrored: {written}")
            last = marker
        time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Mirror a TRUDI trace into a .vera case")
    ap.add_argument("trace", help="TRUDI trace JSON (analysis/<CASE>_trace.json)")
    ap.add_argument("case", help=".vera case file (created if missing)")
    ap.add_argument("--investigator", default="",
                    help="actor stamped on mirrored rows")
    ap.add_argument("--follow", action="store_true",
                    help="keep tailing the trace after the initial pass")
    args = ap.parse_args(argv)
    counts = mirror_trace(args.trace, args.case, args.investigator)
    print(f"mirrored {args.trace} -> {args.case}: "
          + ", ".join(f"{v} {k}" for k, v in counts.items()))
    if args.follow:
        follow(args.trace, args.case, args.investigator)
    return 0


if __name__ == "__main__":
    sys.exit(main())
