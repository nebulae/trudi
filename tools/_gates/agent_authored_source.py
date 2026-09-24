"""Gate: a finding may not rest on an AGENT-AUTHORED file.

After a CHALLENGED verdict, an agent once wrote "verbatim excerpts" of
evidence into an exports/ file with the raw Write tool, read it back with
`read.output`, and earned a CONFIRMED on its own file. Whether or not
the copy was faithful, a reviewer cannot tell it from extractor output, and
nothing prevents a curated line.

Refuses (any tier) when `linked_call_id`, `transfer_call_ids`,
`receipt_call_ids`, `session_binding_call_ids` or `input_call_ids` point at a
Write/Edit entry or at a read.* over a path an agent-authored entry created —
or when the SUPPORTED evaluate this finding relies on fetched rows from one.
Remedy: cite the extractor / read.* call over the TOOL-produced output (the
mailbox export, the CSV) and re-request rows from it.
"""
from __future__ import annotations

from typing import Optional

from ._evidence_calls import agent_authored_paths, authored_source_of


def _cited(ctx) -> list[int]:
    c = getattr(ctx, "claim", None) or {}
    out: list[int] = []
    for v in (getattr(ctx, "linked_call_id", 0), *(getattr(ctx, "input_call_ids", None) or []),
              *(c.get("transfer_call_ids") or []), *(c.get("receipt_call_ids") or []),
              *(c.get("session_binding_call_ids") or [])):
        try:
            iv = int(v)
        except (TypeError, ValueError):
            continue
        if iv and iv not in out:
            out.append(iv)
    return out


def check(ctx) -> Optional[dict]:
    idx = getattr(ctx, "idx", None)
    by_id = getattr(idx, "by_call_id", None) or {}
    calls = (getattr(idx, "by_type", {}) or {}).get("tool_call") or []
    authored = agent_authored_paths(calls)
    if not authored:
        return None
    tainted: list[tuple[int, str]] = []
    for cid in _cited(ctx):
        e = by_id.get(cid) or {}
        p = authored_source_of(e, authored)
        if p:
            tainted.append((cid, p))
    # Rows the matched SUPPORTED evaluate fetched from an authored file taint
    # the verdict too (the evaluate is matched later in the chain, so look at
    # every evaluate the finding cites).
    for cid in _cited(ctx):
        e = by_id.get(cid) or {}
        if e.get("type") == "reason_call" and e.get("tool") == "reason_evaluate_finding":
            for r in e.get("evidence_requests") or []:
                fe = by_id.get(int(r.get("call_id") or 0)) or {}
                p = authored_source_of(fe, authored)
                if p and int(r.get("rows_returned") or 0):
                    tainted.append((int(r.get("call_id") or 0), p))
    if not tainted:
        return None
    shown = "; ".join(f"call {c} → {p}" for c, p in tainted[:4])
    return {
        "success": False,
        "error": (
            f"Refused: this finding rests on an AGENT-AUTHORED file, which is not "
            f"evidence ({shown}). A file written with the Write/Edit tool or a bash "
            f"redirect — even a verbatim excerpt — cannot ground a finding or a "
            f"reviewer verdict. Cite the tool that produced the original output "
            f"(the mailbox export / CSV read via read.*) and re-request rows from it."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "agent_authored_source",
        "tainted_call_ids": [c for c, _ in tainted],
    }
