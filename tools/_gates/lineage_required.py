"""Gate: input_call_ids must be supplied (after genesis grace) and contain only
real, existing trace call_ids.

This turns the trace into a self-describing causal DAG. Every finding /
self_correction / reason call / dair_assess says explicitly which prior entries
informed it — the chain view (and any future audit consumer) gets real foreign
keys instead of substring heuristics.

Genesis grace: the very first ~5 trace entries are allowed to have empty
input_call_ids so the agent can bootstrap (pre-plan reads → reason.plan →
first dair_assess) without a chicken-and-egg loop.
"""
from typing import Optional

_GENESIS_GRACE_THRESHOLD = 5


def check(ctx) -> Optional[dict]:
    cids = list(ctx.input_call_ids or [])
    # 1) Empty: only allowed in the genesis window.
    if not cids:
        if len(ctx.log._entries) < _GENESIS_GRACE_THRESHOLD:
            return None
        return {
            "success": False,
            "error": (
                "input_call_ids is required — list the _trudi_call_id values "
                "of the entries that informed this call. This turns the trace "
                "into an explicit causal DAG so the chain view and audit "
                "consumers can traverse real foreign keys instead of inferring "
                f"links from substrings. Genesis grace expires after the "
                f"{_GENESIS_GRACE_THRESHOLD}th entry; this trace already has "
                f"{len(ctx.log._entries)} entries."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "lineage_required",
        }
    # 2) Validate every cid actually exists in the trace.
    known = ctx.idx.by_call_id if hasattr(ctx.idx, "by_call_id") \
        else {e.get("call_id") for e in ctx.log._entries}
    try:
        known_set = set(known.keys()) if isinstance(known, dict) else set(known)
    except AttributeError:
        known_set = set()
    unknown = [c for c in cids if c not in known_set]
    if unknown:
        return {
            "success": False,
            "error": (
                f"input_call_ids contains call_ids not present in the trace: "
                f"{unknown}. Use the _trudi_call_id from real recorded tool/reason "
                f"results — fabricated or out-of-order ids break the audit chain."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "lineage_required",
            "unknown_cids": unknown,
        }
    return None
