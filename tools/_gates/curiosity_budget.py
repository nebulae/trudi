"""Gate: bound exploratory 'curiosity_probe' entries to the per-dair_assess
allowance, and require each probe to declare a rationale.

WHY THIS EXISTS
---------------
TRUDI's loop is engineered to converge ("Never run tools outside
directives.priority_tools"). That removes the analyst's ability to act on a
hunch — to go look at a less-obvious artifact nobody put on the work order.
A curiosity_probe is the sanctioned address for that act: a read-only,
agent-chosen look, logged with its rationale.

The budget is GRANTED by dair_assess via directives.curiosity_budget and
refreshed on each dair_assess, so the spend is scoped to probes recorded AFTER
the most recent dair_call in the full trace. 0 (or no dair_call) ⇒ no exploration,
i.e. exactly today's behavior — clean rollback / A-B for the accuracy report.

WHY IT CANNOT REGRESS FABRICATION SAFETY
----------------------------------------
This gate governs the BUDGET only, never evidentiary weight. A probe is a
logged intention; any resulting *claim* must cite the actual forensic output
call IDs, where the full finding gate stack applies.
No existing gate is loosened; this is purely additive.

NOTE ON WIRING
--------------
Unlike the record_finding gates, this one is NOT registered in _gates/__init__:GATES
(those run on findings). It guards `misc.record_curiosity_probe`, which calls
`check()` directly. Keeping it out of run_gates means a probe never pays for the
15 finding-specific gate lookups, and a finding never pays for this one.
"""
from typing import Optional


def _latest_dair_budget(window: list[dict]) -> tuple[int, int]:
    """Return (budget_granted, dair_cid) from the most recent dair_call in the
    window, or (0, 0) when none is present."""
    for e in reversed(window):
        if e.get("type") == "dair_call":
            directives = e.get("directives") or {}
            try:
                budget = int(directives.get("curiosity_budget", 0) or 0)
            except (TypeError, ValueError):
                budget = 0
            return budget, int(e.get("call_id", 0) or 0)
    return 0, 0


def status(entries: list[dict]) -> dict:
    """Project the current grant from durable history, independent of chatter."""
    budget, cid = _latest_dair_budget(entries)
    spent = sum(e.get('type') == 'curiosity_probe' and
                int(e.get('call_id', 0) or 0) > cid for e in entries)
    return {'grant_call_id': cid, 'granted': max(0, budget), 'spent': spent,
            'remaining': max(0, budget - spent)}


def check(window: list[dict], rationale: str) -> Optional[dict]:
    """Return None to allow the probe, or a refusal dict carrying gate:
    'curiosity_budget'. `window` must contain the full durable trace;
    `rationale` is the agent-supplied probe rationale.
    """
    if not (rationale or "").strip():
        return {
            "success": False,
            "gate": "curiosity_budget",
            "error": (
                "A curiosity_probe must declare a rationale — the hunch and what "
                "would confirm or kill it. This is the audit hook that separates a "
                "directed probe from an undirected read; without it the probe is "
                "indistinguishable from noise in the trace."
            ),
        }

    budget, dair_cid = _latest_dair_budget(window)
    if budget <= 0:
        return {
            "success": False,
            "gate": "curiosity_budget",
            "error": (
                "No curiosity budget granted by the active dair_assess "
                "(directives.curiosity_budget is 0 or no grant exists). "
                "Run priority_tools first; call dair_assess to receive an exploratory "
                "allowance, then spend it on agent-chosen probes."
            ),
        }

    spent = sum(
        1 for e in window
        if e.get("type") == "curiosity_probe"
        and int(e.get("call_id", 0) or 0) > dair_cid
    )
    if spent >= budget:
        return {
            "success": False,
            "gate": "curiosity_budget",
            "error": (
                f"Curiosity budget for this batch ({budget}) is exhausted "
                f"({spent} probe(s) since dair_assess #{dair_cid}). Summarize the "
                "probes' results to dair_assess — it refreshes the allowance or "
                "advances the phase. Any resulting finding must cite the actual "
                "forensic output call IDs; the probe entry is only intent metadata."
            ),
        }
    return None
