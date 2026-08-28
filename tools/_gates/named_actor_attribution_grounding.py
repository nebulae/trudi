"""Gate: a CONFIRMED/LIKELY finding that attributes a CORE ACT (egress /
delivery / possession / execution / account creation / persistence install /
destruction / lateral movement / credential access / c2) to a HUMAN actor —
without binding an account (that is the sibling gate) — must be grounded in a
logon / session artifact.

Trigger (typed claim, never wording):
  tier ∈ {CONFIRMED, LIKELY}
  AND claim.actor_kind == "human" AND no claim.principal
  AND claim.act ∈ CORE_ACTS.

Naming a person directly does not establish that they — and not a second
principal operating the same host — performed the act.

No name grammar, no stop-list: who the actor is comes from claim.actor.
"""
from typing import Optional

from ._claims import CORE_ACTS, FIELD_HELP
from ._session import session_bound

def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    claim = getattr(ctx, "claim", None) or {}
    if claim.get("actor_kind") != "human" or claim.get("principal"):
        return None
    if claim.get("act") not in CORE_ACTS:
        return None
    bound, _how = session_bound(ctx)
    if bound:
        return None
    who = claim.get("actor") or "the named person"
    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding attributes the act {claim.get('act')!r} to a human "
            f"({who}) but cites no logon/RDP session artifact. Naming a person does "
            f"not establish that they — and not a second principal operating the same "
            f"host — performed the act. Pull the logon-session binding (Security "
            f"4624/4625 logon type + source address, or RDP 4778/4779 — ez.evtxecmd / "
            f"misc.evtx_filter) placing this person at the host during the act and "
            f"pass {FIELD_HELP['session_binding_call_ids']}, or downgrade to SUSPECTED."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "named_actor_attribution_grounding",
        "missing": ["session_binding_call_ids"],
    }
