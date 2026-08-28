"""Gate: a CONFIRMED/LIKELY finding that binds an *account / identity* to a
*human* must be grounded in an authentication or session artifact — not
asserted from assumption.

Trigger (typed claim, never wording):
  tier ∈ {CONFIRMED, LIKELY}
  AND claim.principal is declared (the account/identity being bound)
  AND claim.actor_kind == "human" (it is bound to a person).

Pass (tools/_gates/_session.py): claim.session_binding_call_ids name trace
entries carrying the server-stamped session_artifact marker (or, weaker, a
logon-enumeration COMMAND), or — legacy validator — a session marker appears in
the cited evidence text.

Only CONFIRMED/LIKELY are gated — SUSPECTED/UNCONFIRMED account→actor
hypotheses are acceptable as open propositions.
"""
from typing import Optional

from ._claims import FIELD_HELP
from ._session import session_bound



def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    claim = getattr(ctx, "claim", None) or {}
    if not (claim.get("principal") and claim.get("actor_kind") == "human"):
        return None
    bound, _how = session_bound(ctx)
    if bound:
        return None
    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding binds principal {claim.get('principal')!r} to a human "
            f"({claim.get('actor') or 'unnamed'}) but cites no authentication/session "
            f"artifact. Attributing an account's actions to a person requires a "
            f"logon-session binding — Security 4624/4625 with logon type and source "
            f"address (ez.evtxecmd / misc.evtx_filter), RDP 4778/4779, an SSH/SMB "
            f"session, or a PCAP identity timeline. Pull it and pass "
            f"{FIELD_HELP['session_binding_call_ids']}, or downgrade to SUSPECTED."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "principal_attribution_grounding",
        "missing": ["session_binding_call_ids"],
    }
