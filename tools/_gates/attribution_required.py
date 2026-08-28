"""Gate: a CONFIRMED/LIKELY finding that names a threat-actor group must
declare it (claim.threat_actor) and have a backing attribute_actors call in the
trace window.

The G\\d{4} / APT\\d+ / FIN\\d+ regex is kept as a VALIDATOR over a structured
token space: a group id in the prose without claim.threat_actor is refused
naming the field (declare it, don't hide it); the declared field is what
engages the attribute_actors requirement.
"""
import re
from typing import Optional

from ._claims import FIELD_HELP

_ACTOR_RE = re.compile(r"\b(?:G\d{4}|APT\s*\d{1,3}|FIN\s*\d{1,3})\b", re.IGNORECASE)


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    claim = getattr(ctx, "claim", None) or {}
    declared = str(claim.get("threat_actor") or "").strip()
    in_prose = sorted(set(_ACTOR_RE.findall(ctx.description or "")))
    if not declared and not in_prose:
        return None
    if not declared:
        return {
            "success": False,
            "error": (
                f"Finding names a threat actor ({', '.join(in_prose)}) without declaring "
                f"it — pass {FIELD_HELP['threat_actor']}. The declared field, not the "
                f"wording, engages the attribution requirement."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "attribution_required",
            "missing": ["threat_actor"],
            "actor_tokens": in_prose,
        }
    recent_attribution = None
    for e in reversed(ctx.window):
        if e.get("type") != "tool_call":
            continue
        cmd = (e.get("cmd") or "")
        if "attribute_actors" in cmd or "attribution" in cmd.lower():
            recent_attribution = e
            break
    if recent_attribution is None:
        return {
            "success": False,
            "error": (
                f"Finding attributes to threat actor {declared!r} but no attribute_actors "
                f"call appears in the last 30 trace entries. Call "
                f"attribution.attribute_actors() and ensure the named group appears in "
                f"the top candidates at MEDIUM or HIGH confidence before recording."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "attribution_required",
            "actor_tokens": [declared],
        }
    return None
