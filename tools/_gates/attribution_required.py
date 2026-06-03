"""Gate: findings naming a threat-actor group (G\\d{4}, APT\\d+) require a
backing attribute_actors call in the trace window with that group at the
requested confidence band or higher.

Forces the attribution claim to flow through the pipeline rather than being
asserted from intuition. Mirrors the mitre_technique_validation gate's
philosophy: if you cite a specific entity, the entity must have been
validated by an MCP tool.
"""
import re
from typing import Optional

# Match G0001-G9999 or "APT" + 1-3 digits or "FIN" + digits / common alias forms.
_ACTOR_RE = re.compile(
    r"\b(?:G\d{4}|APT\s*\d{1,3}|FIN\s*\d{1,3})\b",
    re.IGNORECASE,
)

# Band ranking — same direction as tier rank (higher = stronger claim).
_BAND_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INSUFFICIENT": 0}


def check(ctx) -> Optional[dict]:
    description = ctx.description or ""
    matches = _ACTOR_RE.findall(description)
    if not matches:
        return None
    # Only enforce for CONFIRMED/LIKELY findings — UNCONFIRMED actor
    # mentions in narrative findings are acceptable as hypotheses.
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None

    # Look for a recent attribute_actors call. Reach into the trace via
    # ctx.idx since attribution doesn't fit the reason_call type.
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
                f"Finding cites a threat actor ({', '.join(set(matches))}) but no "
                f"attribute_actors call appears in the last 30 trace entries. "
                f"Call attribution.attribute_actors() and ensure the named group "
                f"appears in the top candidates at MEDIUM or HIGH confidence "
                f"before recording an attribution finding."
            ),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "attribution_required",
            "actor_tokens": sorted(set(matches)),
        }
    return None
