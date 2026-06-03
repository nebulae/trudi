"""Gate: any ATT&CK T-ID in the description must validate against the local table.

Auto-validates `T\\d{4}(\\.\\d{3})?` patterns via correlate.mitre_validate.
Unknown T-IDs are an automatic CHALLENGED trigger and refused here so a
fabricated technique can never reach the trace.
"""
import re
import sys
from typing import Optional

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def check(ctx) -> Optional[dict]:
    technique_ids = sorted(set(_TID_RE.findall(ctx.description or "")))
    if not technique_ids:
        return None

    try:
        from tools.correlate import mitre_validate as _mitre_validate
    except Exception as e:
        print(f"[TRUDI WARN] correlate.mitre_validate unavailable: {e}", file=sys.stderr)
        return None  # graceful-degrade: don't refuse if MITRE module is broken

    unknown: list[str] = []
    for tid in technique_ids:
        v = _mitre_validate(tid)
        if v.get("exists"):
            ctx.validated_techniques.append({
                "technique_id": tid,
                "name": v.get("name", ""),
                "tactic": v.get("tactic", ""),
            })
        else:
            unknown.append(tid)

    if not unknown:
        return None
    return {
        "success": False,
        "error": (
            f"Unknown ATT&CK technique ID(s) in finding: {', '.join(unknown)}. "
            "Validate with correlate.mitre_map (to find candidates) and "
            "correlate.mitre_validate (to confirm existence) before citing. "
            "Unverified technique IDs are an automatic CHALLENGED trigger."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "mitre_technique_validation",
        "unknown_technique_ids": unknown,
    }
