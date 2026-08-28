"""Gate: any ATT&CK T-ID in the description must validate against the local table.

Auto-validates `T\\d{4}(\\.\\d{3})?` patterns via correlate.mitre_validate.
Unknown T-IDs are an automatic CHALLENGED trigger and refused here so a
fabricated technique can never reach the trace.
"""
import re
import sys
from typing import Optional

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Enterprise ATT&CK carries ~200 techniques + ~430 sub-techniques; a table
# smaller than this is incomplete and cannot ground a hard refusal.
MITRE_MIN_TECHNIQUES = 600


def check(ctx) -> Optional[dict]:
    claim = getattr(ctx, "claim", None) or {}
    declared = [str(t).strip().upper() for t in (claim.get("techniques") or []) if str(t).strip()]
    bad_shape = [t for t in declared if not _TID_RE.fullmatch(t)]
    if bad_shape:
        return {
            "success": False,
            "error": (f"techniques must be ATT&CK ids (T1234 / T1234.001): "
                      f"{', '.join(bad_shape)}"),
            "description": ctx.description,
            "confidence": ctx.confidence,
            "gate": "mitre_technique_validation",
            "unknown_technique_ids": bad_shape,
        }
    # The regex over the description is a VALIDATOR of a structured token space
    # (T-ids), not a classifier: any id mentioned must exist, declared or not.
    technique_ids = sorted(set(_TID_RE.findall(ctx.description or "")) | set(declared))
    if not technique_ids:
        return None

    try:
        from tools.correlate import mitre_validate as _mitre_validate
    except Exception as e:
        print(f"[TRUDI WARN] correlate.mitre_validate unavailable: {e}", file=sys.stderr)
        return None  # graceful-degrade: don't refuse if MITRE module is broken

    unknown: list[str] = []
    table_size = None
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
            if v.get("available_count") is not None:
                table_size = int(v.get("available_count") or 0)

    if not unknown:
        return None
    # An incomplete local table must not refuse a well-formed id: the shipped
    # cache rejected T1027 (a current technique) because the build filter had
    # dropped it. Below MITRE_MIN_TECHNIQUES the unknown ids are recorded as
    # UNVALIDATED (table_incomplete) on the finding and the record proceeds.
    if table_size is not None and table_size < MITRE_MIN_TECHNIQUES:
        for tid in unknown:
            ctx.validated_techniques.append({
                "technique_id": tid, "name": "", "tactic": "",
                "unvalidated": True, "reason": "table_incomplete",
                "table_size": table_size,
            })
        print(f"[TRUDI WARN] mitre table has {table_size} techniques "
              f"(< {MITRE_MIN_TECHNIQUES}); {', '.join(unknown)} recorded unvalidated — "
              f"rebuild with `python -m tools.mitre.build_mitre_cache`", file=sys.stderr)
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
