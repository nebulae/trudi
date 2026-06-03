"""Gate: refuse negative findings whose linked tool result is truncated.

CLAUDE.md global rule (Directive Binding → "Truncated output follow-up"):
when a tool result has `truncated: true`, treat it as INCOMPLETE — re-run
with a narrower pattern before recording a negative finding. Recording an
UNCONFIRMED ("absent" / "no match") finding whose only evidence is a
truncated scan is the most common failure mode of that rule, observed in
NITROBA-2008 where a 56MB pcap roster sweep was truncated by ngrep's
progress markers and the resulting "no roster match" finding masked the
true CONFIRMED-tier attribution.

This gate makes the rule a hard refusal. It fires only when:
  - tier is UNCONFIRMED (the finding is asserting absence)
  - linked_call_id points at a real tool_call entry
  - that entry has truncated: true

Higher-tier findings (CONFIRMED / LIKELY / SUSPECTED) that cite a truncated
result are tolerated — truncation can hide additional matches but rarely
invalidates a positive observation already present in the visible output.
"""
from typing import Optional


def check(ctx) -> Optional[dict]:
    if ctx.tier != "UNCONFIRMED":
        return None
    if ctx.linked_call_id == 0:
        return None
    entry = ctx.idx.by_call_id.get(ctx.linked_call_id)
    if entry is None:
        return None
    if not entry.get("truncated"):
        return None
    cmd_excerpt = (entry.get("cmd") or entry.get("tool") or "<unknown>")[:120]
    return {
        "success": False,
        "error": (
            f"Refusing UNCONFIRMED finding: linked_call_id={ctx.linked_call_id} "
            f"({cmd_excerpt!s}) returned truncated output. "
            f"Per CLAUDE.md truncated-output rule, re-run with a narrower pattern "
            f"(or use a parallel channel such as `grep -a` on the raw file) and "
            f"link this finding to a non-truncated call before recording the "
            f"negative result."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "negative_from_truncated",
    }
