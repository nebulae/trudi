"""Detection coverage report.

`coverage_report()` walks the trace at end-of-investigation and emits a
checklist of TTPs checked, TTPs found (positive), TTPs deliberately skipped
(in a DAIR recommended_action but never executed), and TTPs that fall under
the case's relevant tactics but were never touched ("gaps").

The point: most autonomous IR agents only report positives. Pairing positive
findings with explicit negative + coverage data gives the hackathon judges
a richer accuracy artifact (Component 6).
"""
from __future__ import annotations
import re
from fastmcp import FastMCP

from core import output_safe

mcp = FastMCP("coverage")

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _extract_tids(text: str) -> set[str]:
    return set(_TID_RE.findall(text or ""))


def _format_markdown(checked, found, skipped, gaps, summary) -> str:
    def _bullet(tids):
        if not tids:
            return "  - _(none)_"
        return "\n".join(f"  - `{t}`" for t in sorted(tids))

    lines = [
        "# Detection Coverage Report",
        "",
        f"**Summary:** {summary}",
        "",
        f"## Checked ({len(checked)})",
        "TTPs that appeared in at least one finding (any tier).",
        _bullet(checked),
        "",
        f"## Found ({len(found)})",
        "TTPs in CONFIRMED or LIKELY findings.",
        _bullet(found),
        "",
        f"## Deliberately skipped ({len(skipped)})",
        "TTPs surfaced in a DAIR `recommended_actions` but never produced "
        "a downstream tool_call. Document the rationale for each.",
        _bullet(skipped),
        "",
        f"## Untouched gaps ({len(gaps)})",
        "TTPs in the MITRE table matching case-relevant tactics but never "
        "checked. Consider sweeping these in a follow-up Scan phase.",
        _bullet(sorted(gaps)[:40]) + ("\n  - …" if len(gaps) > 40 else ""),
    ]
    return "\n".join(lines) + "\n"


@mcp.tool()
@output_safe
def coverage_report(relevant_tactics: str = "") -> dict:
    """
    Emit a TTP coverage checklist over the current trace.

    relevant_tactics: optional comma-separated tactic names to scope the "gaps"
        calculation. If omitted, all tactics in the MITRE table are considered.
        Examples: "Credential Access, Lateral Movement, Persistence".

    Returns: {success, checked, found, skipped, gaps, summary, markdown,
              _trudi_call_id}.
    """
    from core.execution_log import log
    from tools.mitre import load_techniques

    idx = log.index()
    findings = idx.by_type.get("finding", [])
    dair_calls = idx.by_type.get("dair_call", [])
    tool_calls = idx.by_type.get("tool_call", [])

    # Checked: any T-ID appearing in any finding's description.
    checked: set[str] = set()
    found: set[str] = set()
    for f in findings:
        tids = _extract_tids(f.get("description", ""))
        checked.update(tids)
        if (f.get("confidence") or "").upper() in {"CONFIRMED", "LIKELY"}:
            found.update(tids)

    # Skipped: T-IDs recommended by DAIR but never executed as a tool_call.
    # Heuristic: a tool name in recommended_actions that maps to no tool_call
    # AFTER the dair_call that suggested it. T-IDs cited in recommended_actions
    # text count as "skipped" if never appearing in any subsequent finding.
    skipped: set[str] = set()
    seen_after: dict[str, int] = {}  # tid → call_id at which it first appears in checked
    for f in findings:
        cid = int(f.get("call_id") or 0)
        for tid in _extract_tids(f.get("description", "")):
            if tid not in seen_after or cid < seen_after[tid]:
                seen_after[tid] = cid

    for d in dair_calls:
        d_cid = int(d.get("call_id") or 0)
        rec_actions = d.get("recommended_actions") or []
        text_blob = " ".join(str(a) for a in rec_actions)
        for tid in _extract_tids(text_blob):
            # Skipped iff: T-ID was recommended here but never appears in any
            # later checked entry.
            if tid not in seen_after or seen_after[tid] < d_cid:
                skipped.add(tid)

    # Gaps: T-IDs in MITRE table matching relevant tactics but never checked.
    techniques = (load_techniques().get("techniques") or {})
    if relevant_tactics:
        rt = {t.strip().lower() for t in relevant_tactics.split(",") if t.strip()}
        in_scope = {
            tid for tid, info in techniques.items()
            if any(t.lower() in (info.get("tactic") or "").lower() for t in rt)
        }
    else:
        in_scope = set(techniques.keys())

    gaps = in_scope - checked

    summary = (
        f"{len(checked)} TTPs checked, {len(found)} found ({len(checked) - len(found)} "
        f"checked but uncorroborated), {len(skipped)} skipped, {len(gaps)} untouched "
        f"in scope ({len(techniques)} techniques in table)."
    )

    markdown = _format_markdown(
        sorted(checked), sorted(found), sorted(skipped), gaps, summary
    )

    return {
        "success": True,
        "checked": sorted(checked),
        "found": sorted(found),
        "skipped": sorted(skipped),
        "gaps": sorted(gaps),
        "summary": summary,
        "markdown": markdown,
        "scope_techniques": len(in_scope),
        "table_size": len(techniques),
    }
