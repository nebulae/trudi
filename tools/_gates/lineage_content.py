"""Warn-early check: a cited call_id should actually CONTAIN the literal artifact
values the finding quotes — not merely exist.

`lineage_required` verifies that every input_call_id / linked_call_id is a real
trace entry, but not that the entry produced the quoted content. A finding can
therefore cite a call_id transcribed from memory of the batch order rather than
read back from the trace, and the mis-citation passes silently — the finding
looks grounded but points at the wrong evidence.

This surfaces that: if a finding quotes concrete artifact VALUES (hashes, IPv4
addresses, registry keys, absolute paths — the unambiguous, verifiable kind)
and NONE of them appears in the evidence text of any cited entry
(supporting_evidence + the cmd/stdout_excerpt of linked_call_id / input_call_ids),
the citation probably does not support the claim.

Non-blocking by design: the trace's stdout_excerpt is capped, so a value may be
in the full tool output but absent from the excerpt — blocking on that would
produce false refusals. It is emitted as `lineage_content_note` on the finding's
success path (like atomicity / fk_corroboration), for the agent and a Report-time
audit to act on. Deterministic; fail-open at the call site.
"""
from typing import Optional

from ._match import lineage_evidence_text
from ._citation import extract_claims


def lineage_content_note(ctx) -> Optional[str]:
    claims = extract_claims(ctx.description or "")
    if not claims:
        return None  # no verifiable literal to check
    evidence = (lineage_evidence_text(ctx) or "").lower()
    if not evidence.strip():
        return None  # no cited evidence text available (checked elsewhere)
    values = [v for _kind, v in claims]
    matched = [v for v in values if v.lower() in evidence]
    if matched:
        return None  # at least one quoted value is present in cited evidence
    shown = ", ".join(values[:4]) + ("…" if len(values) > 4 else "")
    return (
        f"none of the concrete artifact values this finding quotes ({shown}) "
        f"appears in the evidence of its cited call_ids (linked_call_id / "
        f"input_call_ids / supporting_evidence). The citation may point at the "
        f"wrong tool call — verify the call_id was read back from the trace, "
        f"not transcribed from memory (note: excerpts are capped, so this can "
        f"be a false alarm if the value is only in the full, untruncated output)."
    )
