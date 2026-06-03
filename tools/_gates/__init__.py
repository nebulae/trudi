"""Server-enforced gates on record_finding.

Each gate is a callable that takes a GateContext and returns either None
(pass) or a refusal dict carrying a stable `gate:` field. The public
`record_finding` in tools/misc.py iterates GATES in order; the first
failure short-circuits and returns.

To add a new gate:
  1. Create tools/_gates/<your_gate>.py exposing `check(ctx) -> Optional[dict]`.
  2. Import and append to GATES below (mind ordering — earlier gates run first).
  3. Add a row to tools/misc.py:record_finding's docstring table.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional, Any

from . import (
    mcp_routing,
    dair_required,
    confirmed_requires_linked_call_id,
    linked_call_id_must_exist,
    mitre_technique_validation,
    confirmed_requires_supported_evaluate,
    confidence_and_citation,
    hypothesize_required,
    attribution_required,
    lineage_required,
    negative_from_truncated,
)


@dataclass
class GateContext:
    """All inputs a gate may need. Built once per record_finding call so each
    gate has the same view of the trace and the same precomputed window/index."""
    description: str
    confidence: str          # raw input (case as supplied)
    tier: str                # uppercased confidence ("CONFIRMED", "LIKELY", ...)
    source: str
    linked_call_id: int
    tested_hypothesis_id: str
    log: Any                 # core.execution_log.ExecutionLog
    idx: Any                 # core.execution_log.LogIndex
    window: list[dict]       # last 30 entries

    # Agent-declared upstream lineage — list of _trudi_call_id values for the
    # entries that informed this record_*. The lineage_required gate enforces
    # this is non-empty (after genesis grace) and that every cid actually
    # exists in the trace.
    input_call_ids: list[int] = None  # type: ignore[assignment]

    # Out-band data populated by gates so the success path can carry it. The
    # mitre_technique_validation gate appends to validated_techniques when a
    # T-ID resolves successfully; record_finding propagates this to the result.
    validated_techniques: list[dict] = None  # type: ignore[assignment]

    # Explicit gate-match foreign keys. Set by the gates that find their
    # matching reason_call entry. record_finding stamps these onto the
    # finding entry so downstream consumers (chain view, accuracy report,
    # synthesize) have direct call_id references rather than substring guesses.
    gated_by_evaluate_call_id: int = 0
    gated_by_confidence_call_id: int = 0
    gated_by_cite_check_call_id: int = 0
    gated_by_hypothesize_call_id: int = 0

    def __post_init__(self):
        if self.validated_techniques is None:
            self.validated_techniques = []
        if self.input_call_ids is None:
            self.input_call_ids = []


GateFn = Callable[[GateContext], Optional[dict]]

# Ordering is load-bearing — mcp_routing must run first so its specific message
# wins over the generic dair_required refusal. Tier-specific gates come last so
# infrastructure problems (DAIR not started, invalid linked_call_id) refuse before
# we burn cycles on adversarial-review lookups.
GATES: list[tuple[str, GateFn]] = [
    ("mcp_routing", mcp_routing.check),
    ("dair_required", dair_required.check),
    ("lineage_required", lineage_required.check),
    ("confirmed_requires_linked_call_id", confirmed_requires_linked_call_id.check),
    ("linked_call_id_must_exist", linked_call_id_must_exist.check),
    ("negative_from_truncated", negative_from_truncated.check),
    ("mitre_technique_validation", mitre_technique_validation.check),
    ("confirmed_requires_supported_evaluate", confirmed_requires_supported_evaluate.check),
    ("confidence_and_citation", confidence_and_citation.check),
    ("hypothesize_required", hypothesize_required.check),
    ("attribution_required", attribution_required.check),
]


def run_gates(ctx: GateContext) -> Optional[dict]:
    """Run each gate in order. Return the first refusal dict, or None on pass."""
    for _, gate_fn in GATES:
        failure = gate_fn(ctx)
        if failure is not None:
            return failure
    return None
