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

from . import (mcp_routing, agent_authored_source, dair_required, lineage_required, contracts,
               refusal_rewording, tier_contract)


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

    # Inline supporting evidence. When non-empty, confidence_and_citation runs a
    # DETERMINISTIC citation check on it (tools/_gates/_citation.py) instead of
    # requiring separate reason.confidence_score + reason.cite_check model
    # round-trips. Empty ⇒ legacy path. Set by record_finding.
    supporting_evidence: str = ""
    # Stamped "deterministic" by confidence_and_citation when the fast path is
    # taken, so record_finding can mark the finding's citation provenance.
    citation_mode: str = ""

    # Typed claim declared by the agent: {kind, category, entities, channel,
    # window}. Gates key on this declared structure FIRST (the typed_claims
    # checker enforces its presence for CONFIRMED/LIKELY and classified
    # negatives); description regexes remain only as fallback for legacy
    # findings.
    claim: dict = None  # type: ignore[assignment]

    # Deterministic tier contract (tier_contract gate, data/fk/tiering.yaml):
    # the highest tier the cited artifact classes reach, the classes found
    # ({class: [cids]}) and the rule key (e.g. "egress/ftp"). Stamped on the
    # finding entry by record_finding.
    tier_achievable: str = ""
    artifact_classes: dict = None  # type: ignore[assignment]
    tier_rule: str = ""

    def __post_init__(self):
        if self.artifact_classes is None:
            self.artifact_classes = {}
        if self.validated_techniques is None:
            self.validated_techniques = []
        if self.input_call_ids is None:
            self.input_call_ids = []
        if self.claim is None:
            self.claim = {}


GateFn = Callable[[GateContext], Optional[dict]]

# Ordering is load-bearing. Infrastructure refusals run first; broad evidence
# contracts then run from cheapest/most universal to most claim-specific.
GATES: list[tuple[str, GateFn]] = [
    ("mcp_routing", mcp_routing.check),
    # Uncitable-source refusals next to mcp_routing: a finding resting on a
    # file the agent wrote (Write/Edit/bash redirect) is not evidence.
    ("agent_authored_source", agent_authored_source.check),
    ("dair_required", dair_required.check),
    ("lineage_required", lineage_required.check),
    # Anti-loop: a re-record of a refused finding with only the wording changed
    # (refusal ledger in core/execution_log.record_finding_refused). After the
    # structural gates so a lineageless attempt gets the clearer message first.
    ("refusal_rewording", refusal_rewording.check),
    ("evidence_strength", contracts.evidence_strength),
    # The tier is arithmetic over the cited artifact classes:
    # once the claim is typed and fact-checked, refuse a tier the evidence
    # cannot reach, naming the classes and tools that would reach it.
    ("tier_contract", tier_contract.check),
    ("completeness", contracts.completeness),
    ("attribution", contracts.attribution),
    ("transfer", contracts.transfer),
]


def run_gates(ctx: GateContext) -> Optional[dict]:
    """Run each gate in order. Return the first refusal dict, or None on pass."""
    for _, gate_fn in GATES:
        failure = gate_fn(ctx)
        if failure is not None:
            return failure
    return None
