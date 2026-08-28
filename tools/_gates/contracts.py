"""Broad evidence-contract gates for record_finding.

This module collapses the public gate stack into a few predictable contracts
while reusing the focused checkers internally. The narrow modules remain useful
as implementation details and for direct unit coverage, but record_finding now
reports broad failure classes:

  - evidence_strength
  - completeness
  - attribution
  - transfer
"""
from __future__ import annotations

from typing import Optional

from . import (
    confirmed_requires_linked_call_id,
    linked_call_id_must_exist,
    mitre_technique_validation,
    confirmed_requires_supported_evaluate,
    confidence_and_citation,
    hypothesize_required,
    negative_from_truncated,
    negative_completeness,
    principal_attribution_grounding,
    named_actor_attribution_grounding,
    interactive_injection_grounding,
    exfil_channel_grounding,
    offhost_delivery_grounding,
    attribution_required,
    typed_claims,
    challenge_sticky,
)


def _as_contract(failure: dict | None, gate: str) -> Optional[dict]:
    if failure is None:
        return None
    original = failure.get("gate")
    out = {**failure, "gate": gate}
    if original and original != gate:
        out["detail_gate"] = original
    return out


def evidence_strength(ctx) -> Optional[dict]:
    """Confidence tier, linked evidence, ATT&CK IDs, review, and citations."""
    for check in (
        typed_claims.check,
        confirmed_requires_linked_call_id.check,
        linked_call_id_must_exist.check,
        mitre_technique_validation.check,
        confirmed_requires_supported_evaluate.check,
        challenge_sticky.check,
        confidence_and_citation.check,
        hypothesize_required.check,
    ):
        failure = check(ctx)
        if failure is not None:
            return _as_contract(failure, "evidence_strength")
    return None


def completeness(ctx) -> Optional[dict]:
    """Absence/unknown claims require complete enough searched scope."""
    for check in (
        negative_from_truncated.check,
        negative_completeness.check,
    ):
        failure = check(ctx)
        if failure is not None:
            return _as_contract(failure, "completeness")
    return None


def attribution(ctx) -> Optional[dict]:
    """Human/account/device/threat-actor attribution requires control evidence."""
    for check in (
        principal_attribution_grounding.check,
        named_actor_attribution_grounding.check,
        interactive_injection_grounding.check,
        attribution_required.check,
    ):
        failure = check(ctx)
        if failure is not None:
            return _as_contract(failure, "attribution")
    return None


def transfer(ctx) -> Optional[dict]:
    """Data-movement claims: on-host egress over a named channel requires a
    transfer artifact; an off-host delivery/receipt/possession claim requires a
    destination-side receipt artifact (a host image cannot prove far-end state)."""
    for check in (
        exfil_channel_grounding.check,
        offhost_delivery_grounding.check,
    ):
        failure = check(ctx)
        if failure is not None:
            return _as_contract(failure, "transfer")
    return None
