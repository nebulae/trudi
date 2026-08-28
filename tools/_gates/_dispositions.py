"""Typed dispositions — the ONE way to say "this lead / source / tool /
challenge is settled" without a finding.

Six different prose vocabularies used to waive enforcement: "absent from
evidence", "inapplicable", "ruled out", "controller unknown", "wiped scope
undetermined", "not the actor". Each was a regex over agent-authored text, and
two of them matched the waiver phrase and the target anywhere in the whole
trace. A disposition is now a trace entry with an enumerated target kind, an
enumerated reason, and — for the reasons that assert something about the
evidence — the evidence call_ids that back it.
"""
from __future__ import annotations

from ._entities import norm_entity

TARGET_KINDS = ("source", "tool", "challenge", "principal", "correspondent",
                "device", "hypothesis", "host", "destruction_scope")

REASONS = ("absent_from_evidence", "inapplicable", "out_of_scope", "noise",
           "excluded", "not_a_principal", "controller_unknown",
           "evidence_unavailable", "ruled_out", "refuted", "undetermined",
           "same_as")

# Which reasons make sense for which target.
ALLOWED: dict[str, frozenset] = {
    "source":            frozenset({"absent_from_evidence", "inapplicable", "out_of_scope"}),
    "tool":              frozenset({"absent_from_evidence", "inapplicable", "out_of_scope"}),
    "challenge":         frozenset({"absent_from_evidence", "inapplicable", "out_of_scope"}),
    "principal":         frozenset({"excluded", "not_a_principal", "controller_unknown",
                                    "evidence_unavailable", "refuted", "out_of_scope",
                                    "same_as"}),
    "correspondent":     frozenset({"noise", "out_of_scope", "excluded"}),
    "device":            frozenset({"ruled_out", "absent_from_evidence"}),
    "hypothesis":        frozenset({"refuted", "excluded", "evidence_unavailable"}),
    "host":              frozenset({"out_of_scope", "evidence_unavailable", "excluded"}),
    "destruction_scope": frozenset({"undetermined"}),
}

# Reasons that settle a manifest source / tool / challenge without running it.
SOURCE_WAIVER_REASONS_ALL = ("absent_from_evidence", "inapplicable", "out_of_scope")

# Reasons that assert a fact about the evidence and therefore need it cited.
EVIDENCE_REQUIRED = frozenset({"excluded", "ruled_out", "refuted", "not_a_principal",
                               "same_as"})
# `same_as`: the contested identity is the SAME person/account as an already
# established principal (an alias, a registered-owner string, the account the
# prime subject uses) — not a second actor. Cite the artifacts that tie them.
# It is the honest vocabulary where "refuted" would be backwards.

# Reasons that PARK a principal (it stays unresolved but is honestly declared).
PARKING = frozenset({"controller_unknown", "evidence_unavailable"})


def normalize_target(target_kind: str, target_id: str) -> str:
    """Index key for a disposition target. Entity-like kinds go through the
    shared entity normalizer; structural ids (manifest source id, tool name,
    dair_cid:challenge) are lower-cased and whitespace-stripped."""
    tk = (target_kind or "").strip().lower()
    tid = str(target_id or "").strip()
    if tk in ("principal", "correspondent", "host", "device"):
        return norm_entity(tid)
    return "".join(tid.lower().split())


def validate(target_kind: str, target_id: str, reason: str) -> str:
    """'' when valid, else a message naming the field and its enum."""
    tk = (target_kind or "").strip().lower()
    rs = (reason or "").strip().lower()
    if tk not in TARGET_KINDS:
        return (f"target_kind={target_kind!r} is not valid — one of: "
                f"{', '.join(TARGET_KINDS)}")
    if not str(target_id or "").strip():
        return "target_id is required (the manifest source id, tool name, "\
               "`<dair_call_id>:<challenge claim>`, account/identity, address, host, "\
               "device id, hypothesis id, or finding call_id for destruction_scope)"
    if rs not in REASONS:
        return f"reason={reason!r} is not valid — one of: {', '.join(REASONS)}"
    if rs not in ALLOWED[tk]:
        return (f"reason={rs!r} does not apply to target_kind={tk!r} — allowed: "
                f"{', '.join(sorted(ALLOWED[tk]))}")
    return ""


def _spans(window, day: str) -> bool:
    if not isinstance(window, dict) or not day:
        return False
    s = str(window.get("start") or "")[:10]
    e = str(window.get("end") or "")[:10]
    return bool(s and e and s <= day[:10] <= e)


def find_disposition(idx, target_kind: str, target_id: str, reasons=None,
                     window: dict | None = None) -> dict | None:
    """The most recent disposition for (kind, target) — optionally restricted
    to `reasons`, and (when `window` is given) to one whose own window spans
    the claim's start and end. None when nothing matches."""
    table = getattr(idx, "dispositions", None)
    if not isinstance(table, dict):
        return None
    key = (str(target_kind or "").strip().lower(), normalize_target(target_kind, target_id))
    rows = table.get(key) or []
    want = {r.lower() for r in (reasons or [])}
    best = None
    for d in rows:
        if want and str(d.get("reason") or "").lower() not in want:
            continue
        if window:
            dw = d.get("window")
            s, e = str(window.get("start") or "")[:10], str(window.get("end") or "")[:10]
            if not (dw and _spans(dw, s or e) and _spans(dw, e or s)):
                continue
        if best is None or int(d.get("call_id") or 0) > int(best.get("call_id") or 0):
            best = d
    return best


class _DispIndex:
    def __init__(self):
        self.dispositions: dict = {}


def index_from_entries(entries) -> _DispIndex:
    """A minimal index (only `.dispositions`) built from raw trace entries, for
    block-late checks that receive `entries` rather than a LogIndex."""
    out = _DispIndex()
    for e in entries or []:
        if isinstance(e, dict) and e.get("type") == "disposition":
            key = (str(e.get("target_kind") or "").lower(), str(e.get("target_norm") or ""))
            out.dispositions.setdefault(key, []).append(e)
    return out


def any_disposition(idx, target_kind: str, reasons=None, window: dict | None = None) -> dict | None:
    """The most recent disposition of `target_kind` with any target — used when
    the target id is not known to the caller (e.g. "some flagged device was
    ruled out for this window")."""
    table = getattr(idx, "dispositions", None)
    if not isinstance(table, dict):
        return None
    best = None
    for (kind, _norm), rows in table.items():
        if kind != str(target_kind or "").strip().lower():
            continue
        for d in rows:
            if reasons and str(d.get("reason") or "").lower() not in {r.lower() for r in reasons}:
                continue
            if window:
                dw = d.get("window")
                s, e = str(window.get("start") or "")[:10], str(window.get("end") or "")[:10]
                if not (dw and _spans(dw, s or e) and _spans(dw, e or s)):
                    continue
            if best is None or int(d.get("call_id") or 0) > int(best.get("call_id") or 0):
                best = d
    return best


def disposition_call(target_kind: str, target_id: str, reason: str, evidence: bool = False) -> str:
    """The exact call an agent should make — used in refusal messages."""
    ev = ', evidence_call_ids=[<cid>, ...]' if evidence else ''
    return (f'misc.record_disposition(target_kind="{target_kind}", target_id="{target_id}", '
            f'reason="{reason}"{ev})')


def disposition_batch_hint(target_kind: str = "correspondent", reason: str = "noise") -> str:
    """The batch form — settle many targets in one round-trip. Surfaced in
    multi-target blocker remediations. Each entry still runs the same per-target
    gates as record_disposition and writes its own discrete trace entry."""
    return (f'misc.record_agent_message(content="…", dispositions=['
            f'{{"target_kind":"{target_kind}","target_id":"<addr1>","reason":"{reason}"}}, '
            f'{{"target_kind":"{target_kind}","target_id":"<addr2>","reason":"{reason}"}}, …])')
