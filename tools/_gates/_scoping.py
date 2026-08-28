"""Open scoping leads.

Scan = scoping: pursuing a newly-discovered IOC to depth, on the same host or
another. A lead is a declared candidate pivot (host, forced principal) or a
flagged IOC (keystroke-injector device, injector-payload task) not yet driven
to a finding or settled by a typed disposition. Symmetric: scoping a lead may
equally exonerate — a lead is a thing to look at, never a presumed verdict.

Used in two places, from the same computation: dair_assess (Analyze advances to
Scan while leads are open, else Report) and reason.pre_report_check (warns —
never blocks on content — while a lead is open).
"""
from __future__ import annotations

from ._entities import entity_matches, norm_entity
from ._dispositions import index_from_entries, find_disposition, any_disposition
from ._scheduled_tasks import flagged_injector_present, flagged_payload_tasks

# Only a FORCED principal candidate (created / interactive_logon cue) is a
# mandatory lead; a mere appearance is advisory and does not hold Scan open.
FORCED_CUES = ("forced",)


def _referenced(entries) -> tuple[set, list]:
    """(norm set, raw list) of every entity / principal / recipient cited by a
    finding — the things already driven to a finding."""
    norms: set = set()
    raws: list = []
    for e in entries or []:
        if not (isinstance(e, dict) and e.get("type") == "finding"):
            continue
        c = e.get("claim") if isinstance(e.get("claim"), dict) else {}
        norms |= set(c.get("entities_norm") or [])
        if c.get("principal_norm"):
            norms.add(c["principal_norm"])
        for v in (list(c.get("entities") or []) + list(c.get("recipients") or [])
                  + ([c.get("principal")] if c.get("principal") else [])):
            if v:
                raws.append(str(v))
    return norms, raws


def _in_finding(value, norms, raws) -> bool:
    nv = norm_entity(value)
    if nv and nv in norms:
        return True
    return any(entity_matches(value, r) for r in raws)


def open_scoping_leads(entries) -> list:
    """Leads not yet driven to a finding or settled by a typed disposition.
    Each: {kind: host|principal|device|task, value, why}."""
    entries = entries or []
    idx = index_from_entries(entries)
    norms, raws = _referenced(entries)
    leads: list = []
    seen: set = set()

    def _add(kind, value, why):
        key = (kind, str(value).strip().lower())
        if not value or key in seen:
            return
        seen.add(key)
        leads.append({"kind": kind, "value": value, "why": why})

    # 1 & 2 — candidate pivots the agent DECLARED (forced principals + hosts).
    for e in entries:
        if not (isinstance(e, dict) and e.get("type") == "dair_call"):
            continue
        for pv in e.get("candidate_pivots") or []:
            if not isinstance(pv, dict):
                continue
            kind = str(pv.get("kind") or "").lower()
            val = str(pv.get("value") or "")
            if not val or _in_finding(val, norms, raws):
                continue
            if kind == "principal":
                if str(pv.get("cue") or "").lower() not in FORCED_CUES:
                    continue          # only forced principals are mandatory leads
                if find_disposition(idx, "principal", val) is None:
                    _add("principal", val,
                         "forced principal candidate — controller not established")
            elif kind == "host":
                if find_disposition(idx, "host", val) is None:
                    _add("host", val, "candidate host pivot — not investigated")

    # 3 — a flagged keystroke-injector device, until device-dispositioned.
    if flagged_injector_present(entries):
        if any_disposition(idx, "device",
                           reasons=("ruled_out", "absent_from_evidence")) is None:
            _add("device", "keystroke-injector",
                 "flagged HID keystroke-injector device — not ruled out or investigated")

    # 4 — flagged injector-payload scheduled tasks, until cited by a finding.
    for t in flagged_payload_tasks(entries):
        if not _in_finding(t, norms, raws):
            _add("task", t,
                 "injector-payload scheduled task — not investigated or attributed")

    return leads
