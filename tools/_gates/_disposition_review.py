"""Dispositions a human should look at — surfaced, never blocking.

Two ways a disposition can settle a question without really answering it:

* a challenge closed `out_of_scope` — the one reason that needs no evidence,
  used in a 2026-09-24 run on "classified docs posted to the Chinese share",
  which was the case question itself;
* a `verified` / `absent_from_evidence` / `present_unparseable` disposition
  whose cited evidence barely mentions what the claim is about — e.g. "Volume
  Shadow Copies exist" verified by a USB registry read.

Relevance is judged by term overlap, which is too crude to refuse on (a correct
verification of "temp.zip contains the posted research docs" by a strings dump
of $RZQSNFO.zip shares few literal words with the claim), so these are warnings
and a report section, not a gate.
"""
from __future__ import annotations

import os
import re

_WORD = re.compile(r"[a-z0-9$][a-z0-9_.\-$]{3,}")
_STOP = {"with", "from", "that", "this", "were", "have", "been", "into", "only", "used", "exist",
         "exists", "onward", "over", "contains", "present", "record", "records", "evidence",
         "which", "their", "there", "about", "after", "before", "under", "above"}
_NOISE = re.compile(r"\d{4}-\d\d-\d\d|\d{1,2}:\d\d(:\d\d)?|\d+")
REVIEW_REASONS = ("verified", "absent_from_evidence", "present_unparseable")


def _terms(claim: str) -> set:
    return {w for w in _WORD.findall(claim.lower()) if w not in _STOP and not _NOISE.fullmatch(w)}


def _evidence_text(by_id: dict, cids, cap: int = 2_000_000) -> str:
    parts = []
    for c in cids or []:
        e = by_id.get(c) or by_id.get(str(c)) or {}
        parts += [str(e.get("cmd") or ""), str(e.get("stdout_excerpt") or "")]
        p = e.get("stdout_path")
        if p and os.path.exists(p):
            try:
                with open(p, errors="replace") as fh:
                    parts.append(fh.read(cap))
            except OSError:
                pass
    return " ".join(parts).lower()


def dispositions_to_review(entries) -> list:
    """[{call_id, target_kind, target_id, reason, why, overlap}] for the report."""
    by = {e.get("call_id"): e for e in entries or [] if isinstance(e, dict)}
    out = []
    for d in entries or []:
        if not isinstance(d, dict) or d.get("type") != "disposition":
            continue
        tk, rs = str(d.get("target_kind") or ""), str(d.get("reason") or "")
        tid = str(d.get("target_id") or "")
        row = {"call_id": d.get("call_id"), "target_kind": tk, "target_id": tid[:200], "reason": rs}
        if tk == "challenge" and rs == "out_of_scope":
            out.append({**row, "why": "challenge closed out_of_scope — no evidence required or cited"})
            continue
        if rs not in REVIEW_REASONS or not d.get("evidence_call_ids"):
            continue
        claim = tid.split(":", 1)[-1] if tk == "challenge" else tid
        terms = _terms(claim)
        if len(terms) < 2:
            continue                       # too little to judge relevance on
        text = _evidence_text(by, d.get("evidence_call_ids"))
        hit = sorted(t for t in terms if t in text)
        if len(hit) * 3 <= len(terms):
            out.append({**row, "overlap": f"{len(hit)}/{len(terms)}",
                        "why": (f"cited evidence (calls {d.get('evidence_call_ids')}) mentions "
                                f"{len(hit)} of {len(terms)} claim terms")})
    return out
