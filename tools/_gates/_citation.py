"""Deterministic citation check.

`reason.cite_check`'s own job description is a string match — "UNCITED: the
value appears in the finding but not in supporting_evidence". This implements
exactly that, deterministically, so a finding recorded WITH inline
supporting_evidence does not need a separate 8B-model round-trip.

Scope: only unambiguous artifact *values* are required to be cited — IPv4
addresses, hashes (32-64 hex), MITRE technique IDs, absolute file paths, and
registry keys. Prose, numbers, and ambiguous tokens are intentionally NOT
required (matching cite_check, which only flags concrete artifact claims).
"""
import re
from typing import Optional

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HASH = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Absolute unix path with >= 2 segments (avoids matching a lone "/tmp").
_UNIX_PATH = re.compile(r"/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)+")
# Windows path / registry key. A path segment may contain spaces ("Program
# Files", "Documents and Settings", a spaced user profile name) but is bounded
# so it cannot run into the prose after the path or be cut short at an '@'.
_SC = r"[^\\\s,;:()'\"<>|]"          # one segment char (space and punctuation excluded)
_INT_SEG = rf"{_SC}+(?: {_SC}+){{0,3}}"                 # interior dir: ≤3 internal spaces
# Final segment: a spaced name that ENDS in a file extension ("vacation
# photos.7z"), else a single space-free token (which may itself carry an
# extension). Trailing sentence punctuation is stripped in add().
_FINAL_SEG = rf"(?:{_SC}+ ){{1,3}}{_SC}*\.[A-Za-z0-9]{{1,8}}|{_SC}+"
_WIN_PATH = re.compile(rf"[A-Za-z]:\\(?:{_INT_SEG}\\)*(?:{_FINAL_SEG})")
# Registry subkeys: no internal spaces (safer to under-match a rare spaced key
# than to swallow "HKLM\Software\Vendor value Foo was set").
_REG_KEY = re.compile(rf"\bHK(?:LM|CU|U|CR|CC)(?:\\{_SC}+)+", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:)'\""


def extract_claims(finding: str) -> list[tuple[str, str]]:
    """Return [(kind, value), ...] of citable artifact values in the finding."""
    text = finding or ""
    claims: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(kind: str, value: str):
        value = value.strip().rstrip(_TRAILING_PUNCT)   # "…\file.ini." at sentence end
        key = value.lower()
        if key and key not in seen:
            seen.add(key)
            claims.append((kind, value))

    for m in _IPV4.findall(text):
        add("ipv4", m)
    for m in _HASH.findall(text):
        add("hash", m)
    for m in _TID.findall(text):
        add("technique_id", m)
    for m in _REG_KEY.findall(text):
        add("registry_key", m)
    for m in _WIN_PATH.findall(text):
        add("path", m.strip())
    for m in _UNIX_PATH.findall(text):
        add("path", m)
    return claims


def deterministic_cite_check(finding: str, supporting_evidence: str) -> dict:
    """Verify every citable artifact value in `finding` appears in
    `supporting_evidence`. Mirrors reason.cite_check's verdict vocabulary."""
    evidence = (supporting_evidence or "").lower()
    claims = extract_claims(finding)

    if not claims:
        # No concrete artifact claims to verify (prose-only finding).
        return {"verdict": "ALL_CITED", "cited_claims": [], "uncited_claims": []}

    if not evidence.strip():
        return {
            "verdict": "INSUFFICIENT_EVIDENCE",
            "cited_claims": [],
            "uncited_claims": [v for _, v in claims],
        }

    cited, uncited = [], []
    for _kind, value in claims:
        if value.lower() in evidence:
            cited.append(value)
        else:
            uncited.append(value)

    verdict = "UNCITED_CLAIMS_PRESENT" if uncited else "ALL_CITED"
    return {"verdict": verdict, "cited_claims": cited, "uncited_claims": uncited}
