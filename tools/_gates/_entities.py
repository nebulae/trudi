"""ONE entity normalizer for the whole control plane.

Accounts, people, e-mail addresses, SIDs and hosts are compared in many places
(refusal_rewording, challenge_sticky, the pre-report principal / correspondent
checks, DAIR's known-principal set, the disposition index). Each used to fold
names its own way, so a `jdoe` in one place did not match `J.Doe` in another.
Everything now goes through norm_entity(): case-folded, separators removed,
DOMAIN\\ stripped, e-mail kept whole with its local part available as a variant.
"""
from __future__ import annotations

import re

_QUOTES = "'\"`“”‘’"
_SEP_RE = re.compile(r"[._\-\s$]+")
_RID_RE = re.compile(r"^rid\s*(\d+)$", re.IGNORECASE)
_QUALIFIER_RE = re.compile(r"\s*[\(\[][^\)\]]*[\)\]]\s*$")
_ROLE_SUFFIX_RE = re.compile(r"(?<=\S)\s+(?:account|user account|local account|profile|principal|login)\s*$")


def norm_entity(v) -> str:
    """Canonical key for an entity: lower-cased, quotes/backticks stripped,
    `DOMAIN\\user` → `user`, `. _ - space $` removed; SIDs keep their dashes as
    `s-1-5-…`; `RID 1006` → `rid1006`. '' for empty."""
    s = str(v or "").strip().strip(_QUOTES).strip()
    if not s:
        return ""
    low = s.lower()
    if low.startswith("s-1-"):
        return re.sub(r"\s+", "", low)
    m = _RID_RE.match(low)
    if m:
        return f"rid{m.group(1)}"
    if "\\" in low and "@" not in low:
        low = low.rsplit("\\", 1)[-1]
    # A trailing qualifier is not part of the identity — `Guest (501)`,
    # `svc(1006)`, `User [RID 1001]` fold to the bare name — and neither is a
    # trailing role word (`X account`): qualifier variants must never be
    # tracked as separate principals.
    low = _QUALIFIER_RE.sub("", low)
    low = _ROLE_SUFFIX_RE.sub("", low)
    return _SEP_RE.sub("", low)


def entity_variants(v) -> set[str]:
    """Canonical forms an entity may be referred to by: the full key and, for
    an e-mail address, its local part (`jdoe@x.org` ↔ `jdoe`)."""
    key = norm_entity(v)
    if not key:
        return set()
    out = {key}
    if "@" in key:
        local = key.split("@", 1)[0]
        if len(local) >= 3:
            out.add(local)
    return out


def entity_matches(a, b) -> bool:
    va, vb = entity_variants(a), entity_variants(b)
    return bool(va and vb and (va & vb))


def entity_overlap(A, B) -> float:
    """Jaccard-style overlap between two entity collections under
    entity_matches (0.0–1.0)."""
    A = [a for a in (A or []) if norm_entity(a)]
    B = [b for b in (B or []) if norm_entity(b)]
    if not A or not B:
        return 0.0
    matched = sum(1 for a in A if any(entity_matches(a, b) for b in B))
    union = len(A) + len(B) - matched
    return matched / union if union else 0.0


def entity_in_text(entity, text: str) -> bool:
    """Does `text` mention `entity` (any variant, after folding the text the
    same way)? Substring on folded text — a display name with dots/spaces still
    matches its folded key."""
    vs = entity_variants(entity)
    if not vs or not text:
        return False
    folded = _SEP_RE.sub("", str(text).lower())
    return any(len(v) >= 3 and v in folded for v in vs)


# Role words a reviewer/agent uses in place of an identity ("unknown", "an
# external actor"). They can never be session-bound or refuted as a principal,
# so contested-principal tracking ignores them; findings may still name them.
PLACEHOLDER_PRINCIPALS = frozenset({
    "unknown", "unknownactor", "unknownuser", "unknownprincipal", "unidentified",
    "na", "n/a", "none", "nil", "null", "tbd", "thirdparty", "externalactor", "attacker",
    "adversary", "threatactor", "intruder", "someone", "someoneelse",
})


# Windows/AD built-in accounts: never a pivot on their own, and never a
# contested principal that must be dispositioned unless a finding names one.
BUILTIN_PRINCIPALS = frozenset({
    "administrator", "administrators", "admin", "guest", "defaultaccount", "system",
    "localsystem", "networkservice", "localservice", "homegroupuser", "homegroupuser$",
    "wdagutilityaccount", "trustedinstaller", "krbtgt",
})


def is_builtin(name) -> bool:
    return norm_entity(name) in BUILTIN_PRINCIPALS or str(name or "").strip().lower() in BUILTIN_PRINCIPALS


def is_placeholder(name) -> bool:
    """True when `name` folds to a role placeholder (or to nothing) — including
    qualified forms like 'unknown external actor', 'unidentified remote user'."""
    n = norm_entity(name)
    return (not n or n in PLACEHOLDER_PRINCIPALS
            or n.startswith(("unknown", "unidentified", "unnamed")))


def claim_key(claim: dict | None) -> str:
    """Structural identity of a typed claim: kind|category|act."""
    c = claim or {}
    return "|".join(str(c.get(k) or "").strip().lower() for k in ("kind", "category", "act"))
