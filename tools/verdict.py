"""Shared parser for the reason.evaluate_finding verdict.

The evaluate system prompt asks for `VERDICT: SUPPORTED / CHALLENGED /
UNCERTAIN`. Models render it several ways — inline after a colon, as a bold
heading, or as a numbered heading with the value on the next line — so the
regex must tolerate the colon being absent or on a separate line. One regex,
two callers, no other imports — so the gate package and tools.reasoning can
both import it without a cycle.
"""
import re

EVALUATE_VERDICT_RE = re.compile(
    r"VERDICT"                       # the word (case-insensitive)
    r"[\s:\-—–=*_]*"                 # separators / bold / whitespace (incl. newline)
    r"(?:is|was|of)?"                # optional filler: "verdict IS supported"
    r"[\s:\-—–=*_]*"                 # more separators
    r"(SUPPORTED|CHALLENGED|UNCERTAIN|CONTRADICTED|UNVERIFIABLE)\b",
    re.IGNORECASE,
)

# Fallback: a bare verdict token at the START of a line (after optional list /
# bold / quote / heading markers), followed by a separator or end of line. The
# evaluate template renders "VERDICT — exactly one of: SUPPORTED / …" and models
# often answer with just the token on its own line. Line-anchored so a mid-
# sentence "not SUPPORTED" never false-matches.
_LINE_VERDICT_RE = re.compile(
    r"^[\s>*_#\d.)\-]*"
    r"(SUPPORTED|CHALLENGED|UNCERTAIN|CONTRADICTED|UNVERIFIABLE)\b"
    r"\s*(?:[—:\-–.,]|$)",
    re.IGNORECASE | re.MULTILINE,
)

# Fact-check vocabulary → the gate vocabulary. The reviewer is a
# fact-checker: CONTRADICTED (a cited row contradicts a stated fact) and
# UNVERIFIABLE (the deciding rows were not visible) map onto the sticky
# CHALLENGED / UNCERTAIN the record gates already understand.
FACT_VERDICT_MAP = {"SUPPORTED": "SUPPORTED", "CONTRADICTED": "CHALLENGED",
                    "UNVERIFIABLE": "UNCERTAIN", "CHALLENGED": "CHALLENGED",
                    "UNCERTAIN": "UNCERTAIN"}


def normalize_verdict(v: str) -> str:
    return FACT_VERDICT_MAP.get(str(v or "").strip().upper(), "")


def parse_verdict(text: str) -> str:
    """Return 'SUPPORTED' / 'CHALLENGED' / 'UNCERTAIN' (upper-case) or ''.
    CONTRADICTED / UNVERIFIABLE are normalised to CHALLENGED / UNCERTAIN."""
    if not text:
        return ""
    m = EVALUATE_VERDICT_RE.search(text)
    if m:
        return normalize_verdict(m.group(1))
    # Tier 2: the VERDICT keyword is present but the value is a few words later
    # ("final verdict of the review: CONTRADICTED"). Bounded 60-char window after
    # the keyword; a negated token ("not SUPPORTED") is skipped. Keyword-gated,
    # so the false-positive surface stays small.
    kw = re.search(r"\bVERDICT\b", text, re.IGNORECASE)
    if kw:
        for tm in re.finditer(
                r"(not\s+|n['’]?t\s+)?\b(SUPPORTED|CHALLENGED|UNCERTAIN|CONTRADICTED|UNVERIFIABLE)\b",
                text[kw.end(): kw.end() + 60], re.IGNORECASE):
            if not tm.group(1):
                return normalize_verdict(tm.group(2))
    # Fallback: the last bare verdict line (models restate the final verdict at
    # the end). Line-anchored, so it never picks a mid-sentence mention.
    lines = list(_LINE_VERDICT_RE.finditer(text))
    return normalize_verdict(lines[-1].group(1)) if lines else ""
