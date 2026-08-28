"""Structured-first parsing of reviewer / DAIR model output.

Every reason.* and dair.* prompt asks the model to end its answer with ONE
`RESULT:` block — a single JSON object carrying the machine-read fields
(verdict, blockers, hypotheses, directives, evidence_request, …). That block is
parsed FIRST; the legacy per-block regexes (DIRECTIVES:, BLOCKERS:, VERDICT:,
CITE_CHECK:, …) remain as fallbacks for a backend that ignores the instruction.
Which path produced each entry is stamped as `parse_path` so a run can be
audited for how much of its control plane came from structured output.

Pure stdlib; no project imports (used by tools.reasoning and tools.dair).
"""
from __future__ import annotations

import json
import re

RESULT_JSON = "result_json"
LEGACY_BLOCK = "legacy_block"
PROSE_REGEX = "prose_regex"
NONE = "none"

# `RESULT:` / `**RESULT**:` / `RESULT:\n```json` … followed by an object.
_RESULT_HEAD_RE = re.compile(
    r"\**RESULT\**\s*:?\**\s*(?:```(?:json)?\s*)?(?=\{)", re.IGNORECASE)
_COMMENT_RE = re.compile(r"(?m)^\s*//[^\n]*\n?|\s+//[^\n]*$")


def _balanced_object(text: str, start: int) -> int | None:
    """Index just past the object starting at text[start] == '{', honouring
    strings/escapes; None when unbalanced."""
    depth, i, n, in_str, esc = 0, start, len(text), False, False
    while i < n:
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return None


def find_result_span(text: str) -> tuple[int, int] | None:
    """(start, end) of the LAST well-formed RESULT block in `text`, header
    included, or None."""
    if not text:
        return None
    best = None
    for m in _RESULT_HEAD_RE.finditer(text):
        end = _balanced_object(text, m.end())
        if end is None:
            continue
        body = text[m.end():end]
        try:
            json.loads(_COMMENT_RE.sub("", body))
        except (json.JSONDecodeError, ValueError):
            continue
        # swallow a closing fence
        tail = re.match(r"\s*```[ \t]*\n?", text[end:])
        best = (m.start(), end + (tail.end() if tail else 0))
    return best


def parse_result_block(text: str) -> tuple[dict | None, str]:
    """(object, path) — the last RESULT JSON object in `text` and
    RESULT_JSON, or (None, '') when absent/malformed."""
    span = find_result_span(text)
    if span is None:
        return None, ""
    m = _RESULT_HEAD_RE.search(text, span[0])
    end = _balanced_object(text, m.end())
    try:
        obj = json.loads(_COMMENT_RE.sub("", text[m.end():end]))
    except (json.JSONDecodeError, ValueError):
        return None, ""
    return (obj, RESULT_JSON) if isinstance(obj, dict) else (None, "")


def strip_result_block(text: str) -> str:
    """Remove the RESULT block only (surgical — sections after it survive)."""
    span = find_result_span(text)
    if span is None:
        return text
    s, e = span
    return (text[:s].rstrip() + ("\n" + text[e:] if text[e:].strip() else "")).rstrip()


def result_instruction(shape: str, note: str = "") -> str:
    """Prompt suffix asking for the RESULT block with the given JSON shape."""
    return (
        "\n\nRESULT BLOCK (machine-read): after your full analysis, end with exactly one "
        "block — the literal line `RESULT:` followed by ONE JSON object, no code fence, "
        "no // comments, no prose after it:\nRESULT:\n" + shape +
        "\nThe RESULT object is the authoritative structured answer; the prose above it "
        "is for humans. Fields you also emit as legacy blocks (DIRECTIVES, EVIDENCE_AUDIT, "
        "BLOCKERS, CITE_CHECK, CONFIDENCE_SCORE, EVIDENCE_REQUEST) may instead be given as "
        "keys of RESULT under the same lower-case names." + (" " + note if note else "")
    )


def str_list(v) -> list[str]:
    """Coerce a RESULT list field to a clean list[str]."""
    if not isinstance(v, list):
        return []
    return [str(x).strip() for x in v if str(x).strip()]
