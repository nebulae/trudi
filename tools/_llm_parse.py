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
    fields = '"schema_version": 1, '
    if '"rationale"' not in shape:
        fields += '"rationale": "brief explanation", '
    shape = shape.replace('{', '{' + fields, 1)
    return ("\n\nReturn exactly one RESULT: JSON object, schema_version=1. "
            "Put concise reasoning in rationale and all machine fields in this object. "
            "Do not emit separate legacy blocks or repeat the JSON as prose. No fences/comments.\n"
            "RESULT:\n" + shape + ("\n" + note if note else ""))



def str_list(v) -> list[str]:
    """Coerce a RESULT list field to a clean list[str]."""
    if not isinstance(v, list):
        return []
    return [str(x).strip() for x in v if str(x).strip()]


def validate_result(result: dict, tool: str) -> str:
    """Validate new structured answers; known legacy formats remain explicit adapters."""
    if result.get('truncated'):
        return 'Review output was truncated; review is incomplete'
    raw = result.get('_raw', '')
    rb = result.get('result_block')
    if rb is None:
        if result.get('evidence_requests') and 'RESULT:' not in raw:
            return ''
        if 'RESULT:' in raw:
            return 'Malformed RESULT object'
        # Explicit legacy formats only; absent machine fields are not success.
        if tool == 'reason_synthesize' and result.get('blockers') is None:
            return 'Missing structured synthesis issues/blockers'
        if tool == 'reason_evaluate_finding':
            if not re.search(r'\bVERDICT[\s:\-—–=*_]*(SUPPORTED|CHALLENGED|UNCERTAIN|CONTRADICTED|UNVERIFIABLE)\b', raw, re.I):
                return 'Missing explicit finding verdict'
        if tool == 'reason_audit_findings':
            match = re.search(r'\**AUDIT_FINDINGS\**\s*:?\**\s*(?:```json\s*)?', raw, re.I)
            try:
                arr, _ = json.JSONDecoder().raw_decode(raw[match.end():].lstrip()) if match else (None, 0)
            except ValueError:
                arr = None
            if not isinstance(arr, list) or any(not isinstance(i, dict) for i in arr):
                return 'Missing or malformed audit_findings array'
        return ''
    if type(rb.get('schema_version', 1)) is not int or rb.get('schema_version', 1) != 1:
        return 'Unsupported RESULT schema_version'
    req = rb.get('evidence_request')
    if req:
        if not isinstance(req, list) or any(not isinstance(r, dict) or
                not isinstance(r.get('call_id'), int) or not isinstance(r.get('query', ''), str)
                for r in req):
            return 'Invalid evidence_request'
        return ''
    if not isinstance(rb.get('rationale', ''), str):
        return 'rationale must be text'
    if tool == 'reason_synthesize':
        if not isinstance(rb.get('issues', rb.get('blockers')), list):
            return 'Synthesis requires issues (or legacy blockers) array'
        if not isinstance(rb.get('resolutions', []), list):
            return 'resolutions must be an array'
    if tool == 'reason_evaluate_finding' and rb.get('verdict') not in (
            'SUPPORTED', 'CONTRADICTED', 'UNVERIFIABLE', 'CHALLENGED', 'UNCERTAIN'):
        return 'Invalid or missing finding verdict'
    if tool == 'reason_audit_findings' and not isinstance(rb.get('audit_findings'), list):
        return 'Missing audit_findings array'
    if tool == 'reason_hypothesize' and not isinstance(rb.get('hypotheses'), list):
        return 'Missing hypotheses array'
    if tool == 'reason_plan' and not isinstance(rb.get('directives'), dict):
        return 'Missing planning directives'
    if tool == 'reason_cite_check':
        if rb.get('verdict') not in ('ALL_CITED', 'UNCITED_CLAIMS_PRESENT', 'INSUFFICIENT_EVIDENCE'):
            return 'Invalid citation verdict'
        if any(not isinstance(rb.get(k), list) for k in ('cited_claims', 'uncited_claims')):
            return 'Citation review requires cited_claims and uncited_claims arrays'
    for key in ('directives',):
        if key in rb and not isinstance(rb[key], dict):
            return f'{key} must be an object'
    return ''


def validate_assessment(assessment: dict) -> str:
    phases = {'Triage', 'Collect', 'Analyze', 'Scan', 'Report'}
    if not isinstance(assessment.get('current_phase'), str) or assessment['current_phase'] not in phases:
        return 'Invalid current_phase'
    for key in ('phase_rationale', 'investigation_focus', 'transition_rationale', 'next_phase'):
        if not isinstance(assessment.get(key, ''), str):
            return f'{key} must be text'
    if not assessment.get('phase_rationale') and not assessment.get('investigation_focus'):
        return 'Empty DAIR assessment'
    if assessment.get('stack_action') not in ('stay', 'push', 'pop'):
        return 'Invalid stack_action'
    if type(assessment.get('transition_recommended')) is not bool:
        return 'Invalid transition_recommended'
    if assessment.get('stack_action') in ('push', 'pop') and assessment.get('next_phase') not in phases:
        return 'A transition needs a valid next_phase'
    if not isinstance(assessment.get('verification_challenges', []), list):
        return 'Invalid verification_challenges'
    for c in assessment.get('verification_challenges', []):
        if not isinstance(c, dict) or not c.get('claim') or not c.get('challenge_method'):
            return 'Invalid verification challenge'
        if c.get('verified') is not None and type(c.get('verified')) is not bool:
            return 'Invalid verified flag'
    d = assessment.get('directives', {})
    if not isinstance(d, dict) or not isinstance(d.get('priority_tools', []), list):
        return 'Invalid directives'
    return ''
