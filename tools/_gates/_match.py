"""Shared description-matching helpers for finding gates.

Gates that must tie a reason_call (evaluate / confidence / cite) to the
*specific* finding being recorded match on a normalized prefix of the finding
description appearing in the reason_call's ``inputs.user_message``. Centralising
the matching semantics here keeps them identical across gates and is what stops
one finding's review verdict from satisfying or blocking a *different* finding
(cross-contamination) when several findings are reviewed in one batch.
"""
import re
from typing import Optional

_WHITESPACE_RE = re.compile(r"\s+")


def normalize_desc(text: str) -> str:
    """Lowercase, collapse whitespace, first 60 chars — the stable key used to
    match a finding description against a reason_call's user_message."""
    return _WHITESPACE_RE.sub(" ", (text or "").lower()).strip()[:60]


def find_reason_call(window, tool_name: str, norm_desc: str,
                     after_call_id: int = 0) -> Optional[dict]:
    """Most-recent reason_call of ``tool_name`` whose user_message contains
    ``norm_desc`` and whose call_id > ``after_call_id``. None if no match."""
    if not norm_desc:
        return None
    for entry in reversed(window):
        if entry.get("type") != "reason_call" or entry.get("tool") != tool_name:
            continue
        if int(entry.get("call_id") or 0) <= after_call_id:
            continue
        user_msg = ((entry.get("inputs") or {}).get("user_message") or "").lower()
        if norm_desc in user_msg:
            return entry
    return None


def most_recent_reason_call(window, tool_name: str) -> Optional[dict]:
    """Most-recent reason_call of ``tool_name`` regardless of description."""
    for entry in reversed(window):
        if entry.get("type") == "reason_call" and entry.get("tool") == tool_name:
            return entry
    return None
