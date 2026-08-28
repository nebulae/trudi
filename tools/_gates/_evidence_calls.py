"""What counts as an EVIDENCE-producing tool call — one definition, shared by the
sticky-challenge gate, the refusal-rewording gate and the max-pass-cap gate.

"New evidence" means the agent ran something that could change what the trace
knows: a forensic extractor, a produced-output read (read.* — that is how the
rows a reviewer asked for get pulled), a correlation join. It does NOT mean a
bookkeeping call: the `<py>:misc_record_*` / reason / dair baselines that the
middleware writes for pure-Python meta tools.
"""
from __future__ import annotations

import os
import re

# `<py>:<namespace>_...` baselines of tools that never touch evidence.
_META_PREFIXES = ("<py>:misc_", "<py>:reason_", "<py>:dair_", "<py>:accuracy_",
                  "<py>:monitor_", "<py>:coverage_", "<py>:attribution_")

# ── Agent-authored files are NOT evidence ────────────────────────────────────
# An agent once answered a challenge by writing "verbatim excerpts" of evidence
# into exports/ and citing a read of its own file — indistinguishable from
# extractor output to a reviewer. These helpers find every agent-authored path
# (Write/Edit, bash redirects/tee/cp into produced-output dirs) so the
# resolver, inventory and record gate can refuse reads over them.
_AUTHOR_SOURCES = ("claude_code_write", "claude_code_edit", "claude_code_multiedit",
                   "claude_code_notebookedit")
_BASH_TARGET_RE = re.compile(
    r"(?:>{1,2}\s*|(?<![\w-])tee\s+(?:-a\s+)?|(?<![\w-])(?:cp|mv|install)\s+(?:\S+\s+)+)"
    r"['\"]?((?:/|\./)?[^\s'\"|;&>]*(?:analysis|exports)/[^\s'\"|;&>]+)")
_READ_PATH_RE = re.compile(r"(?:--output|-o|--path|--file)\s+(.+?)(?=\s+--|\s+-[a-z]\b|$)")


def _norm_path(p: str) -> str:
    p = str(p or "").strip().strip("'\"")
    return os.path.normpath(p) if p else ""


def agent_authored_paths(entries) -> set:
    """Normalized paths written by agent-authored entries (Write/Edit tool
    calls and bash writes into analysis/ or exports/)."""
    out: set = set()
    for e in entries or []:
        if not isinstance(e, dict) or e.get("type") != "tool_call":
            continue
        src = str(e.get("source") or "")
        cmd = str(e.get("cmd") or "")
        if src in _AUTHOR_SOURCES:
            parts = cmd.split(None, 1)
            if len(parts) == 2:
                out.add(_norm_path(parts[1]))
        elif src == "claude_code_bash":
            for m in _BASH_TARGET_RE.finditer(cmd):
                out.add(_norm_path(m.group(1)))
    out.discard("")
    return out


def read_target_path(entry: dict) -> str:
    """The produced-output path a read.* call read, '' otherwise."""
    cmd = str((entry or {}).get("cmd") or "")
    if not cmd.startswith("read."):
        return ""
    m = _READ_PATH_RE.search(cmd)
    return _norm_path(m.group(1)) if m else ""


def authored_source_of(entry: dict, authored: set) -> str:
    """The agent-authored path this entry IS or READS, else ''."""
    if not authored or not isinstance(entry, dict):
        return ""
    if str(entry.get("source") or "") in _AUTHOR_SOURCES:
        parts = str(entry.get("cmd") or "").split(None, 1)
        p = _norm_path(parts[1]) if len(parts) == 2 else ""
        return p if p in authored else ""
    p = read_target_path(entry)
    if not p:
        return ""
    if p in authored:
        return p
    for a in authored:                       # a read of a file under an authored dir
        if a and (p == a or p.startswith(a.rstrip("/") + "/")):
            return a
    return ""


def is_evidence_tool_call(entry: dict) -> bool:
    if not isinstance(entry, dict) or entry.get("type") != "tool_call":
        return False
    if not entry.get("success"):
        return False
    cmd = entry.get("cmd")
    if not isinstance(cmd, str) or not cmd.strip():
        return False
    return not cmd.startswith(_META_PREFIXES)


def _tool_calls(by_type) -> list:
    if not isinstance(by_type, dict):
        return []
    calls = by_type.get("tool_call", [])
    return calls if isinstance(calls, list) else []


def last_evidence_call_id(by_type) -> int:
    """Highest call_id of an evidence tool call; 0 when none (or idx unusable)."""
    best = 0
    for e in _tool_calls(by_type):
        if is_evidence_tool_call(e):
            best = max(best, int(e.get("call_id") or 0))
    return best


def evidence_calls_after(by_type, cid: int) -> list:
    """Evidence tool calls with call_id strictly greater than `cid`."""
    return [e for e in _tool_calls(by_type)
            if is_evidence_tool_call(e) and int(e.get("call_id") or 0) > int(cid or 0)]
