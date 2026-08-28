#!/usr/bin/env python3
"""PreToolUse hook: execution-time guard for the ACTIVE investigation session.

Deny rules, applied only for the session that owns the TRUDI trace beacon
(dev sessions elsewhere are never touched):

Bash:
1. Produced-output reads — python/jq/grep/cat/… over data files in
   analysis|exports|reports. Those reads are untraced and uncitable
   (`claude_code_bash` entries carry no `_trudi_call_id`), which is how
   body-level evidence ends up ungrounded. The read.* MCP tools are the
   traced, citable equivalent.
2. Forensic binaries — the mcp_routing ban list, moved from finding-time to
   execution time: the refusal (with the MCP wrapper hint) lands BEFORE the
   evidence is gathered the wrong way, not when the finding is recorded.
3. Writes into the case's evidence dirs — reports/, exports/, analysis/
   (redirects, tee, cp/mv/install) — see below.

Write / Edit / MultiEdit:
4. Any file under <case>/reports/, exports/ or analysis/. Those dirs hold TOOL
   output only; the final report is written ONLY through misc.write_final_report,
   gated on reason.pre_report_check ready_to_report=true (misc.export_execution_log
   carries the same gate). A raw write to these dirs bypasses that gate entirely,
   so the agent has no raw-write capability to them; reasoning and notes go in
   the trace via misc.record_agent_message.

Fail-open everywhere: any parse/import error, a missing payload field, or a
non-owner session exits 0 with no output. Emergency off: TRUDI_GUARD_DISABLE=1.
"""
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))       # _session_owner
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))   # repo root (core.*)

_READER_RE = re.compile(
    r"(?<![\w-])(?:python3?|jq|grep|egrep|fgrep|cat|awk|sed|head|tail|"
    r"sqlite3|cut|sort|uniq|less|more)\b")
# A produced-output data file named directly (relative or absolute path).
_PRODUCED_FILE_RE = re.compile(
    r"(?:^|[/\s'\"=(])(?:analysis|exports|reports)/[^\s'\"()]*"
    r"\.(?:csv|tsv|json|jsonl|txt|mbox|eml|db|sqlite|md)\b")
# cd-into-the-dir-then-glob style: a produced dir referenced anywhere plus a
# data extension anywhere in the same command (e.g. cd exports/mail + *.mbox).
_PRODUCED_DIR_RE = re.compile(r"(?:^|[/\s'\"=(])(?:analysis|exports|reports)(?:/|\s|$)")
_DATA_EXT_RE = re.compile(r"\.(?:csv|tsv|json|jsonl|txt|mbox|eml|db|sqlite)\b")
# ls/find ENUMERATION is not a produced-output READ: its output is a filename
# listing, and a downstream `head`/`grep` filters that listing, not file
# contents. Exempted only for a SINGLE pipeline (no ';'/'&&'/'||'/newline that
# could chain a real read) with no `find … -exec <reader>` or `xargs`.
_ENUM_LEAD_RE = re.compile(r"^\s*(?:ls|find)\b")
_ENUM_CONTENT_READ_RE = re.compile(
    r"-exec\s+(?:python3?|jq|grep|egrep|fgrep|cat|awk|sed|head|tail|"
    r"sqlite3|cut|sort|uniq|less|more)\b"
    r"|(?<![\w-])xargs\b")
_CMD_CHAIN_RE = re.compile(r"[;\n]|&&|\|\|")
# Claude Code caches every MCP tool result to a SECOND copy outside the case
# sidecar (~/.claude/projects/<project>/<session>/tool-results/mcp-*.txt) — the
# same bytes as analysis/.tool_output/<cid>.txt but outside _PROTECTED_DIRS, so
# a bash read of it would slip past the produced-output check. Match the cache
# path so the same reader rule refuses it and steers to read.read_output.
_MCP_RESULT_CACHE_RE = re.compile(
    r"(?:^|[/\\\s'\"=(])\.claude[/\\]projects[/\\][^/\\\s'\"]+[/\\][^/\\\s'\"]+[/\\]"
    r"tool-results[/\\]mcp-[^\s'\"()]+")
# The agent writes NOTHING to the evidence-output dirs: reports/ (final
# report), exports/ (extractor output) and analysis/ (sidecars + parsed CSVs).
# Everything there is produced by an MCP tool or the stdout-sidecar middleware;
# an agent-authored file there becomes citable "evidence" once read back and a
# raw report write defeats the pre_report_check gate — the laundering / bypass
# paths this guard closes (bash redirects, tee, cp/mv/install included).
_PROTECTED_DIRS = ("reports", "exports", "analysis")
_PROTECTED_TARGET = r"(?:^|[\s'\"=(])(?:\./)?(?:reports|exports|analysis)/"
_BASH_REPORT_WRITE_RE = re.compile(
    r"(?:>>?\s*['\"]?(?:\./)?(?:reports|exports|analysis)/"
    r"|(?<![\w-])tee\b[^\n|;&]*" + _PROTECTED_TARGET +
    r"|(?<![\w-])(?:cp|mv|install|rsync)\b[^\n|;&]*" + _PROTECTED_TARGET + r")")

# The operator's persistent memory (~/.claude/projects/<project>/memory/) is
# curated OUTSIDE a case; an investigation session must not inject operator-level
# memory. Same capability model as the evidence dirs above: no raw write path
# from an owned investigation session.
_MEMORY_PATH_RE = re.compile(r"[/\\]\.claude[/\\]projects[/\\][^/\\]+[/\\]memory(?:[/\\]|$)")
_MEMORY_TARGET = r"[^\s'\"|;&()]*\.claude/projects/[^/\s]+/memory/"
_BASH_MEMORY_WRITE_RE = re.compile(
    r">>?\s*['\"]?" + _MEMORY_TARGET +
    r"|(?<![\w-])tee\b[^\n|;&]*" + _MEMORY_TARGET +
    r"|(?<![\w-])(?:cp|mv|install|rsync)\b[^\n|;&]*" + _MEMORY_TARGET)
_MEMORY_WRITE_REASON = (
    "Writes into the operator's persistent memory (~/.claude/projects/*/memory/) are "
    "refused for an active investigation session: a forensic case run must not edit "
    "operator-level memory. A product/harness observation goes in the case trace via "
    "misc.record_agent_message; the operator curates memory outside a case session. "
    "(Emergency override: TRUDI_GUARD_DISABLE=1.)"
)

_WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
_REPORT_WRITE_REASON = (
    "Raw writes into <case>/reports/, <case>/exports/ or <case>/analysis/ are refused: "
    "those directories hold TOOL output only. The final report is written via "
    "misc.write_final_report (gated on reason.pre_report_check ready_to_report=true; "
    "misc.export_execution_log carries the same gate) — a raw markdown write to "
    "analysis/ that bypasses that gate is exactly what this refuses. An agent-authored "
    "file is never evidence (gate agent_authored_source). Put reasoning and notes in "
    "the trace via misc.record_agent_message, not a file. (Emergency override: "
    "TRUDI_GUARD_DISABLE=1.)"
)


def _inside_memory(file_path: str, cwd: str) -> bool:
    """Is `file_path` under an operator memory dir (.claude/projects/*/memory/)?"""
    try:
        fp = Path(file_path)
        if not fp.is_absolute():
            fp = Path(cwd or ".") / fp
        fp = Path(os.path.realpath(str(fp)))
        return bool(_MEMORY_PATH_RE.search(str(fp)))
    except Exception:
        return False


def _inside_reports(file_path: str, cwd: str, case_dir: Path) -> bool:
    """Is `file_path` (relative to `cwd` when relative) under one of the
    tool-only directories of <case_dir>?"""
    try:
        fp = Path(file_path)
        if not fp.is_absolute():
            fp = Path(cwd or ".") / fp
        fp = Path(os.path.realpath(str(fp)))
        for sub in _PROTECTED_DIRS:
            d = Path(os.path.realpath(str(case_dir / sub)))
            if d == fp or d in fp.parents:
                return True
        return False
    except Exception:
        return False


def _deny(reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return
    tool = payload.get("tool_name")
    if tool != "Bash" and tool not in _WRITE_TOOLS:
        return
    if os.environ.get("TRUDI_GUARD_DISABLE") == "1":
        return
    tool_input = payload.get("tool_input") or {}

    # Only guard the investigation session that owns the trace beacon.
    try:
        from _session_owner import resolve_owner
        trace_path, _reason = resolve_owner(payload, claim=False)
    except Exception:
        return
    if trace_path is None:
        return  # not the investigation session — never interfere
    case_dir = Path(trace_path).resolve().parent.parent

    # Rule 4 — raw file-tool writes into <case>/reports/.
    if tool in _WRITE_TOOLS:
        try:
            fp = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
            cwd = payload.get("cwd") or ""
            if fp and _inside_reports(fp, cwd, case_dir):
                _deny(_REPORT_WRITE_REASON)
            elif fp and _inside_memory(fp, cwd):
                _deny(_MEMORY_WRITE_REASON)
        except Exception:
            pass
        return

    cmd = tool_input.get("command") or ""
    if not cmd:
        return

    # Rule 3 — bash writes into evidence dirs (redirect / tee / cp / mv / install).
    try:
        if _BASH_REPORT_WRITE_RE.search(cmd):
            _deny(_REPORT_WRITE_REASON)
            return
        if _BASH_MEMORY_WRITE_RE.search(cmd):
            _deny(_MEMORY_WRITE_REASON)
            return
    except Exception:
        pass

    # Rule 2 — forensic binaries (mcp_routing, at execution time).
    # core.forensic_binaries is stdlib-only, so this works under any python3
    # the harness runs hooks with (core.middleware would drag in fastmcp).
    try:
        from core.forensic_binaries import MCP_WRAPPER_HINTS, _identify_forensic_binary
        binkey = _identify_forensic_binary(cmd)
        if binkey is not None:
            hint = MCP_WRAPPER_HINTS.get(
                binkey, "the corresponding MCP wrapper (see the CLAUDE.md namespace table)")
            _deny(
                "Forensic binaries must run through the TRUDI MCP wrapper so the "
                f"call is traced and citable — use {hint}. A bash run has no "
                "_trudi_call_id and any finding citing it is refused (mcp_routing)."
            )
            return
    except Exception:
        pass

    # Rule 1b — bash sqlite over a chat/messenger store (usually raw evidence):
    # misc.chat_db_export is the traced, read-only-immutable path.
    try:
        if re.search(r"(?<![\w-])sqlite3\b", cmd) and re.search(
                r"main\.db|msgstore\.db", cmd, re.IGNORECASE):
            _deny(
                "Chat/messenger sqlite stores must be exported through "
                "misc.chat_db_export (strict read-only immutable open, traced, "
                "citable — messages + Transfers + participants CSVs), then read "
                "with read.read_output."
            )
            return
    except Exception:
        pass

    # Rule 1 — bash reads of produced output.
    try:
        _is_enum = (bool(_ENUM_LEAD_RE.match(cmd))
                    and not _ENUM_CONTENT_READ_RE.search(cmd)
                    and not _CMD_CHAIN_RE.search(cmd))
        if not _is_enum and _READER_RE.search(cmd) and (
            _PRODUCED_FILE_RE.search(cmd)
            or (_PRODUCED_DIR_RE.search(cmd) and _DATA_EXT_RE.search(cmd))
            or _MCP_RESULT_CACHE_RE.search(cmd)
        ):
            _deny(
                "Reading produced output via Bash is untraced and uncitable — this "
                "includes the Claude Code MCP result cache "
                "(~/.claude/projects/*/*/tool-results/mcp-*), which is a second copy "
                "of the same tool output that lives outside the case sidecar. Use "
                "read.read_output (CSV/JSON/TXT under analysis|exports|reports — "
                "supports query/columns/where; it reads the traced "
                "analysis/.tool_output/<cid>.txt) or read.read_mail (extracted "
                "mbox/.eml — returns message BODIES) instead; both return a "
                "_trudi_call_id to cite in record_finding. "
                "(Emergency override: TRUDI_GUARD_DISABLE=1.)"
            )
            return
    except Exception:
        pass


if __name__ == "__main__":
    main()
