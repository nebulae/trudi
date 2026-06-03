"""Cross-tool correlation — joins outputs from existing TRUDI tools into
structured findings that judges can verify in the audit trail.

These are higher-order analytical tools: they don't run new forensic processes;
they read prior tool_call results from the execution log and merge them.
"""
import json
import os
import re
from typing import Optional
from fastmcp import FastMCP

from tools.mitre import (
    DEFAULT_TECHNIQUES_PATH as DEFAULT_MITRE_PATH,
    load_techniques as _load_mitre_techniques,
)

mcp = FastMCP("correlate")


def _load_mitre(path: Optional[str] = None) -> dict:
    """Thin shim over tools.mitre.load_techniques. Kept as a name so existing
    call sites don't have to change. Returns the full doc including _meta."""
    return _load_mitre_techniques(path)


def _recent_tool_stdouts(tool_substring: str, max_entries: int = 50) -> list[dict]:
    """Return recent tool_call entries whose cmd contains tool_substring.

    Used by correlation tools to look up the actual output the agent collected.
    Returns a list of {call_id, cmd, stdout_excerpt, success} dicts.
    """
    from core.execution_log import log
    matches = []
    for e in reversed(log._entries):
        if e.get("type") != "tool_call":
            continue
        cmd = e.get("cmd", "") or ""
        if tool_substring not in cmd:
            continue
        matches.append({
            "call_id": e.get("call_id"),
            "cmd": cmd,
            "stdout_excerpt": e.get("stdout_excerpt", "") or "",
            "success": e.get("success", False),
        })
        if len(matches) >= max_entries:
            break
    return list(reversed(matches))


# ── Process ↔ File correlation ──────────────────────────────────────────────

_PID_LINE_RE = re.compile(r"\b(?:PID|Pid)[:=]?\s*(\d+)\b")
# Windows path or absolute Linux path with at least 2 segments. The Linux side
# requires a non-empty middle segment so things like "/r" inside "r/r" don't
# match as a path.
_PATH_RE = re.compile(
    r"([A-Z]:\\[^\s\"'<>|]+|/[A-Za-z0-9_.\-]+/[^\s\"'<>|]+)"
)


def _best_path(line: str) -> Optional[str]:
    """Return the longest path-like token in line, or None.

    Prefers full Windows paths (C:\\…) over short Unix-style fragments. Resolves
    regex alternation order bias in lines that contain both "r/r" markers (TSK)
    and Windows paths.
    """
    matches = _PATH_RE.findall(line)
    if not matches:
        return None
    return max(matches, key=len)


@mcp.tool()
def process_to_file(pid: Optional[int] = None, path_substring: Optional[str] = None) -> dict:
    """
    Join vol.psscan/pslist (memory) findings to tsk.fls/MFTECmd (disk) records
    for the same image paths. Useful for confirming that a memory-resident
    process maps to an on-disk artifact (and vice versa).

    pid: optional PID filter — return correlations only for this process.
    path_substring: optional path filter (e.g. "Temp", "System32").

    Returns:
      correlations: list of {pid, process_name, memory_call_id, file_path,
                              disk_call_id, source_excerpts}.
    """
    # Pull recent vol process listings + recent disk listings from the trace.
    vol_entries = _recent_tool_stdouts("vol")
    disk_entries = (
        _recent_tool_stdouts("fls")
        + _recent_tool_stdouts("MFTECmd")
        + _recent_tool_stdouts("mftecmd")
    )

    # Extract (pid, candidate_path) tuples from vol output, keyed to call_ids.
    process_records: list[dict] = []
    for e in vol_entries:
        text = e["stdout_excerpt"]
        for line in text.splitlines():
            if pid is not None and str(pid) not in line:
                continue
            pid_match = _PID_LINE_RE.search(line) or re.search(r"^\s*\*?\s*(\d+)\s", line)
            path = _best_path(line)
            if pid_match and path:
                p = int(pid_match.group(1))
                if pid is not None and p != pid:
                    continue
                process_records.append({
                    "pid": p,
                    "candidate_path": path,
                    "memory_call_id": e["call_id"],
                    "memory_excerpt": line.strip()[:200],
                })

    # Build a path → disk_call_id index from disk_entries.
    disk_index: dict[str, dict] = {}
    for e in disk_entries:
        for line in e["stdout_excerpt"].splitlines():
            path = _best_path(line)
            if not path:
                continue
            disk_index.setdefault(path.lower(), {
                "disk_call_id": e["call_id"],
                "disk_excerpt": line.strip()[:200],
            })

    correlations = []
    for proc in process_records:
        cand = proc["candidate_path"]
        if path_substring and path_substring.lower() not in cand.lower():
            continue
        disk = disk_index.get(cand.lower())
        if not disk:
            # Try basename match as fallback
            basename = cand.replace("\\", "/").split("/")[-1].lower()
            for k, v in disk_index.items():
                if k.endswith("/" + basename) or k.endswith("\\" + basename):
                    disk = v
                    break
        if disk:
            correlations.append({
                "pid": proc["pid"],
                "candidate_path": cand,
                "memory_call_id": proc["memory_call_id"],
                "disk_call_id": disk["disk_call_id"],
                "memory_excerpt": proc["memory_excerpt"],
                "disk_excerpt": disk["disk_excerpt"],
            })

    return {
        "success": True,
        "correlations": correlations,
        "process_records_examined": len(process_records),
        "disk_paths_indexed": len(disk_index),
    }


# ── Network ↔ Process correlation ───────────────────────────────────────────

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PORT_RE = re.compile(r":(\d{1,5})\b")


@mcp.tool()
def network_to_process(ip: Optional[str] = None, port: Optional[int] = None) -> dict:
    """
    Join vol.netscan/netstat connections to vol.pslist/psscan process names
    for the same PID. Surfaces which process owned each suspicious connection.

    ip: optional IP filter (substring match).
    port: optional port filter (exact match).

    Returns:
      connections: list of {pid, process_name, local_endpoint, remote_endpoint,
                            netscan_call_id, pslist_call_id, excerpt}.
    """
    netscan_entries = _recent_tool_stdouts("netscan") + _recent_tool_stdouts("netstat")
    process_entries = _recent_tool_stdouts("pslist") + _recent_tool_stdouts("psscan")

    # Build pid → process_name from process listings.
    pid_to_name: dict[int, dict] = {}
    for e in process_entries:
        for line in e["stdout_excerpt"].splitlines():
            m = re.match(r"\s*\*?\s*(\d+)\s+(\S+)", line)
            if m:
                p = int(m.group(1))
                pid_to_name.setdefault(p, {
                    "name": m.group(2),
                    "pslist_call_id": e["call_id"],
                })

    connections = []
    for e in netscan_entries:
        for line in e["stdout_excerpt"].splitlines():
            ips = _IPV4_RE.findall(line)
            ports = [int(p) for p in _PORT_RE.findall(line)]
            pid_match = re.search(r"\b(\d{2,5})\s+(?:\S+\.exe|\S+)$", line)
            if ip and not any(ip in i for i in ips):
                continue
            if port and port not in ports:
                continue
            if not ips:
                continue
            line_pid = None
            for token in line.split():
                if token.isdigit():
                    v = int(token)
                    if 4 <= v <= 65535 and (pid_match is None or v == int(pid_match.group(1))):
                        line_pid = v
                        break
            proc_info = pid_to_name.get(line_pid or -1, {})
            connections.append({
                "pid": line_pid,
                "process_name": proc_info.get("name", ""),
                "ips": ips,
                "ports": ports,
                "netscan_call_id": e["call_id"],
                "pslist_call_id": proc_info.get("pslist_call_id"),
                "excerpt": line.strip()[:200],
            })

    return {
        "success": True,
        "connections": connections,
        "pids_indexed": len(pid_to_name),
    }


# ── Finding ↔ MITRE ATT&CK mapping ──────────────────────────────────────────

@mcp.tool()
def mitre_map(finding_text: str, top_n: int = 5,
              table_path: Optional[str] = None) -> dict:
    """
    Map a finding to candidate MITRE ATT&CK technique IDs by keyword score.

    finding_text: the finding description (or any investigative text).
    top_n: number of candidates to return.
    table_path: override the default ATT&CK reference path.

    Returns:
      candidates: list of {technique_id, name, tactic, score, matched_keywords}.
                  Sorted by score descending.
    """
    table = _load_mitre(table_path or DEFAULT_MITRE_PATH)
    techniques = table.get("techniques", {})
    if not techniques:
        return {"success": False, "error":
                f"MITRE table not found or empty: {table_path or DEFAULT_MITRE_PATH}"}

    text_lower = finding_text.lower()
    scored: list[dict] = []
    for tid, info in techniques.items():
        keywords = info.get("keywords", []) or []
        matched = []
        for k in keywords:
            kl = k.lower()
            # Word-boundary match so "tor" doesn't match inside "doctor" or
            # "notarealthreat". For multi-word phrases (e.g. "scheduled task"),
            # fall back to substring match since \b doesn't work mid-phrase.
            if " " in kl:
                if kl in text_lower:
                    matched.append(k)
            else:
                if re.search(rf"\b{re.escape(kl)}\b", text_lower):
                    matched.append(k)
        if not matched:
            continue
        scored.append({
            "technique_id": tid,
            "name": info.get("name", ""),
            "tactic": info.get("tactic", ""),
            "score": round(len(matched) / max(len(keywords), 1), 3),
            "matched_keywords": matched,
        })

    scored.sort(key=lambda x: (-x["score"], -len(x["matched_keywords"]), x["technique_id"]))
    return {
        "success": True,
        "candidates": scored[:top_n],
        "techniques_examined": len(techniques),
    }


@mcp.tool()
def mitre_validate(technique_id: str, table_path: Optional[str] = None) -> dict:
    """
    Verify an ATT&CK technique ID exists in the reference table.

    Returns: {exists: bool, name, tactic, description} or {exists: False}.
    Use before writing a technique ID into a report.
    """
    table = _load_mitre(table_path or DEFAULT_MITRE_PATH)
    techniques = table.get("techniques", {})
    info = techniques.get(technique_id)
    if info:
        return {
            "success": True,
            "exists": True,
            "technique_id": technique_id,
            "name": info.get("name", ""),
            "tactic": info.get("tactic", ""),
            "description": info.get("description", ""),
        }
    return {
        "success": True,
        "exists": False,
        "technique_id": technique_id,
        "available_count": len(techniques),
    }
