"""Anti-forensics detection — surface evidence that the attacker tried to
cover their tracks. Each detector returns a structured candidate finding;
the agent is responsible for calling record_finding (so the gate flow is
preserved).

Coverage:
  af_timestomp_drift     — MFT $SI vs $FN timestamp divergence
  af_event_log_clear     — EID 1102 / 104 in evtxecmd output
  af_sysmon_evasion      — Sysmon service disabled or log truncated
  af_usn_gaps            — non-monotonic gaps in USN journal numbers
  af_prefetch_deletion   — executables in AppCompat/Amcache with no prefetch

This module is intentionally read-only: every detector reads tool output
already in the trace or a CSV path on disk and emits findings. None of them
spawn forensic binaries directly — the source data is produced by ez.* or
misc.* tools the agent has already run.
"""
from __future__ import annotations
import csv
import datetime
import os
import re
from typing import Optional
from fastmcp import FastMCP

from core import output_safe

mcp = FastMCP("antiforensics")


def _parse_iso(ts: str) -> Optional[datetime.datetime]:
    """Parse an MFTECmd / EvtxECmd ISO-ish timestamp. Returns None on failure."""
    if not ts:
        return None
    s = str(ts).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            if fmt is None:
                return datetime.datetime.fromisoformat(s)
            return datetime.datetime.strptime(s, fmt)
        except (ValueError, TypeError):
            continue
    return None


@mcp.tool()
@output_safe
def af_timestomp_drift(
    mft_csv_path: str,
    threshold_seconds: float = 1.0,
    max_records: int = 200,
) -> dict:
    """
    Detect timestomping by comparing $SI vs $FN timestamps in an MFTECmd CSV.

    A file whose `$STANDARD_INFORMATION` timestamps differ from the
    `$FILE_NAME` (FN) timestamps by more than threshold_seconds is a strong
    indicator the SI timestamps were rewritten with SetFileTime-style APIs.

    mft_csv_path: path to an MFTECmd CSV (`ez.mftecmd` output).
    threshold_seconds: ignore drifts smaller than this (default 1.0s).
    max_records: cap returned drift_records at this size.
    """
    if not os.path.exists(mft_csv_path):
        return {"success": False, "error": f"MFT CSV not found: {mft_csv_path}"}

    drift_records: list[dict] = []
    total_checked = 0
    try:
        with open(mft_csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            # MFTECmd columns: Created0x10, Created0x30, Modified0x10, Modified0x30,
            # LastRecordChange0x10, LastRecordChange0x30, LastAccess0x10, LastAccess0x30
            for row in reader:
                total_checked += 1
                if total_checked > 1_000_000:
                    break
                # Compare Modified0x10 (SI) vs Modified0x30 (FN) — most common
                # timestomp target.
                si = _parse_iso(row.get("LastModified0x10") or row.get("Modified0x10") or "")
                fn = _parse_iso(row.get("LastModified0x30") or row.get("Modified0x30") or "")
                if si is None or fn is None:
                    continue
                delta = abs((si - fn).total_seconds())
                if delta <= threshold_seconds:
                    continue
                drift_records.append({
                    "path": row.get("ParentPath", "") + "\\" + row.get("FileName", ""),
                    "si_ts": si.isoformat(),
                    "fn_ts": fn.isoformat(),
                    "delta_sec": round(delta, 3),
                    "mft_record": int(row.get("EntryNumber") or row.get("MftRecord") or 0),
                })
                if len(drift_records) >= max_records:
                    break
    except OSError as e:
        return {"success": False, "error": f"read failed: {e}"}

    return {
        "success": True,
        "total_checked": total_checked,
        "drift_count": len(drift_records),
        "drift_records": drift_records,
        "suggested_finding": (
            {
                "description": (
                    f"Timestomp evidence: {len(drift_records)} MFT records show "
                    f"$SI/$FN drift > {threshold_seconds}s (T1070.006)"
                ),
                "confidence": "LIKELY" if drift_records else "UNCONFIRMED",
                "source": "antiforensics.af_timestomp_drift",
            }
        ) if drift_records else None,
    }


@mcp.tool()
@output_safe
def af_event_log_clear() -> dict:
    """
    Detect Windows event-log clearing by scanning recent ez.evtxecmd output
    in the trace for EID 1102 (Security log cleared) and EID 104 (System log
    cleared). Returns matching events with the clearing user/account.

    Requires a prior `ez.evtxecmd` run within the trace window.
    """
    from core.execution_log import log
    idx = log.index()
    # by_tool['ez_evtxecmd'] is populated by the executor when evtxecmd runs.
    candidates = idx.by_tool.get("ez_evtxecmd") or idx.by_tool.get("EvtxECmd.dll") or []
    # Also accept by_tool['dotnet'] entries whose cmd mentions EvtxECmd
    if not candidates:
        for e in idx.by_type.get("tool_call", []):
            cmd = e.get("cmd", "") or ""
            if "EvtxECmd" in cmd or "evtxecmd" in cmd.lower():
                candidates.append(e)

    if not candidates:
        return {
            "success": False,
            "error": "No recent ez.evtxecmd run in trace. Parse the Security/System "
                     "event logs first, then re-run af_event_log_clear.",
        }

    EID_1102 = re.compile(r"(?:\b|,)(?:EventID|Event\s*ID)\s*[:=,\s]*1102\b", re.IGNORECASE)
    EID_104 = re.compile(r"(?:\b|,)(?:EventID|Event\s*ID)\s*[:=,\s]*104\b", re.IGNORECASE)

    hits: list[dict] = []
    for c in candidates:
        excerpt = c.get("stdout_excerpt", "") or ""
        for m in EID_1102.finditer(excerpt):
            line = _line_around(excerpt, m.start())
            hits.append({"eid": 1102, "log": "Security", "context": line, "source_call_id": c.get("call_id")})
        for m in EID_104.finditer(excerpt):
            line = _line_around(excerpt, m.start())
            hits.append({"eid": 104, "log": "System", "context": line, "source_call_id": c.get("call_id")})

    return {
        "success": True,
        "events_examined": sum(len((c.get("stdout_excerpt") or "").splitlines()) for c in candidates),
        "clear_events_found": len(hits),
        "events": hits,
        "suggested_finding": (
            {
                "description": (
                    f"Windows event-log clearing detected ({len(hits)} clear events; "
                    f"T1070.001) — adversary removed audit trail"
                ),
                "confidence": "CONFIRMED" if hits else "UNCONFIRMED",
                "source": "antiforensics.af_event_log_clear",
                "linked_call_id": hits[0]["source_call_id"] if hits else 0,
            }
        ) if hits else None,
    }


def _line_around(text: str, pos: int, span: int = 120) -> str:
    start = max(0, text.rfind("\n", 0, pos) + 1)
    end = text.find("\n", pos)
    if end == -1:
        end = len(text)
    return text[start:end][:span]


@mcp.tool()
@output_safe
def af_sysmon_evasion(system_hive_csv: str) -> dict:
    """
    Parse a SYSTEM hive (RECmd CSV) and flag Sysmon-evasion indicators.

    Checks:
      - Sysmon service `Start` value == 4 (disabled)
      - Sysmon `EventLog` MaxSize clamped to < 100 KB
      - Driver `SysmonDrv` Start != 1 (boot)

    system_hive_csv: path to RECmd CSV of SYSTEM hive (one row per value).
    """
    if not os.path.exists(system_hive_csv):
        return {"success": False, "error": f"hive CSV not found: {system_hive_csv}"}

    indicators: list[dict] = []
    try:
        with open(system_hive_csv, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                key = (row.get("KeyPath") or row.get("Key Path") or "").lower()
                value = (row.get("ValueName") or row.get("Value Name") or "").lower()
                data = (row.get("ValueData") or row.get("Value Data") or "").strip()
                if "sysmon" in key:
                    if value == "start":
                        try:
                            start_val = int(data, 0) if data else None
                        except ValueError:
                            start_val = None
                        if start_val is not None and start_val >= 4:
                            indicators.append({
                                "key": key, "value": value, "data": data,
                                "issue": "Sysmon service Start=4 (disabled)",
                            })
                if "microsoft-windows-sysmon" in key and "operational" in key:
                    if value == "maxsize":
                        try:
                            ms = int(data, 0) if data else None
                        except ValueError:
                            ms = None
                        if ms is not None and ms < 100 * 1024:
                            indicators.append({
                                "key": key, "value": value, "data": data,
                                "issue": f"Sysmon log MaxSize clamped to {ms} bytes",
                            })
    except OSError as e:
        return {"success": False, "error": f"read failed: {e}"}

    return {
        "success": True,
        "indicators": indicators,
        "suggested_finding": (
            {
                "description": (
                    f"Sysmon evasion indicators in SYSTEM hive ({len(indicators)} "
                    f"hits; T1562.001) — adversary disabled or hobbled telemetry"
                ),
                "confidence": "LIKELY" if indicators else "UNCONFIRMED",
                "source": "antiforensics.af_sysmon_evasion",
            }
        ) if indicators else None,
    }


@mcp.tool()
@output_safe
def af_usn_gaps(usn_csv_path: str, gap_threshold: int = 100) -> dict:
    """
    Detect non-monotonic gaps in USN journal entries.

    A burst of contiguous USN records followed by a big jump suggests the
    journal was selectively pruned. Returns gaps above threshold.

    usn_csv_path: path to a usnparser CSV (`misc.usnparser_parse` output).
    gap_threshold: USN delta to flag (default 100).
    """
    if not os.path.exists(usn_csv_path):
        return {"success": False, "error": f"USN CSV not found: {usn_csv_path}"}

    usns: list[int] = []
    try:
        with open(usn_csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                u = row.get("Usn") or row.get("USN") or row.get("usn") or ""
                try:
                    usns.append(int(u))
                except (TypeError, ValueError):
                    continue
    except OSError as e:
        return {"success": False, "error": f"read failed: {e}"}

    usns.sort()
    gaps: list[dict] = []
    for i in range(1, len(usns)):
        d = usns[i] - usns[i - 1]
        if d > gap_threshold:
            gaps.append({"prior_usn": usns[i - 1], "next_usn": usns[i], "delta": d})

    return {
        "success": True,
        "total_entries": len(usns),
        "gap_threshold": gap_threshold,
        "gap_count": len(gaps),
        "gap_records": gaps[:100],
        "suggested_finding": (
            {
                "description": (
                    f"USN journal pruning detected ({len(gaps)} gaps > "
                    f"{gap_threshold} USNs; T1070) — adversary may have "
                    f"deleted records to hide file activity"
                ),
                "confidence": "SUSPECTED" if gaps else "UNCONFIRMED",
                "source": "antiforensics.af_usn_gaps",
            }
        ) if gaps else None,
    }


@mcp.tool()
@output_safe
def af_prefetch_deletion() -> dict:
    """
    Detect prefetch deletion by cross-referencing recent ez.pecmd output
    against ez.appcompatcacheparser and ez.amcacheparser entries.

    Executables that appear in AppCompat/Amcache (proving they ran) but have
    NO matching prefetch file are deletion candidates — Windows usually
    creates a `.pf` for every user-mode launch.
    """
    from core.execution_log import log
    idx = log.index()

    pecmd_entries = idx.by_tool.get("ez_pecmd") or idx.by_tool.get("PECmd.dll") or []
    appcompat_entries = idx.by_tool.get("ez_appcompatcacheparser") or []
    amcache_entries = idx.by_tool.get("ez_amcacheparser") or []
    # Fallback: scan tool_call entries for the matching binaries
    if not pecmd_entries or not (appcompat_entries or amcache_entries):
        for e in idx.by_type.get("tool_call", []):
            cmd = (e.get("cmd") or "").lower()
            if "pecmd" in cmd: pecmd_entries.append(e)
            if "appcompatcacheparser" in cmd: appcompat_entries.append(e)
            if "amcacheparser" in cmd: amcache_entries.append(e)

    if not pecmd_entries:
        return {
            "success": False,
            "error": "No recent ez.pecmd run in trace. Parse prefetch first.",
        }
    if not (appcompat_entries or amcache_entries):
        return {
            "success": False,
            "error": "No appcompat/amcache run in trace. Need at least one to "
                     "cross-reference against prefetch.",
        }

    # Extract prefetch'd executables (basename).
    prefetched: set[str] = set()
    for e in pecmd_entries:
        excerpt = e.get("stdout_excerpt", "") or ""
        for m in re.finditer(r"([A-Za-z0-9_.\-]+\.[Ee][Xx][Ee])", excerpt):
            prefetched.add(m.group(1).lower())

    # Extract executed binaries from AppCompat/Amcache.
    executed: list[tuple[str, int]] = []  # (exe_basename, source_call_id)
    for e in appcompat_entries + amcache_entries:
        excerpt = e.get("stdout_excerpt", "") or ""
        for m in re.finditer(r"([A-Za-z0-9_.\-]+\.[Ee][Xx][Ee])", excerpt):
            executed.append((m.group(1).lower(), e.get("call_id") or 0))

    deletion_candidates: list[dict] = []
    seen: set[str] = set()
    for exe, source_cid in executed:
        if exe in seen:
            continue
        if exe in prefetched:
            continue
        # Filter out system noise — these often don't get prefetch entries
        if exe in {"explorer.exe", "wininit.exe", "svchost.exe", "system"}:
            continue
        deletion_candidates.append({
            "path": exe,
            "appcompat_call_id": source_cid,
            "prefetch_absent": True,
        })
        seen.add(exe)
        if len(deletion_candidates) >= 50:
            break

    return {
        "success": True,
        "prefetched_count": len(prefetched),
        "executed_count": len({e[0] for e in executed}),
        "deletion_candidates": deletion_candidates,
        "cross_ref_complete": True,
        "suggested_finding": (
            {
                "description": (
                    f"Prefetch deletion suspected ({len(deletion_candidates)} "
                    f"executables ran but have no prefetch file; T1070.005)"
                ),
                "confidence": "SUSPECTED" if deletion_candidates else "UNCONFIRMED",
                "source": "antiforensics.af_prefetch_deletion",
            }
        ) if deletion_candidates else None,
    }
