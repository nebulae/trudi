"""Parsed output a run produced but never read.

A bulk parser (MVT, ios_apt, a RECmd batch) writes dozens of tables, and the
agent tends to read the few it expected. On Bogus Bill the answers to two
flags sat in tables nobody opened: ios_apt Wifi.csv (the ATM-night network)
and MVT shortcuts.json (the cipher shortcuts), and the printer that a negative
denied was in RECmd's system_USB.csv.

Tools stamp `parsed_outputs` — every output file holding at least one record —
on their trace entry. A file is READ when a read.output call names it, and
SETTLED when a source disposition names the file or its directory
(misc.record_disposition(target_kind="source", target_id=<path>,
reason="inapplicable"|"out_of_scope")). The rest are leads: DAIR sees them from
Collect on, pre_report_check warns, the report lists them. Never a blocker.
"""
from __future__ import annotations

import csv
import json
import os
import time

_ROWS_MAX_BYTES = 64 * 1024 * 1024       # count rows only in files this small
_TABLE_EXTS = (".csv", ".tsv", ".json", ".jsonl")
_STAMP_CAP = 300


def count_rows(path: str) -> int | None:
    """Records in a produced file: JSON array length, CSV/TSV rows (header
    excluded), JSONL lines. None for other or large files."""
    low = path.lower()
    try:
        if os.path.getsize(path) > _ROWS_MAX_BYTES:
            return None
        if low.endswith(".json"):
            with open(path, "r", errors="replace") as fh:
                data = json.load(fh)
            return len(data) if isinstance(data, list) else None
        if low.endswith(".jsonl"):
            with open(path, "rb") as fh:
                return sum(1 for ln in fh if ln.strip())
        if low.endswith((".csv", ".tsv")):
            csv.field_size_limit(min(2**31 - 1, 512 * 1024 * 1024))
            with open(path, "r", errors="replace", newline="") as fh:
                rdr = csv.reader((ln.replace("\x00", "") for ln in fh),
                                 delimiter="\t" if low.endswith(".tsv") else ",")
                return max(0, sum(1 for _ in rdr) - 1)
    except Exception:
        return None
    return None


def collect(out_dir: str, since: float | None = None, skip_dirs: tuple = ()) -> list[dict]:
    """[{file, rows}] for table files under out_dir with ≥1 record, written at or
    after `since` (so a reused output dir does not re-credit an older run)."""
    out: list[dict] = []
    if not out_dir or not os.path.isdir(out_dir):
        return out
    for dp, dn, fn in os.walk(out_dir):
        if os.path.relpath(dp, out_dir).split(os.sep)[0] in skip_dirs:
            dn[:] = []
            continue
        for n in sorted(fn):
            if not n.lower().endswith(_TABLE_EXTS):
                continue
            p = os.path.abspath(os.path.join(dp, n))
            try:
                if since is not None and os.path.getmtime(p) < since - 1:
                    continue
            except OSError:
                continue
            rows = count_rows(p)
            if rows:
                out.append({"file": p, "rows": rows})
            if len(out) >= _STAMP_CAP:
                return out
    return out


def stamp(result: dict, out_dir: str, since: float | None = None, skip_dirs: tuple = ()) -> None:
    """Annotate the tool_call entry with its parsed outputs. Best-effort."""
    cid = result.get("_trudi_call_id")
    if not cid or not result.get("success"):
        return
    try:
        files = collect(out_dir, since, skip_dirs)
        if files:
            from core.execution_log import log
            log.annotate_tool_call(cid, parsed_outputs=files)
    except Exception:
        pass


def now() -> float:
    return time.time()


def _norm(p: str) -> str:
    return "".join(os.path.abspath(p).lower().split())


def unread(entries: list) -> list[dict]:
    """Stamped output files no read.output call named and no source disposition
    settled: [{file, rows, call_id, tool}], newest producer first."""
    reads: list[str] = []
    settled: set[str] = set()
    produced: list[dict] = []
    for e in entries or []:
        t = e.get("type")
        if t == "tool_call":
            cmd = str(e.get("cmd") or "")
            if cmd.startswith(("read.output", "read.read_output")) or \
                    e.get("mcp_tool") in ("read_output", "read.output"):
                reads.append(cmd.lower())
            for f in e.get("parsed_outputs") or []:
                if isinstance(f, dict) and f.get("file"):
                    produced.append({**f, "call_id": e.get("call_id"),
                                     "tool": e.get("mcp_tool") or cmd.split(" ")[0]})
        elif t == "disposition" and str(e.get("target_kind") or "").lower() == "source":
            settled.add(_norm(str(e.get("target_id") or "")))
    seen, out = set(), []
    for f in reversed(produced):
        path = f["file"]
        if path in seen:
            continue
        seen.add(path)
        low = path.lower()
        if any(low in r for r in reads):
            continue
        n = _norm(path)
        if n in settled or any(n.startswith(s.rstrip("/") + "/") for s in settled if s):
            continue
        out.append(f)
    return out


def dair_block(entries: list, phase: str, limit: int = 25) -> str:
    """DAIR lead block: unread parsed tables, from Collect on."""
    if phase not in ("Collect", "Analyze", "Scan", "Report"):
        return ""
    items = unread(entries)
    if not items:
        return ""
    lines = [f"\nUNREAD PARSER OUTPUT ({len(items)} table(s) holding records that no "
             f"read.output call has opened — answers often sit in the tables nobody "
             f"expected; prescribe read.output on the relevant ones, or settle a table "
             f"or its directory with misc.record_disposition(target_kind=\"source\", "
             f"target_id=\"<path>\", reason=\"inapplicable\")):"]
    for f in items[:limit]:
        lines.append(f"- {f['file']} ({f['rows']} records; from {f['tool']} call {f['call_id']})")
    if len(items) > limit:
        lines.append(f"- … {len(items) - limit} more")
    return "\n".join(lines)
