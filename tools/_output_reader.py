"""Shared reader engine for produced tool output (CSV/JSON/mbox/…).

Streams a produced file, ranks rows/lines by query-term relevance (top-K,
header-preserving, byte-bounded), builds a cheap INVENTORY of an output (row
count, columns, size — cached per file version), and locates a tool's output
file from its recorded cmd. Used by reason.* citation grounding
(tools/reasoning.py: evidence inventory + EVIDENCE_REQUEST fetches) and by the
agent-facing read tools (tools/read_output.py). Pure stdlib; the only
non-stdlib dependency (extract_claims) is imported lazily to avoid a cycle.
"""
import os
import re
from dataclasses import dataclass

# Safety ceiling on bytes scanned from a produced file. The whole file is
# streamed (a match can be anywhere in a large chronological CSV, not the first
# N bytes); this bounds a pathological file, not a read window.
COMPAT_CITED_FILE_BYTES = int(os.environ.get("TRUDI_REASON_CITED_FILE_BYTES") or "268435456")

# One payload-heavy row (an EvtxECmd row carries the full Payload JSON, ~2 KB)
# must never consume a whole file budget. Rows are capped per FIELD first
# (_FIELD_CHARS) so a long early column (HivePath, Payload) cannot push the
# discriminating late columns (ValueName, ValueData) past the row cap
# (_ROW_CHARS) — clipping the row tail was how a reviewer lost the very field it
# asked for. Any clip is reported (ScanResult.clipped_rows / truncated).
_ROW_CHARS = int(os.environ.get("TRUDI_REASON_ROW_CHARS") or "1200")
_FIELD_CHARS = int(os.environ.get("TRUDI_REASON_FIELD_CHARS") or "400")

# An output this small is inlined COMPLETE in the reviewer's evidence inventory
# instead of being summarized — nothing to request.
COMPAT_EVIDENCE_COMPLETE_CHARS = int(os.environ.get("TRUDI_REASON_EVIDENCE_COMPLETE_CHARS") or "600")

# Flags that name a tool's OUTPUT target (file or directory), not input flags.
# --csvf/--jsonf name a file inside the --csv/--json dir; -t/-o name a dir tree.
_OUTPUT_FLAGS = frozenset({
    "--csv", "--json", "--csvf", "--jsonf", "--body", "--bodyf",
    "-o", "--output", "-t", "-w", "-O", "--out", "--outdir",
})
_OUTPUT_FILE_EXTS = (".csv", ".json", ".txt", ".tsv", ".jsonl", ".eml", ".mbox")

_CITED_TOPK = 400   # best-scoring matching lines retained while scanning


@dataclass
class ScanResult:
    body: str = ""
    total_rows: int = 0      # data rows iterated (header excluded)
    matched_rows: int = 0    # rows hitting ≥1 query term
    shown_rows: int = 0      # rows emitted in body (header excluded)
    truncated: bool = False
    clipped_rows: int = 0    # emitted rows that lost characters to a field/row cap
    truncation_reason: str = ""   # "" | "row_clip" | "budget" | "scan_cap" | "scan_error"
    missing_columns: list = None  # requested columns absent from the header
    available_columns: list = None
    columns_ignored: bool = False  # projection dropped (non-CSV / no such columns / csv error)
    scan_error: str = ""           # projected scan aborted (csv.Error …) — line scan used

    @property
    def scan_complete(self) -> bool:
        """Did the scan see the WHOLE source? False after a scan cap or a
        scan error — a miss then proves nothing about absence."""
        return self.truncation_reason not in ("scan_cap", "scan_error") and not self.scan_error

    def _note_trunc(self, reason: str) -> None:
        # Stronger reasons win: scan_cap > budget > row_clip.
        order = {"": 0, "row_clip": 1, "budget": 2, "scan_cap": 3}
        self.truncated = True
        if order.get(reason, 0) > order.get(self.truncation_reason, 0):
            self.truncation_reason = reason


_FIELD_MARK = " …[field truncated]"
_ROW_MARK = " …[row truncated]"


def _cap_line(s: str) -> tuple[str, bool]:
    if len(s) <= _ROW_CHARS:
        return s, False
    return s[:_ROW_CHARS].rstrip() + _ROW_MARK, True


def _cap_fields(cells: list, delim: str) -> tuple[str, bool]:
    """Cap each cell, then the joined row. Returns (text, clipped)."""
    out, clipped = [], False
    for c in cells:
        if len(c) > _FIELD_CHARS:
            out.append(c[:_FIELD_CHARS].rstrip() + _FIELD_MARK); clipped = True
        else:
            out.append(c)
    text, row_clipped = _cap_line(delim.join(out))
    return text, clipped or row_clipped


def _cap_row_text(s: str, delim: str | None) -> tuple[str, bool]:
    """Line-scan row cap: per-field when the file is tabular (delimiter known),
    else a plain line cap."""
    if delim and delim in s:
        return _cap_fields(s.split(delim), delim)
    return _cap_line(s)


def _cap_row(s: str) -> str:
    """Legacy single-string cap (kept for callers outside the scanners)."""
    return _cap_line(s)[0]


def _cited_query_terms(text: str) -> list[str]:
    """Distinctive tokens from a finding used to pull the RELEVANT rows from a
    large output file: emails, SIDs, quoted strings, capitalised identifiers,
    3+ digit numbers, filename tokens, plus artifact literals. Lowercased,
    deduped, short/stop tokens dropped, non-maximal substrings removed. Empty
    list = no filter (head-of-file)."""
    text = text or ""
    terms: set[str] = set()
    for m in re.findall(r"[\w.+-]+@[\w.-]+\.\w+", text):            # emails
        terms.add(m.lower())
    for m in re.findall(r"S-1-5-\d+(?:-\d+)+", text, re.I):         # SIDs
        terms.add(m.lower())
    for m in re.findall(r"'([^'\n]{3,60})'|\"([^\"\n]{3,60})\"", text):  # quoted
        terms.add((m[0] or m[1]).strip().lower())
    for m in re.findall(r"\b[A-Z][A-Za-z0-9]{2,}\b", text):         # proper ids ≥3 chars ("Bob")
        terms.add(m.lower())
    for m in re.findall(r"\b\d{3,}\b", text):                       # event IDs, counts
        terms.add(m)
    # Filename tokens with an extension — single token before the extension so
    # prose isn't grabbed; a spaced name's final token still substring-matches.
    for m in re.findall(r"\b[\w-]+\.[A-Za-z0-9]{1,5}(?:\.[A-Za-z0-9]{1,5})?\b", text):
        if not m[0].isdigit():          # skip bare version numbers like 1.5.2
            terms.add(m.lower())
    try:
        from tools._gates._citation import extract_claims
        for _k, v in extract_claims(text):
            terms.add(v.lower())
    except Exception:
        pass
    _stop = {"true", "false", "none", "null", "this", "that", "with", "from",
             "finding", "evidence", "supporting", "context", "which", "were", "value",
             # generic DFIR/schema nouns that match almost any row and drown the
             # discriminating terms in relevance ranking.
             "user", "account", "name", "date", "time", "size", "type", "path",
             "computer", "host", "record", "event", "system", "windows", "file",
             "profile", "target", "source", "logon", "session", "the", "and",
             # title-case 3-char function words the ≥3-char proper-id regex
             # admits, plus month/day abbreviations (they match nearly every
             # dated row and drown the discriminating terms).
             "not", "for", "was", "has", "are", "all", "any", "its", "one",
             "two", "via", "per", "had", "did", "who", "how", "why", "out",
             "off", "new", "own", "she", "his", "her", "him", "you",
             "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep",
             "oct", "nov", "dec", "mon", "tue", "wed", "thu", "fri", "sat", "sun"}
    kept = [t for t in terms if len(t) >= 3 and t not in _stop]
    # Drop any term that is a substring of a longer kept term, so a SID's numeric
    # fragments don't each score and drown the discriminating terms.
    kept.sort(key=len, reverse=True)
    maximal = []
    for t in kept:
        if not any(t in u for u in maximal):
            maximal.append(t)
    return maximal


def _cmd_output_paths(cmd: str) -> list[str]:
    """Output file/dir paths named in a recorded tool cmd, best-effort."""
    if not cmd:
        return []
    import shlex
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    out = []
    for i, t in enumerate(toks[:-1]):
        if t in _OUTPUT_FLAGS:
            out.append(toks[i + 1])
    return out


def _cmd_input_paths(cmd: str) -> set:
    """Absolute-path tokens a recorded cmd READ (its input artifacts): every
    path-like token that does not follow an output flag. Best-effort and
    symmetric — used only to find sibling calls over the same artifact."""
    if not cmd:
        return set()
    import shlex
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    out: set = set()
    for i, t in enumerate(toks):
        if not t.startswith("/") or len(t) < 4:
            continue
        if i > 0 and toks[i - 1] in _OUTPUT_FLAGS:
            continue
        if t.endswith((".dll", ".py", ".exe")) or "/opt/" in t or "/usr/" in t:
            continue                       # tool binaries, not artifacts
        out.add(os.path.normpath(t))
    return out


def sibling_match_counts(by_id: dict, entry: dict, terms: list, limit: int = 3) -> list[dict]:
    """Full disclosure: other successful tool calls over the SAME input
    artifact, each with its own match count for `terms`. Symmetric — a
    non-empty sibling prevents a false absence; siblings that also match 0
    strengthen it. [{call_id, cmd, rows}] (rows = matched rows/lines)."""
    mine = _cmd_input_paths(str((entry or {}).get("cmd") or ""))
    if not mine:
        return []
    me = int((entry or {}).get("call_id") or 0)
    out: list[dict] = []
    for cid, e in sorted((by_id or {}).items(), key=lambda kv: kv[0] if isinstance(kv[0], int) else 0):
        if not isinstance(e, dict) or int(e.get("call_id") or 0) == me:
            continue
        if e.get("type") != "tool_call" or e.get("success") is not True:
            continue
        if not (mine & _cmd_input_paths(str(e.get("cmd") or ""))):
            continue
        rows = 0
        for src in entry_text_sources(e):
            if src.kind in ("file", "stdout_sidecar"):
                try:
                    rows += _scan_relevant(src.path, terms, 400).matched_rows
                except Exception:
                    continue
            elif src.kind == "stdout_excerpt" and src.text:
                rows += sum(1 for ln in src.text.splitlines()
                            if any(t in ln.lower() for t in terms))
        out.append({"call_id": int(e.get("call_id") or 0),
                    "cmd": str(e.get("cmd") or "")[:80], "rows": rows})
        if len(out) >= limit:
            break
    return out


def _candidate_output_files(tgt: str) -> list[str]:
    """Files behind one output target: a dir → its newest 5 data files; a file →
    itself; a prefix (--csvf names a file inside a sibling --csv dir) → glob."""
    import glob
    try:
        if os.path.isdir(tgt):
            cands = [f for f in glob.glob(os.path.join(tgt, "**", "*"), recursive=True)
                     if os.path.isfile(f) and f.lower().endswith(_OUTPUT_FILE_EXTS)]
            cands.sort(key=lambda f: os.path.getmtime(f), reverse=True)
            return cands[:5]
        if os.path.isfile(tgt):
            return [tgt]
        return sorted(glob.glob(tgt + "*"))[:1] or []
    except OSError:
        return []


# ── Relevance scan ────────────────────────────────────────────────────────────

def _scan_lines(path: str, terms: list[str], budget: int) -> ScanResult:
    """Line-oriented scan. The WHOLE file is streamed (a match can sit anywhere
    in a large chronological CSV) with a bounded top-K by DISTINCT-term score so
    the row hitting the most terms wins over incidental single-term rows —
    without holding the file in memory. Header retained for CSVs; head-of-file
    when there is no filter. Bounded by COMPAT_CITED_FILE_BYTES scanned."""
    import heapq
    res = ScanResult()
    lo_terms = [t for t in terms if t]
    header = ""
    delim = None
    heap = []            # min-heap of (score, -index, (line, clipped)); size ≤ _CITED_TOPK
    head, head_len = [], 0
    scanned = 0
    try:
        with open(path, "r", errors="replace") as fh:
            for i, ln in enumerate(fh):
                scanned += len(ln)
                if scanned > COMPAT_CITED_FILE_BYTES:
                    res._note_trunc("scan_cap")
                    break
                s = ln.rstrip("\n")
                if i == 0 and ("," in s or "\t" in s):
                    header = s
                    delim = "\t" if ("\t" in s and s.count("\t") >= s.count(",")) else ","
                    continue
                res.total_rows += 1
                if not lo_terms:
                    if head_len < budget:
                        head.append(_cap_row_text(s, delim)); head_len += len(s) + 1
                    continue
                low = s.lower()
                n = sum(1 for t in lo_terms if t in low)
                if n:
                    res.matched_rows += 1
                    # -i so that on a score tie the EARLIER line is preferred.
                    heapq.heappush(heap, (n, -i, _cap_row_text(s, delim)))
                    if len(heap) > _CITED_TOPK:
                        heapq.heappop(heap)
    except (OSError, ValueError):
        return res
    if not lo_terms:
        picked = head
    else:
        best = sorted(heap, key=lambda x: (-x[0], -x[1]))   # score desc, then file order
        picked, total = [], 0
        for _n, _negi, item in best:
            picked.append(item); total += len(item[0]) + 1
            if total >= budget:
                break
    res.shown_rows = len(picked)
    res.clipped_rows = sum(1 for _t, c in picked if c)
    if res.clipped_rows:
        res._note_trunc("row_clip")
    lines = [t for t, _c in picked]
    if header and lines:
        lines = [_cap_row_text(header, delim)[0]] + lines
    if not lines:
        return res
    body = "\n".join(lines)
    if len(body) > budget:
        body = body[:budget].rstrip() + " …[truncated]"
        res._note_trunc("budget")
    res.body = body
    return res


def _scan_csv_columns(path: str, terms: list[str], budget: int,
                      columns: list[str]) -> ScanResult | None:
    """CSV/TSV column-aware scan: rank rows by distinct-term hits, keep the
    header, project to `columns` (case-insensitive). None when the file has no
    parseable header or none of the requested columns exist (caller falls back
    to the line scan)."""
    import csv
    import heapq
    res = ScanResult()
    delim = "\t" if path.lower().endswith(".tsv") else ","
    lo_terms = [t for t in terms if t]
    want = [c.strip().lower() for c in columns if c.strip()]
    # EZ-tool CSVs carry registry blobs far past csv's 128 KB field default.
    try:
        csv.field_size_limit(min(2**31 - 1, 512 * 1024 * 1024))
    except (OverflowError, ValueError):
        pass
    try:
        with open(path, "r", errors="replace", newline="") as fh:
            # NUL bytes (binary registry values) abort csv.reader with
            # "line contains NUL" — observed on a RECmd SYSTEM csv after 783 of
            # 5600 rows, which then read as "no rows match; source COMPLETE".
            rdr = csv.reader((ln.replace("\x00", "") for ln in fh), delimiter=delim)
            try:
                fields = next(rdr)
            except StopIteration:
                return None
            norm = [f.lstrip("﻿").strip().lower() for f in fields]
            idx = [norm.index(w) for w in want if w in norm]
            res.available_columns = [f.lstrip("﻿").strip() for f in fields][:40]
            res.missing_columns = [c for c in columns if c.strip() and c.strip().lower() not in norm]
            if not idx:
                # Header parsed but none of the requested columns exist: the
                # caller falls back to the line scan and TELLS the reviewer the
                # projection was ignored (never 0 rows for a projection miss).
                res.columns_ignored = True
                return res

            def project(row):
                return _cap_fields([row[i] if i < len(row) else "" for i in idx], delim)

            header_line = project(fields)[0]
            heap, head, head_len, scanned = [], [], 0, len(",".join(fields))
            for i, row in enumerate(rdr):
                line = delim.join(row)
                scanned += len(line)
                if scanned > COMPAT_CITED_FILE_BYTES:
                    res._note_trunc("scan_cap")
                    break
                res.total_rows += 1
                if not lo_terms:
                    if head_len < budget:
                        p = project(row); head.append(p); head_len += len(p[0]) + 1
                    continue
                low = line.lower()
                n = sum(1 for t in lo_terms if t in low)
                if n:
                    res.matched_rows += 1
                    heapq.heappush(heap, (n, -i, project(row)))
                    if len(heap) > _CITED_TOPK:
                        heapq.heappop(heap)
    except (OSError, ValueError, csv.Error) as e:
        # A mid-file parse error used to return `res` with the matched heap
        # DROPPED and total_rows frozen at the failure point — a silent
        # false "no rows match". Report the error; the caller re-scans by line.
        res.scan_error = f"{type(e).__name__}: {str(e)[:80]}"
        res._note_trunc("scan_error")
        res.columns_ignored = True
        return res
    if not lo_terms:
        picked = head
    else:
        picked, total = [], 0
        for _n, _negi, p in sorted(heap, key=lambda x: (-x[0], -x[1])):
            picked.append(p); total += len(p[0]) + 1
            if total >= budget:
                break
    res.shown_rows = len(picked)
    res.clipped_rows = sum(1 for _t, c in picked if c)
    if res.clipped_rows:
        res._note_trunc("row_clip")
    if not picked:
        return res
    body = header_line + "\n" + "\n".join(t for t, _c in picked)
    if len(body) > budget:
        body = body[:budget].rstrip() + " …[truncated]"
        res._note_trunc("budget")
    res.body = body
    return res


_DELIMITED_EXTS = (".csv", ".tsv")


def _scan_relevant(path: str, terms: list[str], budget: int,
                   columns: list[str] | None = None) -> ScanResult:
    """Column projection is best-effort: on a non-delimited source (mbox,
    txt, sidecar), on a header with none of the requested columns, or on a
    csv parse error, the LINE scan runs and the result says the columns were
    ignored. A projection miss must never turn into "0 rows" — observed six
    times in one run, blinding the reviewer to the rows it asked for."""
    if columns:
        if path.lower().endswith(_DELIMITED_EXTS):
            r = _scan_csv_columns(path, terms, budget, columns)
            if r is not None and not r.columns_ignored:
                return r
            fallback = _scan_lines(path, terms, budget)
            fallback.columns_ignored = True
            if r is not None:
                fallback.missing_columns = r.missing_columns
                fallback.available_columns = r.available_columns
                fallback.scan_error = r.scan_error
            else:
                fallback.missing_columns = list(columns)
            return fallback
        r = _scan_lines(path, terms, budget)
        r.columns_ignored = True
        r.missing_columns = list(columns)
        return r
    return _scan_lines(path, terms, budget)


def _read_relevant_from_file(path: str, terms: list[str], budget: int) -> str:
    return _scan_lines(path, terms, budget).body


def _read_relevant_csv_columns(path: str, terms: list[str], budget: int,
                               columns: list[str]) -> str:
    return _scan_relevant(path, terms, budget, columns).body


def read_relevant(path: str, terms: list[str], budget: int,
                  columns: list[str] | None = None) -> str:
    """Public entry point. Line-scan (header-preserving top-K) by default;
    when `columns` is given and the file is CSV/TSV, project to those columns
    (case-insensitive) after ranking. Returns '' on error/empty."""
    return _scan_relevant(path, terms, budget, columns).body


def read_relevant_stats(path: str, terms: list[str], budget: int,
                        columns: list[str] | None = None) -> ScanResult:
    """As read_relevant, but with the scan statistics (total/matched/shown rows,
    truncation) — what an evidence fetch reports back to the reviewer."""
    return _scan_relevant(path, terms, budget, columns)


# ── Cited-output resolution (push mode) ───────────────────────────────────────

def _resolve_paths_stats(files: list[str], terms: list[str], budget: int,
                         columns: list[str] | None = None) -> tuple[str, list[dict]]:
    """Read the RELEVANT part of the given output files, plus per-file scan
    stats. Each chunk carries an inventory line so a truncated read is visible
    as such. '' if nothing usable."""
    remaining = budget
    chunks, stats = [], []
    for f in files:
        if remaining <= 0:
            break
        if True:
            r = _scan_relevant(f, terms, remaining, columns)
            if not r.body:
                continue
            shown_terms = ", ".join(terms[:6]) + ("…" if len(terms) > 6 else "")
            head = (f"  ({os.path.basename(f)}): {r.total_rows} rows; "
                    f"{r.matched_rows} match [{shown_terms}]; showing {r.shown_rows}")
            if r.shown_rows < r.matched_rows:
                head += " — request more via EVIDENCE_REQUEST"
            chunks.append(f"{head}\n{r.body}")
            stats.append({"file": f, "total_rows": r.total_rows,
                          "matched_rows": r.matched_rows, "shown_rows": r.shown_rows,
                          "truncated": r.truncated, "clipped_rows": r.clipped_rows,
                          "truncation_reason": r.truncation_reason})
            remaining -= len(r.body)
    return "\n".join(chunks), stats


def _resolve_cited_output_stats(cmd: str, terms: list[str], budget: int,
                                columns: list[str] | None = None) -> tuple[str, list[dict]]:
    files = [f for tgt in _cmd_output_paths(cmd) for f in _candidate_output_files(tgt)]
    return _resolve_paths_stats(files, terms, budget, columns)


def _resolve_cited_output(cmd: str, terms: list[str], budget: int) -> str:
    return _resolve_cited_output_stats(cmd, terms, budget)[0]


# ── Text sources of a trace entry ─────────────────────────────────────────────

@dataclass
class TextSource:
    """One place the text of a cited call can be read from.

    kind: "file" (the tool's own artifact: --csv dir, output_path),
          "stdout_sidecar" (the complete stdout persisted by the trace),
          "stdout_excerpt" (the ≤600-char excerpt on the entry — COMPLETE only
          when the trace recorded that the whole stdout fit in it),
          "conclusion" (a reason_call's text).
    complete: whether this source holds the WHOLE output. A miss over a
          PARTIAL source is not evidence of absence."""
    kind: str
    path: str = ""
    text: str = ""
    complete: bool = True
    total_chars: int = 0
    stored_chars: int = 0
    label: str = ""


def entry_text_sources(entry: dict) -> list[TextSource]:
    """Ordered, fetchable text sources for a trace entry — files first (the
    tool's artifact, then the full-stdout sidecar), then the stored excerpt."""
    out: list[TextSource] = []
    if not isinstance(entry, dict):
        return out
    if entry.get("type") == "reason_call":
        concl = (entry.get("conclusion") or "").strip()
        out.append(TextSource("conclusion", text=concl, complete=True,
                              total_chars=len(concl), stored_chars=len(concl),
                              label=str(entry.get("tool") or "reason")))
        return out
    seen: set[str] = set()
    op = entry.get("output_path")
    if op:
        for f in _candidate_output_files(str(op)):
            if f not in seen:
                seen.add(f); out.append(TextSource("file", path=f, label=os.path.basename(f)))
    for tgt in _cmd_output_paths(entry.get("cmd") or ""):
        for f in _candidate_output_files(tgt):
            if f not in seen:
                seen.add(f); out.append(TextSource("file", path=f, label=os.path.basename(f)))
    sp = entry.get("stdout_path")
    if sp and os.path.isfile(sp):
        out.append(TextSource("stdout_sidecar", path=sp,
                              complete=not entry.get("stdout_partial"),
                              total_chars=int(entry.get("stdout_chars") or 0),
                              label="stdout (complete)"))
    excerpt = (entry.get("stdout_excerpt") or "").strip()
    if excerpt or not out:
        total = entry.get("stdout_chars")
        if total is None:
            # Legacy entry (no stdout_chars): the excerpt is complete only when
            # it is clearly under the cap and the executor did not truncate.
            complete = len(excerpt) < 590 and not entry.get("truncated")
            total = len(excerpt)
        else:
            total = int(total)
            complete = total <= len(entry.get("stdout_excerpt") or "")
        out.append(TextSource("stdout_excerpt", text=excerpt, complete=bool(complete),
                              total_chars=int(total), stored_chars=len(excerpt),
                              label="stdout excerpt"))
    return out


def entry_output_inventory(entry: dict, terms: list[str]) -> list[dict]:
    """Inventory of an entry's FILE-like sources (artifact files and the
    full-stdout sidecar): file, kind, bytes, total_rows, columns, term_hits,
    complete-text when small. The stdout excerpt is not a file and is handled
    by the caller from entry_text_sources()."""
    out = []
    for src in entry_text_sources(entry):
        if src.kind not in ("file", "stdout_sidecar"):
            continue
        try:
            inv = _file_inventory(src.path)
        except OSError:
            continue
        item = {"file": src.path, "kind": src.kind, "label": src.label,
                "bytes": inv["bytes"], "total_rows": inv["total_rows"],
                "columns": inv["columns"], "term_hits": _term_hits(src.path, terms, inv["bytes"]),
                "complete": None, "source_complete": src.complete}
        if inv["bytes"] <= COMPAT_EVIDENCE_COMPLETE_CHARS and src.complete:
            try:
                with open(src.path, "r", errors="replace") as fh:
                    item["complete"] = fh.read(COMPAT_EVIDENCE_COMPLETE_CHARS + 1).rstrip()
            except OSError:
                pass
        out.append(item)
    return out


# ── Evidence inventory (pull mode) ────────────────────────────────────────────

# (path, size, mtime) → {bytes, total_rows, columns}. Row counting is a full
# pass; a 250 MB CSV is counted once per server lifetime, not per reviewer call.
_INVENTORY_CACHE: dict[tuple, dict] = {}

# Term-hit counting is a per-call scan; skip it for files past this size and
# report "?" so a reviewer call never waits on a huge file just for a hint.
_TERM_HITS_MAX_BYTES = 64 * 1024 * 1024


def _file_inventory(path: str) -> dict:
    st = os.stat(path)
    key = (path, st.st_size, int(st.st_mtime))
    hit = _INVENTORY_CACHE.get(key)
    if hit is not None:
        return hit
    total, columns, scanned = 0, [], 0
    low = path.lower()
    is_table = low.endswith((".csv", ".tsv"))
    delim = "\t" if low.endswith(".tsv") else ","
    try:
        with open(path, "r", errors="replace") as fh:
            for i, ln in enumerate(fh):
                scanned += len(ln)
                if scanned > COMPAT_CITED_FILE_BYTES:
                    break
                if i == 0 and is_table:
                    columns = [c.strip().lstrip("﻿") for c in ln.rstrip("\n").split(delim)][:20]
                    continue
                total += 1
    except OSError:
        pass
    inv = {"bytes": st.st_size, "total_rows": total, "columns": columns}
    if len(_INVENTORY_CACHE) > 512:
        _INVENTORY_CACHE.clear()
    _INVENTORY_CACHE[key] = inv
    return inv


def _term_hits(path: str, terms: list[str], size: int) -> int | None:
    lo = [t for t in terms if t]
    if not lo or size > _TERM_HITS_MAX_BYTES:
        return None
    n = 0
    try:
        with open(path, "r", errors="replace") as fh:
            for i, ln in enumerate(fh):
                if i == 0:
                    continue
                low = ln.lower()
                if any(t in low for t in lo):
                    n += 1
    except OSError:
        return None
    return n


def output_inventory(cmd: str, terms: list[str]) -> list[dict]:
    """What a tool's recorded cmd produced, without reading it into the prompt:
    one dict per output file — file, bytes, total_rows, columns, term_hits, and
    `complete` (the whole content) when the output is small enough to inline."""
    out = []
    for tgt in _cmd_output_paths(cmd):
        for f in _candidate_output_files(tgt):
            try:
                inv = _file_inventory(f)
            except OSError:
                continue
            item = {"file": f, "bytes": inv["bytes"], "total_rows": inv["total_rows"],
                    "columns": inv["columns"], "term_hits": _term_hits(f, terms, inv["bytes"]),
                    "complete": None}
            if inv["bytes"] <= COMPAT_EVIDENCE_COMPLETE_CHARS:
                try:
                    with open(f, "r", errors="replace") as fh:
                        item["complete"] = fh.read(COMPAT_EVIDENCE_COMPLETE_CHARS + 1).rstrip()
                except OSError:
                    pass
            out.append(item)
    return out
