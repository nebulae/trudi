"""read.* — traced, citable readers for produced tool output.

The forensic extractors (ez.*, misc.readpst_extract/pff_export, chainsaw, capa,
floss, carve.*) write records to a file/dir and return only a banner + path.
These tools read that produced output — filtered to what matters — so the agent
never needs raw Bash (cat/jq/grep/python) for the content-read step. Each read
self-logs a tool_call with the file behind an output flag, so it gets a real
_trudi_call_id (citable in a finding) and the reviewer's cited-file expansion can
re-read it. Read-only; only reads under analysis/ exports/ reports/.
"""
import os
from fastmcp import FastMCP
from core import assert_readable_output
from core.paths import resolve_path_ci
from core.executor import _log_tool, OUTPUT_CAP
from tools._output_reader import read_relevant, _read_relevant_from_file

mcp = FastMCP("read")

_EXCERPT = 600   # trace stdout_excerpt is capped ~600; the cmd path is the citable source



# Output markers for the tier contract: STRUCTURAL only (never vocabulary —
# a body merely mentioning "attachment" or a filename must not become a
# transfer artifact). Attachment = an actual MIME attachment part; receipt =
# a bounce-daemon sender whose body carries an SMTP status/diagnostic code.
import re as _re
_DSN_CODE_RE = _re.compile(r"\b[245]\d\d\b\s+\d\.\d+\.\d+|\bstatus\s*[:=]?\s*[245]\.\d+\.\d+"
                           r"|\bdiagnostic-code\b|\bdelivery status notification\b", _re.IGNORECASE)

def _query_terms(query: str) -> list[str]:
    """Literal terms from an agent query (whitespace/comma split, len>=2)."""
    import re
    return [t for t in re.split(r"[\s,]+", (query or "").lower()) if len(t) >= 2]


def _guard(path: str):
    """Resolve+validate a produced-output path. Returns (resolved, None) or
    (None, error_dict)."""
    try:
        resolved = assert_readable_output(path)
    except ValueError as e:
        return None, {"success": False, "error": str(e),
                      "hint": "Extract the artifact via its typed wrapper first, "
                              "then read the produced file under analysis/exports/reports."}
    if not os.path.exists(resolved):
        corrected, _ = resolve_path_ci(resolved)
        return None, {"success": False, "error": f"file not found: {path}",
                      "hint": f"nearest match: {corrected}" if corrected != resolved else
                              "check the extractor's output_dir/output_file."}
    return resolved, None


def _selflog(cmd: str, body: str, success: bool = True) -> int:
    """Self-log a read as a tool_call so it is citable; return _trudi_call_id."""
    result = {"success": success, "stdout": (body or "")[:_EXCERPT], "stderr": "",
              "exit_code": 0 if success else 1, "truncated": False, "retries": 0,
              "elapsed_seconds": 0.0, "cmd": cmd,
              # Full body → stdout sidecar (E-01): the reviewer must be able to
              # fetch exactly the rows/columns the agent read, not a 600-char
              # head of them ("excerpt omits the MAC/MachineID columns").
              "_stdout_full": body or "", "_stdout_chars": len(body or "")}
    try:
        _log_tool(result)
    except Exception:
        pass
    return result.get("_trudi_call_id") or 0


@mcp.tool()
def read_output(path: str, query: str = "", columns: str = "", where: str = "",
                max_rows: int = 200, max_chars: int = 20000) -> dict:
    """Read a PRODUCED-OUTPUT file (CSV/TSV/JSON/JSONL/TXT) under analysis/,
    exports/, or reports/ and return the rows/lines most relevant to `query`.
    Traced and citable — use this instead of Bash (python csv / jq / grep) so the
    read is recorded with a call_id and the reviewer can re-verify it.

    query:   space/comma-separated terms; rows are ranked by how many distinct
             terms they contain (whole file scanned, header kept). Empty → head.
    columns: CSV only — comma-separated column names to project (case-insensitive).
    where:   CSV only — a single 'column=value' exact-match row filter.
    max_rows/max_chars: output caps; `truncated` is set when hit.

    NEVER reads raw evidence or mounted volumes — extract first via ez.*,
    plaso.*, misc.readpst_extract, etc. Returns _trudi_call_id for record_finding.
    """
    resolved, err = _guard(path)
    if err:
        return err
    terms = _query_terms(query)
    cols = [c.strip() for c in columns.split(",") if c.strip()] or None
    budget = max(500, min(int(max_chars), OUTPUT_CAP))

    where_col = where_val = None
    if where and "=" in where:
        where_col, where_val = (s.strip() for s in where.split("=", 1))

    if cols or where_col:
        body = _read_csv(resolved, terms, budget, cols, where_col, where_val, max_rows)
    else:
        body = read_relevant(resolved, terms, budget)
        if body and max_rows:
            lines = body.split("\n")
            if len(lines) > max_rows + 1:
                body = "\n".join(lines[:max_rows + 1]) + "\n…[row cap]"

    _cmd = f"read.read_output --output {resolved}"
    if query:   _cmd += f" query={query[:80]}"
    if cols:    _cmd += f" columns={','.join(cols)}"
    if where:   _cmd += f" where={where[:60]}"
    cid = _selflog(_cmd, body)
    truncated = bool(body) and ("[truncated]" in body or "[row cap]" in body)
    return {"success": True, "_trudi_call_id": cid, "path": resolved,
            "query": query, "columns": cols or [], "where": where or "",
            "body": body, "truncated": truncated,
            "hint": "cite this _trudi_call_id in record_finding"}


def _read_csv(path, terms, budget, cols, where_col, where_val, max_rows) -> str:
    """CSV/TSV column-aware read with an optional exact where-filter, then the
    shared term-ranked projection. Falls back to a line-scan if not parseable."""
    import csv
    delim = "\t" if path.lower().endswith(".tsv") else ","
    if where_col:
        # Pre-filter rows to where_col=where_val, then rank/project the survivors.
        try:
            rows_out = []
            with open(path, "r", errors="replace", newline="") as fh:
                rdr = csv.DictReader(fh, delimiter=delim)
                fmap = {(f or "").lstrip("﻿").strip().lower(): f for f in (rdr.fieldnames or [])}
                key = fmap.get(where_col.lower())
                if not key:
                    return read_relevant(path, terms, budget, columns=cols)
                lo_terms = [t for t in terms if t]
                for r in rdr:
                    if (r.get(key) or "").strip().lower() != where_val.lower():
                        continue
                    if lo_terms:
                        blob = " ".join(str(v) for v in r.values()).lower()
                        if not any(t in blob for t in lo_terms):
                            continue
                    if cols:
                        r = {c: r.get(fmap.get(c.lower(), c), "") for c in cols}
                    rows_out.append(r)
                    if len(rows_out) >= max_rows:
                        break
            if not rows_out:
                return ""
            hdr = list(rows_out[0].keys())
            out = [delim.join(hdr)] + [delim.join(str(r.get(h, "")) for h in hdr) for r in rows_out]
            body = "\n".join(out)
            return body[:budget].rstrip() + " …[truncated]" if len(body) > budget else body
        except (OSError, ValueError, csv.Error):
            return read_relevant(path, terms, budget, columns=cols)
    return read_relevant(path, terms, budget, columns=cols)


@mcp.tool()
def read_mail(mail_path: str, query: str = "", field: str = "any",
              mode: str = "messages", max_results: int = 50,
              max_chars: int = 24000, include_body: bool = True) -> dict:
    """Read an EXTRACTED mail store (a .mbox file, or a directory of .eml/.mbox
    from misc.readpst_extract / misc.pff_export) and return message BODIES — not
    just headers — matching a query. Traced and citable replacement for
    `python mailbox` / grep over exports/mail. NEVER reads a raw PST/OST from
    evidence; extract it first.

    query:  terms to match (space/comma separated).
    field:  any | sender | recipient (To+Cc) | subject | body — where to match.
    mode:   messages (matching msgs with headers + body excerpt + a quotable
            locator) | senders (sender↔recipient roster + counts) | threads
            (subject-normalized grouping).
    Returns _trudi_call_id for record_finding — a recipient/dissemination claim
    should cite this (the To:/body), not an extraction/strings call.
    """
    import mailbox
    import email
    from email import policy

    def _pff_item(msg_dir):
        """One pffexport item dir (MessageNNNNN/) → an email.message. Primary
        source is InternetHeaders.txt (RFC822); OutlookHeaders.txt fills
        From/To/Subject/Date when internet headers are absent (e.g. some OSTs).
        Body from Message.txt, else de-tagged Message.html."""
        import re as _re
        def _read(name):
            p = os.path.join(msg_dir, name)
            try:
                with open(p, "r", errors="replace") as fh:
                    return fh.read()
            except OSError:
                return ""
        hdrs = _read("InternetHeaders.txt")
        body = _read("Message.txt")
        if not body:
            html = _read("Message.html")
            if html:
                html = _re.sub(r"<style.*?</style>", " ", html, flags=_re.S | _re.I)
                body = _re.sub(r"<[^>]+>", " ", html)
        if "From:" not in hdrs and "from:" not in hdrs:
            # fall back to the Outlook-side labelled headers
            ok = {}
            for ln in _read("OutlookHeaders.txt").splitlines():
                if ":" in ln:
                    k, _, v = ln.partition(":")
                    ok[k.strip().lower()] = v.strip()
            recips = _read("Recipients.txt").strip().replace("\n", ", ")
            hdrs = (f"From: {ok.get('sender name','')} <{ok.get('sender email address','')}>\n"
                    f"To: {recips}\n"
                    f"Subject: {ok.get('subject','')}\n"
                    f"Date: {ok.get('client submit time','')}\n")
        try:
            m = email.message_from_string(hdrs, policy=policy.default)
            m.set_payload(body)
            return m
        except Exception:
            return None

    resolved, err = _guard(mail_path)
    if err:
        return err
    terms = _query_terms(query)
    field = (field or "any").lower()
    mode = (mode or "messages").lower()
    body_cap = 4000
    scan_cap = 5000  # messages

    def _msgs():
        n = 0
        if os.path.isdir(resolved):
            import glob
            # pffexport item tree: MessageNNNNN/ dirs holding InternetHeaders.txt.
            item_dirs = sorted(
                d for d in glob.glob(os.path.join(resolved, "**", "Message*"), recursive=True)
                if os.path.isfile(os.path.join(d, "InternetHeaders.txt")))
            if item_dirs:
                for d in item_dirs:
                    if n >= scan_cap:
                        return
                    m = _pff_item(d)
                    if m is not None:
                        yield m; n += 1
                return
            for f in sorted(glob.glob(os.path.join(resolved, "**", "*"), recursive=True)):
                if n >= scan_cap:
                    return
                fl = f.lower()
                if fl.endswith(".eml") and os.path.isfile(f):
                    try:
                        with open(f, "rb") as fh:
                            yield email.message_from_binary_file(fh, policy=policy.default)
                        n += 1
                    except Exception:
                        continue
                elif fl.endswith(".mbox") and os.path.isfile(f):
                    try:
                        for m in mailbox.mbox(f):
                            yield m; n += 1
                            if n >= scan_cap:
                                return
                    except Exception:
                        continue
        else:
            try:
                for m in mailbox.mbox(resolved):
                    yield m; n += 1
                    if n >= scan_cap:
                        return
            except Exception:
                return

    def _body(m):
        try:
            if m.is_multipart():
                for part in m.walk():
                    if part.get_content_type() == "text/plain":
                        return (part.get_payload(decode=True) or b"").decode("utf-8", "replace")[:body_cap]
                return ""
            return (m.get_payload(decode=True) or b"").decode("utf-8", "replace")[:body_cap]
        except Exception:
            return ""

    def _hit(m, body):
        if not terms:
            return True
        sender = str(m.get("From", "")).lower()
        rcpt = (str(m.get("To", "")) + " " + str(m.get("Cc", ""))).lower()
        subj = str(m.get("Subject", "")).lower()
        hay = {"sender": sender, "recipient": rcpt, "subject": subj,
               "body": (body or "").lower()}.get(field)
        if hay is None:  # "any"
            hay = " ".join((sender, rcpt, subj, (body or "").lower()))
        return any(t in hay for t in terms)

    import collections
    from email.utils import getaddresses
    matched, senders, threads = [], collections.Counter(), collections.defaultdict(lambda: [0, set()])
    saw_attachment = saw_dsn = False
    total_chars = 0
    observed: set = set()
    observed_cap = 1000   # roster size bound (annotation size), NOT a scan bound
    # Per-address direction counts (sent vs written-to): the pre-report
    # recipient check uses them to tell an engaged correspondent from a
    # one-shot inbound sender, so bulk senders never force dispositions.
    stats: dict = {}
    # Bulk-class senders identified by the RFC-standard bulk-mail headers
    # (List-Unsubscribe / List-Id / Precedence: bulk|list|junk). Volume alone
    # is not engagement — a newsletter that sends many messages is not a
    # correspondent the subject engaged; the standard headers mark it as bulk
    # so the pre-report exhaustion check inventories it instead of blocking.
    bulk_senders: set = set()
    consumed = 0
    capped = False
    for m in _msgs():
        consumed += 1
        # Correspondent roster from EVERY scanned message — annotated onto the
        # trace entry below as a registry feeder (server-stamped, not prose).
        try:
            _is_bulk = bool(m.get("List-Unsubscribe") or m.get("List-Id")
                            or _re.search(r"\b(bulk|list|junk|auto[- ]?reply)\b",
                                          str(m.get("Precedence", "")), _re.IGNORECASE))
            for _dn, _addr in getaddresses([str(m.get("From", ""))]):
                if _addr:
                    a = _addr.lower()
                    if len(observed) < observed_cap:
                        observed.add(a)
                    if a in observed:
                        s = stats.setdefault(a, {"from": 0, "to": 0})
                        s["from"] += 1
                        if _is_bulk:
                            bulk_senders.add(a)
            for _dn, _addr in getaddresses([str(m.get("To", "")), str(m.get("Cc", ""))]):
                if _addr:
                    a = _addr.lower()
                    if len(observed) < observed_cap:
                        observed.add(a)
                    if a in observed:
                        s = stats.setdefault(a, {"from": 0, "to": 0})
                        s["to"] += 1
        except Exception:
            pass
        body = _body(m) if (include_body or field == "body" or mode == "messages") else ""
        if mode == "senders":
            senders[f"{m.get('From','?')} -> {m.get('To','?')}"] += 1
            continue
        if mode == "threads":
            subj = str(m.get("Subject", ""))
            norm = subj.lower().lstrip()
            for p in ("re:", "fwd:", "fw:"):
                while norm.startswith(p):
                    norm = norm[len(p):].lstrip()
            threads[norm or "(no subject)"][0] += 1
            threads[norm or "(no subject)"][1].add(str(m.get("From", "?")))
            continue
        if capped:
            continue   # result caps hit — keep scanning for the roster only
        if not _hit(m, body):
            continue
        rec = {"date": str(m.get("Date", "")), "from": str(m.get("From", "")),
               "to": str(m.get("To", "")), "cc": str(m.get("Cc", "")),
               "subject": str(m.get("Subject", ""))}
        if include_body:
            rec["body"] = body
        # Structural markers over the RETURNED messages (see _DSN_CODE_RE note)
        try:
            if m.is_multipart() and any(
                    p.get_filename() or p.get_content_disposition() == "attachment"
                    for p in m.walk()):
                saw_attachment = True
                rec["has_attachment"] = True
            fr_l = str(m.get("From", "")).lower()
            if (("mailer-daemon" in fr_l or "postmaster" in fr_l)
                    and _DSN_CODE_RE.search(body or "")):
                saw_dsn = True
        except Exception:
            pass
        matched.append(rec)
        total_chars += len(str(rec))
        if len(matched) >= max_results or total_chars >= max_chars:
            capped = True   # stop matching; the scan continues for the roster

    # A silent empty read is an integrity fault — a store that yields zero
    # messages is retried once (transient extraction/settling), and a persisting
    # zero yield is flagged so no registry or absence claim rests on it.
    zero_yield = False
    if consumed == 0:
        for m in _msgs():
            consumed += 1
            try:
                for _dn, _addr in getaddresses([str(m.get("From", "")), str(m.get("To", "")), str(m.get("Cc", ""))]):
                    if _addr and len(observed) < observed_cap:
                        observed.add(_addr.lower())
            except Exception:
                pass
            body = _body(m)
            if not capped and _hit(m, body):
                rec = {"date": str(m.get("Date", "")), "from": str(m.get("From", "")),
                       "to": str(m.get("To", "")), "cc": str(m.get("Cc", "")),
                       "subject": str(m.get("Subject", ""))}
                if include_body:
                    rec["body"] = body
                matched.append(rec)
                if len(matched) >= max_results:
                    capped = True
        zero_yield = consumed == 0
    # The cmd carries mode/field/query so the trace shows HOW the store was
    # read (a roster listing is not a body read) — audit-traceable.
    _cmd = f"read.read_mail -o {resolved} mode={mode} field={field}" + (f" q={query[:60]}" if query else "")
    cid = _selflog(_cmd,
                   "\n".join(f"{r.get('from')} -> {r.get('to')} | {r.get('subject')}" for r in matched))
    if cid:
        # Registry feeder: the full correspondent roster of this scan, stamped
        # server-side so exhaustion checks consume real data, not agent prose.
        try:
            from core.execution_log import log as _elog
            # Tier-contract markers: STRUCTURAL only — an actual MIME
            # attachment part is a transfer artifact; a bounce-daemon message
            # carrying an SMTP status code is a destination-side receipt.
            _xfer = saw_attachment
            _rcpt = saw_dsn
            _elog.annotate_tool_call(
                cid,
                observed_correspondents=sorted(observed),
                observed_correspondent_stats={a: stats[a] for a in sorted(observed) if a in stats},
                observed_correspondent_bulk=sorted(bulk_senders),
                # partial ONLY when the SCAN was actually cut short — a large
                # roster is not incompleteness (K-3a: a false partial flag
                # silently disabled every completeness check downstream). A
                # zero-yield store never feeds the registry as complete.
                messages_scanned=consumed,
                correspondents_partial=(consumed >= scan_cap or len(observed) >= observed_cap
                                        or zero_yield),
                transfer_artifact=True if _xfer else None,
                receipt_artifact=True if _rcpt else None,
            )
        except Exception:
            pass
    out = {"success": True, "_trudi_call_id": cid, "path": resolved,
           "query": query, "field": field, "mode": mode,
           "messages_scanned": consumed,
           "hint": "cite this _trudi_call_id — recipient/body evidence lives here"}
    if zero_yield:
        out["warning"] = ("store yielded 0 messages after a retry — verify the "
                         "extraction produced mail files; do NOT treat this as an "
                         "empty mailbox or as absence")
    if mode == "senders":
        out["senders"] = senders.most_common(max_results)
    elif mode == "threads":
        out["threads"] = [{"subject": k, "count": v[0], "participants": sorted(v[1])[:10]}
                          for k, v in sorted(threads.items(), key=lambda kv: -kv[1][0])[:max_results]]
    else:
        out["messages"] = matched
        out["match_count"] = len(matched)
    return out
