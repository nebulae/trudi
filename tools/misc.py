"""Miscellaneous SIFT tools — evtx parsing, registry, USN journal, AV, browser forensics.

Also includes email-forensics, packer-detection, capability-analysis, Office-macro,
Sigma-hunt, and batch-execution helpers.
"""
import os
import re
import shutil
from typing import Optional
from fastmcp import FastMCP
from core import run, run_with_output_file, output_safe
from core.paths import assert_output_safe

mcp = FastMCP("misc")


def _bin_or_warn(name: str) -> Optional[str]:
    """Return the absolute path to `name` if installed, else None.
    Lets tool wrappers degrade gracefully when an optional dep is missing."""
    return shutil.which(name)


# ── Event log parsing (python-evtx) ──────────────────────────────────────────

_EVTX_MAGIC = b"ElfFile\x00"   # EVTX file header, offset 0
_EVT_MAGIC = b"LfLe"           # legacy EVT: ELF_LOG_SIGNATURE at offset 4


def _sniff_event_log(path: str) -> str:
    """'evtx' | 'evt' | 'unknown'. Lenient: an unreadable/missing file or an
    unrecognised header is 'unknown' and the caller proceeds as before, so
    only a POSITIVE legacy-EVT detection changes behaviour."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(12)
    except OSError:
        return "unknown"
    if head.startswith(_EVTX_MAGIC):
        return "evtx"
    if len(head) >= 8 and head[4:8] == _EVT_MAGIC:
        return "evt"
    return "unknown"


@mcp.tool()
@output_safe
def evtx_dump(evtx_file: str, output_path: Optional[str] = None) -> dict:
    """
    Dump a Windows event log to text. EVTX (Vista+) is rendered to XML via
    python-evtx; legacy EVT (NT/2000/XP/2003, "LfLe" header) is routed to
    libevt's `evtexport`, because python-evtx parses only the binary-XML
    EVTX format and, handed an EVT file, exits 0 with an empty <Events/>
    document — a silent false negative that makes an XP-era event log look
    empty. The result carries `log_format` so the caller knows which parser
    produced it.
    """
    fmt = _sniff_event_log(evtx_file)
    if fmt == "evt":
        cmd = ["evtexport", "-m", "all", evtx_file]
    else:
        cmd = ["/usr/local/bin/evtx_dump.py", evtx_file]
    if output_path:
        r = run_with_output_file(cmd, output_path=output_path, mode="w", timeout=300)
    else:
        r = run(cmd, timeout=300)
    if isinstance(r, dict):
        r["log_format"] = fmt
        if fmt == "evt":
            r["note"] = ("legacy EVT parsed with libevt evtexport (text records, not "
                         "EVTX XML); ez.evtxecmd / misc.evtx_filter do not apply")
    return r


@mcp.tool()
@output_safe
def evtx_filter(evtx_file: str, event_ids: str,
                max_results: int = 200,
                wall_clock_budget_s: int = 60) -> dict:
    """
    Stream-filter an EVTX for specific event IDs without buffering the
    entire XML dump in memory.

    Buffering the whole evtx_dump.py XML output before filtering can expand a
    large Security.evtx to hundreds of MB and blow both memory and the client
    tool-timeout. This pipes evtx_dump.py through a line-by-line state machine
    that keeps only the current Event in a small buffer and accumulates matches
    as it goes.

    event_ids: comma-separated event IDs e.g. '4624,4625,4688,4698'.
    max_results: stop streaming after this many matches (default 200).
    wall_clock_budget_s: kill the stream after this many seconds so the
                         MCP client doesn't time us out from the outside
                         (default 60).
    """
    import re
    import subprocess
    import threading
    import time
    from core.executor import _log_tool

    ids = {int(x.strip()) for x in event_ids.split(",") if x.strip().isdigit()}
    if not ids:
        return {"success": False, "error": "no valid event_ids parsed",
                "event_ids_requested": []}

    # python-evtx cannot read legacy EVT; streaming it would yield zero
    # events and look like an empty log. Refuse loudly instead.
    if _sniff_event_log(evtx_file) == "evt":
        return {
            "success": False,
            "error": (f"{evtx_file} is a legacy EVT log (NT/2000/XP/2003); "
                      "python-evtx parses EVTX only, so an ID filter here would "
                      "return zero events regardless of content"),
            "log_format": "evt",
            "hint": "Use misc.evtx_dump (routes EVT to libevt evtexport) and grep the text records.",
            "event_ids_requested": sorted(ids),
            "events_scanned": 0, "matches": [],
        }

    cmd = ["/usr/local/bin/evtx_dump.py", evtx_file]
    id_pattern = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
    EVENT_BYTE_CAP = 200_000  # defensive — one Event shouldn't exceed this

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
    except OSError as e:
        _log_tool({"success": False, "stdout": "", "stderr": str(e),
                   "exit_code": -1, "truncated": False, "cmd": " ".join(cmd),
                   "retries": 0, "elapsed_seconds": 0.0})
        return {"success": False, "error": f"failed to spawn evtx_dump: {e}"}

    stderr_buf: list[str] = []

    def _drain_err():
        try:
            for line in proc.stderr:
                stderr_buf.append(line.rstrip())
                if len(stderr_buf) > 200:
                    break
        except Exception:
            pass

    err_thread = threading.Thread(target=_drain_err, daemon=True)
    err_thread.start()

    results: list[str] = []
    events_scanned = 0
    oversized_dropped = 0
    in_event = False
    cur_lines: list[str] = []
    cur_bytes = 0
    timed_out = False
    cap_hit = False
    start = time.monotonic()
    deadline = start + max(1, int(wall_clock_budget_s))

    try:
        for line in proc.stdout:
            if time.monotonic() > deadline:
                timed_out = True
                break
            if not in_event:
                if not line.lstrip().startswith("<Event "):
                    continue
                in_event = True
                cur_lines = []
                cur_bytes = 0
            # Fall through — append the line and check the same-line close
            # tag, so single-line events (open + close on one line) are not
            # missed.
            cur_lines.append(line)
            cur_bytes += len(line)
            if cur_bytes > EVENT_BYTE_CAP:
                # Pathological event — resync at the next start tag.
                oversized_dropped += 1
                in_event = False
                cur_lines = []
                cur_bytes = 0
                continue
            if line.rstrip().endswith("</Event>"):
                events_scanned += 1
                event_xml = "".join(cur_lines)
                m = id_pattern.search(event_xml)
                if m and int(m.group(1)) in ids:
                    results.append(event_xml[:2000])
                    if len(results) >= max_results:
                        cap_hit = True
                        break
                in_event = False
                cur_lines = []
                cur_bytes = 0
    finally:
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        err_thread.join(timeout=1)

    elapsed = round(time.monotonic() - start, 2)
    stderr_text = "\n".join(stderr_buf)[:512]
    success = events_scanned > 0 or bool(results)

    # Persist the MATCHED events to the sidecar: a finding citing this call
    # must let the reviewer fetch the rows it vouches for; an empty stdout
    # would read as a COMPLETE source whose misses imply absence.
    _joined = "\n".join(results)
    _tc = {
        "success": success,
        "stdout": _joined[:600],
        "_stdout_full": _joined,
        "_stdout_chars": len(_joined),
        "stderr": stderr_text,
        "exit_code": proc.returncode if proc.returncode is not None else -1,
        "truncated": cap_hit or timed_out,
        "cmd": " ".join(cmd),
        "retries": 0,
        "elapsed_seconds": elapsed,
    }
    _log_tool(_tc)
    try:
        from tools._gates._session import SESSION_EVENT_IDS
        _sess = sorted(ids & SESSION_EVENT_IDS)
        if success and results and _sess and _tc.get("_trudi_call_id"):
            from core.execution_log import log as _elog
            _elog.annotate_tool_call(_tc["_trudi_call_id"], session_artifact=True,
                                     session_event_ids=_sess)
    except Exception:
        pass

    return {
        "success": success,
        "event_ids_requested": sorted(ids),
        "events_scanned": events_scanned,
        "matches_found": len(results),
        "events": results,
        "oversized_events_dropped": oversized_dropped,
        "cap_hit": cap_hit,
        "wall_clock_timed_out": timed_out,
        "elapsed_seconds": elapsed,
    }


# ── Registry (regripper) ──────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def regripper_hive(
    hive_path: str,
    plugin: Optional[str] = None,
    all_plugins: bool = True,
) -> dict:
    """
    Parse a registry hive with regripper (rip.pl).
    plugin: run a specific plugin e.g. 'userassist', 'services', 'autoruns'.
    all_plugins: run all applicable plugins (ignored if plugin is specified).
    """
    cmd = ["/usr/local/bin/rip.pl", "-r", hive_path]
    if plugin:
        cmd += ["-p", plugin]
    elif all_plugins:
        cmd.append("-a")
    return run(cmd, timeout=120)


@mcp.tool()
@output_safe
def regripper_list_plugins() -> dict:
    """List all available regripper plugins."""
    return run(["/usr/local/bin/rip.pl", "-l"], timeout=30)


# ── USN Journal ───────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def usnparser_parse(usn_journal: str, output_path: Optional[str] = None) -> dict:
    """
    Parse the NTFS USN Change Journal ($UsnJrnl:$J).
    usn_journal: path to extracted $J stream (from tsk_icat on inode 11-128-4).
    output_path: optional CSV output path.
    """
    if output_path:
        assert_output_safe(output_path)
    cmd = ["/usr/local/bin/usnparser", "-f", usn_journal]
    if output_path:
        cmd += ["-o", output_path]
    return run(cmd, timeout=300)


# ── MFT analysis ─────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def analyzemft_parse(mft_path: str, output_csv: str) -> dict:
    """
    Parse $MFT file using analyzeMFT (Python-based alternative to MFTECmd).
    mft_path: path to extracted $MFT.
    output_csv: destination CSV file.
    """
    return run(
        ["/usr/local/bin/analyzemft", "-f", mft_path, "-o", output_csv],
        timeout=600,
        output_dir=output_csv,
    )


# ── Browser forensics ─────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def hindsight_chrome(
    profile_path: str,
    output_dir: str,
    output_format: str = "jsonl",
) -> dict:
    """
    Parse Chrome/Chromium browser history, cookies, cache, and extensions using Hindsight.
    profile_path: path to Chrome 'Default' profile directory.
    output_format: 'jsonl' (default, one record per line — parseable), 'sqlite',
        or 'xlsx'. These are the only formats hindsight accepts; common aliases
        ('json'→'jsonl', 'csv'/'xls'→'xlsx') are mapped, anything else falls
        back to 'jsonl' rather than failing on an invalid -f choice.
    """
    import os
    _VALID = {"jsonl", "sqlite", "xlsx"}
    _ALIAS = {"json": "jsonl", "csv": "xlsx", "xls": "xlsx", "db": "sqlite", "sqlite3": "sqlite"}
    fmt = (output_format or "").strip().lower()
    fmt = _ALIAS.get(fmt, fmt)
    if fmt not in _VALID:
        fmt = "jsonl"
    output_file = os.path.join(output_dir, "hindsight_chrome")
    cmd = [
        "/usr/local/bin/hindsight.py",
        "-i", profile_path,
        "-o", output_file,
        "-f", fmt,
        # Explicit log location: hindsight's default log path is resolved by
        # the tool itself and landed somewhere unwritable in two runs
        # (logging.basicConfig FileHandler crash before any parsing).
        "-l", os.path.join(output_dir, "hindsight.log"),
    ]
    # cwd=output_dir: hindsight opens its log relative to the working
    # directory and crashes in FileHandler otherwise; the directory must
    # exist BEFORE Popen(cwd=…) or the spawn itself fails.
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError:
        pass
    r = run(cmd, timeout=300, output_dir=output_dir, cwd=output_dir)
    if isinstance(r, dict):
        r["output_format"] = fmt
    return r


# ── AV scanning ──────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def clamscan_file(file_path: str) -> dict:
    """Scan a file for malware using ClamAV. Exit 1 = infected (a RESULT,
    logged success=True with exit_meaning); exit 2 = error."""
    from tools._exit_codes import policy
    return run(["clamscan", "--no-summary", file_path], timeout=120,
               **policy("clamscan"))


@mcp.tool()
@output_safe
def clamscan_directory(directory: str, recursive: bool = True) -> dict:
    """Scan a directory for malware using ClamAV."""
    from tools._exit_codes import policy
    cmd = ["clamscan", "--no-summary"]
    if recursive:
        cmd.append("-r")
    cmd.append(directory)
    return run(cmd, timeout=1800, **policy("clamscan"))


# ── USB device forensics ──────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def usbdeviceforensics(registry_path: str, output_path: Optional[str] = None) -> dict:
    """
    Extract USB device connection history from registry hives.
    registry_path: path to SYSTEM hive or a directory containing SYSTEM.
    """
    if output_path:
        assert_output_safe(output_path)
    cmd = ["/usr/local/bin/usbdeviceforensics", registry_path]
    return run(cmd, timeout=60)


@mcp.tool()
@output_safe
def chat_db_export(db_path: str, output_dir: str = "", chat_app: str = "auto") -> dict:
    """Export a chat/messenger sqlite store (Skype main.db, WhatsApp
    msgstore.db) to normalized CSVs — the comms channel the mail extractors
    (readpst/pff_export) do not cover, and a first-class exfil channel
    (message bodies AND the Transfers file-transfer trail).

    ENUMERATE, DON'T SEARCH: the whole Messages/Transfers tables are exported
    (one row each), plus a participants roster, so a correspondent or file
    transfer cannot be missed by grepping the wrong string. The db is opened
    STRICTLY read-only (sqlite immutable URI — no -wal/-shm sidecars, no
    locks), safe against read-only evidence mounts; an uncheckpointed -wal
    sibling is surfaced as a warning.

    db_path:   the store on the mounted image (e.g. .../AppData/Roaming/Skype/
               <account>/main.db). Read-only.
    output_dir: CSV destination (default ./exports/chat/); must be under
               analysis/exports/reports.
    chat_app:  auto | skype | whatsapp.

    Read the produced CSVs with read.read_output. Returns _trudi_call_id for
    record_finding; participants are annotated onto the trace entry so
    correspondent-exhaustion checks can consume them.
    """
    import csv as _csv
    from core.executor import _log_tool
    from core.chat_db import parse_chat_db

    out_dir = output_dir or os.path.join(".", "exports", "chat")
    assert_output_safe(out_dir)

    parsed = parse_chat_db(db_path, chat_app=chat_app)
    output_paths: dict = {}
    if parsed.get("success"):
        try:
            os.makedirs(out_dir, exist_ok=True)
            specs = (
                ("messages.csv", parsed.get("messages", []),
                 ["ts_utc", "author", "author_display", "chat", "partner", "body"]),
                ("transfers.csv", parsed.get("transfers", []),
                 ["start_utc", "finish_utc", "partner", "partner_display",
                  "filename", "filesize", "status"]),
                ("participants.csv",
                 [{"participant": p} for p in parsed.get("participants", [])],
                 ["participant"]),
            )
            for name, rows, header in specs:
                p = os.path.join(out_dir, name)
                with open(p, "w", newline="", encoding="utf-8") as fh:
                    w = _csv.DictWriter(fh, fieldnames=header)
                    w.writeheader()
                    for r in rows:
                        w.writerow({k: r.get(k, "") for k in header})
                output_paths[name] = p
        except OSError as e:
            parsed["warning"] = f"CSV write failed: {e}"

    cov = parsed.get("coverage_window")
    parts = parsed.get("participants", [])
    if parsed.get("success"):
        summary = (f"{parsed.get('app')}: {parsed.get('message_count', 0)} messages, "
                   f"{parsed.get('transfer_count', 0)} file transfers, "
                   f"{len(parts)} participants, coverage "
                   f"{(cov or {}).get('start', '?')} -> {(cov or {}).get('end', '?')}")
        if parsed.get("warning"):
            summary += f"\n⚠ {parsed['warning']}"
    else:
        summary = parsed.get("error", "chat db export failed")

    # Self-log with the SOURCE DB PATH in cmd — the comms-coverage and
    # chat_messenger manifest regexes match on it (main.db/msgstore/skype/...),
    # so this call satisfies them with no gate edits. Failed attempts are
    # logged too: the attempt is part of the audit trail.
    result = {"success": parsed.get("success", False), "stdout": summary,
              "stderr": "" if parsed.get("success") else parsed.get("error", ""),
              "exit_code": 0 if parsed.get("success") else 1, "truncated": False,
              "retries": 0, "elapsed_seconds": 0.0,
              "cmd": f"misc.chat_db_export {db_path}"}
    _log_tool(result)
    cid = result.get("_trudi_call_id")
    if cid and parsed.get("success"):
        try:
            from core.execution_log import log
            log.annotate_tool_call(
                cid,
                chat_db_export=True,
                coverage_window=cov,
                message_count=parsed.get("message_count", 0),
                transfer_count=parsed.get("transfer_count", 0),
                # tier-contract marker: the Transfers table is a transfer artifact
                transfer_artifact=True if int(parsed.get("transfer_count") or 0) > 0 else None,
                participant_count=len(parts),
                observed_correspondents=parts[:200],
                correspondents_partial=len(parts) > 200,
            )
        except Exception:
            pass

    return {
        "success": parsed.get("success", False),
        "error": parsed.get("error"),
        "warning": parsed.get("warning"),
        "_trudi_call_id": cid,
        "app": parsed.get("app"),
        "partial": parsed.get("partial", False),
        "wal_present": parsed.get("wal_present", False),
        "message_count": parsed.get("message_count", 0),
        "transfer_count": parsed.get("transfer_count", 0),
        "participant_count": len(parts),
        "participants_preview": parts[:40],
        "coverage_window": cov,
        "output_paths": output_paths,
        "summary": summary,
    }


@mcp.tool()
@output_safe
def device_install_inventory(setupapi_log_path: str, output_path: Optional[str] = None) -> dict:
    """COMPLETE structured inventory of every device from the Windows device-install
    log (setupapi.dev.log) — the BadUSB / removable-media ingress lens.

    ENUMERATE, DON'T SEARCH. This parses the WHOLE log into one de-duplicated row
    per physical device (class, vendor, product, VID:PID, interfaces, first/last
    seen), so a keystroke injector cannot be missed by grepping the wrong string,
    head-capping the dump, or windowing the wrong section. It flags the structural
    keystroke-injector profile — a device exposing both HID/keyboard and mass-storage
    interfaces — as a HINT on top of the full inventory; even an unflagged device is
    present as a visible row for you to judge. This is the artifact a 'no BadUSB'
    negative or an 'interactive human authorship' finding must be grounded on
    (enforced by the broad attribution / completeness gates).

    setupapi_log_path: path to setupapi.dev.log on the mounted image / triage set.
    output_path: optional CSV of the FULL inventory (must be under analysis/ etc.).
    """
    from core.executor import _log_tool
    from core.device_inventory import parse_device_install_log

    if output_path:
        assert_output_safe(output_path)

    inv = parse_device_install_log(setupapi_log_path)
    cov = inv.get("coverage_window")
    flagged = inv.get("flagged", [])

    # Summary — flagged devices FIRST so they're unmissable even if the client
    # truncates the result display.
    lines = []
    if flagged:
        lines.append(f"⚠ {len(flagged)} FLAGGED device(s):")
        for d in flagged:
            lines.append(f"  [{d.get('first_seen')}] {d.get('device_class')} "
                         f"vid={d.get('vid')} ven={d.get('vendor')!r} "
                         f"prod={d.get('product')!r} :: {'; '.join(d.get('flag_reasons', []))}")
    lines.append(f"{inv.get('device_count', 0)} unique devices, "
                 f"{inv.get('event_count', 0)} events, coverage "
                 f"{(cov or {}).get('start', '?')} -> {(cov or {}).get('end', '?')}")
    summary = "\n".join(lines)

    if output_path and inv.get("success"):
        try:
            import csv
            flag_ids = {d["identity"] for d in flagged}
            with open(output_path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["first_seen", "last_seen", "device_class", "vendor",
                            "product", "vid", "pid", "interfaces", "actions", "flagged"])
                for d in inv.get("devices", []):
                    w.writerow([d.get("first_seen"), d.get("last_seen"), d.get("device_class"),
                                d.get("vendor"), d.get("product"), d.get("vid"), d.get("pid"),
                                "|".join(d.get("interfaces", [])), "|".join(d.get("actions", [])),
                                "YES" if d.get("identity") in flag_ids else ""])
        except OSError:
            pass

    # Self-log the tool_call and stamp the structured markers the gates read. The
    # agent cannot fabricate these in a finding's prose.
    result = {"success": inv.get("success", False), "stdout": summary,
              "stderr": inv.get("error", "") if not inv.get("success") else "",
              "exit_code": 0 if inv.get("success") else 1, "truncated": False,
              "retries": 0, "elapsed_seconds": 0.0,
              "cmd": f"misc.device_install_inventory {setupapi_log_path}"}
    _log_tool(result)
    cid = result.get("_trudi_call_id")
    if cid and inv.get("success"):
        try:
            from core.execution_log import log
            log.annotate_tool_call(
                cid,
                device_install_inventory=True,
                coverage_window=cov,
                device_count=inv.get("device_count"),
                flagged_count=len(flagged),
            )
        except Exception:
            pass

    return {
        "success": inv.get("success", False),
        "error": inv.get("error"),
        "_trudi_call_id": cid,
        "device_count": inv.get("device_count", 0),
        "event_count": inv.get("event_count", 0),
        "coverage_window": cov,
        "flagged": flagged,
        "devices": inv.get("devices", []),
        "summary": summary,
        "output_path": output_path,
    }


# ── Scheduled tasks (disk) ────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def parse_scheduled_tasks(tasks_dir: str) -> dict:
    """
    List and read Windows Scheduled Task XML files from disk — the persistence
    look an injected task lives in (no 4698 event when task-auditing is off).
    tasks_dir: path to Windows/System32/Tasks/ on a mounted volume.

    Windows task XML is UTF-16; it is decoded here. Each task is scanned for
    keystroke-injector PAYLOAD signatures (%duck%/%bunny%/hak5, hidden/encoded
    PowerShell) — flagged as a LEAD (presence flags a payload; absence supports
    the benign reading). Self-logged as a citable tool_call.
    """
    import os
    from tools._gates._scheduled_tasks import INJECTOR_PAYLOAD_RE
    from core.executor import _log_tool
    results, errors, injector_tasks = [], [], []

    def _decode(fpath):
        with open(fpath, "rb") as f:
            raw = f.read(16384)
        for enc in ("utf-16", "utf-8", "latin-1"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, UnicodeError):
                continue
        return raw.decode("latin-1", "replace")

    ok = os.path.isdir(tasks_dir)
    if ok:
        for root, _dirs, files in os.walk(tasks_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    content = _decode(fpath)
                    rel = fpath.replace(tasks_dir, "")
                    entry = {"task": rel, "content": content[:8192]}
                    if INJECTOR_PAYLOAD_RE.search(content):
                        entry["injector_payload"] = True
                        injector_tasks.append(rel)
                    results.append(entry)
                except Exception as e:
                    errors.append({"task": fpath, "error": str(e)})

    summary = (f"{len(results)} scheduled tasks; "
               f"{len(injector_tasks)} with injector-payload signatures"
               + (f": {injector_tasks[:5]}" if injector_tasks else ""))
    tc = {"success": ok, "stdout": summary, "stderr": "" if ok else f"not a directory: {tasks_dir}",
          "exit_code": 0 if ok else 1, "truncated": False, "retries": 0,
          "elapsed_seconds": 0.0, "cmd": f"misc.parse_scheduled_tasks {tasks_dir}",
          "_stdout_full": summary + "\n" + "\n".join(r["task"] for r in results),
          "_stdout_chars": None}
    try:
        _log_tool(tc)
        cid = tc.get("_trudi_call_id")
        if cid and injector_tasks:
            from core.execution_log import log as _elog
            _elog.annotate_tool_call(cid, injector_payload_tasks=injector_tasks[:50])
    except Exception:
        cid = None
    if not ok:
        return {"success": False, "error": f"not a directory: {tasks_dir}",
                "_trudi_call_id": cid}
    return {"success": True, "_trudi_call_id": cid, "task_count": len(results),
            "injector_payload_tasks": injector_tasks, "tasks": results, "errors": errors}


# ── PDF analysis ──────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def pdfid_scan(pdf_path: str) -> dict:
    """
    Quick triage of a PDF file using pdfid.
    Reports counts of key PDF keywords: /JS, /JavaScript, /AA, /OpenAction, /Launch, etc.
    High counts of these suggest malicious or suspicious content.
    """
    return run(["/usr/local/bin/pdfid.py", pdf_path], timeout=30)


@mcp.tool()
@output_safe
def pdf_parser_analyze(pdf_path: str, object_id: Optional[int] = None) -> dict:
    """
    Deep analysis of a PDF file using pdf-parser.
    object_id: analyze a specific PDF object by ID (from pdfid output).
    """
    cmd = ["/usr/local/bin/pdf-parser.py", pdf_path]
    if object_id is not None:
        cmd += ["-o", str(object_id)]
    return run(cmd, timeout=60)


# ── PE analysis ───────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def pe_scanner(file_path: str) -> dict:
    """Scan a PE executable for suspicious characteristics using pe-scanner."""
    return run(["/usr/local/bin/pe-scanner", file_path], timeout=30)


@mcp.tool()
@output_safe
def pe_carver(file_path: str, output_dir: str) -> dict:
    """Carve PE files from a binary blob (memory dump, disk image segment) using pe-carver."""
    return run(["/usr/local/bin/pe-carver", "-f", file_path, "-o", output_dir], timeout=120, output_dir=output_dir)


@mcp.tool()
@output_safe
def packerid(file_path: str) -> dict:
    """Identify PE packer or protector using packerid."""
    return run(["/usr/local/bin/packerid.py", file_path], timeout=30)


# ── Execution trace log ───────────────────────────────────────────────────────

def _pre_report_ready_gate() -> dict | None:
    """Return a refusal dict unless the latest pre-report check is ready.

    Shared by export_execution_log and write_final_report so the final
    deliverable and the trace export cannot diverge.
    """
    from core.execution_log import log

    pre_report_entry = None
    pre_report_window = log._entries[-50:] if len(log._entries) > 50 else log._entries
    for e in reversed(pre_report_window):
        if e.get("type") == "reason_call" and e.get("tool") == "reason_pre_report_check":
            pre_report_entry = e
            break
    if pre_report_entry is None:
        return {
            "success": False,
            "error": (
                "refused: no reason.pre_report_check call found in the last "
                "50 trace entries. Call reason.pre_report_check() after "
                "reason.synthesize and resolve any blocking_issues before "
                "exporting the trace or writing the final report."
            ),
            "gate": "pre_report_check_required",
            "missing_check": "reason_pre_report_check",
        }
    conclusion = (pre_report_entry.get("conclusion") or "")
    if "ready_to_report" not in pre_report_entry:
        return {
            "success": False,
            "error": (
                "refused: the most recent reason.pre_report_check entry predates the "
                "typed ready_to_report flag — re-run reason.pre_report_check() before "
                "exporting the trace or writing the final report."
            ),
            "gate": "pre_report_check_required",
            "missing_check": "reason_pre_report_check",
        }
    is_ready = pre_report_entry.get("ready_to_report") is True
    if not is_ready:
        return {
            "success": False,
            "error": (
                "refused: most recent reason.pre_report_check returned "
                "READY_TO_REPORT: false. Resolve the blocking_issues and "
                "re-run pre_report_check before exporting the trace or "
                "writing the final report."
            ),
            "gate": "pre_report_check_required",
            "pre_report_conclusion": conclusion[:500],
        }
    return None

@mcp.tool()
@output_safe
def start_execution_log(case_id: str, output_path: str,
                        launch_dashboard: bool = True,
                        case_dir: str = "",
                        dashboard_port: int = 8765) -> dict:
    """
    Open the execution trace log for a case. Call this at the very start of
    every investigation, before any tool runs.

    If a trace file already exists at output_path for this case_id (e.g. after
    a server restart or reconnect), automatically resumes appending without
    overwriting prior entries. Safe to call every time — no data is lost.

    case_id: unique case identifier e.g. 'CASE-001'.
    output_path: path for the JSON log — must be in analysis/, exports/, or reports/.
    launch_dashboard: if True (default), discover the running standalone
                      dashboard and surface a deep-link URL pre-loaded with
                      this case's trace. The dashboard itself is a separate
                      long-lived process (`trudi-dashboard`) — this tool no
                      longer spawns one in-process.
    case_dir: optional explicit case directory. If empty, derived from
              output_path by walking up past `analysis/`.
    dashboard_port: accepted for back-compat and ignored — the standalone
                    dashboard owns its port.

    Returns: log info + optional dashboard_url. The URL is also printed to
    stderr and written to <analysis_dir>/dashboard.url for easy retrieval.
    """
    from core.execution_log import log
    # Normalize: the dashboard discovers traces by *_trace.json — an
    # extension-less output_path (models omit it) would make the run
    # invisible there while writing fine.
    if not output_path.endswith(".json"):
        output_path = output_path + ".json"
    # Self-test: configure flushes the initial empty trace, and our explicit
    # sentinel write confirms record_* works end-to-end. Either failure
    # surfaces as a clean error return rather than an unhandled exception.
    try:
        recovered = log.configure(case_id, output_path)
        log.record_system_error("trace_initialized",
                                f"trace path {output_path}")
    except Exception as e:
        return {
            "success": False,
            "case_id": case_id,
            "log_path": output_path,
            "error": (f"trace setup failed — cannot write to {output_path}: {e}. "
                      f"Fix the path/permissions and retry start_execution_log."),
        }

    result: dict = {
        "success": True,
        "case_id": case_id,
        "log_path": output_path,
        "entries_recovered": recovered,
        "resumed": recovered > 0,
    }

    if launch_dashboard:
        # Derive case_dir if not given: walk up from output_path past any
        # analysis/ exports/ reports/ segment.
        if not case_dir:
            abs_out = os.path.abspath(output_path)
            parent = os.path.dirname(abs_out)
            if os.path.basename(parent) in ("analysis", "exports", "reports"):
                case_dir = os.path.dirname(parent)
            else:
                case_dir = parent
        try:
            # Qualify the call — the boolean parameter `launch_dashboard`
            # shadows the function of the same name in this scope.
            import sys as _modsys
            _dash_fn = _modsys.modules[__name__].launch_dashboard
            try:
                dash = _dash_fn(case_dir, port=dashboard_port,
                                trace_path=output_path)
            except (OSError, ValueError) as _disc_err:
                # Disk / parse / discovery problems are non-fatal — the
                # investigation can run without the dashboard. Surface in
                # the trace as a system_error so the failure is visible.
                log.record_system_error(
                    "dashboard",
                    f"dashboard discovery raised "
                    f"{type(_disc_err).__name__}: {_disc_err}",
                )
                result["dashboard_error"] = (
                    f"discovery {type(_disc_err).__name__}: {_disc_err}"
                )
                return result
            if dash.get("success"):
                url = dash["url"]
                result["dashboard_url"] = url
                result["dashboard_port"] = dash["port"]
                # Surface the URL prominently in three places:
                # 1) stderr so the operator sees it in the MCP-server terminal.
                import sys
                print(f"\n[TRUDI DASHBOARD] {url}\n", file=sys.stderr, flush=True)
                # 2) Persist to analysis/dashboard.url so it survives restarts.
                try:
                    analysis_dir = os.path.dirname(os.path.abspath(output_path))
                    os.makedirs(analysis_dir, exist_ok=True)
                    with open(os.path.join(analysis_dir, "dashboard.url"), "w") as f:
                        f.write(url + "\n")
                except OSError as _e:
                    print(f"[TRUDI WARN] could not write dashboard.url: {_e}",
                          file=sys.stderr)
                # 3) Log to the trace as an investigation_narration so the
                #    dashboard URL itself appears in the trace it serves.
                try:
                    log.record_agent_message(f"Trace dashboard live at {url}")
                except Exception as _e:
                    import sys as _sys
                    print(f"[TRUDI WARN] dashboard URL narration failed: {_e}",
                          file=_sys.stderr)
            else:
                result["dashboard_error"] = dash.get("error", "")
                if dash.get("hint_url"):
                    # No live dashboard — surface the hint URL so the operator
                    # knows what to point at once they run `trudi-dashboard`.
                    result["dashboard_hint_url"] = dash["hint_url"]
                    import sys
                    print(f"\n[TRUDI DASHBOARD] {dash['error']}\n"
                          f"  Once running, open: {dash['hint_url']}\n",
                          file=sys.stderr, flush=True)
        except Exception as e:
            # Programmer error (NameError/AttributeError/etc.) — surface
            # loudly via system_error AND record the message in dashboard_error
            # so the operator sees both the high-level error and the trace
            # entry. The investigation itself proceeds.
            try:
                log.record_system_error(
                    "dashboard",
                    f"unexpected {type(e).__name__} in dashboard discovery: {e!r}",
                )
            except Exception:
                pass
            result["dashboard_error"] = f"{type(e).__name__}: {e}"
            import sys as _sys
            print(f"[TRUDI WARN] dashboard discovery raised: {e!r}",
                  file=_sys.stderr)

    return result


_HYPOTHESIZE_KEYWORDS = (
    "process", "service", "scheduled task", "task ",
    "persist", "c2", "beacon", "exfil", "lateral",
    "ghost", "orphan", "detached", "null cmdline",
    "unsigned", "credential", "implant", "stager",
)

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_finding_text(text: str) -> str:
    """Lowercase + whitespace-collapse + truncate. Used for description matching
    when correlating findings to recent reason.* calls."""
    return _WHITESPACE_RE.sub(" ", (text or "").lower()).strip()[:60]


def _infer_input_call_ids(window: list[dict], k: int = 5) -> list[int]:
    """Fallback lineage: call_ids of the most recent tool/reason results (newest
    last). Used when the agent omits input_call_ids so the causal DAG still gets
    real foreign keys instead of an empty (or hand-mistyped) edge."""
    cids = [
        int(e["call_id"])
        for e in window
        if e.get("type") in ("tool_call", "reason_call") and e.get("call_id")
    ]
    return cids[-k:]


@mcp.tool()
@output_safe
def record_curiosity_probe(
    rationale: str,
    seeded_by: str = "",
    input_call_ids: list[int] | None = None,
) -> dict:
    """
    Log an exploratory probe — a read-only artifact you chose to look at on a
    HUNCH, outside the current dair_assess directives.priority_tools.

    Use this when an artifact or absence makes you want to check something the
    work order didn't name (a second SID's Recycle.Bin, an untouched comms
    store, the device-install log, a less-obvious exfil channel). Run the
    read-only forensic tool as normal, then call this to record that you spent
    one unit of the batch's exploratory budget and WHY.

    Budget is granted by dair_assess (directives.curiosity_budget) and refreshed
    each call. The probe is refused if the budget is exhausted or no rationale is
    given (gate: curiosity_budget).

    A probe is NOT a finding and carries no weight on its own. To turn a probe
    that paid off into evidence, feed its returned call_id into
    reason.hypothesize / record_finding via input_call_ids — the normal finding
    gates then apply. So probing widens coverage without ever loosening a gate.

    rationale:  the hunch + what result would confirm or kill it (required).
    seeded_by:  hypothesis_id of a reason.hypothesize(mode="absence") that
                pointed here, if any — builds the absence→probe→finding chain.
    input_call_ids: _trudi_call_id values of the artifacts that prompted the hunch.
    """
    from core.execution_log import log
    from tools._gates import curiosity_budget
    failure = curiosity_budget.check(log.last_n_window(30), rationale)
    if failure is not None:
        return failure
    cid = log.record_curiosity_probe(rationale, seeded_by, input_call_ids)
    return {"success": True, "call_id": cid}


@mcp.tool()
def record_disposition(
    target_kind: str,
    target_id: str,
    reason: str,
    evidence_call_ids: list[int] | None = None,
    note: str = "",
    window: dict | None = None,
    input_call_ids: list[int] | None = None,
) -> dict:
    """
    Record a TYPED disposition — the only way to settle a lead, source, tool,
    verification challenge, principal, correspondent, device, hypothesis or host
    without a finding. Gates and reason.pre_report_check look these up by
    (target_kind, target_id); prose such as "absent from evidence" or
    "controller unknown" in a finding/narration is NOT read.

    target_kind: source | tool | challenge | principal | correspondent | device |
                 hypothesis | host | destruction_scope
    target_id:   source → manifest source id (from the refusal); tool → the MCP
                 tool name (e.g. "ez.pecmd"); challenge → "<dair_call_id>:<challenge
                 claim>"; principal / correspondent / host / device → the identity
                 (any spelling; normalized server-side); hypothesis → H-id;
                 destruction_scope → the finding call_id.
    reason:      absent_from_evidence | inapplicable | out_of_scope | noise |
                 excluded | not_a_principal | controller_unknown |
                 evidence_unavailable | ruled_out | refuted | undetermined
                 (each target_kind accepts a subset — the refusal lists it).
    evidence_call_ids: REQUIRED for excluded / ruled_out / refuted /
                 not_a_principal — the evidence tool calls that establish it.
    window:      {start, end} ISO dates the disposition covers (device rule-outs).
    """
    from core.execution_log import log
    from tools._gates import _dispositions as D
    from tools._gates._evidence_calls import is_evidence_tool_call
    msg = D.validate(target_kind, target_id, reason)
    if msg:
        return {"success": False, "error": msg, "gate": "typed_disposition",
                "target_kinds": list(D.TARGET_KINDS), "reasons": list(D.REASONS)}
    idx = log.index()
    if not (idx.by_type.get("dair_call") or []):
        return {"success": False, "gate": "dair_required",
                "error": "Dispositions only exist inside an active DAIR investigation "
                         "(no dair_assess call in the trace). Call dair_assess first."}
    rs = reason.strip().lower()
    tk = target_kind.strip().lower()
    cids = sorted({int(c) for c in (evidence_call_ids or []) if c})
    if rs in D.EVIDENCE_REQUIRED:
        bad = [c for c in cids if not is_evidence_tool_call(idx.by_call_id.get(c) or {})]
        if not cids or bad:
            return {"success": False, "gate": "typed_disposition",
                    "missing": ["evidence_call_ids"],
                    "error": (f"reason={rs!r} asserts a fact about the evidence — pass "
                              f"evidence_call_ids=[<_trudi_call_id>, ...] of the successful "
                              f"evidence tool calls that establish it"
                              + (f" (not evidence tool calls: {bad})" if bad else ""))}
    # Evidence cited to settle a question must BEAR ON that question's class
    # and window. A device rule-out answers "did this device act at install/
    # creation time?" — later-operation artifacts (RDP sessions, FTP logs, mail
    # reads) describe how an account was USED and cannot settle it. The check
    # is over evidence CLASS and WINDOW only — never the direction of the
    # conclusion: the same classes serve to rule the device in or out.
    if tk == "device" and rs == "ruled_out":
        if not isinstance(window, dict) or not window.get("start") or not window.get("end"):
            return {"success": False, "gate": "typed_disposition",
                    "missing": ["window"],
                    "error": ("device ruled_out settles a mechanism at install/creation "
                              "time — pass window={\"start\", \"end\"} (ISO dates) the "
                              "rule-out covers")}
        from tools._gates._tiering import classify_entry
        # Classes that describe the DEVICE ITSELF (its install/connection
        # record) — an account-creation or session event describes what an
        # account did, not what the device is; a generic registry parse is too
        # broad to bear on a specific device.
        _DEVICE_CLASSES = {"device_install", "usb_storage"}
        classes = set()
        for c in cids:
            classes |= classify_entry(idx.by_call_id.get(c) or {})
        # Ruling out a FLAGGED keystroke-injector cannot skip the look for
        # what an injection leaves behind. Symmetric — the scheduled-task /
        # autorun enumeration either supports the rule-out (no injection
        # artifacts) or refutes it (an injector-payload task).
        from tools._gates._scheduled_tasks import tasks_examined, flagged_injector_present
        _entries_now = getattr(log, "_entries", None) or []
        if flagged_injector_present(_entries_now) and not tasks_examined(_entries_now, idx):
            return {"success": False, "gate": "typed_disposition",
                    "detail_gate": "injector_ruleout_requires_task_look",
                    "error": ("ruling out a FLAGGED keystroke-injector requires having "
                              "examined where an injection leaves traces: enumerate "
                              "\\Windows\\System32\\Tasks and the SOFTWARE TaskCache "
                              "(misc.parse_scheduled_tasks / vol.scheduled_tasks) — or "
                              "record misc.record_disposition(target_kind=\"source\", "
                              "target_id=\"scheduled_tasks\", reason=\"absent_from_evidence\") "
                              "— before ruling the device out. A hidden PowerShell task off "
                              "a removable/%duck% path is the injection; not looking is not "
                              "a rule-out.")}
        if not (classes & _DEVICE_CLASSES):
            return {"success": False, "gate": "typed_disposition",
                    "detail_gate": "disposition_evidence_relevance",
                    "error": (f"device ruled_out requires evidence bearing on the device's "
                              f"install/creation record — none of the cited calls carries a "
                              f"device-mechanism artifact class "
                              f"({', '.join(sorted(_DEVICE_CLASSES))}); the cited classes are "
                              f"{{{', '.join(sorted(classes)) or 'none'}}}. Later-operation "
                              f"artifacts (sessions, transfer logs, mail) describe how an "
                              f"account was USED, not how it was created — cite the "
                              f"setupapi/USB-registry/event evidence for the window, or do "
                              f"not rule the device out.")}
    else:
        unknown = [c for c in cids if c not in idx.by_call_id]
        if unknown:
            return {"success": False, "gate": "typed_disposition",
                    "error": f"evidence_call_ids not in trace: {unknown}"}
    # An ENGAGED correspondent (the subject wrote to them, a chat participant,
    # or a case-roster match) cannot be settled reason="noise": "noise" asserts
    # inbound spam/clutter, and mislabelling would sweep a real recipient out of
    # the recipient-exhaustion duty. Steer to out_of_scope or excluded — this
    # constrains the LABEL, not the conclusion. Mirrors the pre-report check's
    # engagement predicate (wrote_to / chat / roster), so single-target and
    # batch dispositions both inherit it.
    if tk == "correspondent" and rs == "noise":
        from tools._gates._entities import entity_matches as _emx
        tnorm = target_id.strip().lower()
        crec = (getattr(idx, "correspondents", {}) or {}).get(tnorm) or {}
        wrote_to = int(crec.get("to") or 0) > 0
        chat = any("chat" in str(s) for s in (crec.get("sources") or []))
        roster = any(_emx(tnorm, t) for t in (getattr(idx, "roster", {}) or {}))
        if wrote_to or chat or roster:
            why = ("the subject WROTE TO this address" if wrote_to
                   else "this is a chat participant" if chat
                   else "this matches the case roster")
            return {"success": False, "gate": "typed_disposition",
                    "detail_gate": "engaged_correspondent_not_noise",
                    "error": (
                        f"{target_id} is an ENGAGED correspondent ({why}) — reason=\"noise\" "
                        f"asserts inbound spam/clutter, which cannot be true for an address "
                        f"the subject engaged or the roster names, and would sweep a possible "
                        f"recipient out of the exhaustion duty by mislabel. Settle it "
                        f"out_of_scope (relevant channel, not this case) or excluded (evidence "
                        f"rules it out), or reference it in a finding — do not label an engaged "
                        f"correspondent noise.")}

    # A near-alias correspondent (same domain, same-length local part, one
    # character apart from another observed correspondent) cannot be EXCLUDED on
    # a roster/senders listing. Excluding asserts it is uninvolved — for a
    # near-twin of an engaged address that must rest on reading ITS messages,
    # not an assumed typo. Require a body read (read.read_mail mode=messages)
    # that queried this address among the cited evidence. Symmetric: the same
    # read can equally prove the pair distinct.
    if tk == "correspondent" and rs in ("excluded", "out_of_scope", "noise"):
        tnorm = target_id.strip().lower()
        corr = getattr(idx, "correspondents", {}) or {}

        def _near(a, b):
            if "@" not in a or "@" not in b:
                return False
            la, da = a.rsplit("@", 1)
            lb, db = b.rsplit("@", 1)
            return (da == db and len(la) == len(lb) and la != lb
                    and sum(1 for x, y in zip(la, lb) if x != y) == 1)

        if any(_near(tnorm, other) for other in corr if other != tnorm):
            local = tnorm.split("@", 1)[0]
            stems = {tnorm} | {local[i:i + 4] for i in range(max(1, len(local) - 3))}
            body_read = any(
                "read.read_mail" in (cmd := str((idx.by_call_id.get(c) or {}).get("cmd", "")).lower())
                and "mode=messages" in cmd and any(s in cmd for s in stems)
                for c in cids)
            if not body_read:
                return {
                    "success": False, "gate": "typed_disposition",
                    "detail_gate": "near_alias_needs_body_read",
                    "error": (
                        f"{target_id} is a near-alias (one character apart, same domain) "
                        f"of another observed correspondent — settling it {rs!r} dismisses "
                        f"it, which for a near-twin of an engaged address must rest on "
                        f"reading ITS messages, not an assumed typo. Cite a read.read_mail "
                        f"mode=messages call that queried {target_id} (field=body) among "
                        f"evidence_call_ids, or resolve the pair with a finding — do not "
                        f"dismiss it on a roster/senders listing.")}
    cid = log.record_disposition(target_kind, target_id, reason, evidence_call_ids=cids,
                                 note=note, window=window, input_call_ids=input_call_ids)
    return {"success": True, "call_id": cid, "_trudi_call_id": cid,
            "target_kind": target_kind.strip().lower(),
            "target_norm": D.normalize_target(target_kind, target_id), "reason": rs}


@mcp.tool()
@output_safe
def record_finding(
    description: str,
    confidence: str,
    source: str = "",
    linked_call_id: int = 0,
    tested_hypothesis_id: str = "",
    input_call_ids: list[int] | None = None,
    supporting_evidence: str = "",
    supersedes: int = 0,
    claim_kind: str = "",
    category: str = "",
    entities: list[str] | None = None,
    channel: str = "",
    window: dict | None = None,
    act: str = "",
    actor_kind: str = "",
    actor: str = "",
    principal: str = "",
    recipients: list[str] | None = None,
    scope: list[str] | None = None,
    session_type: str = "",
    threat_actor: str = "",
    techniques: list[str] | None = None,
    artifacts: list[str] | None = None,
    session_binding_call_ids: list[int] | None = None,
    transfer_call_ids: list[int] | None = None,
    receipt_call_ids: list[int] | None = None,
    rule_outs: list[dict] | None = None,
    resolves: str = "",
    answers_case_question: bool = False,
) -> dict:
    """
    Record a confirmed finding to the execution trace.
    confidence: CONFIRMED / LIKELY / SUSPECTED / UNCONFIRMED.
    supersedes: call_id of an earlier finding this record replaces (e.g. re-tier
                a LIKELY finding to CONFIRMED after new evidence earns a SUPPORTED
                evaluate). The old entry is marked superseded; the report and
                accuracy layer then count only this final tier. Runs the full
                gate set, so an upward re-tier still needs its SUPPORTED
                reason.evaluate_finding + citation.
    source: tool or artifact that produced the finding e.g. 'vol.psscan', 'ez.mftecmd'.
    linked_call_id: the _trudi_call_id value from the tool result that produced this
                    finding — enables judges to trace any finding back to its source
                    tool execution in the audit log.
    supporting_evidence: RECOMMENDED for CONFIRMED/LIKELY. When supplied, the
                    confidence_and_citation gate runs a DETERMINISTIC citation
                    check on it (every concrete artifact value in the description
                    — IPs, hashes, paths, technique IDs — must appear here) INSTEAD
                    of requiring separate reason.confidence_score + reason.cite_check
                    model calls. This is the fast path: one call instead of three.
                    Omit it only to use the legacy path (those two reason calls
                    must precede the record). CONFIRMED still also needs a
                    SUPPORTED reason.evaluate_finding either way.
    TYPED CLAIM (tools/_gates/_claims.py) — declare what the finding asserts;
                    gates key ONLY on these fields, never on your wording.
                    REQUIRED for CONFIRMED / LIKELY / UNCONFIRMED (SUSPECTED optional):
                      claim_kind  'positive'|'negative'
                      category    'exfil'|'logon_auth'|'identity'|'persistence'|
                                  'device_initial_access'|'execution'|'delivery'|
                                  'destruction'|'attribution'|'other'
                      act         'presence'|'execution'|'timeline'|'account_creation'|
                                  'persistence_install'|'logon'|'egress'|'delivery'|
                                  'possession'|'c2'|'lateral_movement'|'credential_access'|
                                  'destruction'|'attribution'|'other'
                    Conditional: act='egress' ⇒ channel ('removable'|'cloud'|'email'|
                    'web'|'ftp'|'chat'|'c2'|'other') and transfer_call_ids (the
                    transfer artifact entries); act in delivery/possession ⇒
                    recipients (+ receipt_call_ids); actor_kind='human' ⇒ actor;
                    principal ⇒ actor_kind human|unknown and session_binding_call_ids
                    (the logon/session artifact entries binding it); a negative in
                    logon_auth / device_initial_access ⇒ window {start,end}.
                    Optional: entities, scope (sources searched, negatives),
                    session_type, threat_actor, techniques, artifacts, rule_outs
                    [{what, call_ids}], resolves ('confirmed'|'refuted' for
                    tested_hypothesis_id), answers_case_question.
    input_call_ids: N:M upstream lineage. If omitted, it is auto-inferred from the
                    recent tool/reason results (stamped lineage_inferred); pass it
                    explicitly for precise provenance.

    Gates (any failure refuses the call; the response carries a broad
    `gate: "<snake_case_identifier>"` field the agent can switch on. Some
    broad gates also include `detail_gate` naming the focused checker that
    refused the finding):

      - `mcp_routing`: linked_call_id (if non-zero) must NOT point to a raw-bash
        tool_call executing a forensic binary — forensic execution must flow
        through the typed MCP wrapper. Error names the wrapper to switch to.
      - `dair_required`: Recent dair_assess required (any tier). Findings only
        exist inside an active DAIR-directed investigation.
      - `lineage_required`: findings must cite upstream trace call IDs, either
        explicitly or via the auto-inferred recent-input path.
      - `tier_contract`: the tier a CONFIRMED/LIKELY finding asks for must be
        reachable from the ARTIFACT CLASSES its cited calls carry
        (data/fk/tiering.yaml — deterministic, never the reviewer's opinion).
        The refusal carries `tier_achievable` and `tier_path` (the missing
        classes and the tools that produce them); a success carries
        `tier_achievable` and, when you under-asked, `tier_headroom`.
      - `evidence_strength`: confidence tier, linked evidence, ATT&CK IDs,
        SUPPORTED fact-check evaluation for CONFIRMED/LIKELY findings, citation
        support for CONFIRMED/LIKELY findings, and required hypothesis review.
      - `completeness`: absence/unknown claims must not rely on truncated output,
        and case-inverting absence claims require a complete source manifest plus
        coverage over the claimed time window.
      - `attribution`: account/person/device/threat-actor attribution requires
        auth, session, or control evidence; interactive authorship must address
        automation/device alternatives when removable media is in evidence.
      - `transfer`: named exfiltration channels require a transfer artifact, not
        mere file presence, sync-folder presence, ADS, or tool execution.
    """
    from core.execution_log import log
    from tools._gates import GateContext, run_gates

    # Auto-infer lineage when the agent omits it. The trace already knows which
    # recent tool/reason results preceded this finding, and hand-typing the
    # foreign keys is a footgun (out-of-order / fabricated cids). Inference is
    # recorded as lineage_inferred so the audit shows the edge was derived, not
    # declared. Explicit input_call_ids always win.
    lineage_inferred = False
    if not input_call_ids:
        _auto = _infer_input_call_ids(log.last_n_window(30))
        if _auto:
            input_call_ids = _auto
            lineage_inferred = True

    # Typed claim — normalized once; gates key on this declared structure only.
    from tools._gates._claims import normalize_claim, declared as _claim_declared
    claim = normalize_claim(
        claim_kind=claim_kind, category=category, entities=entities, channel=channel,
        window=window, act=act, actor_kind=actor_kind, actor=actor, principal=principal,
        recipients=recipients, scope=scope, session_type=session_type,
        threat_actor=threat_actor, techniques=techniques, artifacts=artifacts,
        session_binding_call_ids=session_binding_call_ids,
        transfer_call_ids=transfer_call_ids, receipt_call_ids=receipt_call_ids,
        rule_outs=rule_outs, resolves=resolves, answers_case_question=answers_case_question)

    ctx = GateContext(
        description=description,
        confidence=confidence,
        tier=(confidence or "").upper(),
        source=source,
        linked_call_id=linked_call_id,
        tested_hypothesis_id=tested_hypothesis_id,
        log=log,
        idx=log.index(),
        window=log.last_n_window(30),
        input_call_ids=list(input_call_ids) if input_call_ids else [],
        supporting_evidence=supporting_evidence or "",
        claim=claim,
    )

    failure = run_gates(ctx)
    if failure is not None:
        # Refusal ledger — the single write site (record_agent_message delegates
        # here, so batched findings get exactly one entry each). The
        # refusal_rewording gate reads these to refuse a re-record that only
        # changed the wording.
        try:
            log.record_finding_refused(
                description, ctx.tier, failure.get("gate", ""),
                failure.get("detail_gate", ""),
                claim=claim if _claim_declared(claim) else None,
                input_call_ids=ctx.input_call_ids or None,
                cited_call_ids=[*(ctx.input_call_ids or []),
                                *([linked_call_id] if linked_call_id else [])],
                extra={k: failure[k] for k in ("evaluate_verdict", "evaluate_match",
                                               "claim_mismatch", "tier_achievable",
                                               "tier_path", "artifact_classes",
                                               "missing") if k in failure},
                tested_hypothesis_id=tested_hypothesis_id or "",
                error=str(failure.get("error") or ""),
            )
        except Exception:
            pass
        return failure

    # Carry every gate-matched call_id onto the finding entry as an explicit
    # foreign key. The chain view, accuracy report, and synthesize all use
    # these directly instead of inferring links from user_message substrings.
    gate_metadata = {}
    if ctx.gated_by_evaluate_call_id:
        gate_metadata["gated_by_evaluate_call_id"] = ctx.gated_by_evaluate_call_id
    if ctx.gated_by_confidence_call_id:
        gate_metadata["gated_by_confidence_call_id"] = ctx.gated_by_confidence_call_id
    if ctx.gated_by_cite_check_call_id:
        gate_metadata["gated_by_cite_check_call_id"] = ctx.gated_by_cite_check_call_id
    if ctx.gated_by_hypothesize_call_id and not tested_hypothesis_id:
        # only stamp if the agent didn't supply tested_hypothesis_id directly
        gate_metadata["gated_by_hypothesize_call_id"] = ctx.gated_by_hypothesize_call_id
    if ctx.validated_techniques:
        gate_metadata["validated_techniques"] = ctx.validated_techniques
    if ctx.citation_mode:
        # "deterministic" ⇒ citation verified inline from supporting_evidence
        # (no confidence_score/cite_check model round-trips were needed).
        gate_metadata["citation_mode"] = ctx.citation_mode
    if lineage_inferred:
        gate_metadata["lineage_inferred"] = True
    if ctx.tier_achievable:
        # Deterministic tier contract: what the cited artifact classes
        # reach, stamped for the audit whatever tier was recorded.
        gate_metadata["tier_achievable"] = ctx.tier_achievable
        gate_metadata["tier_rule"] = ctx.tier_rule
        gate_metadata["artifact_classes"] = ctx.artifact_classes

    log.record_finding(
        description, confidence, source, linked_call_id, tested_hypothesis_id,
        gate_metadata=gate_metadata,
        input_call_ids=input_call_ids,
        supersedes=supersedes,
        supporting_evidence=supporting_evidence or "",
        claim=claim if _claim_declared(claim) else None,
    )
    result = {"success": True, "description": description, "confidence": confidence}
    if ctx.tier_achievable:
        from tools._gates._tiering import _RANK as _TRANK
        result["tier_achievable"] = ctx.tier_achievable
        result["artifact_classes"] = ctx.artifact_classes
        if _TRANK.get(ctx.tier_achievable, 0) > _TRANK.get(ctx.tier, 0):
            result["tier_headroom"] = (
                f"tier–evidence concordance: recorded {ctx.tier}; the cited artifact "
                f"classes reach {ctx.tier_achievable} (rule {ctx.tier_rule}). The tier "
                f"must match the evidence in both directions — re-examine and either "
                f"re-record at {ctx.tier_achievable} (supersedes=<this call_id>) or "
                f"leave a documented reason. This is arithmetic, not an instruction "
                f"to strengthen a conclusion.")
    if supersedes:
        result["supersedes"] = int(supersedes)
    if ctx.validated_techniques:
        result["validated_techniques"] = ctx.validated_techniques
    if gate_metadata:
        result["gate_chain"] = {
            k: v for k, v in gate_metadata.items()
            if k.startswith("gated_by_")
        }
    # warn-early: FK-driven corroboration completeness. Non-blocking advisory on
    # a valid CONFIRMED/LIKELY finding whose grounding artifact's corroborators
    # (per the FK sheet) never ran — a nudge while collection is still possible.
    # The hard block is reason.pre_report_check. Fail-open: never breaks a finding.
    try:
        from tools._gates.fk_corroboration import note_for_finding
        note = note_for_finding(
            tier=ctx.tier, description=description, source=source, idx=ctx.idx, claim=claim)
        if note:
            result["completeness_note"] = note
    except Exception:
        pass
    # warn-early: atomicity advisory. Non-blocking nudge when a CONFIRMED/LIKELY
    # description bundles multiple distinct claims, which would share one
    # linked_call_id and lose per-claim traceability. Fail-open.
    if ctx.tier in {"CONFIRMED", "LIKELY"}:
        try:
            from tools._gates.atomicity import atomicity_note
            anote = atomicity_note(description)
            if anote:
                result["atomicity_note"] = anote
        except Exception:
            pass
    # warn-early: lineage content check. Non-blocking nudge when a finding
    # quotes concrete artifact values that appear in NONE of its cited call_ids'
    # evidence — a mis-transcribed call_id that lineage_required cannot catch
    # (it only checks the id exists). Fail-open.
    try:
        from tools._gates.lineage_content import lineage_content_note
        lnote = lineage_content_note(ctx)
        if lnote:
            result["lineage_content_note"] = lnote
    except Exception:
        pass
    return result


@mcp.tool()
@output_safe
def record_self_correction(
    trigger: str,
    prior_belief: str,
    new_belief: str,
    evidence: str = "",
    linked_call_id: int = 0,
    input_call_ids: list[int] | None = None,
) -> dict:
    """
    Record a first-class self-correction event in the execution trace. Use this
    whenever the investigation revises a prior belief — refuted IOC, rejected
    hypothesis, retried tool sequence, downgraded confidence tier, etc.

    trigger: one of evaluate_challenged, dair_max_pass_cap, tool_failure_recovery,
             hypothesis_refuted, verification_challenge_refuted, gate_refusal.
    prior_belief: what you thought before the correction.
    new_belief: what you think now, and why.
    evidence: short citation (tool name + key field) for the revision.
    linked_call_id: _trudi_call_id of the result that triggered the correction.
    input_call_ids: list of _trudi_call_id values that informed this correction
                    (the calls whose results made you change your mind).
    """
    from core.execution_log import log
    if trigger == "dair_max_pass_cap":
        # The cap may not override OPEN verification challenges (operator
        # decision): refuse while the latest dair_assess still carries a
        # verified:null challenge whose challenge_method has not run.
        from tools._gates.max_pass_cap import max_pass_cap_gate
        refusal = max_pass_cap_gate(log)
        if refusal is not None:
            return refusal
    cid = log.record_self_correction(
        trigger, prior_belief, new_belief, evidence, linked_call_id,
        input_call_ids=input_call_ids,
    )
    return {"success": True, "trigger": trigger, "_trudi_call_id": cid}


@mcp.tool()
@output_safe
def export_execution_log(output_path: str) -> dict:
    """
    Export the execution trace to <output_path>.json and <output_path>.md.
    Call after reason.synthesize completes and before writing the final report.
    output_path must be in analysis/, exports/, or reports/.

    Gate: refuses unless the most recent reason.pre_report_check call returned
    READY_TO_REPORT: true. Guarantees the final report cannot be written
    without the mandatory pre-report verification step.
    """
    from core.execution_log import log

    refusal = _pre_report_ready_gate()
    if refusal is not None:
        if "error" in refusal:
            refusal = {
                **refusal,
                "error": refusal["error"].replace(
                    "refused:", "export_execution_log refused:", 1
                ),
            }
        return refusal

    result = log.export(output_path)
    return {
        "success": True,
        "entry_count": result.get("entry_count", 0),
        "json_path": output_path + ".json",
        "md_path": output_path + ".md",
    }


@mcp.tool()
@output_safe
def write_final_report(output_path: str, content: str) -> dict:
    """
    Write the final Markdown report only after reason.pre_report_check returned
    READY_TO_REPORT: true. This is the report-side counterpart to
    export_execution_log; use it instead of raw file writes for final reports.
    """
    refusal = _pre_report_ready_gate()
    if refusal is not None:
        if "error" in refusal:
            refusal = {
                **refusal,
                "error": refusal["error"].replace(
                    "refused:", "write_final_report refused:", 1
                ),
            }
        return refusal

    assert_output_safe(output_path)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    from core.execution_log import log
    # H-6: synthesize blockers that pre_report_check demoted to warnings (round
    # 2+ with no new evidence) are carried into the report verbatim, so the
    # reader sees what the reviewer could not settle. Appended server-side —
    # the agent cannot leave them out.
    limitations: list = []
    try:
        for e in reversed(log._entries):
            if e.get("type") == "reason_call" and e.get("tool") == "reason_pre_report_check":
                limitations = list(e.get("synthesize_blockers_unresolved") or [])
                break
    except Exception:
        limitations = []
    # The evidence-registry inventory (correspondents / identities /
    # surfaced principals with their status) is rendered into the report
    # server-side — everything the checks did not require a disposition for
    # is still SHOWN, so relevance scoping never hides an identity.
    inventory: dict = {}
    lifecycle: dict = {}
    try:
        for e in reversed(log._entries):
            if e.get("type") == "reason_call" and e.get("tool") == "reason_pre_report_check":
                inventory = dict(e.get("registry_inventory") or {})
                lifecycle = dict(e.get("lifecycle_coverage") or {})
                break
    except Exception:
        inventory = {}

    # Attack-lifecycle coverage table — per phase, whether the
    # investigation established it, ruled it out, examined its sources, or never
    # looked. Rendered so every report states its own coverage of the five DFIR
    # goals (never a demand that an attack exist).
    if lifecycle and "attack-lifecycle coverage" not in content.lower():
        _order = ["persistence", "privilege_escalation", "lateral_movement", "execution", "exfil"]
        _lbl = {"established": "established", "ruled_out": "ruled out",
                "examined": "examined (no verdict)", "not_examined": "NOT examined"}
        _sec = ["\n\n## Attack-lifecycle coverage",
                "Coverage of the five DFIR goals for this investigation. A phase is covered "
                "by establishing it, ruling it out with a grounded negative, or examining its "
                "artifact sources; `NOT examined` marks a blind spot.",
                "\n| phase | status | sources examined |\n|---|---|---|"]
        for _pid in _order:
            _c = lifecycle.get(_pid)
            if not _c:
                continue
            _sec.append(f"| {_c.get('label', _pid)} | {_lbl.get(_c.get('status'), _c.get('status',''))} "
                        f"| {len(_c.get('sources_examined') or [])}/{_c.get('sources_total', 0)} |")
        content = content.rstrip() + "\n".join(_sec) + "\n"
    inv_rows = 0
    if inventory and "registry inventory" not in content.lower():
        sec = ["\n\n## Evidence registry inventory",
               "Every correspondent, identity and surfaced principal the parsed stores and "
               "the investigation registered, with how it was settled. Items marked "
               "`inventory` matched no case roster, were not engaged and were not forced — "
               "they were not required to be dispositioned and are listed for completeness."]
        corr = inventory.get("correspondents") or []
        if corr:
            sec.append("\n### Correspondents (mail / chat stores)\n")
            sec.append("| address | from | to | sources | status |\n|---|---|---|---|---|")
            for r in corr:
                sec.append(f"| {r.get('address','')} | {r.get('from', '')} | {r.get('to', '')} | "
                           f"{', '.join(r.get('sources') or [])} | {r.get('status','')} |")
                inv_rows += 1
        ids = inventory.get("identities") or []
        if ids:
            sec.append("\n### Identities (PCAP / structured extractors)\n")
            sec.append("| identity | first call | status |\n|---|---|---|")
            for r in ids:
                sec.append(f"| {r.get('value','')} | {r.get('first_cid','')} | {r.get('status','')} |")
                inv_rows += 1
        prs = inventory.get("principals") or []
        if prs:
            sec.append("\n### Surfaced principals\n")
            sec.append("| principal | how | status |\n|---|---|---|")
            for r in prs:
                sec.append(f"| {r.get('value','')} | {r.get('how','')} | {r.get('status','')} |")
                inv_rows += 1
        leads = inventory.get("alias_leads") or []
        if leads:
            sec.append("\n### Near-alias correspondent pairs (unresolved — one character apart)\n")
            sec.append("| address A | address B |\n|---|---|")
            for r in leads:
                sec.append(f"| {r.get('a','')} | {r.get('b','')} |")
                inv_rows += 1
        roster = inventory.get("roster") or []
        if roster:
            sec.append(f"\nCase roster terms used for relevance: {len(roster)} "
                       f"(derived by misc.knowns_pattern_generate).")
        if inv_rows:
            content = content.rstrip() + "\n".join(sec) + "\n"
    appended = 0
    if limitations and "reviewer limitations" not in content.lower():
        content = (content.rstrip() + "\n\n## Reviewer limitations (unresolved synthesize blockers)\n"
                   "The adversarial reviewer raised the following points that could not be settled "
                   "with the evidence in scope; the recorded tiers already reflect the evaluate "
                   "reviewer's caps.\n"
                   + "\n".join(f"- {b}" for b in limitations) + "\n")
        appended = len(limitations)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    cid = log.record_tool_call(
        cmd=f"<py>:misc_write_final_report {output_path}",
        success=True,
        truncated=False,
        retries=0,
        exit_code=0,
    )
    if limitations or inv_rows:
        try:
            # appended = the server added the section; present = the agent
            # already wrote one (the typed list is still on the pre_report entry).
            log.annotate_tool_call(cid, limitations_appended=appended or None,
                                   limitations_present=len(limitations) or None,
                                   inventory_rows_appended=inv_rows or None)
        except Exception:
            pass
    return {
        "success": True,
        "output_path": output_path,
        "bytes_written": len(content.encode("utf-8")),
        "limitations_appended": appended,
        "limitations_present": len(limitations),
        "inventory_rows_appended": inv_rows,
        "_trudi_call_id": cid,
    }


@mcp.tool()
@output_safe
def record_agent_message(
    content: str,
    input_call_ids: list[int] | None = None,
    findings: list[dict] | None = None,
    dispositions: list[dict] | None = None,
) -> dict:
    """
    Log the orchestrator's analysis or interpretation to the execution trace,
    optionally with structured findings recorded atomically.

    Call this at these moments:
    - After interpreting a batch of parallel tool results (before selecting next tools)
    - After each reason.* call (what the reviewer concluded, which directives apply)
    - Whenever you reach a conclusion that changes the investigation direction

    content: the analysis text — what you observed, concluded, or decided to do next.
    input_call_ids: list of _trudi_call_id values from the tool results being interpreted.
    findings: optional list of structured findings produced by this analysis. Each is
              {description, confidence, linked_call_id, source, tested_hypothesis_id?}.
              Each finding is validated by the same gates as misc.record_finding (recent
              dair_call required, CONFIRMED requires non-zero linked_call_id + recent
              SUPPORTED evaluate_finding, etc.). Per-finding gate failures come back in
              the response so the agent can react; the narration entry is still written.

    Use the `findings=[…]` parameter whenever your analysis contains factual claims
    (CONFIRMED behavior, attribution, attacker tooling, exfiltration channel, etc.).
    Prose-only analysis is for reasoning and direction; facts go through `findings`.

    dispositions: optional list to settle many leads at once — one round-trip
              instead of one misc.record_disposition call each. Each is
              {target_kind, target_id, reason, evidence_call_ids?, note?, window?}.
              Every entry runs the SAME per-target gates as misc.record_disposition
              (nothing is loosened); per-entry results and any_disposition_refused
              come back. Use it to clear a batch of inapplicable tools or inventory
              correspondents without a call-per-target grind.
    """
    from core.execution_log import log
    cid = log.record_agent_message(content, input_call_ids)
    result: dict = {"success": True, "call_id": cid}

    # Batch dispositions (mirrors findings=[…]) — one round-trip to settle many
    # tools/correspondents/sources instead of one call each. Each entry runs the
    # SAME per-target gates as misc.record_disposition (relevance, near-alias,
    # evidence-required, injector rule-out), so nothing is loosened; per-entry
    # results come back so the agent can react to any refusal.
    if dispositions:
        disp_out: list[dict] = []
        any_disp_failed = False
        for d in dispositions:
            d_cids = d.get("input_call_ids")
            if d_cids is None:
                d_cids = input_call_ids
            r = record_disposition(
                target_kind=d.get("target_kind", "") or "",
                target_id=d.get("target_id", "") or "",
                reason=d.get("reason", "") or "",
                evidence_call_ids=d.get("evidence_call_ids") or None,
                note=d.get("note", "") or "",
                window=d.get("window") or None,
                input_call_ids=d_cids,
            )
            disp_out.append(r)
            if not r.get("success"):
                any_disp_failed = True
        result["dispositions"] = disp_out
        result["any_disposition_refused"] = any_disp_failed

    if not findings:
        return result

    # Each finding goes through the SAME gate as record_finding (DRY by
    # delegation, so the rules can never diverge). Per-finding input_call_ids
    # default to the agent-message's input_call_ids — the message and its
    # findings logically share the same upstream evidence.
    findings_out: list[dict] = []
    any_failed = False
    for f in findings:
        f_input_cids = f.get("input_call_ids")
        if f_input_cids is None:
            f_input_cids = input_call_ids  # inherit from the surrounding message
        r = record_finding(
            description=f.get("description", ""),
            confidence=f.get("confidence", ""),
            source=f.get("source", ""),
            linked_call_id=int(f.get("linked_call_id") or 0),
            tested_hypothesis_id=f.get("tested_hypothesis_id", "") or "",
            input_call_ids=f_input_cids,
            # Forward supporting_evidence so batched findings can hit the
            # deterministic evidence fast path.
            supporting_evidence=f.get("supporting_evidence", "") or "",
            supersedes=int(f.get("supersedes") or 0),
            # Typed-claim fields — batched findings must not silently lose them.
            claim_kind=f.get("claim_kind", "") or "",
            category=f.get("category", "") or "",
            entities=f.get("entities") or [],
            channel=f.get("channel", "") or "",
            window=f.get("window") or {},
            act=f.get("act", "") or "",
            actor_kind=f.get("actor_kind", "") or "",
            actor=f.get("actor", "") or "",
            principal=f.get("principal", "") or "",
            recipients=f.get("recipients") or [],
            scope=f.get("scope") or [],
            session_type=f.get("session_type", "") or "",
            threat_actor=f.get("threat_actor", "") or "",
            techniques=f.get("techniques") or [],
            artifacts=f.get("artifacts") or [],
            session_binding_call_ids=f.get("session_binding_call_ids") or [],
            transfer_call_ids=f.get("transfer_call_ids") or [],
            receipt_call_ids=f.get("receipt_call_ids") or [],
            rule_outs=f.get("rule_outs") or [],
            resolves=f.get("resolves", "") or "",
            answers_case_question=bool(f.get("answers_case_question")),
        )
        findings_out.append(r)
        if not r.get("success"):
            any_failed = True
    result["findings"] = findings_out
    result["any_finding_refused"] = any_failed
    return result


@mcp.tool()
@output_safe
def clear_case_run(case_dir: str) -> dict:
    """
    Reset a case for a fresh investigation run. Deletes:
      - analysis/, exports/, reports/ contents
      - ~/.cache/trudi/session.json (prevents auto-reconnect to stale trace)
      - ~/.claude/projects/<encoded>/memory/ files (clears case memory)

    case_dir: absolute path to the case directory e.g. ~/cases/example-case
    """
    import shutil
    import glob
    cleared = []
    errors = []

    for subdir in ("analysis", "exports", "reports"):
        target = os.path.join(case_dir, subdir)
        for item in glob.glob(os.path.join(target, "*")):
            try:
                if os.path.isdir(item):
                    shutil.rmtree(item)
                else:
                    os.remove(item)
                cleared.append(item)
            except OSError as e:
                errors.append(str(e))

    session = os.path.expanduser("~/.cache/trudi/session.json")
    if os.path.exists(session):
        try:
            os.remove(session)
            cleared.append(session)
        except OSError as e:
            errors.append(str(e))

    encoded = case_dir.replace("/", "-")
    memory_dir = os.path.expanduser(f"~/.claude/projects/{encoded}/memory")
    if os.path.isdir(memory_dir):
        for item in glob.glob(os.path.join(memory_dir, "*")):
            try:
                os.remove(item)
                cleared.append(item)
            except OSError as e:
                errors.append(str(e))

    return {
        "success": len(errors) == 0,
        "cleared_count": len(cleared),
        "cleared": cleared,
        "errors": errors,
    }


# ── Email forensics ─────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def pff_export(pst_path: str, output_dir: str, mode: str = "items") -> dict:
    """
    Extract PST/OST email containers using pffexport (libpff).

    mode: items (default — produces a directory tree of messages), all,
          recovered, or debug. Outputs are written under output_dir.
    """
    binary = _bin_or_warn("pffexport")
    if not binary:
        return {"success": False, "error": "pffexport not installed — apt install pff-tools"}
    os.makedirs(output_dir, exist_ok=True)
    # -q: quiet — suppress the progress banner from stdout. pffexport APPENDS
    # ".export" to the -t target, so the real output tree is
    # `<output_dir>.export/` (a call reporting output_dir left it empty and the
    # agent read "no mail" — a false-absence episode). Surface the true path
    # and a read hint so read.read_mail is pointed at the tree that exists.
    r = run([binary, "-q", "-m", mode, "-t", output_dir, pst_path], timeout=1800)
    if isinstance(r, dict) and r.get("success"):
        actual = output_dir + ".export"
        r["output_path"] = actual if os.path.isdir(actual) else output_dir
        r["layout"] = "pffexport_items"
        r["read_hint"] = (f"read.read_mail over {r['output_path']} — pffexport item tree "
                          f"(MessageNNNNN/ dirs), consumed natively; or use "
                          f"misc.readpst_extract for an mbox.")
    return r


@mcp.tool()
@output_safe
def readpst_extract(pst_path: str, output_dir: str, format_mbox: bool = True) -> dict:
    """
    Convert a PST file to mbox (default) or per-message MIME using readpst.

    format_mbox: True → -o mbox; False → -e (per-message .eml files).
    """
    binary = _bin_or_warn("readpst")
    if not binary:
        return {"success": False, "error": "readpst not installed — sudo apt install pst-utils"}
    os.makedirs(output_dir, exist_ok=True)
    # -q: quiet — only error messages on stdout (progress banner otherwise
    # dominates the trace excerpt; converted mail is written under output_dir).
    cmd = [binary, "-q", "-o", output_dir]
    if not format_mbox:
        cmd.append("-e")
    cmd.append(pst_path)
    return run(cmd, timeout=1800)


# ── Packer / entropy detection ──────────────────────────────────────────────

@mcp.tool()
@output_safe
def densityscout_scan(target: str, threshold: float = 0.10) -> dict:
    """
    Run densityscout to identify packed / encrypted regions in a file or directory.

    target: file or directory path.
    threshold: density threshold (0.0–1.0). Higher = more permissive matches.
    Output rows are formatted as `<density> <offset> <path>` per region.
    """
    binary = _bin_or_warn("densityscout") or "/usr/local/bin/densityscout"
    if not os.path.exists(binary):
        return {"success": False, "error": "densityscout not installed"}
    cmd = [binary, "-pe", "-t", str(threshold), target]
    return run(cmd, timeout=600)


# ── Sigma-rule hunting on EVTX ──────────────────────────────────────────────

@mcp.tool()
@output_safe
def chainsaw_hunt(evtx_dir: str, sigma_dir: Optional[str] = None,
                  output_path: Optional[str] = None) -> dict:
    """
    Run chainsaw to hunt Sigma rules across EVTX logs.

    evtx_dir: directory of EVTX files (or a single file).
    sigma_dir: directory of Sigma rules. Defaults to chainsaw's bundled
               sigma_rules/ if installed in /opt/chainsaw or /usr/local/share.
    output_path: optional CSV/JSON output destination (must be under analysis/,
                 exports/, or reports/).

    Sigma is a generic detection-rule language for SIEMs; chainsaw applies it
    locally against EVTX. Complementary to EvtxECmd's flat extraction.
    """
    if output_path:
        assert_output_safe(output_path)
    binary = _bin_or_warn("chainsaw")
    if not binary:
        return {"success": False, "error":
                "chainsaw not installed — see install.sh for the binary release "
                "(github.com/WithSecureLabs/chainsaw)"}
    if sigma_dir is None:
        for candidate in ("/opt/chainsaw/sigma", "/usr/local/share/chainsaw/sigma",
                          "/usr/share/chainsaw/sigma"):
            if os.path.isdir(candidate):
                sigma_dir = candidate
                break
    cmd = [binary, "hunt", evtx_dir]
    if sigma_dir:
        cmd += ["-s", sigma_dir, "--mapping", sigma_dir + "/../mappings/sigma-event-logs-all.yml"]
    if output_path:
        cmd += ["--csv", "--output", output_path]
    return run(cmd, timeout=3600)


# ── Capability analysis (FLARE capa) ────────────────────────────────────────

@mcp.tool()
@output_safe
def capa_analyze(file_path: str, output_path: Optional[str] = None) -> dict:
    """
    Analyze a binary's capabilities using FLARE's capa. Identifies what the
    sample CAN do (network I/O, encryption, persistence, anti-analysis, …) and
    maps each capability to MITRE ATT&CK technique IDs.

    file_path: PE or ELF binary, or shellcode buffer.
    output_path: optional JSON report destination.
    """
    if output_path:
        assert_output_safe(output_path)
    binary = _bin_or_warn("capa")
    if not binary:
        return {"success": False, "error":
                "capa not installed — pip install flare-capa"}
    cmd = [binary]
    if output_path:
        cmd += ["-j"]  # JSON output to stdout, we redirect via run() if needed
    cmd.append(file_path)
    result = run(cmd, timeout=600)
    if output_path and result.get("success") and result.get("stdout"):
        try:
            with open(output_path, "w") as f:
                f.write(result["stdout"])
            result["output_path"] = output_path
        except OSError as e:
            result["write_error"] = str(e)
    return result


# ── Office macro analysis (python-oletools) ─────────────────────────────────

@mcp.tool()
@output_safe
def olevba_scan(office_path: str, decode: bool = True) -> dict:
    """
    Extract and analyze VBA macros from Microsoft Office documents using olevba.

    office_path: .doc, .docx, .xls, .xlsm, .ppt, .pptm, etc.
    decode: decode obfuscated strings (recommended).

    Flags suspicious patterns (AutoOpen, Shell, URLDownloadToFile, MZ headers
    in strings, IOCs, etc.) — a strong signal for phishing-borne initial access.
    """
    binary = _bin_or_warn("olevba") or _bin_or_warn("olevba3")
    if not binary:
        return {"success": False, "error":
                "olevba not installed — pip install oletools"}
    cmd = [binary]
    if decode:
        cmd.append("--decode")
    cmd.append(office_path)
    return run(cmd, timeout=300)


@mcp.tool()
@output_safe
def mraptor_scan(office_path: str) -> dict:
    """
    Triage an Office document for malicious-macro indicators using MRaptor.

    Faster than full olevba — returns SUSPICIOUS or CLEAN with the trigger
    pattern (auto-exec, write to system, execute external command, etc.).
    """
    from tools._exit_codes import policy
    binary = _bin_or_warn("mraptor") or _bin_or_warn("mraptor3")
    if not binary:
        return {"success": False, "error":
                "mraptor not installed — pip install oletools"}
    return run([binary, office_path], timeout=120, **policy("mraptor"))


# ── Parallel batch execution ────────────────────────────────────────────────

@mcp.tool()
@output_safe
def batch_run(tool_calls: list[dict], max_concurrent: int = 4) -> dict:
    """
    Execute multiple independent shell tool calls concurrently and return all
    results. Use this when DAIR's priority_tools contains several commands that
    don't depend on each other.

    tool_calls: list of {"cmd": ["binary", "arg1", ...], "timeout": optional int}
    max_concurrent: maximum parallel workers (default 4).

    Returns: {"success": all_succeeded, "results": [per-call dicts]}.

    Note: this runs raw subprocess commands. For typed MCP forensic tools, the
    agent should still call them one at a time (or use the MCP client's own
    parallel-call mechanism). This helper is for low-level batches like
    "hash these 10 files" or "strings on these 5 binaries".
    """
    import concurrent.futures

    def _one(spec):
        cmd = spec.get("cmd")
        if not cmd or not isinstance(cmd, list):
            return {"success": False, "error": "missing or invalid 'cmd' (must be list)"}
        timeout = int(spec.get("timeout") or 300)
        return run(cmd, timeout=timeout)

    if not tool_calls:
        return {"success": True, "results": []}
    if max_concurrent < 1:
        max_concurrent = 1

    results = [None] * len(tool_calls)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as ex:
        futures = {ex.submit(_one, spec): i for i, spec in enumerate(tool_calls)}
        for fut in concurrent.futures.as_completed(futures):
            results[futures[fut]] = fut.result()

    return {
        "success": all(r.get("success") for r in results if r),
        "results": results,
    }


# ── Trace dashboard discovery ───────────────────────────────────────────────
# The dashboard runs as a separate long-lived process (`trudi-dashboard`).
# These helpers discover it via the file the dashboard writes to
# ~/.cache/trudi/dashboard.url on startup, and surface a deep-link URL that
# pre-selects this case's trace.

_DASHBOARD_DISCOVERY_FILE = os.path.expanduser("~/.cache/trudi/dashboard.url")


def _detect_case_id(case_dir: str) -> str:
    """Best-effort case_id discovery: look for `**Case ID**` in CLAUDE.md."""
    md = os.path.join(case_dir, "CLAUDE.md")
    if os.path.exists(md):
        try:
            with open(md) as f:
                text = f.read(8192)
            m = re.search(r"\*\*Case ID\*\*[:\s|]+([A-Za-z0-9_\-]+)", text)
            if m:
                return m.group(1)
            m = re.search(r"case[_\s]id[:\s|]+([A-Za-z0-9_\-]+)", text, re.IGNORECASE)
            if m:
                return m.group(1)
        except OSError:
            pass
    return os.path.basename(os.path.abspath(case_dir))


def _discover_dashboard() -> dict | None:
    """Read ~/.cache/trudi/dashboard.url and verify the standalone is alive.

    Returns the parsed discovery payload (url, port, cases_root, pid) or None
    if no dashboard is reachable. The PID is checked first so a stale file
    from a crashed dashboard doesn't masquerade as a live one.
    """
    import json
    if not os.path.exists(_DASHBOARD_DISCOVERY_FILE):
        return None
    try:
        with open(_DASHBOARD_DISCOVERY_FILE) as f:
            info = json.load(f)
    except (OSError, ValueError):
        return None
    pid = info.get("pid")
    if isinstance(pid, int):
        try:
            os.kill(pid, 0)
        except (OSError, ProcessLookupError):
            return None
    return info


def launch_dashboard(case_dir: str, port: int = 8765,
                     trace_path: str = "") -> dict:
    """Discover the running standalone dashboard and return a deep-link URL.

    Does NOT start any server — that's the standalone `trudi-dashboard`
    process's job. If the standalone isn't reachable, returns a hint for the
    operator to launch it. `port` is accepted for back-compat and ignored
    (the standalone owns the port).

    Returned shape matches the prior in-process server's contract so callers
    in start_execution_log don't need to branch.
    """
    case_dir = os.path.abspath(os.path.expanduser(case_dir))
    if not os.path.isdir(case_dir):
        return {"success": False, "error": f"case_dir not a directory: {case_dir}"}

    info = _discover_dashboard()
    case_id = _detect_case_id(case_dir)
    case_basename = os.path.basename(case_dir)
    if trace_path:
        # Deep-link the ACTUAL trace file — the {case_id}_trace.json guess
        # breaks whenever the operator/agent named the trace differently.
        trace_rel = f"/{case_basename}/analysis/{os.path.basename(trace_path)}"
    else:
        trace_rel = f"/{case_basename}/analysis/{case_id}_trace.json"

    if not info:
        return {
            "success": False,
            "error": ("no standalone dashboard reachable — run "
                      "`trudi-dashboard` in another terminal"),
            "case_id": case_id,
            "case_dir": case_dir,
            "hint_url": ("http://127.0.0.1:8765/_dashboard/dashboard.html"
                         f"?trace={trace_rel}"),
        }

    cases_root = info.get("cases_root", "")
    if cases_root and not case_dir.startswith(os.path.abspath(cases_root) + os.sep):
        return {
            "success": False,
            "error": (f"case_dir {case_dir!r} is outside the dashboard's "
                      f"cases_root ({cases_root!r}); restart `trudi-dashboard` "
                      f"with --cases-root {os.path.dirname(case_dir)!r}"),
            "case_id": case_id,
            "case_dir": case_dir,
        }

    base = info["url"]
    url = f"{base}?trace={trace_rel}"
    return {
        "success": True,
        "url": url,
        "port": info.get("port"),
        "case_id": case_id,
        "case_dir": case_dir,
        "cases_root": cases_root,
    }


@mcp.tool()
@output_safe
def serve_dashboard(case_dir: str, port: int = 8765) -> dict:
    """
    Return a deep-link URL into the running standalone TRUDI dashboard.

    The dashboard is its own long-lived process — launch it once with
    `trudi-dashboard` (from any terminal) and it stays available across MCP
    restarts. This tool does NOT start a server; it discovers the running
    one via ~/.cache/trudi/dashboard.url and returns a URL with the case's
    trace pre-selected in the dropdown.

    case_dir: absolute path of the case (e.g. ~/cases/example-case).
              Must live under the dashboard's --cases-root.
    port: accepted for back-compat; the standalone owns its own port.
    """
    return launch_dashboard(case_dir, port)


# ── Knowns-driven IOC hunting helper ─────────────────────────────────────────

def _derive_person_variants(full_name: str) -> list[str]:
    """Generate common username/email-prefix variants from 'Firstname Lastname'.
    Includes initial+last, first.last, first_last, last+initial, first+last,
    initial+last+initial, plus the raw first and last names. Lowercased."""
    parts = [p for p in full_name.strip().lower().split() if p]
    if not parts:
        return []
    if len(parts) == 1:
        return [parts[0]]
    first, *_, last = parts
    return [
        first + last,           # e.g. janedoe
        first + "." + last,     # e.g. jane.doe
        first + "_" + last,     # e.g. jane_doe
        first[0] + last,        # e.g. jdoe
        first[0] + last + first[0],  # e.g. jdoej
        first[0] + "." + last,  # e.g. j.doe
        last + first[0],        # e.g. doej
        first,                  # e.g. jane
        last,                   # e.g. doe
    ]


def _derive_hostname_variants(host: str) -> list[str]:
    """Generate variants of a hostname (case-folded, with/without domain suffix,
    short form)."""
    h = host.strip().lower()
    if not h:
        return []
    parts = h.split(".")
    variants = {h}
    if len(parts) > 1:
        variants.add(parts[0])         # short form
        variants.add("." + parts[-1])  # apex suffix marker
    return sorted(variants)


@mcp.tool()
@output_safe
def knowns_pattern_generate(
    reference_set: list[str],
    derivation_type: str,
    output_path: Optional[str] = None,
) -> dict:
    """
    Generate combined search patterns from a known reference set for use as
    IOCs against evidence. Inverts the usual search direction: instead of
    finding artifacts and matching against knowns, you hunt FOR the knowns
    as IOCs in the first batch.

    reference_set: list of strings — names, hostnames, hashes, domains, etc.
    derivation_type: one of:
        - "person_username" — for 'Firstname Lastname' rosters; emits
          jdoe / jane.doe / janedoe / etc.
        - "hostname" — short and FQDN forms of each host
        - "hash" — passes through unchanged (use the raw hash as the IOC)
        - "domain" — apex match (each domain plus '.<tld>' marker)
        - "exact" — passes through unchanged

    Returns a dict with:
        all_terms: every derived term, lowercased, deduplicated
        ngrep_pattern: pipe-joined alternation for ngrep -i / grep -E
        regex_pattern: same as ngrep_pattern but in regex-safe form
        by_source: mapping from each original reference entry to its derived terms

    output_path: optional path under analysis/ or exports/ to persist the
    generated patterns as JSON.
    """
    import json
    import re as _re

    dt = (derivation_type or "exact").strip().lower()
    by_source: dict[str, list[str]] = {}
    all_terms: list[str] = []
    seen: set[str] = set()

    for entry in reference_set or []:
        raw = (entry or "").strip()
        if not raw:
            continue
        if dt == "person_username":
            variants = _derive_person_variants(raw)
        elif dt == "hostname":
            variants = _derive_hostname_variants(raw)
        elif dt in ("hash", "exact"):
            variants = [raw.lower()] if dt == "hash" else [raw]
        elif dt == "domain":
            d = raw.strip().lower().lstrip(".")
            parts = d.split(".")
            variants = [d]
            if len(parts) >= 2:
                variants.append("." + ".".join(parts[-2:]))
        else:
            return {
                "success": False,
                "error": f"unknown derivation_type {derivation_type!r} (expected "
                         "person_username, hostname, hash, domain, exact)",
            }
        by_source[raw] = variants
        for v in variants:
            if v and v not in seen:
                seen.add(v)
                all_terms.append(v)

    # Escape for regex/ngrep — keep simple, just escape pipe and grouping chars
    escaped = [_re.escape(t) for t in all_terms]
    pattern = "|".join(escaped) if escaped else ""

    result = {
        "success": True,
        "derivation_type": dt,
        "input_count": len(reference_set or []),
        "term_count": len(all_terms),
        "all_terms": all_terms,
        "ngrep_pattern": pattern,
        "regex_pattern": pattern,
        "by_source": by_source,
    }

    if output_path:
        assert_output_safe(output_path)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        result["output_path"] = output_path

    # Self-log and stamp the roster server-side: the knowns the
    # operator declared become the relevance model of the pre-report
    # exhaustion checks (a registry identity that matches the roster is
    # mandatory; one that matches nothing is report inventory).
    from core.executor import _log_tool
    tc = {"success": True, "stdout": f"{len(all_terms)} terms from {len(reference_set or [])} knowns ({dt})",
          "stderr": "", "exit_code": 0, "truncated": False, "retries": 0,
          "elapsed_seconds": 0.0,
          "cmd": f"misc.knowns_pattern_generate {dt} n={len(reference_set or [])}"}
    _log_tool(tc)
    cid = tc.get("_trudi_call_id")
    if cid:
        result["_trudi_call_id"] = cid
        try:
            from core.execution_log import log as _elog
            _elog.annotate_tool_call(cid, knowns_roster=list(all_terms)[:2000],
                                     knowns_reference_set=[str(x) for x in (reference_set or [])][:500],
                                     knowns_derivation=dt)
        except Exception:
            pass

    return result
