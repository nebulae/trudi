"""Miscellaneous SIFT tools — evtx parsing, registry, USN journal, AV, browser forensics.

Also includes the email-forensics, packer-detection, capability-analysis, Office-macro,
Sigma-hunt, and batch-execution helpers added under the post-hackathon expansion plan.
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

@mcp.tool()
@output_safe
def evtx_dump(evtx_file: str, output_path: Optional[str] = None) -> dict:
    """
    Dump an EVTX file to XML using python-evtx.
    Useful for inspection without EZ Tools or for piping to grep.
    """
    cmd = ["/usr/local/bin/evtx_dump.py", evtx_file]
    if output_path:
        return run_with_output_file(cmd, output_path=output_path, mode="w", timeout=300)
    return run(cmd, timeout=300)


@mcp.tool()
@output_safe
def evtx_filter(evtx_file: str, event_ids: str,
                max_results: int = 200,
                wall_clock_budget_s: int = 60) -> dict:
    """
    Stream-filter an EVTX for specific event IDs without buffering the
    entire XML dump in memory.

    The previous implementation called subprocess.run(capture_output=True)
    on evtx_dump.py for the whole file — for an 18 MB Security.evtx that
    expands to hundreds of MB of XML before any filtering can start,
    blowing both memory and the client tool-timeout. This version pipes
    evtx_dump.py through a line-by-line state machine that keeps only the
    current Event in a small buffer and accumulates matches as it goes.

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

    _log_tool({
        "success": success,
        "stdout": "",
        "stderr": stderr_text,
        "exit_code": proc.returncode if proc.returncode is not None else -1,
        "truncated": cap_hit or timed_out,
        "cmd": " ".join(cmd),
        "retries": 0,
        "elapsed_seconds": elapsed,
    })

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
    output_format: str = "json",
) -> dict:
    """
    Parse Chrome/Chromium browser history, cookies, cache, and extensions using Hindsight.
    profile_path: path to Chrome 'Default' profile directory.
    output_format: 'json', 'sqlite', 'csv'.
    """
    import os
    output_file = os.path.join(output_dir, "hindsight_chrome")
    cmd = [
        "/usr/local/bin/hindsight.py",
        "-i", profile_path,
        "-o", output_file,
        "-f", output_format,
    ]
    return run(cmd, timeout=300, output_dir=output_dir)


# ── AV scanning ──────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def clamscan_file(file_path: str) -> dict:
    """Scan a file for malware using ClamAV."""
    return run(["clamscan", "--no-summary", file_path], timeout=120)


@mcp.tool()
@output_safe
def clamscan_directory(directory: str, recursive: bool = True) -> dict:
    """Scan a directory for malware using ClamAV."""
    cmd = ["clamscan", "--no-summary"]
    if recursive:
        cmd.append("-r")
    cmd.append(directory)
    return run(cmd, timeout=1800)


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


# ── Scheduled tasks (disk) ────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def parse_scheduled_tasks(tasks_dir: str) -> dict:
    """
    List and read Windows Scheduled Task XML files from disk.
    tasks_dir: path to Windows/System32/Tasks/ on a mounted volume.
    """
    import os
    results = []
    errors = []
    try:
        for root, dirs, files in os.walk(tasks_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read(8192)
                    results.append({"task": fpath.replace(tasks_dir, ""), "content": content})
                except Exception as e:
                    errors.append({"task": fpath, "error": str(e)})
        return {"success": True, "task_count": len(results), "tasks": results, "errors": errors}
    except Exception as e:
        return {"success": False, "error": str(e)}


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
                dash = _dash_fn(case_dir, port=dashboard_port)
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


@mcp.tool()
@output_safe
def record_finding(
    description: str,
    confidence: str,
    source: str = "",
    linked_call_id: int = 0,
    tested_hypothesis_id: str = "",
    input_call_ids: list[int] | None = None,
) -> dict:
    """
    Record a confirmed finding to the execution trace.
    confidence: CONFIRMED / LIKELY / SUSPECTED / UNCONFIRMED.
    source: tool or artifact that produced the finding e.g. 'vol.psscan', 'ez.mftecmd'.
    linked_call_id: the _trudi_call_id value from the tool result that produced this
                    finding — enables judges to trace any finding back to its source
                    tool execution in the audit log.

    Gates (any failure refuses the call; the response carries a
    `gate: "<snake_case_identifier>"` field the agent can switch on):

      - `mcp_routing`: linked_call_id (if non-zero) must NOT point to a raw-bash
        tool_call executing a forensic binary — forensic execution must flow
        through the typed MCP wrapper. Error names the wrapper to switch to.
      - `dair_required`: Recent dair_assess required (any tier). Findings only
        exist inside an active DAIR-directed investigation.
      - `confirmed_requires_linked_call_id`: CONFIRMED requires linked_call_id != 0.
      - `linked_call_id_must_exist`: linked_call_id (if non-zero) must refer to
        a known entry in the trace.
      - `negative_from_truncated`: UNCONFIRMED ("absent / no match") findings
        whose linked_call_id points at a tool_call with truncated: true are
        refused — per CLAUDE.md truncated-output rule, re-run narrower (or
        use a parallel channel like grep -a) and link to a non-truncated
        call before recording the negative.
      - `mitre_technique_validation`: T-IDs in the description are auto-
        validated via correlate.mitre_validate. Any unknown T-ID refuses
        the finding.
      - `confirmed_requires_supported_evaluate`: CONFIRMED requires a recent
        reason.evaluate_finding whose verdict is SUPPORTED (not CHALLENGED)
        within the last 30 entries.
      - `confidence_and_citation`: CONFIRMED/LIKELY require a recent
        reason.confidence_score AND reason.cite_check whose inputs reference
        this finding's description. confidence_score's parsed tier must not
        be lower than the requested tier; cite_check's verdict must not be
        UNCITED_CLAIMS_PRESENT.
      - `hypothesize_required`: CONFIRMED/LIKELY findings that mention
        process / service / persistence / C2 / lateral-movement keywords
        require a recent reason.hypothesize call (or non-empty
        tested_hypothesis_id) within the last 30 entries.
    """
    from core.execution_log import log
    from tools._gates import GateContext, run_gates

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
    )

    failure = run_gates(ctx)
    if failure is not None:
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

    log.record_finding(
        description, confidence, source, linked_call_id, tested_hypothesis_id,
        gate_metadata=gate_metadata,
        input_call_ids=input_call_ids,
    )
    result = {"success": True, "description": description, "confidence": confidence}
    if ctx.validated_techniques:
        result["validated_techniques"] = ctx.validated_techniques
    if gate_metadata:
        result["gate_chain"] = {
            k: v for k, v in gate_metadata.items()
            if k.startswith("gated_by_")
        }
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

    # Pre-report check required: scan the last 50 entries for the most recent
    # reason_pre_report_check trace entry; parse READY_TO_REPORT from its
    # conclusion. Lookback 50 > the per-finding gates' 30 because pre-report
    # verification often precedes a long synthesize/correction block before
    # export.
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
                "export_execution_log refused: no reason.pre_report_check call "
                "found in the last 50 trace entries. Call reason.pre_report_check() "
                "after reason.synthesize and resolve any blocking_issues before "
                "exporting the trace and writing the final report."
            ),
            "gate": "pre_report_check_required",
            "missing_check": "reason_pre_report_check",
        }
    conclusion = (pre_report_entry.get("conclusion") or "")
    ready_match = re.search(r"READY_TO_REPORT:\s*(true|false)", conclusion, re.IGNORECASE)
    is_ready = bool(ready_match and ready_match.group(1).lower() == "true")
    if not is_ready:
        return {
            "success": False,
            "error": (
                "export_execution_log refused: most recent reason.pre_report_check "
                "returned READY_TO_REPORT: false. Resolve the blocking_issues "
                "(re-run reason.plan/synthesize as needed, address missing "
                "evaluate_finding calls, etc.) and re-run pre_report_check."
            ),
            "gate": "pre_report_check_required",
            "pre_report_conclusion": conclusion[:500],
        }

    result = log.export(output_path)
    return {
        "success": True,
        "entry_count": result.get("entry_count", 0),
        "json_path": output_path + ".json",
        "md_path": output_path + ".md",
    }


@mcp.tool()
@output_safe
def record_agent_message(
    content: str,
    input_call_ids: list[int] | None = None,
    findings: list[dict] | None = None,
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
    """
    from core.execution_log import log
    cid = log.record_agent_message(content, input_call_ids)
    result: dict = {"success": True, "call_id": cid}
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
      - analysis/, exports/, reports/ contents (preserves generate_pdf_report.py)
      - ~/.cache/trudi/session.json (prevents auto-reconnect to stale trace)
      - ~/.claude/projects/<encoded>/memory/ files (clears case memory)

    case_dir: absolute path to the case directory e.g. /home/trin/cases/srl-2018-demo
    """
    import shutil
    import glob
    cleared = []
    errors = []

    for subdir in ("analysis", "exports", "reports"):
        target = os.path.join(case_dir, subdir)
        for item in glob.glob(os.path.join(target, "*")):
            if os.path.basename(item) == "generate_pdf_report.py":
                continue
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
    return run([binary, "-m", mode, "-t", output_dir, pst_path], timeout=1800)


@mcp.tool()
@output_safe
def readpst_extract(pst_path: str, output_dir: str, format_mbox: bool = True) -> dict:
    """
    Convert a PST file to mbox (default) or per-message MIME using readpst.

    format_mbox: True → -o mbox; False → -e (per-message .eml files).
    """
    binary = _bin_or_warn("readpst")
    if not binary:
        return {"success": False, "error": "readpst not installed — apt install libpst-utils"}
    os.makedirs(output_dir, exist_ok=True)
    cmd = [binary, "-o", output_dir]
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
    binary = _bin_or_warn("mraptor") or _bin_or_warn("mraptor3")
    if not binary:
        return {"success": False, "error":
                "mraptor not installed — pip install oletools"}
    return run([binary, office_path], timeout=120)


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


def launch_dashboard(case_dir: str, port: int = 8765) -> dict:
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

    case_dir: absolute path of the case (e.g. /home/trin/cases/srl-2018-demo).
              Must live under the dashboard's --cases-root.
    port: accepted for back-compat; the standalone owns its own port.
    """
    return launch_dashboard(case_dir, port)


# ── Knowns-driven IOC hunting helper ─────────────────────────────────────────

def _derive_person_variants(full_name: str) -> list[str]:
    """Generate common username/email-prefix variants from 'Firstname Lastname'.
    Includes initial+last, first.last, first_last, last+initial, first+last,
    plus the raw first and last names. Lowercased."""
    parts = [p for p in full_name.strip().lower().split() if p]
    if not parts:
        return []
    if len(parts) == 1:
        return [parts[0]]
    first, *_, last = parts
    return [
        first + last,           # johnnycoach
        first + "." + last,     # johnny.coach
        first + "_" + last,     # johnny_coach
        first[0] + last,        # jcoach
        first[0] + "." + last,  # j.coach
        last + first[0],        # coachj
        first,                  # johnny
        last,                   # coach
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
          jcoach / johnny.coach / johnnycoach / etc.
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

    return result
