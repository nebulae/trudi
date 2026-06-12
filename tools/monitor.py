"""Live-monitoring lifecycle: baseline → watcher → alert queue.

Composes `velo.*` (Velociraptor API) and filesystem state under
``~/cases/<case>/monitoring/`` into an agent-facing surface.

Storage layout (per case):
    monitoring/
      baselines/<client_id>.json     baseline allowlists (process names, paths, endpoints)
      artifacts/<artifact>.yaml      rendered Custom.TRUDI.* artifacts (pushed to server)
      watchers/<client_id>.pid       sidecar process id
      watchers/<client_id>.log       sidecar stdout/stderr
      alerts/_seq.txt                monotonic alert sequence number
      alerts/_seq.lock               fcntl lock around _seq.txt
      alerts/<seq>_<detector>.json   one alert per file, written by the sidecar

Tools here are read-only WRT evidence (per the global TRUDI policy) but DO
write to ``~/cases/<case>/monitoring/`` — TRUDI-generated state, not evidence.
"""
from __future__ import annotations
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

from fastmcp import FastMCP

from core import output_safe

mcp = FastMCP("monitor")

CASES_ROOT = Path(os.environ.get("TRUDI_CASES_ROOT") or os.path.expanduser("~/cases"))

# Snapshot artifacts collected during baseline_capture. Each one's rows feed
# a slice of the baseline allowlist.
BASELINE_ARTIFACTS = [
    "Linux.Sys.Pslist",
    "Linux.Sys.Crontab",
    "Linux.Network.Netstat",
]


# ── Filesystem helpers ──────────────────────────────────────────────────────

def _case_dir(case_id: str) -> Path:
    if not case_id or "/" in case_id or ".." in case_id:
        raise ValueError(f"case_id invalid: {case_id!r}")
    return CASES_ROOT / case_id


def _monitoring_dir(case_id: str) -> Path:
    d = _case_dir(case_id) / "monitoring"
    return d


def _baseline_path(case_id: str, client_id: str) -> Path:
    return _monitoring_dir(case_id) / "baselines" / f"{client_id}.json"


def _watcher_pid_path(case_id: str, client_id: str) -> Path:
    return _monitoring_dir(case_id) / "watchers" / f"{client_id}.pid"


def _watcher_log_path(case_id: str, client_id: str) -> Path:
    return _monitoring_dir(case_id) / "watchers" / f"{client_id}.log"


def _alerts_dir(case_id: str) -> Path:
    return _monitoring_dir(case_id) / "alerts"


def _seq_file(case_id: str) -> Path:
    return _alerts_dir(case_id) / "_seq.txt"


def _ensure_layout(case_id: str) -> None:
    base = _monitoring_dir(case_id)
    for sub in ("baselines", "watchers", "artifacts", "alerts"):
        (base / sub).mkdir(parents=True, exist_ok=True)


# ── Per-investigation trace path helpers ────────────────────────────────────
#
# For live-monitoring cases, each `/trudi-check-alerts` tick that finds
# new alerts opens (or resumes) ONE investigation, identified by an
# `INV-NNN` id. All alerts in that tick share one trace file at
# `analysis/<case>_<inv>_trace.json` (flat under analysis/ so the
# dashboard scan picks it up). The case-wide trace at
# `analysis/<case>_trace.json` only records orchestration
# (check_alerts, list_watchers, ack_alert, start/end_investigation
# markers).
#
# State files:
#   monitoring/_inv_seq.txt         monotonic per-case INV counter
#   monitoring/_open_investigation.json  tracker for an investigation
#                                        that spans /loop ticks (e.g.
#                                        awaiting operator approval)

def _analysis_dir(case_id: str) -> Path:
    return _case_dir(case_id) / "analysis"


def _reports_dir(case_id: str) -> Path:
    return _case_dir(case_id) / "reports"


def _case_wide_trace_path(case_id: str) -> Path:
    """The orchestration trace — `analysis/<case>_trace.json`."""
    return _analysis_dir(case_id) / f"{case_id}_trace.json"


def _investigation_trace_path(case_id: str, investigation_id: str) -> Path:
    """Per-investigation trace — `analysis/<case>_<inv>_trace.json`.
    Flat under analysis/ so the dashboard's non-recursive scan picks it
    up alongside the case-wide trace."""
    return _analysis_dir(case_id) / f"{case_id}_{investigation_id}_trace.json"


def _investigation_report_base(case_id: str, investigation_id: str) -> Path:
    """Per-investigation report base (no extension) —
    `reports/<case>_<inv>`. `log.export()` appends `.json` and `.md`."""
    return _reports_dir(case_id) / f"{case_id}_{investigation_id}"


def _open_investigation_path(case_id: str) -> Path:
    """Tracker file for an in-flight investigation. Present iff an
    investigation is open across /loop ticks."""
    return _monitoring_dir(case_id) / "_open_investigation.json"


def _inv_seq_path(case_id: str) -> Path:
    """Monotonic per-case INV counter file."""
    return _monitoring_dir(case_id) / "_inv_seq.txt"


def _detector_short(detector: str) -> str:
    """Trim `Custom.TRUDI.NewProcess` to `NewProcess`."""
    return detector.rsplit(".", 1)[-1]


def _ensure_investigation_layout(case_id: str) -> None:
    _analysis_dir(case_id).mkdir(parents=True, exist_ok=True)
    _reports_dir(case_id).mkdir(parents=True, exist_ok=True)
    _monitoring_dir(case_id).mkdir(parents=True, exist_ok=True)


def _find_alert_by_id(case_id: str, alert_id: str) -> Optional[dict]:
    """Walk `<case>/monitoring/alerts/*.json` looking for the alert whose
    `alert_id` matches. Returns the parsed alert dict (with `_path` added),
    or None if not found."""
    alerts_dir = _alerts_dir(case_id)
    if not alerts_dir.exists():
        return None
    for path in sorted(alerts_dir.glob("*_*.json")):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("alert_id") == alert_id:
            data["_path"] = str(path)
            return data
    return None


def _load_alerts_by_ids(case_id: str, alert_ids: list[str]) -> tuple[list[dict], list[str]]:
    """Resolve a list of alert_ids to their on-disk payloads.

    Returns (found_alerts, missing_ids). The found list preserves the
    sort order of `alert_ids` so the slash command keeps a deterministic
    bundle ordering for the genesis narration.
    """
    alerts_dir = _alerts_dir(case_id)
    by_id: dict[str, dict] = {}
    if alerts_dir.exists():
        for path in sorted(alerts_dir.glob("*_*.json")):
            try:
                data = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            aid = data.get("alert_id")
            if aid:
                data["_path"] = str(path)
                by_id[aid] = data
    found: list[dict] = []
    missing: list[str] = []
    for aid in alert_ids:
        if aid in by_id:
            found.append(by_id[aid])
        else:
            missing.append(aid)
    return found, missing


def _summarize_bundle(alerts: list[dict]) -> str:
    """Render a multi-line summary of a bundle of alerts for the
    genesis agent_message. Includes detector counts, seq range,
    distinct hostnames, and per-alert one-line summaries."""
    if not alerts:
        return "(empty bundle)"
    detectors: dict[str, int] = {}
    hosts: set[str] = set()
    seqs: list[int] = []
    for a in alerts:
        d = a.get("detector") or "Unknown"
        detectors[d] = detectors.get(d, 0) + 1
        h = a.get("hostname") or a.get("client_id") or "?"
        hosts.add(str(h))
        s = a.get("seq")
        if isinstance(s, int):
            seqs.append(s)
    parts = [
        f"Bundle of {len(alerts)} alert(s).",
        "detector_counts=" + ", ".join(f"{k}={v}" for k, v in sorted(detectors.items())),
        "hosts=" + ", ".join(sorted(hosts)),
    ]
    if seqs:
        parts.append(f"seq_range={min(seqs)}..{max(seqs)}")
    parts.append("alerts:")
    for a in alerts:
        s = a.get("seq", "?")
        d = a.get("detector", "?")
        summary = (a.get("summary") or "").strip()
        parts.append(f"  seq={s} det={d}: {summary[:140]}")
    return "\n".join(parts)


def _read_open_investigation(case_id: str) -> Optional[dict]:
    """Read and parse the open-investigation tracker; None if absent or unreadable."""
    p = _open_investigation_path(case_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _write_open_investigation(case_id: str, record: dict) -> None:
    """Atomically write the tracker. Caller already holds whatever locking
    they need; this just does a tmp+rename."""
    p = _open_investigation_path(case_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(record, indent=2))
    os.replace(tmp, p)


def _mutate_open_investigation(case_id: str, fn) -> Optional[dict]:
    """Read-modify-write the open-investigation tracker via `fn(record)`.
    No-op (returns None) if no investigation is open."""
    rec = _read_open_investigation(case_id)
    if rec is None:
        return None
    fn(rec)
    _write_open_investigation(case_id, rec)
    return rec


def _next_inv_seq(case_id: str) -> int:
    """fcntl-locked atomic increment of the per-case INV counter."""
    import fcntl
    seq_path = _inv_seq_path(case_id)
    seq_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = seq_path.with_suffix(".lock")
    with open(lock_path, "w") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            try:
                cur = int(seq_path.read_text().strip() or "0")
            except (OSError, ValueError):
                cur = 0
            cur += 1
            seq_path.write_text(str(cur))
            return cur
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _format_inv_id(n: int) -> str:
    """Format a counter value as `INV-NNN` zero-padded to 3 digits."""
    return f"INV-{n:03d}"


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# ── Baseline capture ────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def baseline_capture(client_id: str, case_id: str, timeout_seconds: int = 300) -> dict:
    """Snapshot processes / persistence / network for `client_id`; write baseline JSON.

    Runs each artifact in BASELINE_ARTIFACTS via `velo.collect_artifact`,
    waits for completion, and assembles a baseline document with the
    fields the detector templates expect (process_names, image_paths,
    persistence_paths, endpoints).

    Idempotent: re-running overwrites the existing baseline.
    """
    if not client_id.startswith("C."):
        return {"success": False, "error": f"client_id must look like 'C.xxx', got {client_id!r}"}

    from tools.velo import collect_artifact, wait_for_flow, get_collection_results

    _ensure_layout(case_id)

    flow_results: dict[str, list[dict]] = {}
    flow_ids: list[str] = []

    for artifact in BASELINE_ARTIFACTS:
        kicked = collect_artifact(client_id, artifact)
        if not kicked.get("success") or not kicked.get("flow_id"):
            return {
                "success": False,
                "error": f"failed to collect {artifact}: {kicked.get('stderr') or kicked.get('error')}",
                "_partial_results": flow_results,
            }
        fid = kicked["flow_id"]
        flow_ids.append(fid)
        finished = wait_for_flow(client_id, fid, timeout_seconds=timeout_seconds)
        if not finished.get("success") or finished.get("final_state") != "FINISHED":
            return {
                "success": False,
                "error": f"flow {fid} ({artifact}) did not finish: {finished.get('error') or finished.get('stderr')}",
                "_partial_results": flow_results,
            }
        results = get_collection_results(client_id, fid, artifact)
        flow_results[artifact] = results.get("rows") or []

    process_names: set[str] = set()
    image_paths: set[str] = set()
    for row in flow_results.get("Linux.Sys.Pslist", []):
        # Velociraptor's Linux.Sys.Pslist row schema: Name, Pid, Ppid, Exe, ...
        name = row.get("Name") or row.get("Exe")
        if name:
            process_names.add(os.path.basename(name))
        if row.get("Exe"):
            image_paths.add(row["Exe"])

    persistence_paths: set[str] = set()
    for row in flow_results.get("Linux.Sys.Crontab", []):
        if row.get("Path"):
            persistence_paths.add(row["Path"])

    endpoints: list[dict] = []
    for row in flow_results.get("Linux.Network.Netstat", []):
        # Schema varies between Velociraptor versions; handle a few shapes.
        rip = (row.get("Raddr") or {}).get("IP") if isinstance(row.get("Raddr"), dict) else row.get("RaddrIP")
        rport = (row.get("Raddr") or {}).get("Port") if isinstance(row.get("Raddr"), dict) else row.get("RaddrPort")
        if rip and rport:
            endpoints.append({"remote_ip": rip, "remote_port": int(rport)})

    baseline = {
        "client_id": client_id,
        "case_id": case_id,
        "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "flow_ids": flow_ids,
        "process_names": sorted(process_names),
        "image_paths": sorted(image_paths),
        "persistence_paths": sorted(persistence_paths),
        "endpoints": endpoints,
        "yara_rules_path": "/rules/trudi-demo.yar",
    }

    path = _baseline_path(case_id, client_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2))

    return {
        "success": True,
        "baseline_path": str(path),
        "summary": {
            "process_names": len(baseline["process_names"]),
            "image_paths": len(baseline["image_paths"]),
            "persistence_paths": len(baseline["persistence_paths"]),
            "endpoints": len(baseline["endpoints"]),
        },
        "flow_ids": flow_ids,
    }


# ── Watcher lifecycle ───────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def start_watcher(
    client_id: str,
    case_id: str,
    detectors: Optional[list[str]] = None,
) -> dict:
    """Render detector artifacts, push them to the client event table, spawn sidecar.

    detectors: list of Custom.TRUDI.* artifact names; defaults to all four.

    Refuses if no baseline exists or if a watcher is already alive for
    this (case, client) pair.
    """
    if not client_id.startswith("C."):
        return {"success": False, "error": f"client_id must look like 'C.xxx', got {client_id!r}"}

    from tools.velo import upload_artifact_yaml, update_client_event_table
    from monitoring import render

    baseline_path = _baseline_path(case_id, client_id)
    if not baseline_path.exists():
        return {
            "success": False,
            "error": f"no baseline found at {baseline_path}. Run monitor.baseline_capture first.",
        }

    detectors = detectors or render.list_detector_templates()
    if not detectors:
        return {"success": False, "error": "no detector templates available under monitoring/artifacts/"}

    _ensure_layout(case_id)

    pid_path = _watcher_pid_path(case_id, client_id)
    if pid_path.exists():
        try:
            existing_pid = int(pid_path.read_text().strip())
        except (ValueError, OSError):
            existing_pid = 0
        if _pid_alive(existing_pid):
            return {
                "success": False,
                "error": f"watcher already running (pid={existing_pid}). Stop it with monitor.stop_watcher.",
            }

    baseline = json.loads(baseline_path.read_text())

    pushed: list[dict] = []
    for name in detectors:
        rendered = render.render_template(name, baseline)
        # Persist the rendered YAML in the case dir for audit.
        out = _monitoring_dir(case_id) / "artifacts" / f"{name}.yaml"
        out.write_text(rendered)
        upload = upload_artifact_yaml(rendered)
        if not upload.get("success"):
            return {
                "success": False,
                "error": f"upload_artifact_yaml({name}) failed: {upload.get('stderr') or upload.get('error')}",
                "_partial": pushed,
            }
        pushed.append({"artifact": name, "_trudi_call_id": upload.get("_trudi_call_id")})

    update = update_client_event_table(client_id, detectors)
    if not update.get("success"):
        return {
            "success": False,
            "error": f"update_client_event_table failed: {update.get('stderr') or update.get('error')}",
        }

    sidecar = Path(__file__).resolve().parent.parent / "bin" / "trudi-velo-watcher.py"
    log_path = _watcher_log_path(case_id, client_id)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = open(log_path, "a", buffering=1)
    log_fh.write(
        f"\n=== watcher start {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
        f"case={case_id} client={client_id} artifacts={','.join(detectors)} ===\n"
    )

    proc = subprocess.Popen(
        [
            sys.executable, str(sidecar),
            "--case-id", case_id,
            "--client-id", client_id,
            "--artifacts", ",".join(detectors),
            "--alerts-dir", str(_alerts_dir(case_id)),
        ],
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )

    pid_path.write_text(str(proc.pid))

    return {
        "success": True,
        "pid": proc.pid,
        "pid_file": str(pid_path),
        "log_file": str(log_path),
        "artifacts": detectors,
        "uploaded": pushed,
    }


@mcp.tool()
@output_safe
def stop_watcher(client_id: str, case_id: str) -> dict:
    """SIGTERM the sidecar; remove TRUDI artifacts from the client event table."""
    if not client_id.startswith("C."):
        return {"success": False, "error": f"client_id must look like 'C.xxx', got {client_id!r}"}

    from tools.velo import update_client_event_table

    pid_path = _watcher_pid_path(case_id, client_id)
    if not pid_path.exists():
        return {"success": False, "error": "no watcher pid file — nothing to stop"}

    try:
        pid = int(pid_path.read_text().strip())
    except (ValueError, OSError) as e:
        return {"success": False, "error": f"unreadable pid file: {e}"}

    killed = False
    if _pid_alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for _ in range(20):
            if not _pid_alive(pid):
                killed = True
                break
            time.sleep(0.25)
        if not killed:
            try:
                os.kill(pid, signal.SIGKILL)
                killed = True
            except ProcessLookupError:
                killed = True
    else:
        killed = True

    pid_path.unlink(missing_ok=True)

    # Clear the client monitoring table (push empty artifact list).
    cleared = update_client_event_table(client_id, ["Generic.Client.Stats"])

    return {
        "success": True,
        "killed_pid": pid,
        "graceful": killed,
        "event_table_cleared": cleared.get("success", False),
    }


@mcp.tool()
@output_safe
def list_watchers(case_id: str) -> dict:
    """All watchers for the case — alive/dead, uptime, alerts emitted."""
    _ensure_layout(case_id)
    out: list[dict] = []
    watchers_dir = _monitoring_dir(case_id) / "watchers"
    for pid_file in watchers_dir.glob("*.pid"):
        client_id = pid_file.stem
        try:
            pid = int(pid_file.read_text().strip())
        except (ValueError, OSError):
            pid = 0
        out.append({
            "client_id": client_id,
            "pid": pid,
            "alive": _pid_alive(pid),
            "log_file": str(_watcher_log_path(case_id, client_id)),
        })
    seq_file = _seq_file(case_id)
    seq = 0
    try:
        if seq_file.exists():
            seq = int(seq_file.read_text().strip() or "0")
    except (ValueError, OSError):
        pass
    return {"success": True, "watchers": out, "alerts_emitted": seq}


# ── Alert queue ─────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def check_alerts(case_id: str, since_seq: int = 0, max_alerts: int = 50) -> dict:
    """Return alerts with seq > since_seq, oldest first, capped at max_alerts.

    Does NOT mark consumed — that's `ack_alert`'s job. Idempotent reads
    are useful for the /loop pattern: each tick pulls the same un-acked
    alerts until they're processed.
    """
    _ensure_layout(case_id)
    alerts_dir = _alerts_dir(case_id)
    alerts: list[dict] = []
    for path in sorted(alerts_dir.glob("*_*.json")):
        try:
            seq_str = path.stem.split("_", 1)[0]
            seq = int(seq_str)
        except (ValueError, IndexError):
            continue
        if seq <= since_seq:
            continue
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        data["_path"] = str(path)
        alerts.append(data)
        if len(alerts) >= max_alerts:
            break
    return {"success": True, "alerts": alerts, "count": len(alerts)}


@mcp.tool()
@output_safe
def ack_alert(case_id: str, alert_id: str) -> dict:
    """Mark an alert consumed (set consumed=true on the alert JSON)."""
    _ensure_layout(case_id)
    alerts_dir = _alerts_dir(case_id)
    for path in alerts_dir.glob("*_*.json"):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("alert_id") == alert_id:
            data["consumed"] = True
            data["consumed_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            path.write_text(json.dumps(data, indent=2))
            return {"success": True, "alert_id": alert_id, "path": str(path)}
    return {"success": False, "error": f"alert_id {alert_id!r} not found under {alerts_dir}"}


# ── Per-investigation trace lifecycle ──────────────────────────────────────
#
# Five tools manage the investigation lifecycle. The slash command flow
# is documented in ~/.claude/commands/trudi-check-alerts.md.

@mcp.tool()
@output_safe
def next_investigation_id(case_id: str) -> dict:
    """Atomically increment `monitoring/_inv_seq.txt` and return the
    next investigation id formatted as `INV-NNN` (zero-padded to 3).

    Call from the slash command before `start_investigation` when no
    open investigation exists. fcntl-locked so concurrent /loop ticks
    can't double-allocate the same id.
    """
    _ensure_investigation_layout(case_id)
    n = _next_inv_seq(case_id)
    return {
        "success": True,
        "investigation_id": _format_inv_id(n),
        "seq": n,
    }


@mcp.tool()
@output_safe
def open_investigation_state(case_id: str) -> dict:
    """Read `monitoring/_open_investigation.json` if present.

    Returns {open: True, investigation_id, alert_ids, opened_at_utc,
    trace_path, report_base, ...} when an investigation is in flight
    across /loop ticks; {open: False} otherwise. Pure read.
    """
    rec = _read_open_investigation(case_id)
    if rec is None:
        return {"success": True, "open": False}
    inv = rec.get("investigation_id") or ""
    return {
        "success": True,
        "open": True,
        "investigation_id": inv,
        "alert_ids": rec.get("alert_ids") or [],
        "opened_at_utc": rec.get("opened_at_utc"),
        "extended_at_utc": rec.get("extended_at_utc"),
        "trace_path": str(_investigation_trace_path(case_id, inv)) if inv else None,
    }


@mcp.tool()
@output_safe
def start_investigation(case_id: str,
                        investigation_id: str,
                        alert_ids: list[str]) -> dict:
    """Switch the active TRUDI trace to a per-investigation file before
    running the investigation chain (`reason.hypothesize` +
    `dair_assess` + tool batch + `record_finding` + `respond.*`).

    All alerts in `alert_ids` share this one trace at
    `<case>/analysis/<case>_<investigation_id>_trace.json`. Calls
    `log.configure(case_id, trace_path)` (rehydrates if file exists —
    idempotent on re-entry, supports resume across /loop ticks), then
    writes a genesis `agent_message` enumerating the bundle.

    Also (re)writes `monitoring/_open_investigation.json` with the
    investigation_id + sorted alert_ids + opened_at_utc, so a future
    /loop tick's `open_investigation_state` returns the same set.

    Operator-typed messages will land in this trace from this point on
    (via the `UserPromptSubmit` hook reading the session beacon that
    `log.configure()` just updated), so the per-investigation trace keeps
    a complete record of operator decisions alongside the agent's chain.

    Returns:
      success, trace_path, case_wide_trace_path, investigation_id,
      alert_ids, alert_summaries, genesis_call_id, rehydrated_entries.
    """
    if not investigation_id or not investigation_id.startswith("INV-"):
        return {
            "success": False,
            "error": f"investigation_id must look like 'INV-NNN', "
                     f"got {investigation_id!r}",
        }
    if not alert_ids:
        return {
            "success": False,
            "error": "alert_ids cannot be empty",
        }

    _ensure_investigation_layout(case_id)
    trace_path = _investigation_trace_path(case_id, investigation_id)
    trace_path.parent.mkdir(parents=True, exist_ok=True)

    # Sort alert_ids deterministically so re-entry produces the same
    # tracker record content.
    sorted_alert_ids = sorted(set(alert_ids))
    alerts, missing = _load_alerts_by_ids(case_id, sorted_alert_ids)

    from core.execution_log import log
    recovered = log.configure(case_id, str(trace_path), save_session=True)

    summary = _summarize_bundle(alerts)
    genesis_lines = [
        f"Investigation {investigation_id} opened on {len(alerts)} alert(s).",
        summary,
    ]
    if missing:
        genesis_lines.append(
            f"WARNING: {len(missing)} alert_id(s) not found on disk: "
            f"{missing[:5]}{'...' if len(missing) > 5 else ''}"
        )
    if recovered:
        genesis_lines.append(
            f"(resumed per-investigation trace with {recovered} pre-existing entries)"
        )
    genesis_content = "\n".join(genesis_lines)[:1900]
    genesis_cid = log.record_agent_message(content=genesis_content)

    # Persist / refresh the open-investigation tracker.
    existing = _read_open_investigation(case_id) or {}
    record = {
        "investigation_id": investigation_id,
        "case_id": case_id,
        "alert_ids": sorted_alert_ids,
        "opened_at_utc": existing.get("opened_at_utc")
                         or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trace_path": str(trace_path),
        "report_base": str(_investigation_report_base(case_id, investigation_id)),
    }
    if existing.get("extended_at_utc"):
        record["extended_at_utc"] = existing["extended_at_utc"]
    _write_open_investigation(case_id, record)

    return {
        "success": True,
        "trace_path": str(trace_path),
        "case_wide_trace_path": str(_case_wide_trace_path(case_id)),
        "investigation_id": investigation_id,
        "alert_ids": sorted_alert_ids,
        "alert_summaries": [
            {
                "alert_id": a.get("alert_id"),
                "seq": a.get("seq"),
                "detector": a.get("detector"),
                "summary": a.get("summary"),
            }
            for a in alerts
        ],
        "missing_alert_ids": missing,
        "genesis_call_id": genesis_cid,
        "rehydrated_entries": recovered,
    }


@mcp.tool()
@output_safe
def extend_investigation(case_id: str,
                         investigation_id: str,
                         new_alert_ids: list[str]) -> dict:
    """Append `new_alert_ids` to an existing open investigation.

    Used when a /loop tick finds new alerts while an investigation is
    already open: the new alerts join the same trace, and a fresh
    `agent_message` is recorded summarising the additions. Updates
    `monitoring/_open_investigation.json` in place.

    Refuses if no investigation is open, or if `investigation_id`
    doesn't match the open one — so a buggy slash command can't
    silently fold alerts into the wrong investigation.

    Returns: success, investigation_id, total_alert_ids, added_alert_ids,
             extension_call_id.
    """
    rec = _read_open_investigation(case_id)
    if rec is None:
        return {
            "success": False,
            "error": "no open investigation — call start_investigation first",
        }
    open_id = rec.get("investigation_id") or ""
    if open_id != investigation_id:
        return {
            "success": False,
            "error": f"open investigation is {open_id!r}, refusing to extend "
                     f"with mismatched id {investigation_id!r}",
        }

    existing_ids = set(rec.get("alert_ids") or [])
    truly_new = [a for a in new_alert_ids if a not in existing_ids]
    if not truly_new:
        return {
            "success": True,
            "investigation_id": investigation_id,
            "total_alert_ids": sorted(existing_ids),
            "added_alert_ids": [],
            "extension_call_id": 0,
            "noop": True,
        }

    combined = sorted(existing_ids | set(truly_new))
    new_alerts, missing = _load_alerts_by_ids(case_id, truly_new)

    # Ensure the active trace is the per-investigation one before we
    # record. The slash command should have called start_investigation
    # already this tick, but be defensive.
    from core.execution_log import log
    trace_path = _investigation_trace_path(case_id, investigation_id)
    if log._path != str(trace_path):
        log.configure(case_id, str(trace_path), save_session=True)

    ext_lines = [
        f"Investigation {investigation_id} extended with "
        f"{len(truly_new)} new alert(s).",
        _summarize_bundle(new_alerts),
    ]
    if missing:
        ext_lines.append(
            f"WARNING: {len(missing)} new alert_id(s) not found on disk: "
            f"{missing[:5]}{'...' if len(missing) > 5 else ''}"
        )
    ext_cid = log.record_agent_message(content="\n".join(ext_lines)[:1900])

    rec["alert_ids"] = combined
    rec["extended_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _write_open_investigation(case_id, rec)

    return {
        "success": True,
        "investigation_id": investigation_id,
        "total_alert_ids": combined,
        "added_alert_ids": truly_new,
        "missing_alert_ids": missing,
        "extension_call_id": ext_cid,
    }


def _load_suggestions(case_id: str) -> list[dict]:
    """Read all ACT-*.json containment suggestions for the case, in order."""
    sug_dir = (CASES_ROOT / case_id / "monitoring" / "response" / "suggestions")
    out: list[dict] = []
    if not sug_dir.is_dir():
        return out
    for p in sorted(sug_dir.glob("ACT-*.json")):
        try:
            out.append(json.loads(p.read_text()))
        except (OSError, json.JSONDecodeError):
            continue
    return out


def _append_containment_section(case_id: str, report_base: Path) -> int:
    """Append a 'Recommended Containment Commands (run manually)' section to the
    exported report `.md`, and mirror the list into the `.json`. Returns the
    number of suggestions written.

    This runs AFTER `log.export()` and touches ONLY the per-investigation report
    files — never the shared `core.execution_log.export()` path — so static-case
    reports are byte-for-byte unchanged.
    """
    suggestions = _load_suggestions(case_id)
    if not suggestions:
        return 0

    md_path = Path(str(report_base) + ".md")
    lines = [
        "",
        "## Recommended Containment Commands (run manually)",
        "",
        "TRUDI does **not** execute remediation. The commands below are derived "
        "from each CONFIRMED/LIKELY finding; a human runs them out-of-band.",
        "",
    ]
    for s in suggestions:
        rev = "reversible" if s.get("reversible") else "NOT reversible"
        lines.append(f"### {s.get('action_id', '?')} — {s.get('description', '').strip()}")
        lines.append("")
        lines.append(f"- Detector: `{s.get('detector', '?')}` · risk: "
                     f"{s.get('risk', 'medium')} · {rev}")
        unresolved = s.get("unresolved_placeholders") or []
        if unresolved:
            lines.append(f"- ⚠️ Unresolved placeholders (evidence missing): "
                         f"{', '.join(unresolved)} — review before running")
        cmd = (s.get("manual_command") or "").strip()
        lines.append("")
        lines.append("```bash")
        lines.append(cmd if cmd else "# (no command template for this action)")
        lines.append("```")
        lines.append("")

    try:
        with md_path.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        return 0

    # Mirror into the .json report (additive key; leaves export() output intact).
    json_path = Path(str(report_base) + ".json")
    try:
        doc = json.loads(json_path.read_text())
        if isinstance(doc, dict):
            doc["recommended_containment_commands"] = suggestions
            json_path.write_text(json.dumps(doc, indent=2))
    except (OSError, json.JSONDecodeError):
        pass

    return len(suggestions)


def _load_executions(case_id: str) -> list[dict]:
    """Read all ACT-*.json execution records for the case, in order."""
    ex_dir = (CASES_ROOT / case_id / "monitoring" / "response" / "executions")
    out: list[dict] = []
    if not ex_dir.is_dir():
        return out
    for p in sorted(ex_dir.glob("ACT-*.json")):
        try:
            out.append(json.loads(p.read_text()))
        except (OSError, json.JSONDecodeError):
            continue
    return out


def _would_be_rollback(suggestion: dict) -> Optional[str]:
    """Best-effort rollback command for an action not yet executed (awaiting
    approval), derived from its revert_template + raw_evidence."""
    rt = suggestion.get("revert_template")
    if not rt:
        return None
    try:
        from core import ssh_exec
        argv = ssh_exec.build_argv(rt, suggestion.get("raw_evidence") or {})
        if len(argv) >= 3 and argv[0:2] == ["/bin/sh", "-c"]:
            return argv[2]
        return " ".join(argv)
    except Exception:  # noqa: BLE001
        return None


def _append_response_section(case_id: str, report_base: Path) -> int:
    """Append an 'Autonomous Response Actions' section to the report `.md` and
    mirror a structured ledger into the `.json`. Records what TRUDI actually
    did (auto-executed / approved / reverted / awaiting approval), each with its
    verbatim rollback/undo command. Returns the number of action rows written.

    Like `_append_containment_section`, this runs AFTER `log.export()` and
    touches only the per-investigation report files.
    """
    executions = _load_executions(case_id)
    rec = _read_open_investigation(case_id) or {}
    awaiting = set(rec.get("awaiting_approval") or [])
    if not executions and not awaiting:
        return 0

    suggestions = _load_suggestions(case_id)
    exec_by_id = {e.get("action_id"): e for e in executions}

    ledger: list[dict] = []
    rows: list[str] = []
    rollback_lines: list[str] = []
    for s in suggestions:
        aid = s.get("action_id")
        e = exec_by_id.get(aid)
        if e:
            cls = e.get("classification", "?")
            if e.get("reverted"):
                status = "reverted"
            elif e.get("success"):
                status = "auto-executed" if e.get("mode") == "auto" else "executed (approved)"
            else:
                status = "execution FAILED"
            cmd = e.get("command_str", "")
            result = f"exit {e.get('exit_code')}"
            rollback = e.get("rollback_command") or "—"
        elif aid in awaiting:
            cls = "NEEDS_APPROVAL"
            status = "awaiting operator approval"
            cmd = (s.get("manual_command") or "").strip()
            result = "—"
            rollback = _would_be_rollback(s) or "—"
        else:
            continue

        ledger.append({
            "action_id": aid, "classification": cls, "status": status,
            "detector": s.get("detector"), "command": cmd,
            "result": result, "rollback_command": None if rollback == "—" else rollback,
        })
        rows.append(f"| {aid} | {cls} | {status} | `{cmd}` | {result} | "
                    f"{('`' + rollback + '`') if rollback != '—' else '—'} |")
        if rollback != "—":
            rollback_lines.append(f"# undo {aid} ({status})\n{rollback}")

    if not rows:
        return 0

    lines = [
        "",
        "## Autonomous Response Actions",
        "",
        "TRUDI auto-executes only the **reversible + low-risk** tier; destructive "
        "actions wait for an operator-typed `approve ACT-N`. Every action below is "
        "logged with the exact command run and its rollback/undo command.",
        "",
        "| Action | Class | Status | Command run | Result | Rollback / undo |",
        "|--------|-------|--------|-------------|--------|-----------------|",
        *rows,
        "",
    ]
    if rollback_lines:
        lines += ["### Rollback commands (run to undo)", "", "```bash",
                  "\n\n".join(rollback_lines), "```", ""]

    md_path = Path(str(report_base) + ".md")
    try:
        with md_path.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        return 0

    json_path = Path(str(report_base) + ".json")
    try:
        doc = json.loads(json_path.read_text())
        if isinstance(doc, dict):
            doc["autonomous_response_actions"] = ledger
            json_path.write_text(json.dumps(doc, indent=2))
    except (OSError, json.JSONDecodeError):
        pass

    return len(rows)


@mcp.tool()
@output_safe
def get_response_state(case_id: str) -> dict:
    """Report autonomous-response state for the open investigation.

    Returns paused (True while any action awaits operator approval),
    awaiting_approval (action_ids), and auto_executed (action_ids that ran
    autonomously). The slash command reads this at tick start: while paused it
    re-surfaces the pending `approve ACT-N` prompts and takes no new autonomous
    action."""
    rec = _read_open_investigation(case_id)
    awaiting = list((rec or {}).get("awaiting_approval") or [])
    auto_done = [e.get("action_id") for e in _load_executions(case_id)
                 if e.get("mode") == "auto" and e.get("success")]
    return {
        "success": True,
        "open": rec is not None,
        "investigation_id": (rec or {}).get("investigation_id"),
        "paused": bool(awaiting),
        "awaiting_approval": awaiting,
        "auto_executed": auto_done,
    }


@mcp.tool()
@output_safe
def set_awaiting_approval(case_id: str, action_ids: list[str]) -> dict:
    """Mark destructive action_ids as awaiting operator approval — pauses
    autonomous response for the open investigation until they're approved."""
    def _add(rec):
        cur = set(rec.get("awaiting_approval") or [])
        cur.update(action_ids or [])
        rec["awaiting_approval"] = sorted(cur)
    rec = _mutate_open_investigation(case_id, _add)
    if rec is None:
        return {"success": False, "error": "no open investigation to pause"}
    return {"success": True, "awaiting_approval": rec.get("awaiting_approval", []),
            "paused": bool(rec.get("awaiting_approval"))}


@mcp.tool()
@output_safe
def clear_awaiting_approval(case_id: str, action_id: str) -> dict:
    """Clear one action_id from the awaiting-approval set (after it's approved +
    executed). When the set empties, autonomy resumes and the investigation may
    close."""
    def _rm(rec):
        rec["awaiting_approval"] = [a for a in (rec.get("awaiting_approval") or [])
                                    if a != action_id]
    rec = _mutate_open_investigation(case_id, _rm)
    if rec is None:
        return {"success": False, "error": "no open investigation"}
    return {"success": True, "awaiting_approval": rec.get("awaiting_approval", []),
            "paused": bool(rec.get("awaiting_approval"))}


@mcp.tool()
@output_safe
def end_investigation(case_id: str,
                      investigation_id: str,
                      outcome_note: str = "") -> dict:
    """Finalise the investigation: export `.json` + `.md` to
    `<case>/reports/<case>_<investigation_id>.{json,md}`, swap the
    trace back to the case-wide file, log a closing `agent_message`
    in the case-wide trace, and remove
    `monitoring/_open_investigation.json`.

    Idempotent: if the open-investigation file is missing or the
    investigation_id mismatches, the export is still attempted and
    the trace swap still runs, but a `warning` flag comes back so
    the caller can investigate the inconsistency.

    Returns: success, report_json_path, report_md_path,
             case_wide_trace_path, closing_call_id, entry_count,
             json_wrote, md_wrote, warning (optional).
    """
    if not investigation_id or not investigation_id.startswith("INV-"):
        return {
            "success": False,
            "error": f"investigation_id must look like 'INV-NNN', "
                     f"got {investigation_id!r}",
        }

    _ensure_investigation_layout(case_id)
    rec = _read_open_investigation(case_id)
    warning = None
    if rec is None:
        warning = "no open-investigation tracker on disk"
    elif rec.get("investigation_id") != investigation_id:
        warning = (f"open investigation is {rec.get('investigation_id')!r}, "
                   f"but caller passed {investigation_id!r}")

    # Loop-pause: keep the investigation OPEN while any action awaits operator
    # approval, so a later /loop tick (after `approve ACT-N`) resumes the same
    # trace. Do not export/swap/unlink here.
    if rec and rec.get("awaiting_approval"):
        return {
            "success": True,
            "closed": False,
            "paused": True,
            "investigation_id": investigation_id,
            "awaiting_approval": rec.get("awaiting_approval"),
            "message": "Investigation kept open — awaiting operator approval for: "
                       + ", ".join(rec.get("awaiting_approval")),
        }

    report_base = _investigation_report_base(case_id, investigation_id)

    from core.execution_log import log
    # Make sure the active trace is the one we're closing before export.
    inv_trace = _investigation_trace_path(case_id, investigation_id)
    if log._path != str(inv_trace) and inv_trace.exists():
        log.configure(case_id, str(inv_trace), save_session=True)

    export_result = log.export(str(report_base))

    # Append operator-runnable containment commands to the report as a fallback.
    # Touches only the per-investigation report files, never the shared export().
    containment_written = _append_containment_section(case_id, report_base)
    # Append the autonomous-response ledger (what TRUDI actually did + rollbacks).
    response_actions_written = _append_response_section(case_id, report_base)

    case_wide = _case_wide_trace_path(case_id)
    case_wide.parent.mkdir(parents=True, exist_ok=True)
    log.configure(case_id, str(case_wide), save_session=True)

    closing = (outcome_note or
               f"Investigation {investigation_id} closed. "
               f"Report at {report_base.name}.{{json,md}}.")
    closing_cid = log.record_agent_message(content=closing[:1900])

    # Remove the tracker. If the file is gone or mismatched, that's
    # already surfaced via `warning` — no need to error.
    p = _open_investigation_path(case_id)
    try:
        if p.exists():
            p.unlink()
    except OSError as e:
        warning = (warning + f" + unlink failed: {e}") if warning else f"unlink failed: {e}"

    out = {
        "success": True,
        "investigation_id": investigation_id,
        "report_json_path": str(report_base) + ".json",
        "report_md_path": str(report_base) + ".md",
        "case_wide_trace_path": str(case_wide),
        "closing_call_id": closing_cid,
        "entry_count": export_result.get("entry_count", 0),
        "json_wrote": export_result.get("json_wrote", False),
        "md_wrote": export_result.get("md_wrote", False),
        "containment_commands_written": containment_written,
        "response_actions_written": response_actions_written,
        "closed": True,
    }
    if warning:
        out["warning"] = warning
    return out
