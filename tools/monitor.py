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
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastmcp import FastMCP

from core import output_safe
from response import policy as response_policy

mcp = FastMCP("monitor")

CASES_ROOT = Path(os.environ.get("TRUDI_CASES_ROOT") or os.path.expanduser("~/cases"))

# Snapshot artifacts collected during baseline_capture. Each one's rows feed
# a slice of the baseline allowlist.
# Persistence is NOT captured from Linux.Sys.Crontab — that parses cron
# *schedules* (empty on a stock box) and never matches the file-glob the
# NewPersistence detector watches, which made the allowlist empty and every
# stock cron/systemd file a false positive. Instead baseline_capture collects
# Custom.TRUDI.PersistenceSnapshot, which globs the identical surface.
BASELINE_ARTIFACTS = [
    "Linux.Sys.Pslist",
    "Linux.Network.Netstat",
]
PERSISTENCE_SNAPSHOT_ARTIFACT = "Custom.TRUDI.PersistenceSnapshot"

# Scheduled work. A single process snapshot can never contain the periodic
# children cron launches later (the 06:25 cron.daily chain alerted as a fresh
# intrusion two mornings running in DECOY-DEMO). The baseline therefore also
# records the cron schedule — read root-run via BashShell, best-effort — and
# the cron daemon image(s), which the NewProcess detector's scheduled-work
# exemption walks process ancestry for.
CRONTAB_DUMP_COMMAND = (
    "for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /etc/anacrontab; do "
    "[ -f \"$f\" ] || continue; echo \"## $f\"; cat \"$f\" 2>/dev/null; done; "
    "for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do "
    "[ -d \"$d\" ] || continue; echo \"## $d/\"; ls -1 \"$d\" 2>/dev/null; done"
)
CRON_DAEMON_NAMES = {"cron", "crond", "anacron"}
# Binaries that legitimately cross the uid boundary; verify_clean mirrors the
# PrivilegeEscalation detector and never counts them as the escalated process.
ESCALATION_BROKERS = {"/usr/bin/sudo", "/bin/sudo", "/usr/bin/su", "/bin/su",
                      "/usr/bin/pkexec", "/usr/bin/doas", "/usr/bin/run0"}
# Scheduled-work exemption regexes: the SAME patterns the NewProcess detector
# uses, imported from monitoring.render so the live detector and this
# post-eradication mirror can never drift. (Defaults; a host may override the
# detector params, in which case verify_clean is a conservative approximation.)
from monitoring import render as _render  # noqa: E402  (module-level, no cycle)
SCHEDULED_WORK_BIN_RE = re.compile(_render.TRUSTED_BIN_REGEX)
DROP_PATH_RE = re.compile(_render.DROP_PATH_REGEX)
# Bounded ancestry walk. Real privilege-escalation chains are 1–2 hops
# (shell → sudo → implant); six is a generous safety cap that also bounds cost
# and any pid-reuse loop. A non-root ancestor deeper than this is not found, so
# the cap can only under-alert on pathologically deep chains — never the daily
# cron case, which is root the whole way up.
ANCESTRY_HOPS = 6


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


def _watcher_config_path(case_id: str, client_id: str) -> Path:
    return _monitoring_dir(case_id) / "watchers" / f"{client_id}.json"


def _deploy_detectors(case_id: str, client_id: str, baseline: dict,
                       detectors: list[str]) -> dict:
    """Upload shared neutral definitions; put baseline parameters in the client label."""
    from tools.velo import upload_artifact_yaml, update_client_event_table
    from monitoring import render
    _ensure_layout(case_id)
    if "Custom.TRUDI.NewProcess" in detectors or "Custom.TRUDI.NewPersistence" in detectors:
        helper = render.ARTIFACTS_DIR / "Custom.TRUDI.PersistenceSnapshot.yaml"
        up = upload_artifact_yaml(helper.read_text())
        if not up.get("success"):
            return {"success": False, "error": "persistence snapshot helper upload failed"}
    parameters = {}
    uploaded = []
    for name in detectors:
        rendered = render.render_template(name, baseline)
        dest = _monitoring_dir(case_id) / "artifacts" / client_id
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.yaml").write_text(rendered)
        up = upload_artifact_yaml(render.render_template(name, {}))
        if not up.get("success"):
            return {"success": False, "error": f"upload {name} failed: {up.get('error') or up.get('stderr')}",
                    "uploaded": uploaded}
        uploaded.append({"artifact": name, "_trudi_call_id": up.get("_trudi_call_id")})
        parameters[name] = render.detector_parameters(name, baseline)
        if name == "Custom.TRUDI.NewProcess":
            parameters[name]["ScheduledWorkEnabled"] = str(bool(
                baseline.get("persistence_fingerprints")
                and "Custom.TRUDI.NewPersistence" in detectors)).lower()
    result = update_client_event_table(client_id, detectors, parameters=parameters)
    if result.get("success"):
        _watcher_config_path(case_id, client_id).write_text(json.dumps({
            "os_family": baseline.get("os_family") or _client_os_family(client_id),
            "detectors": detectors, "parameters": parameters,
        }, indent=2))
    return {**result, "uploaded": uploaded}


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

def _alias_for_client(client_id: str) -> Optional[str]:
    """Match a Velociraptor client to its live_hosts.json ssh alias by hostname.

    velo hostname 'victim-a' → ssh alias 'trudi-victim-a'. Best-effort: returns
    None on any ambiguity or lookup failure, in which case response routing
    falls back to the single configured host (no behaviour change for
    single-host cases). This is what lets a multi-host live case route each
    alert's response to the host it came from."""
    try:
        from tools.velo import list_clients
        from core.ssh import list_configured_hosts
    except Exception:  # noqa: BLE001
        return None
    try:
        res = list_clients()
        rows = res.get("rows") or res.get("clients") or []
    except Exception:  # noqa: BLE001
        return None
    hostname = ""
    for r in rows:
        if isinstance(r, dict) and str(r.get("client_id")) == str(client_id):
            hostname = str(r.get("hostname") or "").strip().lower()
            break
    if not hostname:
        return None
    try:
        aliases = list_configured_hosts()
    except Exception:  # noqa: BLE001
        return None

    def _norm(s: str) -> str:
        return s.lower().replace("trudi-", "").replace("_", "-")

    exact = [a for a in aliases if _norm(a) == hostname]
    if len(exact) == 1:
        return exact[0]
    contains = [a for a in aliases if hostname in _norm(a) or _norm(a) in hostname]
    return contains[0] if len(contains) == 1 else None


def _client_os_family(client_id: str) -> str:
    """'windows' or 'linux' (default) for a Velociraptor client, from
    clients().os_info.system. Best-effort — an unresolved client reads linux."""
    try:
        from tools.velo import query as _vq
        r = _vq(f'SELECT os_info.system AS system FROM clients() '
                f'WHERE client_id = {json.dumps(client_id)}')
        rows = r.get("rows") or []
        if rows and str(rows[0].get("system", "")).lower().startswith("win"):
            return "windows"
    except Exception:  # noqa: BLE001
        pass
    return "linux"


def _baseline_capture_windows(client_id: str, case_id: str, timeout_seconds: int) -> dict:
    """Windows analogue of the Linux baseline: snapshot the process image set and
    the autostart surface so the Custom.TRUDI.Win.* detectors have a known-good
    allowlist to diff against. The Linux-only path (Linux.Sys.Pslist, BashShell,
    cron) does not apply to a Windows host — this is the separate OS path the
    real Windows victim needs. Logon sources start empty (a freshly-built host
    has no prior RDP logons); the first real RDP logon is therefore the signal.
    """
    from tools.velo import (collect_artifact, wait_for_flow, get_collection_results,
                            upload_artifact_yaml)
    from monitoring import render

    _ensure_layout(case_id)
    flow_ids: list[str] = []

    def _collect(artifact: str, parameters: Optional[dict] = None) -> tuple[list, Optional[str]]:
        kicked = (collect_artifact(client_id, artifact, parameters=parameters)
                  if parameters else collect_artifact(client_id, artifact))
        if not kicked.get("success") or not kicked.get("flow_id"):
            return [], f"collect {artifact} failed: {kicked.get('stderr') or kicked.get('error')}"
        fid = kicked["flow_id"]
        flow_ids.append(fid)
        done = wait_for_flow(client_id, fid, timeout_seconds=timeout_seconds)
        if not done.get("success") or done.get("final_state") != "FINISHED":
            return [], f"flow {fid} ({artifact}) did not finish"
        return get_collection_results(client_id, fid, artifact, full_output=True).get("rows") or [], None

    ps_rows, err = _collect("Windows.System.Pslist")
    if err:
        return {"success": False, "error": err}

    process_names: set[str] = set()
    image_paths: set[str] = set()
    for row in ps_rows:
        exe = row.get("Exe") or ""
        name = row.get("Name") or (os.path.basename(exe) if exe else "")
        if name:
            process_names.add(name)
        if exe:
            image_paths.add(exe)

    # Autostart surface via the Win.PersistenceSnapshot helper (same globs the
    # detector uses). Upload it first (idempotent), then collect with defaults.
    snap_name = "Custom.TRUDI.Win.PersistenceSnapshot"
    snap_yaml = (render.ARTIFACTS_DIR / f"{snap_name}.yaml").read_text()
    up = upload_artifact_yaml(snap_yaml)
    if not up.get("success"):
        return {"success": False,
                "error": f"failed to upload {snap_name}: {up.get('stderr') or up.get('error')}"}
    snap_rows, err = _collect(snap_name)
    if err:
        return {"success": False, "error": err}
    autoruns: set[str] = set()
    for row in snap_rows:
        ident = row.get("identity") or row.get("path")
        if ident:
            autoruns.add(ident)

    baseline = {
        "client_id": client_id,
        "case_id": case_id,
        "os_family": "windows",
        "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "flow_ids": [f for f in flow_ids if f],
        "process_names": sorted(process_names),
        "image_paths": sorted(image_paths),
        "autoruns": sorted(autoruns),
        "logon_sources": [],
        "benign_signatures": [],
        "extensions": [],
        "yara_rules_path": "",
    }
    path = _baseline_path(case_id, client_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2))

    alias = _alias_for_client(client_id)
    if alias:
        try:
            from response import policy as _policy
            _policy.record_client_host(case_id, client_id, alias)
        except Exception:  # noqa: BLE001
            pass

    return {
        "success": True,
        "baseline_path": str(path),
        "os_family": "windows",
        "host_alias": alias,
        "summary": {
            "process_names": len(baseline["process_names"]),
            "image_paths": len(baseline["image_paths"]),
            "autoruns": len(baseline["autoruns"]),
            "logon_sources": 0,
        },
        "flow_ids": [f for f in flow_ids if f],
    }


@mcp.tool()
@output_safe
def baseline_capture(client_id: str, case_id: str, timeout_seconds: int = 300) -> dict:
    """Snapshot processes / persistence / network for `client_id`; write baseline JSON.

    OS-aware: a Windows client is baselined via `_baseline_capture_windows`
    (process image set + autostart surface for the Custom.TRUDI.Win.* detectors);
    a Linux client runs the path below.

    Runs each artifact in BASELINE_ARTIFACTS via `velo.collect_artifact`,
    waits for completion, and assembles a baseline document with the
    fields the detector templates expect (process_names, image_paths,
    persistence_paths, endpoints).

    Idempotent: re-running overwrites the existing baseline.
    """
    if not client_id.startswith("C."):
        return {"success": False, "error": f"client_id must look like 'C.xxx', got {client_id!r}"}

    if _client_os_family(client_id) == "windows":
        return _baseline_capture_windows(client_id, case_id, timeout_seconds)

    from tools.velo import (collect_artifact, wait_for_flow, get_collection_results,
                            upload_artifact_yaml)
    from monitoring import render

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
        results = get_collection_results(client_id, fid, artifact, full_output=True)
        flow_results[artifact] = results.get("rows") or []

    # Persistence allowlist: collect the PersistenceSnapshot helper, which globs
    # the SAME surface the NewPersistence detector watches (so the allowlist
    # matches exactly). Upload it first (idempotent), then collect with the
    # canonical WatchDirs.
    snap_yaml = (render.ARTIFACTS_DIR / f"{PERSISTENCE_SNAPSHOT_ARTIFACT}.yaml").read_text()
    snap_upload = upload_artifact_yaml(snap_yaml)
    if not snap_upload.get("success"):
        return {
            "success": False,
            "error": f"failed to upload {PERSISTENCE_SNAPSHOT_ARTIFACT}: "
                     f"{snap_upload.get('stderr') or snap_upload.get('error')}",
            "_partial_results": flow_results,
        }
    snap_kick = collect_artifact(
        client_id, PERSISTENCE_SNAPSHOT_ARTIFACT,
        parameters={"WatchDirs": json.dumps(render.PERSISTENCE_WATCH_GLOBS)},
    )
    if not snap_kick.get("success") or not snap_kick.get("flow_id"):
        return {
            "success": False,
            "error": f"failed to collect {PERSISTENCE_SNAPSHOT_ARTIFACT}: "
                     f"{snap_kick.get('stderr') or snap_kick.get('error')}",
            "_partial_results": flow_results,
        }
    snap_fid = snap_kick["flow_id"]
    flow_ids.append(snap_fid)
    snap_done = wait_for_flow(client_id, snap_fid, timeout_seconds=timeout_seconds)
    if not snap_done.get("success") or snap_done.get("final_state") != "FINISHED":
        return {
            "success": False,
            "error": f"flow {snap_fid} ({PERSISTENCE_SNAPSHOT_ARTIFACT}) did not finish: "
                     f"{snap_done.get('error') or snap_done.get('stderr')}",
            "_partial_results": flow_results,
        }
    flow_results[PERSISTENCE_SNAPSHOT_ARTIFACT] = (
        get_collection_results(client_id, snap_fid, PERSISTENCE_SNAPSHOT_ARTIFACT,
                               full_output=True).get("rows") or []
    )

    process_names: set[str] = set()
    image_paths: set[str] = set()
    root_image_paths: set[str] = set()
    for row in flow_results.get("Linux.Sys.Pslist", []):
        # Velociraptor's Linux.Sys.Pslist row schema: Name, Pid, Ppid, Exe,
        # Username, ...
        name = row.get("Name") or row.get("Exe")
        if name:
            process_names.add(os.path.basename(name))
        if row.get("Exe"):
            image_paths.add(row["Exe"])
            # Root-owned image paths feed the PrivilegeEscalation allowlist so a
            # legitimately-root daemon present at baseline is not flagged.
            if (row.get("Username") or row.get("User")) == "root":
                root_image_paths.add(row["Exe"])

    # Logon-source allowlist for the NewLogon (lateral-movement) detector:
    # remote IPs with an ESTABLISHED inbound SSH (:22) flow at baseline time.
    logon_sources: set[str] = set()
    for row in flow_results.get("Linux.Network.Netstat", []):
        laddr = row.get("Laddr")
        lport = (laddr or {}).get("Port") if isinstance(laddr, dict) else row.get("LaddrPort")
        raddr = row.get("Raddr")
        rip = (raddr or {}).get("IP") if isinstance(raddr, dict) else row.get("RaddrIP")
        status = row.get("Status") or row.get("State")
        if lport == 22 and rip and (status in (None, "", "ESTABLISHED")):
            logon_sources.add(rip)

    persistence_paths: set[str] = set()
    persistence_fingerprints: set[str] = set()
    for row in flow_results.get(PERSISTENCE_SNAPSHOT_ARTIFACT, []):
        # The snapshot returns `path` (FullPath); tolerate either key.
        p = row.get("path") or row.get("FullPath")
        if p:
            persistence_paths.add(p)
            if row.get("sha256"):
                persistence_fingerprints.add(f"{p}|{row['sha256']}")

    # Cron daemon image(s) present at baseline — the NewProcess scheduled-work
    # exemption keys on these. Fall back to the stock paths so a host whose
    # cron happened to be stopped at capture time still gets the rule.
    cron_daemon_images: set[str] = set()
    for row in flow_results.get("Linux.Sys.Pslist", []):
        exe = row.get("Exe") or ""
        name = os.path.basename(row.get("Name") or exe)
        if exe and (name in CRON_DAEMON_NAMES or os.path.basename(exe) in CRON_DAEMON_NAMES):
            cron_daemon_images.add(exe)
    if not cron_daemon_images:
        cron_daemon_images.update(render.DEFAULT_CRON_DAEMON_IMAGES)

    # The cron schedule itself (root-run cat of the system crontabs), parsed into
    # jobs. Best-effort: a host without BashShell or crontabs still baselines,
    # with the gap noted in the summary.
    scheduled_jobs: list[dict] = []
    scheduled_jobs_note = ""
    sched_rows, sched_err = _collect_bashshell(
        client_id, CRONTAB_DUMP_COMMAND, timeout_seconds, collect_artifact,
        wait_for_flow, get_collection_results)
    if sched_err:
        scheduled_jobs_note = sched_err
    else:
        if sched_rows:
            flow_ids.append(sched_rows[0].get("_flow_id") or "")
        text = "\n".join((r.get("Stdout") or "") for r in sched_rows)
        scheduled_jobs = _parse_crontab_dump(text)

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
        "os_family": "linux",
        "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "flow_ids": flow_ids,
        "process_names": sorted(process_names),
        "image_paths": sorted(image_paths),
        "root_image_paths": sorted(root_image_paths),
        "persistence_paths": sorted(persistence_paths),
        "persistence_fingerprints": sorted(persistence_fingerprints),
        "endpoints": endpoints,
        "logon_sources": sorted(logon_sources),
        "cron_daemon_images": sorted(cron_daemon_images),
        "scheduled_jobs": scheduled_jobs,
        "benign_signatures": [],
        "extensions": [],
        "yara_rules_path": "/rules/trudi-demo.yar",
    }
    if scheduled_jobs_note:
        baseline["scheduled_jobs_note"] = scheduled_jobs_note

    path = _baseline_path(case_id, client_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2))

    # Record this client's ssh alias so a multi-host case routes each alert's
    # response to the host it came from (best-effort; falls back to the single
    # configured host when unresolved).
    alias = _alias_for_client(client_id)
    if alias:
        try:
            from response import policy as _policy
            _policy.record_client_host(case_id, client_id, alias)
        except Exception:  # noqa: BLE001
            pass

    return {
        "success": True,
        "baseline_path": str(path),
        "host_alias": alias,
        "summary": {
            "process_names": len(baseline["process_names"]),
            "image_paths": len(baseline["image_paths"]),
            "root_image_paths": len(baseline["root_image_paths"]),
            "persistence_paths": len(baseline["persistence_paths"]),
            "endpoints": len(baseline["endpoints"]),
            "logon_sources": len(baseline["logon_sources"]),
            "cron_daemon_images": len(baseline["cron_daemon_images"]),
            "scheduled_jobs": len(baseline["scheduled_jobs"]),
            **({"scheduled_jobs_note": scheduled_jobs_note} if scheduled_jobs_note else {}),
        },
        "flow_ids": [f for f in flow_ids if f],
    }


# ── Scheduled work, process ancestry, benign recurrence ─────────────────────

def _collect_bashshell(client_id: str, command: str, timeout_seconds: int,
                       collect_artifact, wait_for_flow, get_collection_results
                       ) -> tuple[list[dict], Optional[str]]:
    """Run one root shell command on the client via Linux.Sys.BashShell and
    return its rows (each with `_flow_id`), or (rows=[], error)."""
    kicked = collect_artifact(client_id, "Linux.Sys.BashShell", parameters={"Command": command})
    if not kicked.get("success") or not kicked.get("flow_id"):
        return [], f"BashShell collect failed: {kicked.get('stderr') or kicked.get('error')}"
    fid = kicked["flow_id"]
    done = wait_for_flow(client_id, fid, timeout_seconds=timeout_seconds)
    if not done.get("success") or done.get("final_state") != "FINISHED":
        return [], f"BashShell flow {fid} did not finish"
    rows = get_collection_results(client_id, fid, "Linux.Sys.BashShell", full_output=True).get("rows") or []
    for r in rows:
        r["_flow_id"] = fid
    return rows, None


_CRON_SKIP_RE = re.compile(r"^\s*(#|$)|^\s*[A-Za-z_][A-Za-z0-9_]*=")


def _parse_crontab_dump(text: str) -> list[dict]:
    """Parse the output of CRONTAB_DUMP_COMMAND into scheduled-job records.

    Sections start with `## <path>` (a crontab file, or a periodic directory
    ending in `/` whose following lines are script names). Crontab lines are
    `m h dom mon dow [user] command` for system crontabs (`/etc/crontab`,
    `/etc/cron.d/*`), and have no user field for per-user crontabs under
    `/var/spool/cron/crontabs/<user>`. `@reboot`-style specs are kept as the
    schedule. Comments, blanks and VAR=value lines are skipped.
    """
    jobs: list[dict] = []
    source = ""
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if line.startswith("## "):
            source = line[3:].strip()
            continue
        if not source:
            continue
        if source.endswith("/"):
            name = line.strip()
            if name and not name.startswith(".") and name != ".placeholder":
                jobs.append({"source": source.rstrip("/"), "schedule": os.path.basename(source.rstrip("/")),
                             "user": "root", "command": f"{source}{name}", "kind": "periodic_script"})
            continue
        if _CRON_SKIP_RE.match(line):
            continue
        parts = line.split()
        if not parts:
            continue
        if parts[0].startswith("@"):
            spec, rest = parts[0], parts[1:]
        elif len(parts) >= 6:
            spec, rest = " ".join(parts[:5]), parts[5:]
        else:
            continue
        system_crontab = source == "/etc/crontab" or source.startswith("/etc/cron.d/")
        if system_crontab and rest:
            user, command = rest[0], " ".join(rest[1:])
        else:
            user = os.path.basename(source) if source.startswith("/var/spool/cron/") else "root"
            command = " ".join(rest)
        if not command:
            continue
        jobs.append({"source": source, "schedule": spec, "user": user,
                     "command": command, "kind": "crontab"})
    return jobs


def _normalize_cmdline(cmd: str) -> str:
    """Command line with digit runs and whitespace normalised, so `sleep 1140`
    and `sleep 1784` (apt-compat's random sleep) share one signature."""
    s = re.sub(r"\d+", "#", cmd or "")
    return re.sub(r"\s+", " ", s).strip()


def _alert_signature(alert: dict) -> str:
    """Detector-independent identity of the process an alert describes:
    image path, normalised command line and parent image. Two detectors firing
    on one cron child, or the same job on two mornings, yield one signature."""
    ev = alert.get("evidence") or {}
    image = ev.get("image_path") or ev.get("Exe") or ""
    cmd = _normalize_cmdline(ev.get("commandline") or ev.get("CommandLine") or "")
    parent = ev.get("parent_exe") or ""
    if not image and not cmd:
        return ""
    return f"{image}|{cmd}|{parent}"


def _ancestry_flags(ps_rows: list[dict], cron_images: set[str]) -> dict[str, dict]:
    """Per-pid ancestry facts over a process snapshot, mirroring the detectors'
    six-hop walk: {pid: {nonroot_ancestor, cron_descendant, parent_exe}}."""
    by_pid = {str(r.get("Pid")): r for r in ps_rows if r.get("Pid") is not None}
    out: dict[str, dict] = {}
    for pid, row in by_pid.items():
        nonroot = False
        cron = False
        parent_exe = None
        cur = row
        for hop in range(ANCESTRY_HOPS):
            parent = by_pid.get(str(cur.get("Ppid")))
            if parent is None:
                break
            if hop == 0:
                parent_exe = parent.get("Exe")
            if (parent.get("Username") or parent.get("User")) not in (None, "", "root"):
                nonroot = True
            if (parent.get("Exe") or "") in cron_images:
                cron = True
            cur = parent
        out[pid] = {"nonroot_ancestor": nonroot, "cron_descendant": cron, "parent_exe": parent_exe}
    return out


def _is_scheduled_work(exe: str, cmdline: str, flags: dict,
                        schedule_intact: bool = False) -> bool:
    """The NewProcess exemption: a cron-descended standard-bin process whose
    command line names no drop location."""
    return schedule_intact and bool(flags.get("cron_descendant")) and bool(SCHEDULED_WORK_BIN_RE.match(exe or "")) \
        and not DROP_PATH_RE.search(cmdline or "")


# The NewProcess scheduled-work exemption suppresses the PROCESS alerts for a
# cron-launched trusted-bin binary. That is only safe because the INTRODUCTION
# of a new scheduled job is caught FILE-side by NewPersistence. If NewProcess
# runs without NewPersistence, an attacker's own cron job running a stock system
# tool (e.g. /usr/bin/python3) becomes a genuine persistence blind spot.
NEWPROCESS_DETECTOR = "Custom.TRUDI.NewProcess"
NEWPERSISTENCE_DETECTOR = "Custom.TRUDI.NewPersistence"


def _detector_coverage_warnings(detectors: list[str]) -> list[str]:
    """Non-fatal warnings about detector combinations that open a blind spot.

    Today: NewProcess (with its scheduled-work exemption) enabled without
    NewPersistence — the file-side check that is its safety net. Returned by
    start_watcher so the gap is surfaced, never silent; not a hard refusal,
    since process-only monitoring is a legitimate choice on an ephemeral host.
    """
    warnings: list[str] = []
    s = set(detectors)
    if NEWPROCESS_DETECTOR in s and NEWPERSISTENCE_DETECTOR not in s:
        warnings.append(
            f"{NEWPROCESS_DETECTOR} is enabled WITHOUT {NEWPERSISTENCE_DETECTOR}: "
            "the scheduled-work exemption suppresses process alerts for "
            "cron-launched system binaries, and the file-side detector that "
            "catches a newly-planted cron job is not running — an attacker cron "
            "running a stock tool would not be alerted. Enable "
            f"{NEWPERSISTENCE_DETECTOR}, or accept this persistence blind spot "
            "explicitly for this host.")
    return warnings


def _load_baseline_for_alert(case_id: str, alert: dict) -> Optional[dict]:
    cid = alert.get("client_id") or ""
    if not cid.startswith("C."):
        return None
    p = _baseline_path(case_id, cid)
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _annotate_known_benign(case_id: str, alerts: list[dict]) -> None:
    """Stamp `known_benign` on alerts whose process signature a prior
    investigation recorded as benign (baseline `benign_signatures`)."""
    cache: dict[str, dict[str, dict]] = {}
    for a in alerts:
        cid = a.get("client_id") or ""
        if cid not in cache:
            b = _load_baseline_for_alert(case_id, a) or {}
            cache[cid] = {s.get("signature"): s for s in (b.get("benign_signatures") or [])
                          if s.get("signature")}
        sig = _alert_signature(a)
        a["signature"] = sig
        hit = cache[cid].get(sig) if sig else None
        if hit:
            a["known_benign"] = {k: hit.get(k) for k in
                                 ("signature", "reason", "investigation_id", "finding_id", "added_at_utc")}


@mcp.tool()
@output_safe
def baseline_extend(case_id: str, client_id: str,
                    image_paths: Optional[list[str]] = None,
                    process_names: Optional[list[str]] = None,
                    root_image_paths: Optional[list[str]] = None,
                    benign_alert_ids: Optional[list[str]] = None,
                    reason: str = "",
                    finding_id: Optional[str] = None,
                    evidence_call_ids: Optional[list[int]] = None,
                    repush: bool = True) -> dict:
    """Feed a benign verdict back into detection so the same activity does not
    open another investigation tomorrow.

    Extends the client's baseline allowlists (`image_paths`, `process_names`,
    `root_image_paths`) and records the process signatures of
    `benign_alert_ids` under `benign_signatures` (so `check_alerts` can mark a
    recurrence as `known_benign` even when it still slips past the detectors).
    Every extension is logged in the baseline's `extensions` ledger with the
    reason, the investigation it came from, the finding and evidence call ids.

    With `repush` (default), the detector artifacts are re-rendered from the
    updated baseline and re-pushed to the client event table — the running
    watcher sidecar needs no restart.

    Requires a live-monitoring case with an existing baseline; `reason` is
    mandatory — an unexplained allowlist change is not auditable.
    """
    from response import gates as response_gates
    refusal = response_gates.check_live_monitoring_scope(case_id)
    if refusal is not None:
        return refusal
    if not client_id.startswith("C."):
        return {"success": False, "error": f"client_id must look like 'C.xxx', got {client_id!r}"}
    if not (reason or "").strip():
        return {"success": False,
                "error": "reason is required — say why this activity is benign "
                         "(e.g. 'stock Ubuntu cron.daily chain, verified INV-002')."}
    path = _baseline_path(case_id, client_id)
    if not path.exists():
        return {"success": False, "error": f"no baseline at {path}; run monitor.baseline_capture first."}
    try:
        baseline = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return {"success": False, "error": f"baseline unreadable: {e}"}

    inv_id = (_read_open_investigation(case_id) or {}).get("investigation_id")
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    added: dict[str, list] = {"image_paths": [], "process_names": [],
                              "root_image_paths": [], "benign_signatures": []}

    for key, values in (("image_paths", image_paths), ("process_names", process_names),
                        ("root_image_paths", root_image_paths)):
        cur = list(baseline.get(key) or [])
        for v in values or []:
            v = (v or "").strip()
            if v and v not in cur:
                cur.append(v)
                added[key].append(v)
        baseline[key] = sorted(cur)

    missing_alerts: list[str] = []
    if benign_alert_ids:
        alerts, missing_alerts = _load_alerts_by_ids(case_id, list(benign_alert_ids))
        sigs = {s.get("signature") for s in (baseline.get("benign_signatures") or [])}
        for a in alerts:
            sig = _alert_signature(a)
            if not sig or sig in sigs:
                continue
            sigs.add(sig)
            rec = {"signature": sig, "reason": reason, "investigation_id": inv_id,
                   "finding_id": finding_id, "added_at_utc": now,
                   "from_alert_id": a.get("alert_id"), "detector": a.get("detector"),
                   "summary": (a.get("summary") or "")[:160]}
            baseline.setdefault("benign_signatures", []).append(rec)
            added["benign_signatures"].append(sig)

    pending_repush = bool(baseline.get("repush_pending"))
    if not any(added.values()) and not (repush and pending_repush):
        return {"success": True, "noop": True, "baseline_path": str(path),
                "message": "nothing new to add", "missing_alert_ids": missing_alerts}

    if any(added.values()):
        baseline.setdefault("extensions", []).append({
            "at_utc": now, "reason": reason, "investigation_id": inv_id,
            "finding_id": finding_id, "evidence_call_ids": list(evidence_call_ids or []),
            "added": added,
        })
    baseline["repush_pending"] = True
    path.write_text(json.dumps(baseline, indent=2))

    repushed: list[str] = []
    repush_error = None
    if repush:
        from monitoring import render
        config_path = _watcher_config_path(case_id, client_id)
        config = json.loads(config_path.read_text()) if config_path.exists() else {}
        os_family = baseline.get("os_family") or config.get("os_family") or _client_os_family(client_id)
        baseline["os_family"] = os_family
        detectors = config.get("detectors") or render.list_detector_templates(os_family)
        deployed = _deploy_detectors(case_id, client_id, baseline, detectors)
        repushed = [u["artifact"] for u in deployed.get("uploaded", [])]
        if not deployed.get("success"):
            repush_error = deployed.get("error") or deployed.get("stderr") or "detector deployment failed"
        else:
            baseline["repush_pending"] = False
        path.write_text(json.dumps(baseline, indent=2))

    out = {
        "success": repush_error is None,
        "baseline_path": str(path),
        "investigation_id": inv_id,
        "added": added,
        "benign_signatures_total": len(baseline.get("benign_signatures") or []),
        "repushed_detectors": repushed,
        "missing_alert_ids": missing_alerts,
    }
    if repush_error:
        out["error"] = repush_error + " — baseline file was updated; re-run with repush=True."
    return out


# ── Post-eradication verification ────────────────────────────────────────────

def _netstat_fields(row: dict) -> tuple:
    """(laddr_port, raddr_ip, raddr_port, status) from a NetstatEnriched row.

    NetstatEnriched (the SAME source the NewLogon/NewNetwork detectors use) is
    flat: Laddr/Raddr are string IPs, Lport/Rport ints, Status a string. Older
    Linux.Network.Netstat packed Laddr/Raddr as {IP,Port} dicts — tolerate both
    so verify_clean's logon/egress residual check matches what the detectors
    fire on (mismatched parsing previously missed an open :22 session that was
    still alerting, yielding a false clean=true)."""
    laddr, raddr = row.get("Laddr"), row.get("Raddr")
    lport = (laddr.get("Port") if isinstance(laddr, dict)
             else row.get("Lport") if row.get("Lport") is not None else row.get("LaddrPort"))
    rip = (raddr.get("IP") if isinstance(raddr, dict)
           else raddr if isinstance(raddr, str) else row.get("RaddrIP"))
    rport = (raddr.get("Port") if isinstance(raddr, dict)
             else row.get("Rport") if row.get("Rport") is not None else row.get("RaddrPort"))
    status = row.get("Status") or row.get("State")
    try:
        lport = int(lport) if lport is not None else None
    except (TypeError, ValueError):
        pass
    return lport, rip, rport, status


_RFC1918_OR_LOCAL = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|169\.254\.)")

# A point-in-time snapshot unavoidably catches the collection's OWN transient
# processes (the agent's ps/shell/ssh/velociraptor query). verify_clean treats a
# standard system tool in a standard bin dir as ephemeral measurement noise, so
# it does not read as a residual intrusion — while an implant at a NON-standard
# path (e.g. /tmp/.systemd-private, /usr/local/sbin/.trudi-rootsvc) still counts.
_EPHEMERAL_BASENAMES = {
    "ps", "pgrep", "pkill", "kill", "ss", "netstat", "sshd", "sudo", "sleep",
    "sh", "dash", "bash", "env", "grep", "sed", "awk", "cat", "head", "tail",
    "which", "find", "python3", "velociraptor", "cron", "dockerd", "docker-init",
}
_STD_BIN_DIRS = {"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"}


def _is_ephemeral_tool(exe: str) -> bool:
    return (os.path.basename(exe) in _EPHEMERAL_BASENAMES
            and os.path.dirname(exe) in _STD_BIN_DIRS)


@mcp.tool()
@output_safe
def verify_clean(client_id: str, case_id: str, timeout_seconds: int = 300) -> dict:
    """Re-snapshot a client and recompute every detector's residual deviations
    from the baseline — the post-eradication 'is it clean now?' pass.

    Collects the same surfaces as baseline_capture (Pslist, Netstat,
    PersistenceSnapshot) and re-applies the stored baseline allowlists in
    Python, mirroring each detector's filter. Returns per-detector residual
    rows; `clean` is True iff every category is empty. Read-only — never
    remediates.
    """
    if not client_id.startswith("C."):
        return {"success": False, "error": f"client_id must look like 'C.xxx', got {client_id!r}"}

    baseline_path = _baseline_path(case_id, client_id)
    if not baseline_path.exists():
        return {"success": False,
                "error": f"no baseline at {baseline_path}; run monitor.baseline_capture first."}
    baseline = json.loads(baseline_path.read_text())

    from tools.velo import (collect_artifact, wait_for_flow, get_collection_results,
                            upload_artifact_yaml)
    from monitoring import render

    def _collect(artifact: str, parameters: Optional[dict] = None) -> tuple[list, Optional[dict]]:
        kicked = collect_artifact(client_id, artifact, parameters=parameters) if parameters \
            else collect_artifact(client_id, artifact)
        if not kicked.get("success") or not kicked.get("flow_id"):
            return [], {"success": False,
                        "error": f"collect {artifact} failed: {kicked.get('stderr') or kicked.get('error')}"}
        fid = kicked["flow_id"]
        done = wait_for_flow(client_id, fid, timeout_seconds=timeout_seconds)
        if not done.get("success") or done.get("final_state") != "FINISHED":
            return [], {"success": False, "error": f"flow {fid} ({artifact}) did not finish"}
        return get_collection_results(client_id, fid, artifact, full_output=True).get("rows") or [], None

    ps_rows, err = _collect("Linux.Sys.Pslist")
    if err:
        return err
    # Use NetstatEnriched — the SAME artifact the NewLogon/NewNetwork detectors
    # fire on — so a residual session verify sees matches what the detector sees.
    net_rows, err = _collect("Linux.Network.NetstatEnriched")
    if err:
        # Fall back to plain Netstat if the enriched artifact is unavailable.
        net_rows, err = _collect("Linux.Network.Netstat")
        if err:
            return err
    snap_yaml = (render.ARTIFACTS_DIR / f"{PERSISTENCE_SNAPSHOT_ARTIFACT}.yaml").read_text()
    upload_artifact_yaml(snap_yaml)
    persist_rows, err = _collect(
        PERSISTENCE_SNAPSHOT_ARTIFACT,
        parameters={"WatchDirs": json.dumps(render.PERSISTENCE_WATCH_GLOBS)})
    if err:
        return err

    base_images = set(baseline.get("image_paths") or [])
    base_names = set(baseline.get("process_names") or [])
    base_root = set(baseline.get("root_image_paths") or [])
    base_persist = set(baseline.get("persistence_paths") or [])
    base_logon = set(baseline.get("logon_sources") or [])
    base_endpoints = {f"{e['remote_ip']}:{e['remote_port']}" for e in (baseline.get("endpoints") or [])}

    cron_images = set(baseline.get("cron_daemon_images") or render.DEFAULT_CRON_DAEMON_IMAGES)
    flags_by_pid = _ancestry_flags(ps_rows, cron_images)
    baseline_fingerprints = set(baseline.get("persistence_fingerprints") or [])
    current_fingerprints = {f"{r.get('path') or r.get('FullPath')}|{r['sha256']}"
                            for r in persist_rows if r.get("sha256")}
    schedule_intact = bool(baseline_fingerprints) and baseline_fingerprints == current_fingerprints \
        and all(r.get("sha256") for r in persist_rows)

    residual_proc, residual_privesc, residual_logon, residual_net = [], [], [], []
    for row in ps_rows:
        exe = row.get("Exe")
        name = os.path.basename(row.get("Name") or exe or "")
        status = (row.get("Status") or "").lower()
        if not exe or "zombie" in status or _is_ephemeral_tool(exe):
            continue
        flags = flags_by_pid.get(str(row.get("Pid")), {})
        cmdline = row.get("CommandLine") or ""
        # Mirror the NewProcess detector: scheduled work (cron-descended,
        # standard bin, no drop path in the command line) is not a residual.
        if exe not in base_images and name not in base_names \
                and not _is_scheduled_work(exe, cmdline, flags, schedule_intact):
            residual_proc.append({"pid": row.get("Pid"), "image_path": exe,
                                  "username": row.get("Username") or row.get("User"),
                                  "parent_exe": flags.get("parent_exe")})
        # A novel root process is a residual UNLESS it is scheduled work (the
        # all-root cron chain). This deliberately does NOT require the live
        # detector's non-root-ancestor test: after eradication the escalation
        # broker is gone and the implant is reparented to init (root), so the
        # uid-boundary signal has evaporated — but a root binary at a
        # non-standard path is exactly the leftover a clean-check must catch.
        # The scheduled-work exemption still silences the cron chain, so the
        # daily job never reads as a residual.
        if (row.get("Username") or row.get("User")) == "root" and exe not in base_root \
                and exe not in ESCALATION_BROKERS \
                and not _is_scheduled_work(exe, cmdline, flags, schedule_intact):
            residual_privesc.append({"pid": row.get("Pid"), "image_path": exe,
                                     "parent_exe": flags.get("parent_exe")})

    residual_persist = []
    for row in persist_rows:
        p = row.get("path") or row.get("FullPath")
        if p and (not row.get("sha256") or f"{p}|{row['sha256']}" not in baseline_fingerprints):
            residual_persist.append({"path": p, "sha256": row.get("sha256")})
    for missing in baseline_fingerprints - current_fingerprints:
        path = missing.rsplit("|", 1)[0]
        if not any((r.get("path") or r.get("FullPath")) == path for r in persist_rows):
            residual_persist.append({"path": path, "removed": True})

    for row in net_rows:
        lport, rip, rport, status = _netstat_fields(row)
        if status not in (None, "", "ESTABLISHED") or not rip:
            continue
        if lport == 22 and not rip.startswith("127.") and not rip.endswith(".1") \
                and rip not in base_logon:
            residual_logon.append({"remote_ip": rip, "pid": row.get("Pid")})
        if rport and not _RFC1918_OR_LOCAL.match(str(rip)) \
                and f"{rip}:{rport}" not in base_endpoints:
            residual_net.append({"remote_ip": rip, "remote_port": rport})

    residuals = {
        "Custom.TRUDI.NewProcess": residual_proc,
        "Custom.TRUDI.PrivilegeEscalation": residual_privesc,
        "Custom.TRUDI.NewPersistence": residual_persist,
        "Custom.TRUDI.NewLogon": residual_logon,
        "Custom.TRUDI.NewNetwork": residual_net,
    }
    counts = {k: len(v) for k, v in residuals.items()}
    clean = all(c == 0 for c in counts.values())
    return {
        "success": True,
        "client_id": client_id,
        "case_id": case_id,
        "clean": clean,
        "residual_counts": counts,
        "residuals": residuals,
        "checked_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": ("clean=true means no process/root-process/persistence/logon/egress "
                 "deviation from baseline remains on this host."),
    }


# ── Watcher lifecycle ───────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def start_watcher(
    client_id: str,
    case_id: str,
    detectors: Optional[list[str]] = None,
) -> dict:
    """Deploy client-scoped detectors and start the watcher.

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

    # Pick the detector set matching the client's OS so a Windows client gets
    # the Custom.TRUDI.Win.* detectors (pslist()/watch_evtx) and a Linux client
    # the Linux set — never the wrong one. The baseline we just required carries
    # os_family when it was captured by the Windows path; fall back to a live
    # OS probe otherwise.
    try:
        _bl = json.loads(baseline_path.read_text())
    except (OSError, json.JSONDecodeError):
        _bl = {}
    os_family = _bl.get("os_family") or _client_os_family(client_id)
    detectors = detectors or render.list_detector_templates(os_family)
    if not detectors:
        return {"success": False, "error": "no detector templates available under monitoring/artifacts/"}

    coverage_warnings = _detector_coverage_warnings(detectors)

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

    baseline["os_family"] = os_family
    update = _deploy_detectors(case_id, client_id, baseline, detectors)
    if not update.get("success"):
        return update
    pushed = update["uploaded"]
    coverage_warnings.extend(update.get("warnings") or [])

    sidecar = Path(__file__).resolve().parent.parent / "bin" / "trudi-velo-watcher.py"
    log_path = _watcher_log_path(case_id, client_id)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = open(log_path, "a", buffering=1)
    log_fh.write(
        f"\n=== watcher start {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
        f"case={case_id} client={client_id} artifacts={','.join(detectors)} ===\n"
    )
    for w in coverage_warnings:
        log_fh.write(f"[watcher][WARNING] {w}\n")

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
        "warnings": coverage_warnings,
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

    # Remove only this client's label entry; global monitoring stays intact.
    cleared = update_client_event_table(client_id, [])

    return {
        "success": True,
        "killed_pid": pid,
        "graceful": killed,
        "event_table_cleared": cleared.get("success", False),
    }


# ── External-detection ingest (Acalvio ShadowPlex CEF → alert queue) ──────────
#
# A deception platform is a detection SOURCE: the decoy-touch alert is a
# confirmed positive with no false-positive class. The CEF ingest sidecar
# (bin/trudi-cef-ingest.py) turns ShadowPlex CEF-over-syslog into the same
# alert JSON the Velociraptor watcher writes, so the /trudi-watch-alerts loop
# consumes it unchanged. It registers under watchers/ with the pseudo-client
# id "cef-ingest" so list_watchers reports a live producer.

_CEF_INGEST_ID = "cef-ingest"


@mcp.tool()
@output_safe
def start_cef_ingest(case_id: str, listen: str = "0.0.0.0:5514",
                     api_config: Optional[str] = None,
                     resolve_clients: bool = True) -> dict:
    """Spawn the ShadowPlex-CEF ingest sidecar for a live-monitoring case.

    Receives CEF over UDP syslog on `listen` (host:port) — from the decoy
    emulator or a Splunk alert action — and writes Custom.TRUDI.DecoyTouch
    alerts into the case's alerts queue. The source host's Velociraptor
    client_id is resolved from monitoring/config.json `cef_ingest.source_map`,
    then by hostname / last_ip (set resolve_clients=False to skip).

    Refuses if an ingest is already alive for the case. No baseline required —
    the detection comes from the external platform, not a host baseline.
    """
    _ensure_layout(case_id)
    pid_path = _watcher_pid_path(case_id, _CEF_INGEST_ID)
    if pid_path.exists():
        try:
            existing = int(pid_path.read_text().strip())
        except (ValueError, OSError):
            existing = 0
        if _pid_alive(existing):
            return {"success": False,
                    "error": f"cef-ingest already running (pid={existing}). "
                             f"Stop it with monitor.stop_cef_ingest."}

    ingest = Path(__file__).resolve().parent.parent / "bin" / "trudi-cef-ingest.py"
    if not ingest.exists():
        return {"success": False, "error": f"ingest sidecar not found at {ingest}"}

    log_path = _watcher_log_path(case_id, _CEF_INGEST_ID)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = open(log_path, "a", buffering=1)
    log_fh.write(f"\n=== cef-ingest start {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
                 f"case={case_id} listen={listen} ===\n")

    argv = [sys.executable, str(ingest), "--case-id", case_id,
            "--alerts-dir", str(_alerts_dir(case_id)),
            "--listen", listen, "--case-dir", str(_case_dir(case_id))]
    if api_config:
        argv += ["--api-config", os.path.expanduser(api_config)]
    if not resolve_clients:
        argv += ["--no-resolve"]

    proc = subprocess.Popen(argv, stdout=log_fh, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, start_new_session=True)
    pid_path.write_text(str(proc.pid))
    return {"success": True, "pid": proc.pid, "pid_file": str(pid_path),
            "log_file": str(log_path), "listen": listen,
            "source": "acalvio_shadowplex_cef",
            "detector": "Custom.TRUDI.DecoyTouch"}


@mcp.tool()
@output_safe
def stop_cef_ingest(case_id: str) -> dict:
    """SIGTERM the ShadowPlex-CEF ingest sidecar for the case."""
    pid_path = _watcher_pid_path(case_id, _CEF_INGEST_ID)
    if not pid_path.exists():
        return {"success": False, "error": "no cef-ingest pid file — nothing to stop"}
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
    return {"success": True, "killed_pid": pid, "graceful": killed}


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

    Each alert carries its process `signature`; one whose signature a prior
    investigation fed back via `monitor.baseline_extend` is stamped
    `known_benign` (with that investigation/finding), and `all_known_benign`
    says whether the whole batch is a recurrence — the /trudi-check-alerts
    fast path records a recurrence finding instead of a full DAIR cycle.
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
    _annotate_known_benign(case_id, alerts)
    benign = sum(1 for a in alerts if a.get("known_benign"))
    return {"success": True, "alerts": alerts, "count": len(alerts),
            "known_benign_count": benign,
            "all_known_benign": bool(alerts) and benign == len(alerts)}


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
    # Live-monitoring scope: a per-investigation trace is only valid inside a
    # baselined live-monitoring case (the same check respond.* enforces).
    # Without it, one call on a static case would both hijack the active
    # trace and exempt the run from the full-DAIR-cycle report requirement.
    from response import gates as response_gates
    refusal = response_gates.check_live_monitoring_scope(case_id)
    if refusal is not None:
        return refusal

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

    from monitoring.response_store import attach_actions
    attach_actions(_case_dir(case_id), investigation_id, sorted_alert_ids)

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
    from monitoring.response_store import attach_actions
    attach_actions(_case_dir(case_id), investigation_id, combined)

    return {
        "success": True,
        "investigation_id": investigation_id,
        "total_alert_ids": combined,
        "added_alert_ids": truly_new,
        "missing_alert_ids": missing,
        "extension_call_id": ext_cid,
    }


def _act_seq(action_id: str) -> int:
    """Numeric sort key for `ACT-N` ids (glob order sorts ACT-10 before ACT-2)."""
    try:
        return int(str(action_id).rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        return 0


def _belongs_to_investigation(rec: dict, investigation_id: Optional[str],
                              opened_at_utc: Optional[str], ts_key: str) -> bool:
    """Does a suggestion/execution record belong to `investigation_id`?

    Records written since respond.* stamps `investigation_id` match on it.
    Older (unstamped) records fall back to time: they count only if their
    timestamp is at or after the investigation opened. With no investigation
    given, everything matches (case-wide listing).

    The response ledger is one directory per CASE, so without this filter every
    investigation's report reprinted every action the case ever suggested —
    including stale dry-run leftovers aimed at the wrong address.
    """
    if not investigation_id:
        return True
    stamped = rec.get("investigation_id")
    if stamped:
        return stamped == investigation_id
    if rec.get("alert_ids"):
        return False  # modern records are adopted by alert ownership, never time
    ts = rec.get(ts_key) or ""
    return bool(opened_at_utc) and ts >= opened_at_utc


def _load_suggestions(case_id: str, investigation_id: Optional[str] = None,
                      opened_at_utc: Optional[str] = None,
                      include_superseded: bool = False) -> list[dict]:
    """Read the ACT-*.json containment suggestions for the case in ACT order,
    restricted to `investigation_id` when given (see `_belongs_to_investigation`).
    Superseded drafts (re-suggested with enriched evidence) are dropped unless
    `include_superseded`."""
    sug_dir = (CASES_ROOT / case_id / "monitoring" / "response" / "suggestions")
    out: list[dict] = []
    if not sug_dir.is_dir():
        return out
    for p in sorted(sug_dir.glob("ACT-*.json"), key=lambda q: _act_seq(q.stem)):
        try:
            rec = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not _belongs_to_investigation(rec, investigation_id, opened_at_utc, "created_at_utc"):
            continue
        if rec.get("superseded_by") and not include_superseded:
            continue
        out.append(rec)
    return out


def _append_containment_section(case_id: str, report_base: Path,
                                investigation_id: Optional[str] = None,
                                opened_at_utc: Optional[str] = None) -> int:
    """Append a 'Recommended Containment Commands (run manually)' section to the
    exported report `.md`, and mirror the list into the `.json`. Returns the
    number of suggestions written. Only this investigation's live (not
    superseded) suggestions are listed when `investigation_id` is given.

    This runs AFTER `log.export()` and touches ONLY the per-investigation report
    files — never the shared `core.execution_log.export()` path — so static-case
    reports are byte-for-byte unchanged.
    """
    suggestions = _load_suggestions(case_id, investigation_id, opened_at_utc)
    if not suggestions:
        return 0

    md_path = Path(str(report_base) + ".md")
    lines = [
        "",
        "## Recommended Containment Commands (run manually)",
        "",
        "Operator-runnable equivalents of the containment actions suggested for "
        "this investigation's alerts. Actions TRUDI executed itself are listed "
        "under *Autonomous Response Actions*; the rest are for a human to run "
        "out-of-band after review.",
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


def _load_executions(case_id: str, investigation_id: Optional[str] = None,
                     opened_at_utc: Optional[str] = None) -> list[dict]:
    """Read the ACT-*.json execution records for the case in ACT order,
    restricted to `investigation_id` when given (see `_belongs_to_investigation`)."""
    ex_dir = (CASES_ROOT / case_id / "monitoring" / "response" / "executions")
    out: list[dict] = []
    if not ex_dir.is_dir():
        return out
    for p in sorted(ex_dir.glob("ACT-*.json"), key=lambda q: _act_seq(q.stem)):
        try:
            rec = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not _belongs_to_investigation(rec, investigation_id, opened_at_utc, "executed_at_utc"):
            continue
        out.append(rec)
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


def _append_response_section(case_id: str, report_base: Path,
                             investigation_id: Optional[str] = None,
                             opened_at_utc: Optional[str] = None) -> int:
    """Append an 'Autonomous Response Actions' section to the report `.md` and
    mirror a structured ledger into the `.json`. Records what TRUDI actually
    did (auto-executed / approved / reverted / awaiting approval), each with its
    verbatim rollback/undo command. Returns the number of action rows written.
    Scoped to `investigation_id` when given.

    Like `_append_containment_section`, this runs AFTER `log.export()` and
    touches only the per-investigation report files.
    """
    executions = _load_executions(case_id, investigation_id, opened_at_utc)
    rec = _read_open_investigation(case_id) or {}
    awaiting = set(rec.get("awaiting_approval") or [])
    if not executions and not awaiting:
        return 0

    # An executed action is never hidden, even if a later re-suggestion marked
    # its draft superseded — what ran is what the ledger must show.
    suggestions = _load_suggestions(case_id, investigation_id, opened_at_utc,
                                    include_superseded=True)
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
        if s.get("superseded_by") and not e:
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


def _append_no_containment_note(report_base: Path) -> None:
    """When an investigation suggested and executed nothing, say so explicitly
    rather than leaving the containment sections out — a reader should not have
    to infer 'nothing was warranted' from an absence."""
    md_path = Path(str(report_base) + ".md")
    lines = [
        "",
        "## Containment",
        "",
        "No containment actions were suggested or executed for this investigation.",
        "",
    ]
    try:
        with md_path.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        return
    json_path = Path(str(report_base) + ".json")
    try:
        doc = json.loads(json_path.read_text())
        if isinstance(doc, dict):
            doc["recommended_containment_commands"] = []
            doc["autonomous_response_actions"] = []
            doc["containment_note"] = "none suggested or executed"
            json_path.write_text(json.dumps(doc, indent=2))
    except (OSError, json.JSONDecodeError):
        pass


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
    if rec:
        from monitoring.response_store import attach_actions
        attach_actions(_case_dir(case_id), rec["investigation_id"], rec.get("alert_ids") or [])
    executions = _load_executions(case_id, (rec or {}).get("investigation_id"),
                                  (rec or {}).get("opened_at_utc")) if rec else []
    auto_done = [e.get("action_id") for e in executions
                 if e.get("mode") == "auto" and e.get("success")]
    cfg = response_policy.load_config(case_id, cases_root=CASES_ROOT)
    return {
        "success": True,
        "open": rec is not None,
        "investigation_id": (rec or {}).get("investigation_id"),
        "paused": bool(awaiting),
        "awaiting_approval": awaiting,
        "auto_executed": auto_done,
        "auto_protect_enabled": bool(cfg["auto_protect"]["enabled"]),
        "demo_response": cfg.get("demo_response") or {},
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


_TIER_ORDER = ["CONFIRMED", "LIKELY", "SUSPECTED", "UNCONFIRMED"]


def _report_entries(case_id: str, investigation_id: str) -> list[dict]:
    """The investigation's trace entries — in-memory if the log singleton still
    holds them, else re-read from the on-disk per-investigation trace (survives
    an MCP restart). Best-effort: never raises, returns [] on failure."""
    from core.execution_log import log
    try:
        entries = (log.to_json() or {}).get("entries") or []
    except Exception:  # noqa: BLE001
        entries = []
    if entries:
        return entries
    p = _investigation_trace_path(case_id, investigation_id)
    try:
        return (json.loads(p.read_text()) or {}).get("entries") or []
    except (OSError, json.JSONDecodeError):
        return []


def _build_findings_report(case_id: str,
                           investigation_id: str,
                           report_base: Path,
                           rec: Optional[dict]) -> int:
    """Render a human-readable investigation report — verdict, findings grouped
    by confidence tier, and the ATT&CK chain — from the findings recorded in the
    trace. This is DISTINCT from the raw execution trace (which `log.export`
    writes to the `_trace` files): the live flow previously shipped the trace
    dump itself as the report. Deterministic — no model call, so it is safe to
    run inside the (must-not-hang) finalize path. Writes `report_base.{md,json}`
    and returns the finding count. Raises only on an unexpected error, letting
    `end_investigation` fall back to the trace export.
    """
    from core.findings import active_findings

    entries = _report_entries(case_id, investigation_id)
    findings = [e for e in active_findings(entries) if e.get("type") == "finding"]
    rec = rec or {}
    alert_ids = rec.get("alert_ids") or []

    def _claim(f: dict) -> dict:
        return f.get("claim") or {}

    def _tech_id(t) -> str:
        # validated_techniques entries may be plain ids or {technique_id,name,tactic} dicts.
        if isinstance(t, dict):
            return str(t.get("technique_id") or t.get("id") or "").strip()
        return str(t or "").strip()

    def _techs(f: dict) -> list[str]:
        raw = f.get("validated_techniques") or _claim(f).get("techniques") or []
        out: list[str] = []
        for t in raw:
            tid = _tech_id(t)
            if tid and tid not in out:
                out.append(tid)
        return out

    verdict = next((f for f in findings if _claim(f).get("answers_case_question")), None)
    counts = {t: sum(1 for x in findings if x.get("confidence") == t) for t in _TIER_ORDER}
    count_str = ", ".join(f"{t}×{counts[t]}" for t in _TIER_ORDER if counts[t]) or "none"
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    md: list[str] = [
        f"# Investigation Report — {case_id} / {investigation_id}",
        "",
        f"- Generated: `{gen}`",
        f"- Alerts in bundle: {len(alert_ids)}",
        f"- Findings: {len(findings)} ({count_str})",
        f"- Full execution trace: `{report_base.name}_trace.md`",
        "",
        "## Verdict",
        "",
    ]
    if verdict:
        md.append(f"**[{verdict.get('confidence')}]** "
                  f"{(verdict.get('description') or '').strip()}")
    else:
        md.append("_No finding was marked as answering the case question "
                  "(`answers_case_question`)._")
    md += ["", "## Findings", ""]

    any_f = False
    for tier in _TIER_ORDER:
        group = [f for f in findings if f.get("confidence") == tier]
        if not group:
            continue
        any_f = True
        md += [f"### {tier} ({len(group)})", ""]
        for f in group:
            c = _claim(f)
            fid = f.get("finding_id") or f.get("call_id")
            md.append(f"- **{fid}** — {(f.get('description') or '').strip()}")
            meta: list[str] = []
            if c.get("category"):
                meta.append(f"category: `{c['category']}`")
            if c.get("act"):
                meta.append(f"act: `{c['act']}`")
            if c.get("channel"):
                meta.append(f"channel: `{c['channel']}`")
            techs = _techs(f)
            if techs:
                meta.append("ATT&CK: " + ", ".join(f"`{t}`" for t in techs))
            if meta:
                md.append("  - " + " · ".join(meta))
            cites = [f.get("linked_call_id"), *(f.get("input_call_ids") or [])]
            cites = list(dict.fromkeys(str(x) for x in cites if x))
            if cites:
                md.append("  - evidence call_ids: "
                          + ", ".join("#" + x for x in cites))
        md.append("")
    if not any_f:
        md += ["_No findings were recorded for this investigation._", ""]

    chain: list[str] = []
    for f in findings:
        for t in _techs(f):
            if t not in chain:
                chain.append(t)
    if chain:
        md += ["## ATT&CK techniques observed", "",
               ", ".join(f"`{t}`" for t in chain), ""]

    Path(str(report_base) + ".md").write_text("\n".join(md) + "\n", encoding="utf-8")

    doc = {
        "schema_version": 1,
        "report_kind": "investigation_findings",
        "case_id": case_id,
        "investigation_id": investigation_id,
        "generated": gen,
        "alert_count": len(alert_ids),
        "verdict": ({
            "finding_id": verdict.get("finding_id") or verdict.get("call_id"),
            "confidence": verdict.get("confidence"),
            "description": verdict.get("description"),
        } if verdict else None),
        "findings": [{
            "finding_id": f.get("finding_id") or f.get("call_id"),
            "confidence": f.get("confidence"),
            "description": f.get("description"),
            "claim": _claim(f),
            "techniques": _techs(f),
            "linked_call_id": f.get("linked_call_id"),
            "input_call_ids": f.get("input_call_ids") or [],
        } for f in findings],
        "attack_chain": chain,
        "trace_file": report_base.name + "_trace",
    }
    Path(str(report_base) + ".json").write_text(
        json.dumps(doc, indent=2), encoding="utf-8")
    return len(findings)


@mcp.tool()
@output_safe
def end_investigation(case_id: str,
                      investigation_id: str,
                      outcome_note: str = "") -> dict:
    """Finalise the investigation: write a human-readable findings report to
    `<case>/reports/<case>_<investigation_id>.{json,md}` and the full execution
    trace to `<case>/reports/<case>_<investigation_id>_trace.{json,md}`, swap the
    trace back to the case-wide file, log a closing `agent_message`
    in the case-wide trace, and remove
    `monitoring/_open_investigation.json`.

    The report is rendered deterministically from the recorded findings
    (verdict + findings by tier + ATT&CK chain); it is no longer the raw trace
    dump. If the render fails, the trace export is written to the report path as
    a fallback and a `warning` is returned.

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
    from monitoring.response_store import attach_actions
    if rec and rec.get("investigation_id") == investigation_id:
        attach_actions(_case_dir(case_id), investigation_id, rec.get("alert_ids") or [])

    from core.execution_log import log
    # Make sure the active trace is the one we're closing before export.
    inv_trace = _investigation_trace_path(case_id, investigation_id)
    if log._path != str(inv_trace) and inv_trace.exists():
        log.configure(case_id, str(inv_trace), save_session=True)

    # Full execution trace → reports/<case>_<inv>_trace.{json,md}.
    trace_base = str(report_base) + "_trace"
    export_result = log.export(trace_base)

    # Human-readable findings report → reports/<case>_<inv>.{json,md}, DISTINCT
    # from the raw trace. Deterministic (no model call), so it is safe in this
    # must-not-hang finalize path. On any failure, fall back to exporting the
    # trace as the report so a report file always exists.
    report_warning = None
    try:
        findings_written = _build_findings_report(
            case_id, investigation_id, report_base, rec)
    except Exception as e:  # noqa: BLE001 — finalize must never raise
        report_warning = f"findings-report render failed, fell back to trace export: {e}"
        log.export(str(report_base))
        findings_written = 0

    # Append operator-runnable containment commands and the autonomous-response
    # ledger (what TRUDI actually did + rollbacks) — scoped to THIS investigation.
    # The response store is per case, so an unscoped render reprinted every
    # action the case ever suggested in every investigation's report.
    # Touches only the per-investigation report files, never the shared export().
    opened_at = (rec or {}).get("opened_at_utc")
    containment_written = _append_containment_section(
        case_id, report_base, investigation_id, opened_at)
    response_actions_written = _append_response_section(
        case_id, report_base, investigation_id, opened_at)
    if not containment_written and not response_actions_written:
        _append_no_containment_note(report_base)

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
        "trace_json_path": trace_base + ".json",
        "trace_md_path": trace_base + ".md",
        "case_wide_trace_path": str(case_wide),
        "closing_call_id": closing_cid,
        "entry_count": export_result.get("entry_count", 0),
        "json_wrote": export_result.get("json_wrote", False),
        "md_wrote": export_result.get("md_wrote", False),
        "findings_written": findings_written,
        "containment_commands_written": containment_written,
        "response_actions_written": response_actions_written,
        "closed": True,
    }
    warning = " + ".join(w for w in (warning, report_warning) if w) or None
    if warning:
        out["warning"] = warning
    return out
