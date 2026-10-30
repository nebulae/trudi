#!/usr/bin/env python3
"""TRUDI Velociraptor event-stream watcher.

Long-running sidecar that subscribes to Velociraptor's client monitoring
stream for the named Custom.TRUDI.* artifacts and emits one alert JSON per
row into the case's alerts directory.

Usage (spawned detached by tools/monitor.py:start_watcher):

  trudi-velo-watcher \\
      --case-id DEMO-LIVE \\
      --client-id C.abc... \\
      --artifacts Custom.TRUDI.NewProcess,Custom.TRUDI.NewNetwork \\
      --alerts-dir /home/trin/cases/DEMO-LIVE/monitoring/alerts

Each subscribed VQL is run as a separate ``velociraptor query --format=jsonl``
subprocess in a thread. Stdout lines are parsed as JSON and assembled into
the alert schema. ``_seq.txt`` is incremented under an fcntl lock so
concurrent detector threads never collide on the same seq.

Catch-all SIGTERM handler shuts the subprocesses down cleanly so the alert
queue is never left half-written.

No MCP imports — this runs as a standalone Python script.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

VELO_BIN_DEFAULT = "velociraptor"
API_CONFIG_DEFAULT = os.path.expanduser(
    "~/.config/trudi/velociraptor/api.config.yaml"
)

# Detector → list of advisory pivots the slash command will hand to the agent.
# These are hints, not directives — DAIR still prescribes the real batch.
#
# For live-monitoring cases the canonical investigation substrate is
# `velo.collect_artifact(<artifact>)` against the same client the alert
# fired from, not `live.*` SSH calls. `live.*` requires the host to be
# registered in ~/cases/.common/live_hosts.json AND a working SSH path
# from SIFT to the victim — both are absent in the demo container by
# default. Use `live.*` only as a documented fallback when an operator
# has explicitly set up the SSH bridge.
SUGGESTED_PIVOT_TOOLS = {
    "Custom.TRUDI.NewProcess": [
        # Confirm the process and inspect its open files + parent chain.
        "velo.collect_artifact(Linux.Sys.Pslist)",
        "velo.collect_artifact(Linux.Sys.ProcessOpenFiles)",
        "velo.collect_artifact(Linux.Network.Netstat)",
        "yara.scan_strings",
    ],
    "Custom.TRUDI.NewPersistence": [
        # Read the unit/cron file body and the parent context (timeline,
        # owning package). Linux.Sys.SystemdUnits gives a snapshot of all
        # unit files for diffing; live read of the specific path comes
        # from Generic.Forensic.LinuxLogs or a targeted
        # Linux.Detection.AnomalousFiles call.
        "velo.collect_artifact(Linux.Sys.SystemdUnits)",
        "velo.collect_artifact(Linux.Sys.Crontab)",
        "velo.query(SELECT FullPath, Size, Mtime FROM stat(filename=<path>))",
    ],
    "Custom.TRUDI.NewNetwork": [
        "velo.collect_artifact(Linux.Network.Netstat)",
        "velo.collect_artifact(Linux.Sys.Pslist)",
        "enrich.abuseipdb_check",
    ],
    "Custom.TRUDI.YaraProcess": [
        # Dump the process's memory regions and re-scan with broader rules.
        "velo.collect_artifact(Linux.Sys.Pslist)",
        "velo.collect_artifact(Generic.Forensic.LocalHashes.Glob)",
        "yara.scan_strings",
    ],
    # ── Windows victim (Custom.TRUDI.Win.*) ──────────────────────────────────
    "Custom.TRUDI.Win.NewProcess": [
        "velo.collect_artifact(Windows.System.Pslist)",
        "velo.collect_artifact(Windows.System.DNSCache)",
        "velo.collect_artifact(Windows.Network.Netstat)",
    ],
    "Custom.TRUDI.Win.NewLogon": [
        # RDP / lateral logon: pull the Security + TerminalServices events to
        # bind account + source + session, then the process list keyed by logon.
        "velo.collect_artifact(Windows.EventLogs.RDPAuth)",
        "velo.collect_artifact(Windows.EventLogs.Evtx, Channel=Security)",
        "velo.collect_artifact(Windows.Network.Netstat)",
    ],
    "Custom.TRUDI.Win.NewPersistence": [
        "velo.collect_artifact(Windows.Sysinternals.Autoruns)",
        "velo.collect_artifact(Windows.System.TaskScheduler)",
        "velo.query(SELECT * FROM glob(globs=<key>, accessor='registry'))",
    ],
}


# ── Per-detector dedup ──────────────────────────────────────────────────────
#
# Each detector polls on a fixed interval, so the SAME row keeps coming
# down the watch_monitoring stream every tick. The watcher de-duplicates by
# computing a stable "signature" per detector (the natural key of the
# event) and dropping rows whose signature has already been alerted on
# during this watcher's lifetime.
#
# Restarting the watcher clears the dedup cache. That matters: after
# stop_watcher/start_watcher, every still-present anomaly will refire once.
# This is intentional — operators kicking the watcher get a fresh view.

def _detector_leaf(detector: str) -> str:
    """Behavioural leaf of a detector name, so the Linux and Windows variants
    share logic: both `Custom.TRUDI.NewProcess` and `Custom.TRUDI.Win.NewProcess`
    → `NewProcess`."""
    return detector.rsplit(".", 1)[-1]


def _row_signature(detector: str, row: dict) -> str:
    """Stable key for dedup. Empty string means 'no signature — never dedup'.

    Keyed on the detector leaf, and field-tolerant so the Windows detectors
    (source_ip/account for logon, identity for persistence) share the logic
    with their Linux counterparts."""
    leaf = _detector_leaf(detector)
    if leaf in ("NewProcess", "PrivilegeEscalation", "YaraProcess"):
        # A process is identified by image+pid (+ started_utc, since a reused
        # pid on a respawn is a genuinely new event). YaraProcess folds in rule.
        return "|".join([
            str(row.get("image_path") or row.get("Exe") or ""),
            str(row.get("pid") or row.get("Pid") or ""),
            str(row.get("started_utc") or ""),
            str(row.get("rule") or ""),
        ])
    if leaf == "NewPersistence":
        # Windows: identity ("<key>\<value>|<data>") so a CHANGED Run key
        # refires. Linux: path + mtime so a changed file refires.
        return str(row.get("identity") or "|".join([
            str(row.get("path") or ""),
            str(row.get("mtime_utc") or ""),
        ]))
    if leaf == "NewNetwork":
        return "|".join([
            str(row.get("remote_ip") or ""),
            str(row.get("remote_port") or ""),
            str(row.get("Pid") or row.get("pid") or ""),
        ])
    if leaf == "NewLogon":
        if ".Win." in detector:
            # Event streams deliver new sessions, unlike Linux's repeated
            # socket snapshots. Never dedup on account/source alone.
            record = row.get("event_record_id")
            if record is not None:
                return json.dumps([row.get("computer"), row.get("channel"),
                                   record, row.get("event_id"), row.get("timestamp_utc")], default=str)
            if not row.get("timestamp_utc"):
                return ""
            return json.dumps([row.get("source_ip"), row.get("account"), row.get("domain"),
                               row.get("event_id"), row.get("logon_type"), row.get("logon_id"),
                               row.get("timestamp_utc")], default=str)
        # An inbound session is identified by its source + (Linux) the sshd
        # session pid / (Windows) the account + logon type.
        return "|".join([
            str(row.get("remote_ip") or row.get("source_ip") or ""),
            str(row.get("remote_port") or row.get("logon_type") or ""),
            str(row.get("pid") or row.get("account") or ""),
        ])
    return ""


# Cap on per-detector dedup memory. Old entries are evicted FIFO when
# the cache exceeds this size — see _MAX_DEDUP_ENTRIES_PER_DETECTOR.
_MAX_DEDUP_ENTRIES_PER_DETECTOR = 10_000

# detector → ordered dict-like set of signatures already alerted on.
# Plain dicts preserve insertion order in Python 3.7+, so this doubles
# as a FIFO eviction queue.
_seen_signatures: dict[str, dict[str, None]] = {}
_seen_lock = threading.Lock()


def _should_emit(detector: str, row: dict) -> bool:
    """Return True if this row should produce an alert (first time we've
    seen this signature for this detector in this watcher lifetime)."""
    sig = _row_signature(detector, row)
    if not sig:
        return True
    with _seen_lock:
        seen = _seen_signatures.setdefault(detector, {})
        if sig in seen:
            return False
        seen[sig] = None
        if len(seen) > _MAX_DEDUP_ENTRIES_PER_DETECTOR:
            # Pop oldest. dict iteration is insertion-ordered.
            oldest = next(iter(seen))
            del seen[oldest]
        return True

# ── Cross-detector merge ────────────────────────────────────────────────────
#
# NewProcess, PrivilegeEscalation and YaraProcess all poll the same process
# table, so one new process produced one alert PER detector (eight alerts for
# the four children of a cron.daily run in DECOY-DEMO). When a row arrives for
# a (client, pid, image) that already has an alert written within the merge
# window, it is folded into that alert — `detectors` gains the new name,
# `evidence_by_detector` keeps each detector's row, severity takes the max —
# instead of consuming a new seq. Velociraptor flushes event batches per
# artifact tens of seconds apart (77 s observed), hence the generous window.
#
# An alert that an investigation has already picked up (listed in
# monitoring/_open_investigation.json) is never mutated: the second detector's
# row becomes its own alert so the open investigation is extended with it.
_MERGE_WINDOW_SECONDS = 180.0
# Keyed by leaf so the Windows NewProcess merges the same way (see
# _process_key, which uses the leaf).
_PROCESS_DETECTOR_LEAVES = {"NewProcess", "PrivilegeEscalation", "YaraProcess"}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# (client, pid, image, process start time) -> (alert path, time written)
_recent_process_alerts: dict[str, tuple[Path, float]] = {}
_merge_lock = threading.Lock()


def _process_key(client_id: str, detector: str, row: dict) -> str:
    if _detector_leaf(detector) not in _PROCESS_DETECTOR_LEAVES:
        return ""
    pid = row.get("pid") or row.get("Pid")
    if pid in (None, ""):
        return ""
    # Without creation time PID reuse cannot be ruled out. Keep the alert
    # separate rather than merging evidence from unrelated processes.
    started = row.get("started_utc")
    if not started:
        return ""
    return json.dumps([client_id, str(pid), row.get('image_path') or row.get('Exe') or '',
                       str(started)])


def _in_open_investigation(alerts_dir: Path, alert_id: str) -> bool:
    tracker = alerts_dir.parent / "_open_investigation.json"
    try:
        rec = json.loads(tracker.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    return alert_id in (rec.get("alert_ids") or [])


def _try_merge(alerts_dir: Path, client_id: str, detector: str, row: dict,
               now_mono: float | None = None) -> Path | None:
    """Fold `row` into a recent alert about the same process. Returns the
    merged alert's path, or None when a fresh alert should be written."""
    key = _process_key(client_id, detector, row)
    if not key:
        return None
    now_mono = time.monotonic() if now_mono is None else now_mono
    with _merge_lock:
        hit = _recent_process_alerts.get(key)
        if not hit:
            return None
        path, t0 = hit
        if now_mono - t0 > _MERGE_WINDOW_SECONDS or not path.exists():
            _recent_process_alerts.pop(key, None)
            return None
        try:
            alert = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if alert.get("consumed") or _in_open_investigation(alerts_dir, alert.get("alert_id", "")):
            return None
        detectors = list(alert.get("detectors") or [alert.get("detector")])
        if detector in detectors:
            return None  # distinct rows already passed exact-event dedup
        detectors.append(detector)
        alert["detectors"] = detectors
        by_det = alert.get("evidence_by_detector") or {alert.get("detector"): alert.get("evidence")}
        by_det[detector] = row
        alert["evidence_by_detector"] = by_det
        if _SEVERITY_RANK.get(_severity(detector), 0) > _SEVERITY_RANK.get(alert.get("severity"), 0):
            alert["severity"] = _severity(detector)
        alert["summary"] = f"{alert.get('summary', '')} [+{detector.rsplit('.', 1)[-1]}]"
        alert["merged_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        pivots = list(alert.get("suggested_pivot_tools") or [])
        for p in SUGGESTED_PIVOT_TOOLS.get(detector, []):
            if p not in pivots:
                pivots.append(p)
        alert["suggested_pivot_tools"] = pivots
        path.write_text(json.dumps(alert, indent=2))
    print(f"[watcher] merged {detector.rsplit('.', 1)[-1]} row for pid "
          f"{row.get('pid') or row.get('Pid')} into {path.name}", flush=True)
    return path


def _remember_process_alert(client_id: str, detector: str, row: dict, path: Path,
                            now_mono: float | None = None) -> None:
    key = _process_key(client_id, detector, row)
    if not key:
        return
    with _merge_lock:
        _recent_process_alerts[key] = (path, time.monotonic() if now_mono is None else now_mono)
        if len(_recent_process_alerts) > _MAX_DEDUP_ENTRIES_PER_DETECTOR:
            _recent_process_alerts.pop(next(iter(_recent_process_alerts)), None)


# Stop flag set by the SIGTERM handler.
_stop = threading.Event()


def _install_signal_handlers() -> None:
    def _handler(signum, _frame):
        print(f"[watcher] received signal {signum}, shutting down …", flush=True)
        _stop.set()
    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)


def _next_seq(alerts_dir: Path) -> int:
    """Atomically increment _seq.txt; return new value. fcntl-locked."""
    seq_file = alerts_dir / "_seq.txt"
    lock_file = alerts_dir / "_seq.lock"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    with open(lock_file, "w") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            try:
                cur = int(seq_file.read_text().strip() or "0")
            except (OSError, ValueError):
                cur = 0
            cur += 1
            seq_file.write_text(str(cur))
            return cur
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _summarize_row(detector: str, row: dict) -> str:
    """One-line human description for the alert's `summary` field (leaf-keyed, so
    Windows and Linux variants share wording)."""
    leaf = _detector_leaf(detector)
    tag = "Windows " if ".Win." in detector else ""
    if leaf == "NewProcess":
        return (f"New {tag}process not in baseline: "
                f"{row.get('image_path', '?')} (pid={row.get('pid', '?')})")
    if leaf == "NewPersistence":
        return f"New {tag}persistence entry: {row.get('path') or row.get('identity', '?')}"
    if leaf == "NewNetwork":
        return (f"New outbound connection: "
                f"{row.get('remote_ip', '?')}:{row.get('remote_port', '?')} "
                f"(pid={row.get('Pid') or row.get('pid', '?')})")
    if leaf == "YaraProcess":
        return (f"YARA hit {row.get('rule', '?')!r} on process "
                f"{row.get('process_name', '?')} (pid={row.get('pid', '?')})")
    if leaf == "NewLogon":
        if ".Win." in detector or row.get("source_ip"):
            return (f"New {tag}logon type {row.get('logon_type', '?')} as "
                    f"{row.get('account', '?')} from {row.get('source_ip', '?')}")
        return (f"New inbound session from {row.get('remote_ip', '?')} "
                f"(pid={row.get('pid', '?')})")
    if leaf == "PrivilegeEscalation":
        return (f"Privilege escalation: root {row.get('image_path', '?')} "
                f"(pid={row.get('pid', '?')})")
    return f"{detector}: " + json.dumps(row)[:160]


def _severity(detector: str) -> str:
    leaf = _detector_leaf(detector)
    if leaf in ("NewProcess", "YaraProcess", "NewLogon", "NewPersistence"):
        return "high"
    return "medium"


def _write_alert(
    alerts_dir: Path,
    case_id: str,
    client_id: str,
    detector: str,
    row: dict,
) -> Path:
    seq = _next_seq(alerts_dir)
    alert_id = str(uuid.uuid4())
    alert = {
        "alert_id": alert_id,
        "seq": seq,
        "case_id": case_id,
        "client_id": client_id,
        "hostname": row.get("Hostname") or row.get("hostname"),
        "timestamp_utc": row.get("timestamp_utc") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "detector": detector,
        "detectors": [detector],
        "severity": _severity(detector),
        "summary": _summarize_row(detector, row),
        "evidence": row,
        "suggested_pivot_tools": SUGGESTED_PIVOT_TOOLS.get(detector, []),
        "consumed": False,
    }
    safe_detector = detector.split(".")[-1]
    path = alerts_dir / f"{seq:08d}_{safe_detector}.json"
    path.write_text(json.dumps(alert, indent=2))
    print(f"[watcher] wrote alert {path.name}: {alert['summary'][:120]}", flush=True)
    _remember_process_alert(client_id, detector, row, path)
    return path


def _consume_detector(
    detector: str,
    client_id: str,
    case_id: str,
    alerts_dir: Path,
    velo_bin: str,
    api_config: str,
) -> None:
    """One thread per detector — owns its `velociraptor query` subprocess."""
    vql = (
        f"SELECT * FROM watch_monitoring(artifact={json.dumps(detector)}) "
        f"WHERE ClientId = {json.dumps(client_id)}"
    )
    argv = [velo_bin, "--api_config", api_config, "query", "--format", "jsonl", vql]
    print(f"[watcher][{detector}] starting: {shlex.join(argv)}", flush=True)
    while not _stop.is_set():
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as e:
            print(f"[watcher][{detector}] velociraptor binary not found: {e}", flush=True)
            return

        # Drain stderr on a separate thread so it doesn't block stdout.
        def _drain_stderr() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                line = line.rstrip()
                if line:
                    print(f"[watcher][{detector}][stderr] {line}", flush=True)
        threading.Thread(target=_drain_stderr, daemon=True).start()

        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                if _stop.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    print(f"[watcher][{detector}] skipping non-JSON row: {line[:120]}", flush=True)
                    continue
                if not _should_emit(detector, row):
                    # Already-seen signature for this detector in this
                    # watcher lifetime. Skip silently — logging every
                    # duplicate would blow up the log.
                    continue
                if _try_merge(alerts_dir, client_id, detector, row) is not None:
                    continue
                _write_alert(alerts_dir, case_id, client_id, detector, row)
        finally:
            if _stop.is_set():
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

        if _stop.is_set():
            return
        # Stream closed without us asking — server restart, network blip,
        # or velociraptor process exit. Wait a beat and re-subscribe.
        rc = proc.poll()
        print(f"[watcher][{detector}] subprocess exited rc={rc} — reconnecting in 5s", flush=True)
        time.sleep(5)


def main() -> int:
    parser = argparse.ArgumentParser(description="TRUDI Velociraptor event-stream watcher")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--artifacts", required=True,
                        help="comma-separated Custom.TRUDI.* artifact names")
    parser.add_argument("--alerts-dir", required=True)
    parser.add_argument("--velo-bin", default=os.environ.get("TRUDI_VELO_BIN") or VELO_BIN_DEFAULT)
    parser.add_argument("--api-config",
                        default=os.environ.get("TRUDI_VELO_API_CONFIG") or API_CONFIG_DEFAULT)
    args = parser.parse_args()

    detectors = [d.strip() for d in args.artifacts.split(",") if d.strip()]
    if not detectors:
        print("[watcher] no --artifacts given", file=sys.stderr)
        return 2

    alerts_dir = Path(args.alerts_dir)
    alerts_dir.mkdir(parents=True, exist_ok=True)

    if not Path(args.api_config).exists():
        print(f"[watcher] api_config not found: {args.api_config}", file=sys.stderr)
        return 3

    _install_signal_handlers()

    threads: list[threading.Thread] = []
    for d in detectors:
        t = threading.Thread(
            target=_consume_detector,
            args=(d, args.client_id, args.case_id, alerts_dir, args.velo_bin, args.api_config),
            daemon=True,
            name=f"watch-{d}",
        )
        t.start()
        threads.append(t)

    print(f"[watcher] started {len(threads)} detector thread(s) "
          f"for case={args.case_id} client={args.client_id}", flush=True)

    while not _stop.is_set():
        time.sleep(1)
    for t in threads:
        t.join(timeout=10)
    print("[watcher] shut down cleanly", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
