#!/usr/bin/env python3
"""TRUDI external-detection ingest: Acalvio ShadowPlex CEF → TRUDI alert queue.

Long-running sidecar (spawned detached by tools/monitor.py:start_cef_ingest)
that receives ShadowPlex incident records as CEF over UDP syslog — straight
from the decoy/platform, or forwarded by a Splunk alert action — and writes
one alert JSON per incident into the case's `monitoring/alerts/` directory,
in exactly the shape `bin/trudi-velo-watcher.py` writes. The existing
`/trudi-watch-alerts` / `/trudi-check-alerts` loop consumes it unchanged.

  trudi-cef-ingest --case-id DECOY-DEMO \\
      --alerts-dir ~/cases/DECOY-DEMO/monitoring/alerts \\
      --listen 0.0.0.0:5514 [--api-config ~/.config/trudi/velociraptor/api.config.yaml]

  trudi-cef-ingest --case-id DECOY-DEMO --alerts-dir ... --replay sample.cef   # one-shot

Two CEF records share an incidentID: the fused incident (srcIP/dstIP/
credential/MITRE) and the per-protocol "service interaction" (client
fingerprint in cs78 event_data). They are merged into ONE alert when they
arrive within `--merge-window` seconds of each other; a late fingerprint for
an alert already on disk but not yet consumed is folded into that file.

The alert's `client_id` is the Velociraptor client of the SOURCE host (the
one that touched the decoy): resolved from the case config's
authenticated sender binding, else `cef_ingest.source_map`, `last_ip`, and hostname — see
monitoring/cef.py:resolve_client. An unresolved client is written as
`client_id: null` with the reason in `client_resolution`; the agent then
resolves it (velo.list_clients) and records the self-correction.

Lean by default (only `monitoring/cef`); on the live serving path it additionally
**auto-contains** a confirmed-positive alert the instant it writes it — lazily
importing `tools.respond:auto_contain`, which fires the reversible/low-risk
containment server-side (no agent, no tool-schema load, no reasoning in front of
it) for authenticated, source-bound incidents when `auto_protect` is enabled.
Raw UDP remains collection-only. Sender envelopes use monitoring/cef_auth.py;
relays forward them unchanged. Disable with `--no-auto-contain`;
`--replay` never auto-contains. `_seq.txt` is incremented under the same fcntl
lock the Velociraptor sidecar uses, so both can write concurrently.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from monitoring import cef, cef_auth  # noqa: E402

API_CONFIG_DEFAULT = os.path.expanduser("~/.config/trudi/velociraptor/api.config.yaml")
VELO_BIN_DEFAULT = "velociraptor"

_stop = threading.Event()


def _log(msg: str) -> None:
    print(f"[cef-ingest] {msg}", flush=True)


# ── Alert queue (shared conventions with trudi-velo-watcher.py) ─────────────

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


# ── Velociraptor client resolution ──────────────────────────────────────────

class ClientResolver:
    """Caches the server's client list for `ttl` seconds; resolves via
    monitoring/cef.py:resolve_client. Never raises — an unreachable server
    just yields an unresolved alert."""

    def __init__(self, api_config: Optional[str], velo_bin: str,
                 source_map: Optional[dict], ttl: float = 30.0, enabled: bool = True):
        self.api_config, self.velo_bin = api_config, velo_bin
        self.source_map = source_map or {}
        self.ttl, self.enabled = ttl, enabled
        self._clients: list[dict] = []
        self._fetched = 0.0

    def _fetch(self) -> list[dict]:
        if not self.enabled or not self.api_config or not os.path.exists(self.api_config):
            return []
        if time.time() - self._fetched < self.ttl:
            return self._clients
        vql = ("SELECT client_id, os_info.hostname AS hostname, last_ip, "
               "last_seen_at FROM clients()")
        try:
            out = subprocess.run(
                [self.velo_bin, "--api_config", self.api_config, "query", "--format=jsonl", vql],
                capture_output=True, text=True, timeout=20, check=False,
            )
            rows = []
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            self._clients, self._fetched = rows, time.time()
        except (OSError, subprocess.SubprocessError) as e:
            _log(f"client list unavailable: {e}")
        return self._clients

    def resolve(self, evidence: dict) -> dict:
        res = cef.resolve_client(
            self._fetch(),
            source_ip=evidence.get("source_ip"),
            client_host_name=evidence.get("client_host_name"),
            source_map=self.source_map,
        )
        return res


# ── Incident merge buffer ───────────────────────────────────────────────────

class IncidentBuffer:
    """Pairs the fused incident record with its service-interaction record by
    incidentID, flushing each as one alert after `merge_window` seconds (or
    at once when both halves are present)."""

    def __init__(self, alerts_dir: Path, case_id: str, resolver: ClientResolver,
                 merge_window: float = 2.0, auto_contain: bool = False,
                 replay: bool = False):
        self.alerts_dir, self.case_id, self.resolver = alerts_dir, case_id, resolver
        self.merge_window = merge_window
        self.auto_contain = auto_contain
        self.replay = replay
        self.case_dir = alerts_dir.parent.parent
        self._pending: dict[str, dict] = {}       # incident_id → {evidence, fingerprint, raw, t0}
        self._written: dict[str, Path] = {}       # incident_id → alert path (recent)
        self._lock = threading.Lock()

    def ingest_line(self, line: str) -> None:
        envelope, config = None, {}
        try:
            if line.lstrip().startswith("{"):
                envelope = json.loads(line)
                if not isinstance(envelope, dict):
                    raise ValueError("invalid CEF envelope")
                config = cef_auth.verify(envelope, self.case_dir)
                cef_auth.claim_nonce(envelope, self.case_dir)
                line = envelope["cef"]
            parsed = cef.parse_cef(line)
            if not cef_auth.is_shadowplex(parsed):
                raise ValueError("not a supported ShadowPlex incident")
        except ValueError as e:
            _log(f"skipping invalid CEF input ({e})")
            return
        fields = parsed.get("fields", {})
        incident_id = fields["incidentID"]
        # Never let an unsigned fingerprint alter a signed incident (or one
        # authenticated sender alter another sender's incident with the same id).
        key = f"{envelope['sender'] if envelope else 'unsigned'}:{incident_id}"
        with self._lock:
            slot = self._pending.setdefault(key, {"incident_id": incident_id,
                "evidence": None, "fingerprint": None, "raw": [], "t0": time.time(),
                "envelope": None, "bound_client": None})
            slot["raw"].append(parsed["raw"])
            if cef.is_service_interaction(parsed):
                slot["fingerprint"] = cef.service_interaction_to_fingerprint(parsed)
                # Late fingerprint for an alert already written → fold it in.
                if slot["evidence"] is None and key in self._written:
                    self._fold_late_fingerprint(key, slot)
                    return
            else:
                slot["evidence"] = cef.shadowplex_to_evidence(parsed)
                slot["envelope"] = envelope
                slot["bound_client"] = cef_auth.bound_client(parsed, config) if envelope else None
            if slot["evidence"] is not None and slot["fingerprint"] is not None:
                self._flush(key)

    def _fold_late_fingerprint(self, incident_id: str, slot: dict) -> None:
        path = self._written.get(incident_id)
        self._pending.pop(incident_id, None)
        if not path or not path.exists():
            return
        try:
            alert = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return
        if alert.get("consumed"):
            _log(f"fingerprint for {incident_id} arrived after the alert was consumed — not merged")
            return
        alert["evidence"] = cef.merge_fingerprint(alert["evidence"], slot["fingerprint"])
        alert["hostname"] = alert["evidence"].get("client_host_name") or alert.get("hostname")
        alert["summary"] = cef.summarize(alert["evidence"])
        alert["raw_cef"] = list(alert.get("raw_cef", [])) + slot["raw"]
        if not alert.get("client_id"):
            res = self.resolver.resolve(alert["evidence"])
            alert["client_id"], alert["client_resolution"] = res.get("client_id"), res
            if res.get("client_id"):
                alert["evidence"]["ClientId"] = res["client_id"]
        path.write_text(json.dumps(alert, indent=2))
        _log(f"merged late fingerprint into {path.name}")

    def flush_expired(self) -> None:
        now = time.time()
        with self._lock:
            for incident_id in [k for k, v in self._pending.items() if now - v["t0"] >= self.merge_window]:
                self._flush(incident_id)

    def flush_all(self) -> None:
        with self._lock:
            for incident_id in list(self._pending):
                self._flush(incident_id)

    def _flush(self, incident_id: str) -> Optional[Path]:
        slot = self._pending.pop(incident_id, None)
        if slot is None:
            return None
        evidence = slot["evidence"]
        if evidence is None:
            # Only the fingerprint half ever arrived: still an alert, with what we have.
            evidence = cef.merge_fingerprint({"incident_id": slot["incident_id"],
                                              "category": "Service Interaction"}, slot["fingerprint"])
        elif slot["fingerprint"] is not None:
            evidence = cef.merge_fingerprint(evidence, slot["fingerprint"])
        res = self.resolver.resolve(evidence)
        if slot.get("bound_client"):
            res = {"client_id": slot["bound_client"], "method": "authenticated_sender_binding", "matched": True}
        seq = _next_seq(self.alerts_dir)
        alert = cef.build_alert(evidence, case_id=self.case_id, seq=seq,
                                client_id=res.get("client_id"), raw_lines=slot["raw"],
                                client_resolution=res)
        alert["evidence"]["alert_id"] = alert["alert_id"]
        alert["ingress_envelope"] = slot.get("envelope")
        alert["replay"] = self.replay
        alert["response_eligible"] = bool(slot.get("bound_client")) and not self.replay
        alert["ingest_trust"] = {"authenticated": bool(slot.get("envelope")),
                                  "sender": (slot.get("envelope") or {}).get("sender")}
        path = self.alerts_dir / f"{seq:08d}_{cef.DETECTOR.split('.')[-1]}.json"
        path.write_text(json.dumps(alert, indent=2))
        self._written[incident_id] = path
        if len(self._written) > 256:
            for k in list(self._written)[:-128]:
                self._written.pop(k, None)
        _log(f"wrote alert {path.name}: {alert['summary'][:140]}")
        if self.auto_contain and alert["response_eligible"]:
            self._auto_contain(alert)
        return path

    def _auto_contain(self, alert: dict) -> None:
        """Fire the reversible/low-risk containment for this alert immediately,
        server-side — so the block lands in ~seconds, with no agent wake, no
        tool-schema load, and no reasoning call ahead of it. Strictly bounded and
        self-guarding (see tools/respond.py:auto_contain): only a confirmed-positive
        detector class, only when the case opted into `auto_protect`, only the AUTO
        (reversible+low) tier. Best-effort — a failure here never stops the ingest;
        the alert is already on disk for the agent regardless."""
        detector = alert.get("detector") or cef.DETECTOR
        try:
            from tools import respond  # lazy: pulls fastmcp/core only when a real alert fires
            r = respond.auto_contain(self.case_id, detector,
                                     alert.get("evidence") or {}, alert.get("client_id"),
                                     alert_id=alert["alert_id"])
        except Exception as e:  # noqa: BLE001
            _log(f"auto-contain unavailable ({e}) — alert left for the agent")
            return
        if r.get("skipped"):
            _log(f"auto-contain skipped: {r['skipped']}")
            return
        for c in r.get("contained", []):
            status = "OK" if c.get("success") else f"FAILED ({c.get('error')})"
            _log(f"AUTO-CONTAINED {c['action_id']} ({c['template']}) → {status}: {c.get('command')}"
                 + (f" | undo: {c.get('rollback')}" if c.get("rollback") else ""))
        for d in r.get("deferred", []):
            _log(f"auto-contain deferred {d['action_id']} ({d['template']}) → agent handles: {d['reason']}")


# ── Transports ──────────────────────────────────────────────────────────────

def _serve_udp(buf: IncidentBuffer, host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    _log(f"listening for CEF over UDP syslog on {host}:{port}")
    while not _stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            buf.flush_expired()
            continue
        except OSError as e:
            _log(f"socket error: {e}")
            break
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if line.strip():
                buf.ingest_line(line)
        buf.flush_expired()
    sock.close()


def _replay(buf: IncidentBuffer, path: Path) -> int:
    n = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            buf.ingest_line(line)
            n += 1
    buf.flush_all()
    return n


def _load_source_map(case_dir: Optional[Path]) -> dict:
    if not case_dir:
        return {}
    cfg = case_dir / "monitoring" / "config.json"
    try:
        doc = json.loads(cfg.read_text()) if cfg.exists() else {}
    except (OSError, json.JSONDecodeError):
        return {}
    sm = (doc.get("cef_ingest") or {}).get("source_map") or {}
    return sm if isinstance(sm, dict) else {}


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--alerts-dir", required=True)
    ap.add_argument("--listen", default="0.0.0.0:5514", help="UDP host:port for CEF over syslog")
    ap.add_argument("--replay", help="read CEF lines from this file, write alerts, exit")
    ap.add_argument("--merge-window", type=float, default=2.0,
                    help="seconds to wait for the service-interaction record before writing the alert")
    ap.add_argument("--api-config", default=API_CONFIG_DEFAULT)
    ap.add_argument("--velo-bin", default=VELO_BIN_DEFAULT)
    ap.add_argument("--no-resolve", action="store_true",
                    help="do not query Velociraptor for the source host's client_id")
    ap.add_argument("--case-dir", help="case directory (for monitoring/config.json cef_ingest.source_map)")
    ap.add_argument("--no-auto-contain", action="store_true",
                    help="do NOT auto-execute the reversible/low-risk containment on a confirmed-positive "
                         "alert (default: auto-contain is ON for live serving when the case opted into "
                         "auto_protect; it never runs on --replay)")
    args = ap.parse_args(argv)

    alerts_dir = Path(os.path.expanduser(args.alerts_dir))
    alerts_dir.mkdir(parents=True, exist_ok=True)
    case_dir = Path(os.path.expanduser(args.case_dir)) if args.case_dir else alerts_dir.parent.parent
    resolver = ClientResolver(args.api_config, args.velo_bin, _load_source_map(case_dir),
                              enabled=not args.no_resolve)
    # Auto-contain only on the LIVE serving path — never during a one-shot replay
    # (tests / backfill must not mutate an endpoint). The helper self-guards on
    # auto_protect + the confirmed-positive detector class regardless.
    auto_contain = not args.replay and not args.no_auto_contain
    buf = IncidentBuffer(alerts_dir, args.case_id, resolver, merge_window=args.merge_window,
                         auto_contain=auto_contain, replay=bool(args.replay))

    if args.replay:
        n = _replay(buf, Path(os.path.expanduser(args.replay)))
        _log(f"replayed {n} CEF line(s) from {args.replay}")
        return 0

    def _on_signal(signum, _frame):
        _log(f"signal {signum} — flushing and stopping")
        _stop.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    host, _, port = args.listen.rpartition(":")
    _serve_udp(buf, host or "0.0.0.0", int(port))
    buf.flush_all()
    _log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
