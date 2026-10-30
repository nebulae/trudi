#!/usr/bin/env python3
"""Deception decoy EMULATOR for the TRUDI live-monitoring demo.

Stands in for an Acalvio ShadowPlex RDP decoy on the lab LAN. It is NOT
Acalvio software: it listens on the RDP port, recognises the X.224
Connection Request a real RDP client sends first (and the `mstshash`
cookie that leaks the username before any authentication), and emits the
two CEF records the ShadowPlex Incident Mapping Guide (release 2026.8.2.0)
documents — the fused incident and the per-protocol service interaction —
as syslog over UDP to the TRUDI ingest sidecar (bin/trudi-cef-ingest.py).

Nothing is ever legitimately supposed to connect here, so every accepted
connection is an incident:

  bare TCP connect, no RDP request  → cat="Discovery"            (T1046)
  RDP X.224 CR (+ mstshash cookie)  → cat="Endpoint Compromise"  (T1021.001 + T1046)

The accepted socket is HELD open (default 600 s) so the touching host's
netstat shows the flow ESTABLISHED long enough for the investigation pivot
to find the owning pid — the demo attacker holds its end the same way.

Configuration (env):
  DECOY_NAME         decoy endpoint name reported as dstEndpointName  (DESKTOP-GN-806)
  DECOY_PORT         listen port                                      (3389)
  DECOY_SITE         syslog hostname token                            (lab)
  SYSLOG_HOST/PORT   where to send CEF                                (host.docker.internal:5514)
  CALLBACK_BASE      console URL prefix for callbackURL
  HOLD_SECONDS       how long to hold an accepted connection          (600)
  CEF_VERSION        device version string                            (2026.8.2.0)
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cef_format import format_cef  # noqa: E402  (vendored copy of monitoring/cef.py:format_cef)

DECOY_NAME = os.environ.get("DECOY_NAME", "DESKTOP-GN-806")
DECOY_PORT = int(os.environ.get("DECOY_PORT", "3389"))
DECOY_SITE = os.environ.get("DECOY_SITE", "lab")
SYSLOG_HOST = os.environ.get("SYSLOG_HOST", "host.docker.internal")
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "5514"))
CALLBACK_BASE = os.environ.get("CALLBACK_BASE", "https://233.252.0.91/#/incidents")
HOLD_SECONDS = int(os.environ.get("HOLD_SECONDS", "600"))
CEF_VERSION = os.environ.get("CEF_VERSION", "2026.8.2.0")
VENDOR, PRODUCT = "Acalvio", "ShadowPlex"   # format emulation only — see module docstring

# X.224 Connection Confirm inside a TPKT frame: what a real RDP server answers.
_X224_CC = bytes.fromhex("0300000b06d00000123400")


def _log(msg: str) -> None:
    print(f"[decoy] {msg}", flush=True)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sp_time(dt: datetime) -> str:
    """ShadowPlex `start=`/`end=` style: 'July 10 2026 11:36:57.130 UTC'."""
    return dt.strftime("%B %d %Y %H:%M:%S.") + f"{dt.microsecond // 1000:03d} UTC"


def _reverse_name(ip: str) -> str:
    """Docker's embedded DNS reverse-resolves container addresses on user
    networks — the decoy learns the touching host's name the way a real
    decoy fingerprints its client. Empty when unknown."""
    try:
        return socket.gethostbyaddr(ip)[0].split(".", 1)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _parse_rdp_cr(data: bytes) -> tuple[bool, str]:
    """(is_rdp_touch, username). A real RDP client opens with a TPKT v3 / X.224
    Connection Request whose `mstshash=<user>` cookie leaks the username before
    any auth. For the demo the detection is deliberately lenient: either a
    proper X.224 CR (TPKT byte 0x03 + X.224 code 0xE0) OR any payload carrying
    an `mstshash=<user>` token counts as an RDP credential touch, so the
    beachhead can touch the decoy with a one-line send and no packet crafting."""
    marker = b"mstshash="
    i = data.find(marker)
    if i >= 0:
        j = i + len(marker)
        end = len(data)
        for term in (b"\r", b"\n", b" ", b"\x00"):
            t = data.find(term, j)
            if t >= 0:
                end = min(end, t)
        return True, data[j:end].decode("utf-8", errors="replace").strip()
    is_x224 = len(data) >= 6 and data[0] == 0x03 and data[5] == 0xE0
    return is_x224, ""


def _send_syslog(line: str) -> None:
    pri = 114  # local6.info, as in the published sample
    ts = _now().strftime("%Y-%m-%dT%H:%M:%S.") + f"{_now().microsecond // 1000:03d}Z"
    msg = f"<{pri}>{ts} {DECOY_SITE} {line}"
    key_file = os.environ.get("SYSLOG_HMAC_KEY_FILE")
    if key_file:
        from pathlib import Path
        from monitoring.cef_auth import sign
        msg = sign(msg, os.environ.get("SYSLOG_SENDER", "decoy-emulator"),
                   Path(key_file).read_bytes().strip())
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(msg.encode("utf-8"), (SYSLOG_HOST, SYSLOG_PORT))
    except OSError as e:
        _log(f"syslog send to {SYSLOG_HOST}:{SYSLOG_PORT} failed: {e}")
    print(line, flush=True)


def _emit_incident(*, src_ip: str, src_port: int, dst_ip: str, user: str,
                   is_rdp: bool, client_name: str, started: datetime) -> str:
    incident_id = str(uuid.uuid4())
    ended = _now()
    if is_rdp:
        cat, name = "Endpoint Compromise", "ENDPOINT_COMPROMISE"
        tactics = "Lateral Movement,Discovery"
        techniques = "Remote Services.Remote Desktop Protocol,Network Service Discovery"
        severity = 9
    else:
        cat, name = "Discovery", "DISCOVERY"
        tactics, techniques, severity = "Discovery", "Network Service Discovery", 6

    fused = format_cef(
        vendor=VENDOR, product=PRODUCT, version=CEF_VERSION,
        event_class_id="DETECT_AND_RESPOND", name=name, severity=severity,
        extension=[
            ("cat", cat),
            ("cs2Label", "incidentID"), ("cs2", incident_id),
            ("start", _sp_time(started)), ("end", _sp_time(ended)),
            ("cs3Label", "incidentStatus"), ("cs3", "Active"),
            ("cs8Label", "tacticName"), ("cs8", tactics),
            ("cs10Label", "techniqueName"), ("cs10", techniques),
            ("cs15Label", "srcIP"), ("cs15", src_ip),
            ("cs25Label", "dstIP"), ("cs25", dst_ip),
            ("cs26Label", "dstEndpointName"), ("cs26", DECOY_NAME),
            ("cs35Label", "dstPort"), ("cs35", DECOY_PORT),
            ("cs52Label", "userIdAttempted"), ("cs52", user or None),
            ("cs67Label", "callbackURL"), ("cs67", f"{CALLBACK_BASE}?incidentID={incident_id}"),
        ])
    event_data = {
        "user_name": user or None,
        "service_details": {
            "host_mac": None,                 # not observable through a Docker bridge
            "remote_port": src_port,
            "service_name": "MS-WBT-SERVER" if is_rdp else "TCP",
            "service_port": DECOY_PORT,
            "auth_attempted": bool(user),
            "client_host_ip": src_ip,
            "remote_address": src_ip,
            "client_host_name": client_name or None,
            "service_host_name": DECOY_NAME,
            "service_host_address": dst_ip,
        },
    }
    service = format_cef(
        vendor=VENDOR, product=PRODUCT, version=CEF_VERSION,
        event_class_id="DETECT_AND_RESPOND", name="SERVICE_INTERACTION", severity=severity,
        extension=[
            ("cs2Label", "incidentID"), ("cs2", incident_id),
            ("cs78Label", "event_data"), ("cs78", json.dumps(event_data, separators=(",", ":"))),
        ],
        quote_values=False,
    )
    _send_syslog(fused)
    _send_syslog(service)
    return incident_id


def _handle(conn: socket.socket, peer: tuple) -> None:
    src_ip, src_port = peer[0], peer[1]
    dst_ip = conn.getsockname()[0]
    started = _now()
    client_name = _reverse_name(src_ip)
    conn.settimeout(2.0)
    data = b""
    try:
        data = conn.recv(1024)
    except (socket.timeout, OSError):
        pass
    is_rdp, user = _parse_rdp_cr(data)
    if is_rdp:
        try:
            conn.sendall(_X224_CC)
        except OSError:
            pass
    _log(f"touch from {src_ip}:{src_port} ({client_name or '?'}) rdp={is_rdp} user={user!r}")
    incident = _emit_incident(src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, user=user,
                              is_rdp=is_rdp, client_name=client_name, started=started)
    _log(f"incident {incident} emitted → {SYSLOG_HOST}:{SYSLOG_PORT}")
    # Hold the flow ESTABLISHED until the peer closes or HOLD_SECONDS elapse.
    conn.settimeout(1.0)
    deadline = time.time() + HOLD_SECONDS
    try:
        while time.time() < deadline:
            try:
                if conn.recv(4096) == b"":
                    break
            except socket.timeout:
                continue
            except OSError:
                break
    finally:
        try:
            conn.close()
        except OSError:
            pass
        _log(f"connection from {src_ip}:{src_port} closed")


def main() -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", DECOY_PORT))
    srv.listen(16)
    _log(f"{DECOY_NAME} listening on :{DECOY_PORT}; CEF → {SYSLOG_HOST}:{SYSLOG_PORT} "
         f"(format emulation of {VENDOR} {PRODUCT} {CEF_VERSION}; not vendor software)")
    while True:
        conn, peer = srv.accept()
        threading.Thread(target=_handle, args=(conn, peer), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
