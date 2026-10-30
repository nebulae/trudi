#!/usr/bin/env python3
"""UDP CEF relay for the WINDECOY-DEMO.

The deception sensor runs INSIDE the Windows decoy VM (a KVM guest behind the
dockur container's NAT). That guest can reach LAN addresses (it enrolls to the
Velociraptor server at 10.73.0.2), but it cannot use Docker's
`host.docker.internal` / host-gateway shortcut the way a container on the LAN
can. So the sensor sends its ShadowPlex CEF to THIS relay — an ordinary
container on `lan-net` — which forwards each datagram to the TRUDI ingest
sidecar (`bin/trudi-cef-ingest.py`) on the SIFT host via the proven
host-gateway path.

    guest sensor ──udp──▶ relay (10.73.0.55:5514, lan-net)
                                  └─udp─▶ host.docker.internal:5514 (SIFT host ingest)

Pure stdlib, no deps. Datagrams are forwarded verbatim (one syslog/CEF line
per packet), so the ingest parses exactly what the sensor emitted.

Env:
  RELAY_LISTEN    host:port to receive on            (0.0.0.0:5514)
  RELAY_FORWARD   host:port to forward to            (host.docker.internal:5514)
"""
from __future__ import annotations

import os
import socket
import sys


def _addr(spec: str, default_host: str, default_port: int) -> tuple[str, int]:
    host, _, port = spec.rpartition(":")
    return (host or default_host, int(port or default_port))


def main() -> int:
    listen = _addr(os.environ.get("RELAY_LISTEN", "0.0.0.0:5514"), "0.0.0.0", 5514)
    forward = _addr(os.environ.get("RELAY_FORWARD", "host.docker.internal:5514"),
                    "host.docker.internal", 5514)

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind(listen)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[relay] {listen[0]}:{listen[1]} → {forward[0]}:{forward[1]}", flush=True)

    while True:
        try:
            data, peer = rx.recvfrom(65535)
        except OSError as e:
            print(f"[relay] recv error: {e}", flush=True)
            continue
        try:
            tx.sendto(data, forward)
        except OSError as e:
            # Resolve lazily each send so the host gateway coming up late is fine.
            print(f"[relay] forward to {forward[0]}:{forward[1]} failed: {e}", flush=True)
            continue
        print(f"[relay] {len(data)}B from {peer[0]}:{peer[1]} → {forward[0]}:{forward[1]}",
              flush=True)


if __name__ == "__main__":
    sys.exit(main())
