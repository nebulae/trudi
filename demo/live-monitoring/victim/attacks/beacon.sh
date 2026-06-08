#!/bin/bash
# /attacks/beacon.sh — long-lived C2 beacon for the live-monitoring demo.
#
# Fires Custom.TRUDI.NewNetwork. The shipped `network` alias (T1071.001#3) is a
# sub-second curl to a public host: it needs internet egress AND almost never
# survives long enough to be caught in ESTABLISHED state by the detector's 10s
# NetstatEnriched poll. This instead opens a connection to the fake C2 sink
# (203.0.113.10:8080 on c2-net — non-RFC1918, so it passes the detector's filter)
# and HOLDS it open, guaranteeing the poll sees an ESTABLISHED outbound flow.
#
# Reversible: the cleanup path (--cleanup) kills any beacon left running.
set -uo pipefail

C2_IP="${C2_IP:-203.0.113.10}"
C2_PORT="${C2_PORT:-8080}"
HOLD="${HOLD:-86400}"
PIDFILE="/tmp/.trudi_beacon.pid"

if [[ "${1:-}" == "--cleanup" ]]; then
    if [[ -f "${PIDFILE}" ]]; then
        pid="$(cat "${PIDFILE}" 2>/dev/null || true)"
        [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null
        rm -f "${PIDFILE}"
        echo "[beacon] cleaned up pid ${pid:-<none>}"
    else
        echo "[beacon] nothing to clean up"
    fi
    exit 0
fi

# Open the C2 socket and HOLD it open with a single long-lived `sleep` that
# inherits the socket fd. No heartbeat loop — a loop would fork a process per
# tick (sleep/date), each tripping Custom.TRUDI.NewProcess with noise. One held
# process keeps the flow ESTABLISHED, which is all Custom.TRUDI.NewNetwork needs.
# The c2-sink holds its end symmetrically (`nc -lk -p 8080 -e sleep`), so neither
# side sends FIN/RST and the connection stays ESTABLISHED across the 10s poll.
(
    exec 3<>"/dev/tcp/${C2_IP}/${C2_PORT}" 2>/dev/null || {
        echo "[beacon] could not connect to ${C2_IP}:${C2_PORT}" >&2
        exit 1
    }
    echo "${BASHPID}" > "${PIDFILE}"
    exec sleep "${HOLD}"            # replaces this subshell; keeps fd 3 (the socket) open
) </dev/null >/dev/null 2>&1 &
sleep 0.3
if [[ -f "${PIDFILE}" ]]; then
    echo "[beacon] pid $(cat "${PIDFILE}") → ${C2_IP}:${C2_PORT} (held ESTABLISHED; cleanup: /attacks/run beacon --cleanup)"
else
    echo "[beacon] failed to establish connection to ${C2_IP}:${C2_PORT}" >&2
    exit 1
fi
