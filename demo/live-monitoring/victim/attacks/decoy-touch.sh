#!/bin/bash
# /attacks/decoy-touch.sh — touch the deception decoy with a harvested credential.
#
# Runs ON victim-a (the beachhead). Models the moment an actor who has already
# landed tries a credential they found against the first RDP host they see on
# the LAN — which is the decoy. The decoy emulator (demo/live-monitoring/decoy)
# reads the username from the `mstshash` token and emits the ShadowPlex-format
# CEF incident that bin/trudi-cef-ingest.py turns into a Custom.TRUDI.DecoyTouch
# alert.
#
# The connection is HELD open so the investigation pivot on this host finds the
# flow ESTABLISHED in netstat with its owning pid — that pid is what the
# approval-gated kill then targets. The held process runs from its own image
# path (/tmp/.rdp-probe) so kill_by_image has a non-system target.
#
# Reversible: --cleanup closes the held connection and removes the dropped file.
set -uo pipefail

DECOY_HOST="${DECOY_HOST:-decoy}"
DECOY_PORT="${DECOY_PORT:-3389}"
HONEY_USER="${HONEY_USER:-linda}"
HOLD="${HOLD:-3600}"
PIDFILE="/tmp/.trudi_decoy_touch.pid"
TOOL="/tmp/.rdp-probe"

if [[ "${1:-}" == "--cleanup" ]]; then
    if [[ -f "${PIDFILE}" ]]; then
        pid="$(cat "${PIDFILE}" 2>/dev/null || true)"
        [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null
        rm -f "${PIDFILE}"
        echo "[decoy-touch] closed held connection (pid ${pid:-<none>})"
    else
        echo "[decoy-touch] nothing to clean up"
    fi
    rm -f "${TOOL}"
    exit 0
fi

# A tiny held-connection stub, dropped as its own image so the owning process
# has a distinct, non-system image path. It opens one TCP connection to the
# decoy, sends the mstshash credential token once, then idles with the socket
# open (no loop — one held process keeps the flow ESTABLISHED without spawning
# per-tick children that would add process noise).
cat > "${TOOL}" <<'STUB'
#!/bin/bash
# Opens one TCP connection to the decoy, sends the credential token, then holds
# the socket open IN THIS process (no exec, no child) so the ESTABLISHED flow
# keeps this image path as its owner — the investigation pivot (netstat ->
# pslist) finds /tmp/.rdp-probe, and a single-pid kill cleanly tears it down.
host="$1"; port="$2"; user="$3"; hold="$4"
exec 3<>"/dev/tcp/${host}/${port}" || { echo "[rdp-probe] connect failed" >&2; exit 1; }
printf 'Cookie: mstshash=%s\r\n' "${user}" >&3
# Block on the socket until the hold elapses or the peer closes. No newline ever
# arrives (the decoy replies with a binary X.224 Confirm), so read blocks for the
# full timeout without returning early; this process stays /tmp/.rdp-probe.
read -r -u 3 -t "${hold}" _ || true
STUB
chmod +x "${TOOL}"

setsid "${TOOL}" "${DECOY_HOST}" "${DECOY_PORT}" "${HONEY_USER}" "${HOLD}" \
    </dev/null >/dev/null 2>&1 &
sleep 0.3
# Record the held sleep's pid (the leaf process holding the socket).
probe_pid="$(pgrep -f "${TOOL} ${DECOY_HOST}" | tail -1)"
if [[ -n "${probe_pid}" ]]; then
    echo "${probe_pid}" > "${PIDFILE}"
    echo "[decoy-touch] touched ${DECOY_HOST}:${DECOY_PORT} as '${HONEY_USER}' (held pid ${probe_pid}; cleanup: /attacks/run decoy-touch --cleanup)"
else
    echo "[decoy-touch] touch sent to ${DECOY_HOST}:${DECOY_PORT} as '${HONEY_USER}' (pid not captured)"
fi
