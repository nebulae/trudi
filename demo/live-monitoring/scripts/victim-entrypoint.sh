#!/bin/bash
# victim entrypoint.
#
# 1. Wait for the velo-server to publish /config/client.config.yaml.
# 2. Generate (or reuse) a TRUDI SSH keypair under /shared so live.* can SSH in.
# 3. Start auditd (Linux.Events.ProcessExecutions backend), sshd, and the
#    Velociraptor client.

set -euo pipefail

CLIENT_CONFIG=/config/client.config.yaml
TRUDI_KEY=/shared/trudi_live
AUTHORIZED=/home/victim/.ssh/authorized_keys

echo "[victim] Waiting for ${CLIENT_CONFIG} from velo-server …"
for i in {1..120}; do
    if [[ -f "${CLIENT_CONFIG}" ]]; then
        break
    fi
    sleep 1
done
if [[ ! -f "${CLIENT_CONFIG}" ]]; then
    echo "[victim] Timed out waiting for client config — aborting." >&2
    exit 1
fi
echo "[victim] Client config present."

# SSH key for TRUDI live.* — generated on first boot, then pinned.
if [[ ! -f "${TRUDI_KEY}" ]]; then
    mkdir -p /shared
    ssh-keygen -t ed25519 -N "" -C "trudi-live-monitoring-demo" -f "${TRUDI_KEY}"
    chmod 600 "${TRUDI_KEY}"
    chmod 644 "${TRUDI_KEY}.pub"
fi
mkdir -p /home/victim/.ssh
cp "${TRUDI_KEY}.pub" "${AUTHORIZED}"
chown -R victim:victim /home/victim/.ssh
chmod 700 /home/victim/.ssh
chmod 600 "${AUTHORIZED}"

# ── Lateral-movement scenario role setup (compose profile "lateral") ──────────
# VICTIM_ROLE is unset for the standalone DEMO-LIVE `victim` (no-op below).
#   target    — mint the "stolen" devops credential, authorize it, and plant
#               the over-broad sudoers rule that the pivot abuses to reach root.
#   beachhead — wait for that credential and plant it as if already stolen.
LATERAL_KEY=/lateral/devops_id_ed25519

case "${VICTIM_ROLE:-standalone}" in
    target)
        echo "[victim] role=target — provisioning devops account + lateral credential"
        id devops >/dev/null 2>&1 || useradd -m -u 1001 -s /bin/bash devops
        mkdir -p /home/devops/.ssh
        if [[ ! -f "${LATERAL_KEY}" ]]; then
            mkdir -p /lateral
            ssh-keygen -t ed25519 -N "" -C "devops@victim-b" -f "${LATERAL_KEY}"
            chmod 644 "${LATERAL_KEY}.pub"
            chmod 640 "${LATERAL_KEY}"
        fi
        cp "${LATERAL_KEY}.pub" /home/devops/.ssh/authorized_keys
        chown -R devops:devops /home/devops/.ssh
        chmod 700 /home/devops/.ssh
        chmod 600 /home/devops/.ssh/authorized_keys
        # The modelled weakness: devops may run anything as root without a
        # password. This is the privilege-escalation path lateral.sh abuses.
        echo 'devops ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-devops
        chmod 440 /etc/sudoers.d/90-devops
        # Let the lateral volume be group-readable by the beachhead side.
        chmod 755 /lateral 2>/dev/null || true
        ;;
    beachhead)
        echo "[victim] role=beachhead — staging stolen devops key"
        mkdir -p /root/.ssh && chmod 700 /root/.ssh
        for i in $(seq 1 120); do
            if [[ -f "${LATERAL_KEY}" ]]; then
                cp "${LATERAL_KEY}" /root/.ssh/id_lateral
                chmod 600 /root/.ssh/id_lateral
                echo "[victim] staged stolen key → /root/.ssh/id_lateral"
                break
            fi
            sleep 1
        done
        [[ -f /root/.ssh/id_lateral ]] || echo "[victim] WARN: lateral key never appeared (is victim-b up?)" >&2
        ;;
    *)
        : # standalone victim — no lateral setup
        ;;
esac

# Start auditd. Velociraptor's Linux.Events.ProcessExecutions reads from
# the audit netlink socket; without auditd, NewProcess detections would
# miss execve events.
service auditd start || echo "[victim] auditd start failed (continuing without it)"

# Start cron — T1053.003 atomic writes to /etc/cron.d/.
service cron start || true

# Start sshd in the background.
/usr/sbin/sshd -D &
SSHD_PID=$!
echo "[victim] sshd started (pid=${SSHD_PID})"

# Print enrollment hint.
echo "[victim] To use live.* against this container from the SIFT host:"
echo "    cp /shared/trudi_live ~/.ssh/trudi_live   # via docker cp"
echo "    register host 'trudi-victim' in ~/cases/.common/live_hosts.json:"
echo "      {\"trudi-victim\": {\"user\": \"victim\", \"host\": \"localhost\", \"port\": 2222, \"identity\": \"~/.ssh/trudi_live\"}}"
echo

# Start Velociraptor client in the foreground — it owns the process so
# Docker's restart policy hooks onto its lifecycle.
echo "[victim] Starting Velociraptor client …"
exec velociraptor --config "${CLIENT_CONFIG}" client -v
