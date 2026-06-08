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
