# TRUDI live-monitoring demo

Self-contained Velociraptor + Linux victim environment for the Find Evil!
hackathon submission. Brings up a Velociraptor server, an enrolled Ubuntu
client running auditd + sshd + Atomic Red Team, and a CLI for staging
attacks that fire the `Custom.TRUDI.*` detector artifacts.

## Quick start

```bash
cd demo/live-monitoring
./bring-up.sh
```

`bring-up.sh` runs `docker compose up -d --build`, then performs every
post-boot wiring step idempotently: waits for and pulls the Velociraptor API
config, pulls the victim's freshly-generated SSH key to `~/.ssh/trudi_live`,
**merges** the `trudi-victim` entry into `~/cases/.common/live_hosts.json`
(preserving any other hosts), and smoke-tests the SSH path `live.*` uses.
Re-run it any time after `docker compose down -v` — it re-pulls the new key
and leaves `live.*` working.

```bash
./bring-up.sh --no-up      # stack already running; just (re)wire the host
./bring-up.sh --no-build   # up without --build
```

<details>
<summary>Manual equivalent (what bring-up.sh automates)</summary>

```bash
docker compose up -d --build
docker compose logs --tail=20 velo-server | grep -i enroll   # ~30s to enroll

# Velociraptor API config:
mkdir -p ~/.config/trudi/velociraptor
docker compose cp velo-server:/config/api.config.yaml \
    ~/.config/trudi/velociraptor/api.config.yaml
velociraptor --api_config ~/.config/trudi/velociraptor/api.config.yaml \
    query --format=json "SELECT client_id, os_info.hostname FROM clients()"

# SSH keypair for live.*:
docker compose cp victim:/shared/trudi_live ~/.ssh/trudi_live
docker compose cp victim:/shared/trudi_live.pub ~/.ssh/trudi_live.pub
chmod 600 ~/.ssh/trudi_live

# Register the host (this snippet CLOBBERS the file — bring-up.sh merges instead):
mkdir -p ~/cases/.common
cat > ~/cases/.common/live_hosts.json <<'EOF'
{
  "trudi-victim": {
    "user": "victim",
    "host": "localhost",
    "port": 2222,
    "identity": "~/.ssh/trudi_live"
  }
}
EOF
ssh -i ~/.ssh/trudi_live -p 2222 victim@localhost id   # smoke test
```
</details>

## Staging attacks

Each invocation runs one Atomic Red Team test and fires the matching
detector. Add `--cleanup` to reverse the action.

```bash
# By alias (most convenient):
docker exec trudi-victim /attacks/run new-process       # T1059.004
docker exec trudi-victim /attacks/run persistence       # T1053.003
docker exec trudi-victim /attacks/run network           # T1071.001
docker exec trudi-victim /attacks/run yara              # T1055.001
docker exec trudi-victim /attacks/run lolbas            # T1036.005 (self-correction demo)
docker exec trudi-victim /attacks/run all               # all of the above with 5s spacing

# By T-number:
docker exec trudi-victim /attacks/run T1059.004

# Cleanup:
docker exec trudi-victim /attacks/run persistence --cleanup
```

## Ports

| Port  | Service                                  |
|-------|------------------------------------------|
| 8000  | Velociraptor client frontend (TLS)       |
| 8001  | Velociraptor API (TRUDI talks here)      |
| 8889  | Velociraptor GUI (browser, TLS)          |
| 2222  | OpenSSH on the victim (for `live.*`)     |

## Versions

- Velociraptor: pinned in `Dockerfile.velo-server` / `Dockerfile.victim`
  via the `VELOCIRAPTOR_VERSION` build arg.
- Atomic Red Team: cloned from
  `redcanaryco/atomic-red-team@${ATOMIC_RED_TEAM_REF}`. Pin to a specific
  commit by passing `--build-arg ATOMIC_RED_TEAM_REF=<sha>`.

## Teardown

```bash
docker compose down -v        # also wipes generated configs + Velociraptor datastore
```

## Troubleshooting

- **Client doesn't enroll** — check `docker compose logs velo-server` for
  TLS errors. The client config uses `velo-server` as the hostname; if
  you've renamed the service, regenerate configs.
- **auditd events missing** — auditd needs the audit netlink socket,
  which is why the victim runs `privileged: true`. Don't drop that for
  the demo.
- **`SELECT * FROM clients()` returns empty** — wait 30s, then check the
  victim's logs: `docker compose logs --tail=50 victim`.
- **Stale state between runs** — `docker compose down -v && docker compose up -d --build`.
