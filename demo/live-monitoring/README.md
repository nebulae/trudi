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

## Run the TRUDI monitoring loop against it

> **Experimental — not part of the Find Evil! submission.** The judged
> system is the read-only static investigator. This loop is the only mode
> where TRUDI writes to a system, and only *outside* the evidence boundary,
> through the separately-gated `respond.*` path. It runs today; it's
> documented here so a judge or user can exercise it end-to-end.

Once the stack is up (`./bring-up.sh`), point a TRUDI Claude Code session at
the demo case and drive it with the bundled **`/trudi-*` slash commands**
(installed to `~/.claude/commands/` by `install.sh`). The loop is: **baseline →
watcher → drain alerts → investigate → auto-protect**.

| Command | What it does |
|---------|--------------|
| `/trudi-start-watcher [case]` | Resolves the Velociraptor client, ensures a baseline, renders the `Custom.TRUDI.*` detectors onto the client event table, and spawns the alert-draining sidecar |
| `/trudi-watch-alerts [case] [interval]` | **Event-driven** loop — wakes within seconds of a new alert (via the harness `Monitor` tool), then investigates + auto-responds. Preferred over `/loop`. |
| `/trudi-check-alerts [case]` | One investigation per call over all alerts drained this tick — the `/loop`-driven alternative |
| `/trudi-stop-watcher [case]` | SIGTERMs the sidecar(s) and clears the detector artifacts from the event table |
| `/trudi-clear-case [case]` | Resets the case for a fresh run (previews, confirms, then wipes outputs + monitoring state) |

```bash
cd ~/cases/DEMO-LIVE        # bundled brief; or any live-monitoring case dir
claude
```

In the session, bring the case online and start watching:

```
/trudi-start-watcher DEMO-LIVE
/trudi-watch-alerts DEMO-LIVE
```

`/trudi-watch-alerts` is the **preferred** loop: `/loop` re-fires on the
scheduler, which clamps to a **60s floor**, so `/loop 15s /trudi-check-alerts`
really polls ~once a minute. `/trudi-watch-alerts` runs a persistent waiter
under the harness `Monitor` tool and wakes the agent within ~2s of an alert
landing. If you prefer the fixed-interval form instead:

```
/loop 15s /trudi-check-alerts
```

<details>
<summary>What <code>/trudi-start-watcher</code> does under the hood (raw MCP calls)</summary>

```
velo.list_clients()                       # → client_id, e.g. C.1a2b3c...
monitor.baseline_capture(client_id="C.1a2b...", case_id="DEMO-LIVE")
monitor.start_watcher(client_id="C.1a2b...", case_id="DEMO-LIVE",
                      detectors=["new_process","persistence","network","yara"])
```
</details>

In a second terminal, **stage an attack** so the detectors fire (see
[Staging attacks](#staging-attacks) above):

```bash
docker exec trudi-victim /attacks/run persistence    # T1053.003
docker exec trudi-victim /attacks/run lolbas          # T1036.005 — the self-correction demo
```

Within ~15s the loop drains the alert, runs the focused investigation chain
(`reason.hypothesize` → `dair_assess` → tool batch → `record_finding`), and
for CONFIRMED/LIKELY findings runs **auto-protect**:

- **Reversible + low-risk** containment **auto-executes**, with its rollback
  command printed to the console and the report.
- **Destructive** actions (irreversible, or risk ≥ medium) **pause the loop**
  and wait. The console prints the queued `ACT-N`; you authorize it by typing
  literally:

  ```
  approve ACT-3
  ```

  The agent cannot self-approve — the `operator_text_required` gate matches
  your typed text against a `UserPromptSubmit` trace entry before
  `respond.execute_action` will run.

Watch it unfold live in the dashboard (the per-investigation trace lands flat
under `analysis/` so the dashboard picks it up):

```bash
cd ~/trudi && ./dashboard.sh        # http://127.0.0.1:8765 → pick DEMO-LIVE
```

Each investigation exports `reports/DEMO-LIVE_<INV-NNN>.{json,md}` with an
*Autonomous Response Actions* section listing every action taken and its undo
command. Stop watching with `/trudi-stop-watcher DEMO-LIVE`, and reset the case
for another run with `/trudi-clear-case DEMO-LIVE`.

> **Demo vs. real threats.** `demo/live-monitoring` stages *planted* Atomic
> Red Team TTPs. With `monitoring/config.json` `demo_response.respond_to_synthetic=true`
> those confirmed planted TTPs are response-eligible — TRUDI "contains a
> planted demo TTP," not "remediates a real compromise." Keep that language
> precise in any writeup.

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
