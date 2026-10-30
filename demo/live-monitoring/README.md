# TRUDI live-monitoring demo

Self-contained Velociraptor + Linux victim environment for the Find Evil!
hackathon submission. Brings up a Velociraptor server, an enrolled Ubuntu
client running auditd + sshd + Atomic Red Team, and a CLI for staging
attacks that fire the `Custom.TRUDI.*` detector artifacts.

## Quick start

For CEF demos, `bring-up.sh` prepares signing keys in the private `secrets/`
directory. Configure each case's `cef_ingest.senders` with its sender key,
source client, and decoy endpoint before expecting automatic containment;
unsigned UDP remains collection-only. See
[authentication and migration](../../docs/live-monitoring.md#external-detection-ingest--acalvio-shadowplex-cef--autonomous-response).

Existing deployments should remove legacy global TRUDI monitoring entries and
restart watchers using client-specific labels. Old path-only baselines keep the
cron exemption disabled until a trusted content baseline is captured.

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

## Two-host lateral-movement scenario (profile `lateral`)

The default stack is one victim. For the multi-host demo — one host moving
laterally to another, escalating privilege, and persisting — bring up the
`lateral` profile, which adds two more clients sharing the same server:

```bash
./bring-up.sh                                   # or: docker compose --profile lateral up -d --build
docker compose --profile lateral up -d          # if the base stack is already up
```

- **victim-a** (`trudi-victim-a`, SSH :2223) — the beachhead. Holds a "stolen"
  `devops` key and initiates the pivot.
- **victim-b** (`trudi-victim-b`, SSH :2224) — the pivot target. A `devops`
  account + an over-broad `NOPASSWD` sudoers rule are the modelled weakness.

The LAN addresses are pinned: server `10.73.0.2`, victim-a `10.73.0.3`, and
victim-b `10.73.0.4`. This keeps CEF source bindings stable and prevents a
victim from taking the server's address when containers restart in a different
order.

`bring-up.sh` enrolls both as their own Velociraptor clients and registers
`trudi-victim-a` / `trudi-victim-b` in `live_hosts.json`. Drive it with the
bundled **`LATERAL-DEMO`** case (`~/cases/LATERAL-DEMO/`).

Stage the whole chain from the beachhead:

```bash
docker exec trudi-victim-a /attacks/run lateral            # A→B: move, escalate, persist
docker exec trudi-victim-a /attacks/run lateral --cleanup  # reverse it
```

On victim-b this produces, one detector per stage: a new inbound SSH session
(`Custom.TRUDI.NewLogon`, T1021.004), a dropped tool (`NewProcess`, T1059.004),
a root-owned binary via sudo (`PrivilegeEscalation`, T1548.003), and a root
cron entry (`NewPersistence`, T1053.003). The privilege-escalation alert fires
here because the chain crosses a uid boundary: devops shell → `sudo` → root
binary. `PrivilegeEscalation` now requires that boundary (a root process with a
non-root ancestor within six hops), so a root-all-the-way-up chain — the daily
cron run, or anything launched directly as root — does **not** raise it. If a
recording needs to show a `PrivilegeEscalation` alert, run the escalating step
as a non-root user or over SSH (the lateral chain already does); an attack
staged with `docker exec` on victim-a starts as root (parent pid 1) and raises
`NewProcess`/`DecoyTouch` only, not `PrivilegeEscalation`. Auto-protect blocks the source IP and
quarantines/removes the reversible items automatically and pauses for
`approve ACT-N` on the destructive kills; after eradication,
`monitor.verify_clean(client_id=<victim-b>, case_id="LATERAL-DEMO")` confirms the
host is back to baseline. Full runbook: `~/cases/LATERAL-DEMO/CLAUDE.md`.

## Deception-decoy scenario (profile `decoy`)

Drives TRUDI from an **external detection** — an Acalvio ShadowPlex RDP decoy —
instead of TRUDI's own host detectors. The beachhead touches the decoy with a
harvested honey credential; the decoy emits ShadowPlex-format CEF over syslog;
`bin/trudi-cef-ingest.py` turns it into a `Custom.TRUDI.DecoyTouch` alert; the
normal loop investigates and contains the touching host.

> The decoy (`demo/live-monitoring/decoy/`) is a **format emulator** built from
> Acalvio's published CEF spec (release 2026.8.2.0). It is **not** Acalvio
> software and no ShadowPlex instance is required.

Needs the `lateral` profile's `victim-a` to do the touching:

```bash
COMPOSE_PROFILES=lateral,decoy ./bring-up.sh
# or, stack already up:
docker compose --profile lateral --profile decoy up -d
```

- **decoy** (`trudi-decoy`, `10.73.0.50:3389` on `lan-net`) — the emulated RDP
  decoy. Reads the username from the RDP `mstshash` cookie and sends CEF to the
  SIFT host's ingest at `host.docker.internal:5514`.

Drive it with the bundled **`DECOY-DEMO`** case (`~/cases/DECOY-DEMO/`):

```
/trudi-start-watcher DECOY-DEMO        # baselines victim-a + starts the CEF ingest
/trudi-watch-alerts  DECOY-DEMO
```
```bash
docker exec trudi-victim-a /attacks/run decoy-touch            # touch the decoy as 'linda'
docker exec trudi-victim-a /attacks/run decoy-touch --cleanup  # close the held flow
```

Within ~2s TRUDI opens an investigation, auto-blocks the egress to the decoy,
pivots victim-a over Velociraptor to find the touching process, records the
findings (lateral-movement attempt T1021.001 + the honey credential), asks to
approve the kill, and `monitor.verify_clean` confirms clean. The on-camera
self-correction: the alert foregrounds the **decoy**, but the decoy has no
Velociraptor client — TRUDI re-targets the **source host** and records the
correction. Full runbook: `~/cases/DECOY-DEMO/CLAUDE.md`; reference:
`docs/live-monitoring.md`.

**Replay without the containers** (CI / quick check) — feed the two sample CEF
records straight to the ingest:

```bash
python3 bin/trudi-cef-ingest.py --case-id DECOY-DEMO \
    --alerts-dir ~/cases/DECOY-DEMO/monitoring/alerts --no-resolve \
    --replay demo/live-monitoring/decoy/sample-incident.cef
```

## Real Windows RDP victim (profile `winrdp`)

A **true Windows Server 2022** host — a real KVM guest inside a container via
[`dockur/windows`](https://hub.docker.com/r/dockurr/windows), **not** a Windows
container (Linux can't run those). Unlike the decoy, this host IS the
investigation target: `victim-a` opens a genuine RDP session to it, and TRUDI
investigates the Windows side over its Velociraptor **Windows** client with the
`Custom.TRUDI.Win.*` detectors — the real 4624 type-10 (RemoteInteractive)
logon telemetry the Linux containers can't produce.

> **Logon-only.** The attack establishes a real held full-desktop RDP logon; it
> does **not** run a follow-on command on the box. (FreeRDP 2.6.1 can't execute
> a command in the session against Server 2022 — RemoteApp/RAIL crashes and the
> RDP alternate shell is ignored without the RDS role — so the earlier
> process/Run-key beats are not produced. The type-10 logon is the signal.)

Needs the `lateral` profile's `victim-a` to do the logon:

```bash
sudo ./bring-up.sh --profiles lateral,winrdp
# or, stack already up:
docker compose --profile lateral --profile winrdp up -d
```

- **victim-win** (`trudi-victim-win`, `10.73.0.60:3389` on `lan-net`) — the
  Windows VM. Console at `http://localhost:8006`.
- **win-oem-init** — a one-shot init that (after velo-server is healthy) builds
  the OEM payload: the Velociraptor Windows client config repointed at
  `10.73.0.2:8000` (velo-server is joined to `lan-net` at that fixed address so
  the NAT'd guest can reach it), `velociraptor.exe`, and an `install.bat` that
  on first logon installs the client service, enables RDP, and creates the
  `rdpadmin` account.

**First boot takes ~10-20 min** (a ~6 GB Server 2022 eval media pull + an
unattended install); watch `http://localhost:8006`. Server RAM is the limit —
give the VM 4 GB and don't also run the heavy set at the same time.

Drive it with the bundled **`WINRDP-DEMO`** case (`~/cases/WINRDP-DEMO/`):

```
/trudi-start-watcher WINRDP-DEMO       # detects Windows, baselines it, pushes Win.* detectors
/trudi-watch-alerts  WINRDP-DEMO
```
```bash
docker exec trudi-victim-a /attacks/run win-rdp            # real type-10 RDP logon
docker exec trudi-victim-a /attacks/run win-rdp --cleanup  # close the held session
```

The RDP session trips `Custom.TRUDI.Win.NewLogon` (4624 type 10 from victim-a).
TRUDI investigates over the Windows client; response/containment on the
Windows host is out of scope in this phase (the `respond.*` recipes are Linux
SSH-based), so `WINRDP-DEMO` is investigate-only. Runbook:
`~/cases/WINRDP-DEMO/CLAUDE.md`.

### First-boot validation checklist

The Windows-side runtime can only be confirmed once the VM is up (there is no
Windows client to exercise the VQL against until then). On first bring-up:

1. **Install finished** — the `http://localhost:8006` console shows the desktop,
   not the installer.
2. **Enrollment** — a Windows client appears:
   `velociraptor --api_config ~/.config/trudi/velociraptor/api.config.yaml query
   "SELECT client_id, os_info.system FROM clients() WHERE os_info.system =~ 'windows'"`.
   If it never appears, the guest couldn't reach `10.73.0.2:8000` — the most
   likely tweak point. Confirm from the guest console (`curl -k
   https://10.73.0.2:8000/`), and if the NAT path doesn't route, switch
   `victim-win` to a macvlan network (see the dockur README) and repoint
   `VELO_SERVER_LAN_URL` in `win-oem-init`.
3. **Detectors fire** — after `/trudi-start-watcher WINRDP-DEMO`, run the
   `win-rdp` attack and confirm a `Custom.TRUDI.Win.NewLogon` alert lands. If a
   detector errors, check its field names against this Velociraptor version
   (`pslist()`, `watch_evtx`, the 4624 `EventData` keys) — the templates target
   the standard schema but a version skew is possible.

## Real Windows deception decoy (profiles `winrdp` + `windecoy`)

The **decoy demo with a real Windows machine**. This fuses the external
ShadowPlex trigger (as in `decoy`) with the real-Windows investigation (as in
`winrdp`): the decoy that gets touched is the genuine Windows Server 2022 host
(`victim-win`), instrumented as a high-interaction honeypot. `victim-a` replays
a **honey credential (`linda`)** over RDP to it; an on-decoy sensor reports the
honey-account logon as ShadowPlex CEF; TRUDI **contains the beachhead** and
**investigates the real Windows decoy** for CONFIRMED findings over its
Velociraptor Windows client.

> The on-decoy sensor (`demo/live-monitoring/windecoy/sensor.ps1`) is a **format
> emulator** of a ShadowPlex agent, built from Acalvio's published CEF spec
> (release 2026.8.2.0). It is **not** Acalvio software. It is separate from
> Velociraptor, which remains TRUDI's own EDR for the investigation.

Needs the `lateral` beachhead + the `winrdp` box + the `windecoy` relay:

```bash
sudo ./bring-up.sh --profiles lateral,winrdp,windecoy
# or, stack already up:
docker compose --profile lateral --profile winrdp --profile windecoy up -d
```

- **victim-win** — the same Windows VM as the `winrdp` profile, additionally
  provisioned (by `win-oem-init`) with the non-admin honey account `linda` and
  the boot-run ShadowPlex sensor task (dormant unless `linda` logs in).
- **windecoy-relay** (`trudi-windecoy-relay`, `10.73.0.55:5514` on `lan-net`) —
  forwards the sensor's CEF from inside the Windows VM to the SIFT host's ingest
  at `host.docker.internal:5514` (the VM, a KVM guest behind dockur's NAT, can't
  use the host-gateway shortcut itself).

Drive it with the bundled **`WINDECOY-DEMO`** case (`~/cases/WINDECOY-DEMO/`):

```
/trudi-start-watcher WINDECOY-DEMO     # cef_ingest in config → starts the CEF ingest
/trudi-watch-alerts  WINDECOY-DEMO
```
```bash
docker exec trudi-victim-a /attacks/run win-decoy            # honey-credential RDP to the decoy
docker exec trudi-victim-a /attacks/run win-decoy --cleanup  # close RDP; preserve guest evidence
```

TRUDI opens an investigation on the `Custom.TRUDI.DecoyTouch` alert, **contains
the touching host** (`victim-a`: auto-block egress to the decoy, approval-gated
kill of the RDP client), then pivots onto the **real Windows decoy** over its
Velociraptor Windows client and confirms the 4624 type-10 `linda` logon + the
TerminalServices session — CONFIRMED findings with the real Windows toolchain.
The honey-account logon is the signal. The attacker then attempts ordinary-user
discovery, reads synthetic finance files, stages a ZIP in the user's profile,
and installs an HKCU Run value with a harmless sleeping worker. A protected
canary read is denied. The launcher types into the honey account's real RDP
desktop; it does not execute the activity as SYSTEM or through the investigator.
Defender provisioning enables native process/file/script-block auditing and
restricts Windows egress to telemetry, the relay and DHCP. Linda remains a local
standard user with read-only bait and write access to her own profile/HKCU.
Immediate source containment can interrupt this sequence. The
[runbook](windecoy-demo-script.md) documents an explicit exercise response hold
for a full-activity take, and the native evidence needed to corroborate it.
`Custom.TRUDI.Win.HoneyActivity` collects SID-bound Security and PowerShell
records plus current profile staging and persistence. A blocked RDP channel
does not remove these Windows residuals.
The honeytoken discipline: `linda` is a planted credential, not a person — the
action is attributed to the beachhead session, not to "linda."

**Replay without the containers** (CI / quick check) — feed the sensor's two
sample CEF records straight to the ingest:

```bash
python3 bin/trudi-cef-ingest.py --case-id WINDECOY-DEMO \
    --alerts-dir ~/cases/WINDECOY-DEMO/monitoring/alerts --no-resolve \
    --replay demo/live-monitoring/windecoy/sample-sensor-incident.cef
```

### First-boot validation checklist (windecoy additions)

Validated on Windows Server 2022 with Velociraptor 0.76.1 on 2026-10-15:
all three Windows detectors, a real honey-account RDP logon, signed sensor
messages through the Docker relay, source-host containment, and rollback.

On top of the `winrdp` checklist above (install / enrollment / RDP), confirm the
deception trigger end to end:

1. **Honey account + sensor present** — on the desktop, `net user linda` exists
   as a standard user, `C:\ProgramData\TRUDI-Decoy\policy.json` records its SID,
   and `schtasks /query /tn ShadowPlexSensor` shows the task running. On an
   existing VM apply the new `windecoy/provision.ps1` as an administrator;
   rebuilding the OEM payload alone does not update its installed guest.
2. **CEF reaches the ingest** — after `/trudi-start-watcher WINDECOY-DEMO` and
   the `win-decoy` attack, a `Custom.TRUDI.DecoyTouch` alert lands. If not, the
   sensor→relay→ingest path is the suspect: check the relay logs
   (`docker logs trudi-windecoy-relay` — it prints each forwarded datagram), and
   that the VM can reach the relay at `10.73.0.55:5514` (same NAT path it uses
   for `10.73.0.2:8000`). If the VM can't reach `10.73.0.55`, point the sensor
   at the lan-net gateway or adjust `SHADOWPLEX_RELAY_HOST` in `win-oem-init`.
3. **Source resolves** — the alert's `client_id` resolves to `victim-a` (by
   hostname / `last_ip` = the CEF `srcIP` 10.73.0.3), so containment targets the
   beachhead, not the decoy.

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
