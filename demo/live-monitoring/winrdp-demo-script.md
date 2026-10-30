# WINRDP-DEMO — demo runbook + voiceover script

Autonomous investigation of a **real Windows Server 2022** victim. The beachhead
opens a genuine RDP session into the Windows host; TRUDI investigates the
Windows side over its Velociraptor **Windows** client with native telemetry —
the real 4624 type-10 (RemoteInteractive) logon and TerminalServices session a
Linux container can't produce. **Login-only:** the session is held open but no
command runs on the box (FreeRDP 2.6.1 against Server 2022 can't execute
in-session), and it doesn't need to — the type-10 logon is the whole signal.

- Target (investigated): `victim-win` — true Windows Server 2022 (a KVM guest
  via `dockur/windows`, **not** a Windows container)
- Source (beachhead): `victim-a` — already compromised; holds a harvested local
  credential for the Windows host
- Detection: TRUDI's own host detector on the Windows client —
  `Custom.TRUDI.Win.NewLogon` (the held RDP logon is the whole signal)
- Case: `WINRDP-DEMO` (`~/cases/WINRDP-DEMO/`)
- GUI (optional B-roll): `https://localhost:8889` (admin), Windows console:
  `http://localhost:8006`

> This is the counterpart to DECOY-DEMO. There, the RDP target was an emulated
> decoy that is never investigated. Here the Windows host IS the subject, and
> the detection is TRUDI's own, not an external platform.

---

## The machines (introduce these on camera)

| Machine | Container | Address | Role in the story |
|---|---|---|---|
| **Velociraptor server** | `trudi-velo-server` | `velo-net` + `lan-net` `10.73.0.2` | The single pane of glass. Every endpoint enrolls here; TRUDI drives it over the API, and the GUI is at `:8889`. |
| **Beachhead** | `trudi-victim-a` | `lan-net` `10.73.0.3` | The already-compromised Linux foothold. It holds a stolen credential for the Windows host and opens the RDP session. The attacker's starting point. |
| **Windows victim** | `trudi-victim-win` | `lan-net` `10.73.0.60`, RDP `3389` | **A real Windows Server 2022 machine.** The investigation target. Runs the Velociraptor Windows client; console at `:8006`. |
| **TRUDI / SIFT host** | (this host) | — | Where the analyst runs. Holds the `WINRDP-DEMO` case, the Windows detectors, and the OS-aware baseline. |

Supporting cast not used in this demo (ignore on camera): `trudi-victim-b`
(Linux lateral target), `trudi-decoy`, `trudi-c2-sink`.

---

## 0. One-time setup (before you hit record)

The Windows install is slow, so do this **well ahead** of recording.

```bash
cd ~/trudi/demo/live-monitoring
# Build the lateral hosts + the Windows VM. First Windows boot pulls ~6 GB of
# Server 2022 eval media and installs unattended (~10-20 min).
sudo ./bring-up.sh --profiles lateral,winrdp
# Watch the install to the desktop:
#   http://localhost:8006
```

Confirm the Windows client enrolled before recording (filter on OS, since the
Windows computer name is not "victim-win"):

```bash
velociraptor --api_config ~/.config/trudi/velociraptor/api.config.yaml query --format jsonl \
  "SELECT client_id, os_info.hostname AS hostname, os_info.system AS os,
          timestamp(epoch=last_seen_at/1000000) AS last_seen
   FROM clients() WHERE os_info.system =~ 'windows'"
```

A row with `os: windows` and a recent `last_seen` means it is live. (Optional:
log into the GUI at `https://localhost:8889` as `admin` for B-roll.)

Two terminals for the recording:
- **LEFT** — the Claude Code TRUDI session (the analyst).
- **RIGHT** — the attacker's shell on the beachhead:
  ```bash
  # nothing yet — you'll run the attack here in step 4
  ```

Reset for another take (full reinstall — only if you must):
```bash
# in the session: stop watching, then /trudi-clear-case WINRDP-DEMO
# to rebuild the Windows box from scratch:
sudo docker rm -f trudi-victim-win && sudo docker volume rm trudi-live-monitoring_win-storage
sudo docker compose --profile lateral --profile winrdp up -d victim-win
```

---

## Step-by-step (what you do on camera)

| # | Pane | Action | What to point at |
|---|------|--------|------------------|
| 1 | LEFT | Introduce the board | Name the three machines (table above): the server, the beachhead, and the real Windows victim. Stress "a true Windows box, not an emulator." |
| 2 | LEFT | `velo.list_clients` (or the clients query) | One of the enrolled clients is `os: windows` — the Windows victim is live and reporting. |
| 3 | LEFT | `/trudi-start-watcher WINRDP-DEMO` | TRUDI detects the Windows OS, captures a **Windows baseline** (process image set + autostart surface), and pushes the `Custom.TRUDI.Win.*` detectors to the client. Note the dashboard URL. |
| 4 | LEFT | `/trudi-watch-alerts WINRDP-DEMO` | The analyst is watching; it will wake within seconds of an alert. |
| 5 | RIGHT | `sudo docker exec trudi-victim-a /attacks/run win-rdp` | The beachhead opens a **real RDP session** into the Windows host with the stolen credential. The logon itself is the signal — the session is held open, no command runs on the box. |
| 6 | LEFT | (agent acts on its own) | TRUDI wakes on the `Win.NewLogon` alert — a genuine Security 4624 **type 10** (RemoteInteractive) from `10.73.0.3`, the beachhead. It opens an investigation. |
| 7 | LEFT | (agent pivots over Velociraptor) | It collects Windows artifacts from the Windows client — the logon events + TerminalServices session + the live ESTABLISHED RDP session — and binds the session: account `rdpadmin`, source `victim-a`. |
| 8 | LEFT | (distinct-principal beat) | `rdpadmin` is a **local account, not a person** — the agent binds it to the 4624 session before attributing, and cross-references the source against the known hosts. |
| 9 | LEFT | (findings + report) | It records the CONFIRMED lateral-movement RDP logon (T1021.001) — the type-10 logon + TerminalServices session on real Windows — then produces the investigation report. |
| 10 | BROWSER | `https://localhost:8889` → the Windows client | Optional: show the real Windows host in the Velociraptor GUI — the evidence came from an actual Windows endpoint. |

Reset for another take:
```bash
sudo docker exec trudi-victim-a /attacks/run win-rdp --cleanup   # close the held session
# in the session: stop watching, then /trudi-clear-case WINRDP-DEMO
```

---

## Voiceover script (read aloud, ~3.5 min)

**[0:00 — Cold open, the three-machine board]**
"Most of what you've seen TRUDI investigate so far has been Linux. This one is a
real Windows machine. Three boxes on the board: a Velociraptor server that every
endpoint reports to; a beachhead — a Linux host the attacker already owns; and
the target — a genuine Windows Server 2022 machine. Not an emulator, not a
stand-in: a real Windows kernel, booted in a VM, running the same endpoint agent
you'd deploy in production."

**[0:20 — LEFT, step 2]**
"Here are the enrolled endpoints. One of them reports its operating system as
Windows — that's our victim, live and checking in to the same server as the
Linux hosts."

**[0:35 — step 3]**
"I point TRUDI at the case and start the watcher. Watch what it does: it notices
the host is Windows, and it takes a Windows baseline — the processes that are
running and the autostart entries that already exist — then it pushes Windows
detectors to that client. The same idea as the Linux side, but speaking the
Windows event log and registry instead of /proc and cron."

**[0:55 — step 4]**
"Now it's watching. It'll wake within seconds of anything the detectors flag."

**[1:05 — RIGHT, step 5]**
"Over on the beachhead, the attacker uses a credential they harvested earlier
and opens a Remote Desktop session straight into the Windows box — a real RDP
logon. That logon is the move: this is the lateral step every responder knows,
a stolen credential and an RDP session into the next host. The session stays
open, and the logon itself is all we need to catch it."

**[1:30 — LEFT, step 6]**
"TRUDI woke on its own. The signal is a real Windows security event — a 4624,
logon type 10, remote-interactive — and the source address is the beachhead.
This isn't synthesized; it's the same event a Windows SOC would alert on,
pulled live off the endpoint."

**[1:55 — step 7]**
"It pivots over Velociraptor into the Windows host and gathers the evidence on
the Windows host's own terms: the 4624 logon, type 10, naming the source; the
Terminal Services session; and the live, established RDP session itself. Every
one of those is a real Windows artifact collected from a real Windows endpoint —
which is what lets this land as confirmed, not suspected."

**[2:25 — step 8, the discipline beat]**
"Now the careful part. The account that logged in is a local Windows account —
not automatically a person. TRUDI treats it as an identity to be bound, not a
name to be trusted: it ties the account to the logon session and its source
before it attributes anything, and it checks that source against the hosts it
already knows. It won't name a human it can't tie to a session."

**[2:50 — step 9]**
"It records what it can prove: a remote-desktop lateral-movement logon — mapped
to its MITRE technique and linked to the Windows event that proves it. Then it
writes the report."

**[3:10 — BROWSER, step 10]**
"And here's the host it all came from, in the Velociraptor console — a real
Windows Server, enrolled like any endpoint in a fleet. The point of this one:
TRUDI isn't limited to the Linux demo world. Point it at a Windows estate and it
investigates on Windows' own terms — real logons, real registry, real
processes — with the same discipline about who it's willing to blame."

---

## Notes for the presenter

- **Keep the language exact:** "a real Windows machine" / "real Windows event
  log," never "simulated." The decoy demo is the emulated one; this is the real
  one. If asked how a Windows machine runs in Docker: it's a full KVM virtual
  machine inside a Linux container (`dockur/windows`), not a Windows container.
- **This case is investigate-only.** The `respond.*` containment path is Linux
  SSH-based (iptables/kill/sudo), so there is no auto-block or approve-the-kill
  beat here — don't promise one. The value is the Windows-native investigation
  and the findings/report, not containment.
- **It's a freshly-built scenario.** The Windows runtime (enrollment, the
  detectors firing, the exact event fields) is validated on first boot, not in
  CI — so do a full dry run before recording. The most likely rough edge is the
  guest reaching the server at `10.73.0.2:8000`; if a detector misfires, check
  its field names against the live Velociraptor version. See the "First-boot
  validation checklist" in `README.md`.
- **If the RDP session doesn't trip NewLogon**, confirm the attack actually
  authenticated and held (the `win-rdp` logs on victim-a say "session held")
  and that the Security channel path in the detector matches the host. The live
  ESTABLISHED rdp-tcp session on the Windows host corroborates the logon.
- **Login-only.** No command runs on the box (FreeRDP against Server 2022 can't
  execute in-session), so there is no process or Run-key beat to show — the
  type-10 logon + TerminalServices session is the whole, confirmable signal.
- **Timing:** the Windows install is the long pole — have the box installed and
  enrolled before you start recording; the on-camera part is only steps 1-10.
