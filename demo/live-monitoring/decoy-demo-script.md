# DECOY-DEMO — demo runbook + voiceover script

Autonomous investigation + gated response driven by an **external deception
detection** (Acalvio ShadowPlex CEF), mapped onto TRUDI's live-monitoring loop.

- Detection source: emulated ShadowPlex RDP decoy → CEF/syslog → `bin/trudi-cef-ingest.py` → `Custom.TRUDI.DecoyTouch` alert
- Touching host (investigated + contained): `victim-a` (the beachhead)
- Decoy: `DESKTOP-GN-806`, RDP/3389 — the platform's asset, never a target
- Dashboard: http://127.0.0.1:8765/_dashboard/dashboard.html → pick **DECOY-DEMO**

> The decoy is a **format emulator built from Acalvio's published CEF spec**, not
> Acalvio software. No ShadowPlex instance runs. Keep that precise on camera.

---

## 0. One-time setup (before you hit record)

`bring-up.sh` generates the `decoy-emulator` signing key. Before staging the
touch, configure this case's `cef_ingest.senders` with that key, victim-a's
actual source IP/client ID, and `10.73.0.50:3389`. Follow the
[authenticated CEF setup](../../docs/live-monitoring.md#external-detection-ingest--acalvio-shadowplex-cef--autonomous-response).
Unsigned or unbound alerts remain collection-only and will not auto-block.

```bash
cd ~/trudi/demo/live-monitoring
# Build + start the lateral hosts AND the decoy. --build rebuilds victim-a so it
# carries the new /attacks/decoy-touch.sh; builds the trudi-decoy container.
COMPOSE_PROFILES=lateral,decoy ./bring-up.sh
docker ps --format '{{.Names}}' | grep trudi-decoy   # confirm the decoy is up
```

Confirm the dashboard is running (start it if not):

```bash
cd ~/trudi && ./dashboard.sh    # http://127.0.0.1:8765  → DECOY-DEMO
```

Two terminals for the recording:
- **LEFT** — the Claude Code TRUDI session (the agent).
- **RIGHT** — the ingest log + the attack trigger:
  ```bash
  tail -f ~/cases/DECOY-DEMO/monitoring/watchers/cef-ingest.log
  ```

Optional dry run (no containers, proves the mapping):
```bash
python3 bin/trudi-cef-ingest.py --case-id DECOY-DEMO \
    --alerts-dir ~/cases/DECOY-DEMO/monitoring/alerts --no-resolve \
    --replay demo/live-monitoring/decoy/sample-incident.cef
```
Clear it before the real run with `/trudi-clear-case DECOY-DEMO`. Do **not**
just delete the replayed alert file: any `respond.suggest_containment` run
against the replay leaves `ACT-*.json` records under
`~/cases/DECOY-DEMO/monitoring/response/` aimed at the sample's TEST-NET decoy
address (192.0.2.59), and the alert `_seq` / investigation counters keep
climbing. (Reports are scoped to their own investigation, so leftovers no
longer leak into the live take's report — but the live run's ACT numbering
should still start at 1 on camera.)

---

## Step-by-step (what you do on camera)

| # | Pane | Action | What to point at |
|---|------|--------|------------------|
| 1 | LEFT | `/trudi-start-watcher DECOY-DEMO` | Baselines victim-a, starts the CEF ingest sidecar; `list_watchers` shows `cef-ingest` alive. Note the dashboard URL it prints. |
| 2 | LEFT | `/trudi-watch-alerts DECOY-DEMO` | The agent says it's watching; it will wake within ~2s of an alert. |
| 3 | RIGHT | `sudo docker exec trudi-victim-a /attacks/run decoy-touch` | The beachhead touches the decoy as `linda`. |
| 4 | RIGHT | watch the ingest log | One `wrote alert …_DecoyTouch.json` line — the ShadowPlex CEF became a TRUDI alert. |
| 5 | LEFT | (agent acts on its own) | It opens an investigation, hypothesizes, runs DAIR, and **auto-blocks the egress** to the decoy. Read the `🛡️ Auto-contained` line and its printed undo command aloud. |
| 6 | LEFT | (agent self-corrects) | The alert foregrounds the *decoy*; the agent notes the decoy has no Velociraptor client and re-targets the **source host** — a `record_self_correction`. This is the self-correction beat. |
| 7 | LEFT | (agent pivots) | Velociraptor netstat → pslist on victim-a finds the touching process; it records the lateral-movement finding (T1021.001) and dispositions the honey credential `linda` as not-a-principal. |
| 8 | LEFT | **approve the kill** when the popup appears | Select **Approve ACT-N**. The agent kills the process and prints the result. |
| 9 | LEFT | `monitor.verify_clean` (agent runs it) | `clean=true` — the flow to the decoy is gone. |
| 10 | BROWSER | dashboard → DECOY-DEMO | The investigation trace: alert → hypothesis → findings → response actions, each citing a tool call. |

Reset for another take:
```bash
sudo docker exec trudi-victim-a /attacks/run decoy-touch --cleanup
# in the session: stop watching, then /trudi-clear-case DECOY-DEMO
```

---

## Voiceover script (read aloud, ~3.5 min)

**[0:00 — Cold open, dashboard on screen]**
"An AI-speed attacker doesn't repeat a known pattern — which is exactly what
signature and correlation detection was built to catch. So this demo starts
somewhere that has no false-positive problem at all: a deception decoy. Nothing
legitimate ever touches it. Here's TRUDI turning one decoy touch into a contained
incident, on its own."

**[0:20 — LEFT pane, step 1]**
"I point TRUDI at the live case and start the watcher. Two things come up: a
Velociraptor baseline of the host we care about, and a CEF ingest. That ingest is
the bridge — it speaks the same alert format as an Acalvio ShadowPlex deployment,
emulated here from their published spec. No vendor software is running; this is the
alert format landing exactly as it would from a real platform."

**[0:40 — step 2]**
"Now it's watching. It'll wake within about two seconds of anything touching the
decoy."

**[0:50 — RIGHT pane, step 3 and 4]**
"Over on the compromised host, the attacker tries a credential they harvested —
`linda` — against the first RDP machine they see on the network. That machine is
the decoy. Watch the ingest: the ShadowPlex incident just became a TRUDI alert.
One record carried the source host, the decoy, the credential, and the MITRE
mapping; a second carried the attacker's client fingerprint. They share an
incident ID, so TRUDI merged them into one."

**[1:15 — LEFT pane, step 5]**
"TRUDI woke on its own. First move, before any analysis: it cuts the channel to
the decoy — a reversible, low-risk firewall block that runs automatically. It
prints the exact undo command, so a human can reverse it in one line. Containment
first, because a live intrusion doesn't wait for paperwork."

**[1:40 — step 6, the self-correction]**
"Now the interesting part. The alert names the decoy loudly — it's the thing that
got touched. A naive agent pivots straight to it. TRUDI doesn't: it recognizes the
decoy is the deception platform's own asset, with no endpoint agent to question,
and it re-targets the host that *did* the touching. That's a self-correction, and
it's recorded in the trace as one — not hidden."

**[2:05 — step 7]**
"On the real host, over Velociraptor, it finds the process that opened the
connection and ties the alert to a running program. It records the lateral-movement
attempt — mapped to the RDP technique — at the CONFIRMED tier, every claim linked
to the tool call that produced it. And the credential `linda`? It checks the host's
real accounts, doesn't find it, and labels it what it is — a deception breadcrumb,
not a person. It refuses to name a human it can't tie to a session."

**[2:35 — step 8, the approval]**
"Blocking the channel was automatic. Killing the process is destructive and
irreversible, so TRUDI stops and asks. It cannot approve itself — that boundary is
enforced by the server, not by prompt wording. I approve it."

**[2:55 — step 9]**
"It kills the process and then re-checks the host against the baseline. Clean —
no residual connection to the decoy, the process is gone."

**[3:10 — BROWSER, step 10]**
"And here's the whole thing as a record. External alert in, hypothesis, the
self-correction, the findings with their evidence, and every response action with
its undo command. A deception alert became a contained, fully-audited incident,
start to finish, at machine speed — and the one irreversible step still waited for
a human. That's the point: autonomous where it's safe, gated where it isn't."

---

## Notes for the presenter

- **If client resolution misses** (the agent can't map the source IP to a
  Velociraptor client): that's the honest fallback — it resolves via
  `velo.list_clients` and records a self-correction. It does not break the demo;
  it's a second, real self-correction beat if you want it.
- **Keep the language exact:** "contained a planted demo TTP," never "remediated a
  real compromise." The case is opted into `demo_response.respond_to_synthetic`.
- **The decoy is an emulator.** If asked, say so plainly: it reproduces the
  published CEF record layout; it is not Acalvio ShadowPlex.
