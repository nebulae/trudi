# Case: DEMO-LIVE

**Live-monitoring case** — Velociraptor-backed continuous detection on a
Dockerized Linux victim. Unlike static-evidence cases, there is no E01 or
memory image; the "evidence" is a stream of events from `Custom.TRUDI.*`
event artifacts running on the client. TRUDI does **not** execute
remediation — the `respond.*` namespace only *recommends* operator-runnable
containment commands (Velociraptor's client build ships without `execve()`,
and keeping execution out of the agent's hands is the safer posture anyway).

---

## Case Metadata

| Field | Value |
|-------|-------|
| **Case ID** | DEMO-LIVE |
| **Case type** | Live monitoring (Velociraptor) |
| **Target host** | `victim` (Docker container, Ubuntu 22.04) |
| **Velociraptor client_id** | `C.e6de3278ad209722` |
| **Demo env path** | `~/trudi/demo/live-monitoring/` |
| **Opened** | 2026-06-05 UTC |
| **Investigator** | trinity@mentalpad.net |

If the client_id changes (after `docker compose down -v`), update it here
and refresh `~/cases/.common/active_case`.

> client_id history: `C.b26bf213f23d389a` → `C.a7e09ef2f7d2932b` →
> `C.c121f49108aac429` → `C.e6de3278ad209722` (re-resolved 2026-06-12 by
> `/trudi-start-watcher`; victim re-enrolled).

---

## Case Question

**Is there anomalous activity on the monitored host that warrants
containment or eradication?**

Use this as the `observation` of the initial `reason.hypothesize` call
on every alert-driven investigation (per DAIR Triage rules in
`~/.claude/CLAUDE.md`).

---

## Workflow

1. **Baseline** — `monitor.baseline_capture(client_id, "DEMO-LIVE")`
   snapshots processes / persistence / network into
   `monitoring/baselines/<client_id>.json`.

2. **Start watcher** — `monitor.start_watcher(client_id, "DEMO-LIVE")`
   renders detector artifacts from the baseline, uploads them to the
   server, registers them on the client event table, and spawns
   `bin/trudi-velo-watcher.py` as a detached sidecar that drains
   `watch_monitoring()` into `monitoring/alerts/<seq>_<detector>.json`.

3. **Poll for alerts** — `/loop 15s /trudi-check-alerts` (in a Claude
   session). Each tick drains new alerts via `monitor.check_alerts`,
   opens (or extends) one investigation per tick with
   `monitor.start_investigation` (id `INV-NNN`), runs ONE
   `reason.hypothesize` → `dair_assess` → priority-tool batch →
   `misc.record_finding` chain over the whole bundle, and for any
   CONFIRMED/LIKELY finding auto-calls `respond.suggest_containment`.
   `monitor.end_investigation` exports
   `reports/<case>_<INV-NNN>.{json,md}` and flips the active trace
   back to the case-wide file.

4. **Respond (recommend only)** — for each CONFIRMED/LIKELY finding,
   `respond.suggest_containment` renders a copyable `manual_command` from
   the detector's recipe with the alert evidence substituted in. The
   `/trudi-check-alerts` skill surfaces these as a numbered `ACT-N` menu
   (description, risk/reversible, fenced command) after findings but before
   `end_investigation`, and `end_investigation` writes them into the report's
   **Recommended Containment Commands (run manually)** section. TRUDI never
   executes them — the operator runs any command out-of-band. The only gate
   on `respond.*` is `live_monitoring_scope`.

---

## Directory Layout

```
~/cases/DEMO-LIVE/
  CLAUDE.md                              this file
  .claude/settings.json                  MCP tool allowlist for this case
  analysis/                              (all trace files flat under here
                                          so the dashboard scan picks them up)
    DEMO-LIVE_trace.json                 case-wide ORCHESTRATION trace
                                         (check_alerts, list_watchers, ack_alert,
                                          next_investigation_id,
                                          start/end_investigation markers)
    DEMO-LIVE_INV-001_trace.json         one trace per investigation, where
    DEMO-LIVE_INV-002_trace.json           an "investigation" = the bundle of
    ...                                    alerts drained in one /loop tick
                                          (kept open across ticks if approvals
                                          are pending)
  reports/
    DEMO-LIVE_INV-001.json               auto-exported from end_investigation
    DEMO-LIVE_INV-001.md
  exports/                               on-demand CSV / JSON dumps
  monitoring/                            (created on first baseline_capture)
    _inv_seq.txt                         per-case monotonic INV counter
    _open_investigation.json             present iff an investigation is open
                                          across /loop ticks (tracks
                                          investigation_id + alert_ids)
    baselines/<client_id>.json           allowlist snapshot
    artifacts/Custom.TRUDI.*.yaml        rendered detector artifacts (audit copy)
    watchers/<client_id>.{pid,log}       sidecar state
    alerts/                              one file per detector event (the payload)
      _seq.txt                           monotonic sequence
      _seq.lock                          fcntl lock around _seq.txt
      <seq>_<detector>.json              alert payload
    response/                            (created by respond.suggest_containment)
      suggestions/ACT-N.json             rendered description + manual_command
                                          (recommendations only; nothing executes)
    _last_check_seq.txt                  highest seq drained by /trudi-check-alerts
```

**Trace split (live-monitoring specific).** The case-wide trace at
`analysis/DEMO-LIVE_trace.json` records only orchestration: the slash
command's `check_alerts`, `list_watchers`, `ack_alert`, and the
`start_investigation` / `extend_investigation` / `end_investigation`
markers. The focused investigation chain (hypothesize → DAIR Triage →
velo.* tool batch → record_finding → respond.*) lands in a
**per-investigation trace** at
`analysis/DEMO-LIVE_INV-NNN_trace.json` — one per `/loop` tick that
finds alerts. All alerts in the tick share that trace. DAIR's "last
30 entries" gate window is scoped per-trace, so two independent attack
scenarios produce two independent investigation chains with no
cross-contamination.

The dashboard (`http://127.0.0.1:8765/...`) discovers every
`*_trace.json` directly under `analysis/`, so each new investigation
shows up automatically alongside the case-wide trace.

Operator-typed messages follow the active trace automatically (via the
`UserPromptSubmit` hook reading the session beacon that
`log.configure()` updates on every switch). `approve ACT-N` typed
during an open investigation lands in the per-investigation trace,
which is exactly where the `operator_text_required` gate looks. If
approvals are still pending at end of tick, the investigation stays
open — `_open_investigation.json` holds the state, and the next tick
rehydrates the same trace via `start_investigation` (idempotent).

---

## Key Files & Tools

- Slash commands:
  - [`/trudi-start-watcher`](.claude/commands/trudi-start-watcher.md) — resolve live client_id, baseline, render detectors, spawn sidecar
  - [`/trudi-stop-watcher`](.claude/commands/trudi-stop-watcher.md) — SIGTERM the sidecar, clear the client event table
  - [`/trudi-check-alerts`](.claude/commands/trudi-check-alerts.md) — drain alerts, investigate, surface the containment-command menu
  - [`/trudi-clear-case`](.claude/commands/trudi-clear-case.md) — wipe outputs + project memory (+ live monitoring state) for a fresh run
- TRUDI namespaces: `velo.*`, `monitor.*`, `respond.*` (see global
  `~/.claude/CLAUDE.md` namespace table)
- Detector templates: [`~/trudi/monitoring/artifacts/Custom.TRUDI.*.yaml.tmpl`](trudi/monitoring/artifacts/)
- Response recipes: [`~/trudi/response/recipes/Custom.TRUDI.*.yaml`](trudi/response/recipes/)
- Live tooling for investigation: `live.*` (SSH to `trudi-victim` on
  port 2222, registered as `trudi-victim` in
  `~/cases/.common/live_hosts.json`)

---

## Constraints

- **Strict read-only on evidence applies everywhere** — TRUDI never
  writes to the live host. `respond.suggest_containment` only *recommends*
  commands (gated by `live_monitoring_scope` so it's meaningful only for an
  active live-monitoring case); the operator runs anything themselves.
- **Never push detector templates without bumping the table** — a
  detector template change requires `monitor.stop_watcher` →
  `monitor.start_watcher` to upload and recompile; a victim container
  restart may be needed if the client's compiled query cache is stale.
