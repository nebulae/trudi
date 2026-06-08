---
description: "Drain TRUDI live-monitoring alerts and run a per-tick investigation over the bundle"
argument-hint: "[case_id]"
---

# /trudi-check-alerts

Polls the active TRUDI live-monitoring case for new alerts and runs
**one investigation per /loop tick** over the entire bundle of alerts
drained in that tick. Designed to be called on a fixed interval via
`/loop 15s /trudi-check-alerts` so anomalies are investigated within
~30s of firing on the victim host.

The argument, if supplied, names the case. Otherwise read it from
`~/cases/.common/active_case`.

## Trace routing contract — read first

Live-monitoring cases use **per-investigation traces**. Each
`/trudi-check-alerts` tick that finds alerts opens (or resumes) ONE
investigation, identified by an `INV-NNN` id. Its trace lives at
`<case>/analysis/<case>_<INV-NNN>_trace.json` — flat under `analysis/`
so the dashboard scan picks it up. All alerts drained in that tick
share that single trace.

The case-wide trace at `<case>/analysis/<case>_trace.json` records
**orchestration only**: `monitor.list_watchers`,
`monitor.check_alerts`, `monitor.next_investigation_id`,
`monitor.open_investigation_state`,
`monitor.start_investigation` / `extend_investigation` /
`end_investigation` markers, `monitor.ack_alert`, and any operator
messages typed outside an open investigation.

The switch happens via `monitor.start_investigation` and
`monitor.end_investigation`. **Do not call
`misc.start_execution_log` during this workflow** — those helpers
manage the trace path.

Operator-typed messages follow the same routing automatically: the
`UserPromptSubmit` hook reads `~/.cache/trudi/session.json` (which
`log.configure()` updates whenever the trace flips) and appends the
typed prompt to whichever trace is currently active. That's how
`approve ACT-N` lands in the per-investigation trace and how the
`operator_text_required` gate finds it.

If response actions are pending operator approval at end of tick, the
investigation stays open across ticks — `_open_investigation.json`
holds the state, and the next tick rehydrates the same trace via
`start_investigation` (it's idempotent).

## Workflow

### 1. Resolve case + ensure case-wide trace

1. Resolve `case_id` from `$ARGUMENTS` if non-empty, else
   `cat ~/cases/.common/active_case`. Refuse if neither is set.
2. Ensure the case-wide trace is active. If
   `core.execution_log.log._path` is unset (cold start), call
   `misc.start_execution_log(case_id,
   output_path="./analysis/<case>_trace.json")`. Otherwise skip — the
   case-wide trace is already configured from a prior iteration.
3. Call `monitor.list_watchers(case_id)`. If empty or none alive,
   surface a one-line warning and exit — there is nothing to consume.

### 2. Check for an open investigation + drain new alerts

```
state  = monitor.open_investigation_state(case_id)
alerts = monitor.check_alerts(case_id, since_seq=<read _last_check_seq>)
```

Branch:
- `alerts.empty AND not state.open` → print `"No anomalies."` and exit.
- `alerts.empty AND state.open` → continue at step 3 to handle pending
  approvals on the open investigation.
- `alerts.nonempty AND not state.open` → continue at step 3 to open a
  new investigation.
- `alerts.nonempty AND state.open` → continue at step 3 to extend the
  open investigation with the new alerts.

### 3. Open / resume / extend the investigation trace

```
if state.open:
    investigation_id = state.investigation_id
    monitor.start_investigation(case_id, investigation_id,
                                alert_ids=state.alert_ids + [a.alert_id for a in alerts])
        # idempotent — rehydrates the existing trace
        # capture genesis_call_id (cid of the genesis agent_message
        #   that start_investigation just wrote in the per-investigation
        #   trace; root of every input_call_ids chain below)
        # capture rehydrated_entries — if > 0, we're resuming work
    if alerts.nonempty:
        monitor.extend_investigation(case_id, investigation_id,
                                     new_alert_ids=[a.alert_id for a in alerts])
else:
    inv = monitor.next_investigation_id(case_id).investigation_id
    monitor.start_investigation(case_id, inv,
                                alert_ids=[a.alert_id for a in alerts])
    investigation_id = inv
```

After this step, the active trace is the per-investigation file. The
`user_message` hook follows automatically via the session beacon.

### 4. Investigate the bundle (only if new alerts this tick)

If `alerts.nonempty` OR `rehydrated_entries == 0` (i.e. this is the
first time we've actually run the investigation chain), execute the
full chain ONCE on the bundle:

```
reason.hypothesize(
    observation="Live alert burst: <N> alerts via Velociraptor",
    evidence=<json of the bundle: per-alert summary, detector counts, hosts>,
    context="case=<case_id>; investigation=<INV>; alert_ids=...",
    input_call_ids=[genesis_call_id])

dair.dair_assess(
    tool_results_summary="Investigation opened on bundle of <N> alerts",
    phase_stack="[]",
    case_context="CASE_QUESTION: ...; investigation_id=<INV>",
    input_call_ids=[genesis_call_id, hypothesize_cid])
```

The phase stack starts empty — gate windows are scoped to this
per-investigation trace.

Then execute the DAIR `priority_tools` batch (velo.* substrate per the
existing guidance, see Substrate section below). Per finding:
- `reason.confidence_score` + `reason.cite_check` (so the
  `confidence_and_citation` gate passes for tier ≥ LIKELY)
- `misc.record_finding(...)` with
  - `linked_call_id = <source tool cid>`
  - `input_call_ids = [genesis_call_id, hypothesize_cid, <tool cids>]`
  - `tested_hypothesis_id = <hypothesis_id>`
  - description including detector T-numbers where applicable so
    `mitre_technique_validation` passes.

If `rehydrated_entries > 0` AND `alerts.empty` (we're just here to
check approvals on a previously-opened investigation), SKIP this
step — go straight to step 5.

### 5. Recommend containment commands (TRUDI does NOT execute)

If any finding's tier is **CONFIRMED or LIKELY**, call
`respond.suggest_containment(case_id, finding_id=<record_finding cid>,
detector="Custom.TRUDI.<NewNetwork|NewProcess|NewPersistence|YaraProcess>",
evidence=<the alert's evidence dict>)` for each such finding.

TRUDI performs **no** remediation — there is no approve/execute step.
Render the returned actions to the operator as a numbered menu. For each
`ACT-N` show its `description`, `risk`/`reversible`, and the **copyable
command** (`manual_command`) verbatim in a fenced block, e.g.:

> **ACT-1** — iptables REJECT outbound to 203.0.113.10:8080 · risk: low · reversible
> ```
> iptables -I OUTPUT -d 203.0.113.10 -p tcp --dport 8080 -m comment --comment TRUDI_RESPOND -j REJECT
> ```

If a host alias for the victim is registered in
`~/cases/.common/live_hosts.json`, you may also show the
`ssh <alias> -- <manual_command>` form so it runs from a normal terminal.
Tell the operator plainly: "run any of these yourself to contain — nothing
is executed for you." Skip actions whose `unresolved_placeholders` is
non-empty (evidence was missing) or flag them as incomplete.

### 6. Close the investigation

The investigation always closes at the end of the tick (there is no
approval/execution to wait on):
```
monitor.end_investigation(case_id, investigation_id,
    outcome_note="<detector mix / verdict / recommended commands>")
for alert_id in bundle.alert_ids:
    monitor.ack_alert(case_id, alert_id)
```
`end_investigation` writes the recommended commands into the report's
**Recommended Containment Commands (run manually)** section, so the runnable
commands are preserved in the report even after the tick ends.

### 7. Write last-seen seq

Update `~/cases/<case>/monitoring/_last_check_seq.txt` to the highest
seq we **drained** in step 2 (whether or not the investigation closed
this tick). The drained alerts are accounted for in the open
investigation's tracker — they don't need to be re-drained next tick.

## Substrate choice — `velo.*` first, `live.*` only if registered

The alerts came from Velociraptor; the same Velociraptor client is the
canonical investigation surface for this case. Default plan:

- For any artifact-based pivot, use
  `velo.collect_artifact(client_id=<from alert>, artifact=<name>)`
  → `velo.wait_for_flow` → `velo.get_collection_results`.
- For ad-hoc one-shot VQL, use `velo.query(...)`.
- Only fall back to `live.*` SSH tools if BOTH:
  - `~/cases/.common/live_hosts.json` registers a host alias for this
    victim (check it; refuse to call `live.*` otherwise), AND
  - the pivot has no equivalent Velociraptor artifact.

Common detector → recommended `velo.collect_artifact`:

| Detector | Primary artifact |
|---|---|
| `Custom.TRUDI.NewProcess` | `Linux.Sys.Pslist`, then `Linux.Sys.ProcessOpenFiles` |
| `Custom.TRUDI.NewPersistence` | `Linux.Sys.SystemdUnits` (for `.service` paths), `Linux.Sys.Crontab` (for cron paths), or `velo.query("SELECT FullPath, Size, Mtime, IsLink, LinkTarget FROM stat(filename=<path>)")` for symlink/inode inspection |
| `Custom.TRUDI.NewNetwork` | `Linux.Network.Netstat`, then `Linux.Sys.Pslist` keyed by PID |
| `Custom.TRUDI.YaraProcess` | `Linux.Sys.Pslist`, then `velo.query(...)` for memory regions |

DAIR's `priority_tools` directive is binding when it lists specific
MCP tool names — but if those names are `live_*` AND `live_hosts.json`
doesn't register the victim, translate to the equivalent
`velo.collect_artifact` call and record the substitution via
`misc.record_self_correction`.

Pass `_note` on one tool per parallel batch.

## Notes

- The investigation chain runs **once per bundle**, not once per
  alert. The bundle's evidence is the union of every alert's evidence,
  and a single `dair_assess` decides what to investigate for the whole
  set. DAIR's Scan→Triage push will surface per-host pivots inside
  that one investigation if cross-host evidence appears.
- `start_investigation` is idempotent — calling it again with the same
  `investigation_id` rehydrates the existing trace and returns
  `rehydrated_entries > 0`. The slash command can crash, the operator
  can interrupt, the /loop can fire again; nothing is lost.
- If `dair_assess` returns `next_phase: "Report"` inside an
  investigation, that's fine — call `reason.synthesize` +
  `reason.pre_report_check` and let `end_investigation`'s auto-export
  produce the report. The case-wide trace stays minimal.
- The command should be quiet when there's nothing to do — the
  `/loop 15s ...` invocation pattern fires constantly.
