---
description: "Event-driven TRUDI live-monitoring loop — wake on a new alert within seconds (no 60s /loop floor) and auto-respond"
argument-hint: "[case_id] [interval_seconds]"
---

# /trudi-watch-alerts

A **second-granularity, event-driven** alternative to `/loop 15s
/trudi-check-alerts`. `/loop` re-fires on the scheduler, which clamps to a
**60s floor**, so a 15s loop really polls ~once a minute. This command instead
runs a persistent **waiter** (`bin/trudi-alert-waiter.py --follow`) under the
harness **`Monitor`** tool: the waiter watches the case's `monitoring/alerts/`
directory every *N* seconds (default 2) and prints one line **each time** new
alerts land; `Monitor` turns each line into a notification that wakes me
immediately. I then run the same investigation + auto-protect flow as
`/trudi-check-alerts`. Detection is already real-time (the Velociraptor sidecar
streams alerts as they fire); this closes the gap on the *agent* side, with
time-to-response ≈ the poll interval instead of a minute.

The first argument names the case (else read `~/cases/.common/active_case`).
The second, if given, is the waiter poll interval in seconds (default `2`).

## Why Monitor, not a one-shot background task

A one-shot waiter that exits on the first alert must be **re-armed** by the
agent after every investigation — and that re-arm step is easily dropped when
the agent dispatches into the long `/trudi-check-alerts` flow, so the loop runs
once and dies (alerts that arrive after the first batch are then missed). The
`Monitor` tool runs the `--follow` waiter **persistently**: it keeps emitting an
event per new-alert batch with no re-arm, and alerts that land *while I'm
investigating* still queue as later events. This is the robust mechanism.

## Steps

### 1. Cold start (operator invoked this command)
1. Resolve `CASE` (argument or `cat ~/cases/.common/active_case`); `N` = second
   argument or `2`.
2. **Pre-warm the response tool schemas — do this NOW, while nothing is on fire.**
   `monitor_*`/`respond_*`/`velo_*` are deferred tools; loading their schemas
   mid-alert cost a real run **~30 s of ToolSearch latency before it could even
   contain**. Load the whole live-response set in ONE batched call up front so
   every tick is warm:
   ```
   ToolSearch("select:monitor_list_watchers,monitor_open_investigation_state,monitor_check_alerts,monitor_get_response_state,monitor_next_investigation_id,monitor_start_investigation,monitor_extend_investigation,monitor_set_awaiting_approval,monitor_clear_awaiting_approval,monitor_end_investigation,monitor_ack_alert,monitor_baseline_extend,respond_snapshot_evidence,respond_suggest_containment,respond_execute_action,respond_revert_action,respond_approve_action,velo_collect_artifact,velo_wait_for_flow,velo_get_collection_results,velo_query")
   ```
   The forensic tools (`reason_*`, `dair_assess`, `misc_record_finding`, …) are not
   on the latency-critical path — let them load when step 6 begins. Once loaded,
   a schema stays callable for the rest of the session: **do NOT re-`ToolSearch`
   per tick.**
3. `monitor.list_watchers(CASE)` — confirm a sidecar is alive. If none, STOP and
   tell the operator to run `/trudi-start-watcher` first (without the sidecar the
   alerts directory never fills).
4. **Start the persistent watcher** with the `Monitor` tool:
   - `command`: `python3 ~/trudi/bin/trudi-alert-waiter.py --follow --case-id <CASE> --interval <N>`
   - `description`: `new TRUDI alerts for <CASE>`
   - `persistent`: `true`
   The `--follow` waiter reads `monitoring/_last_check_seq.txt` for its start
   cursor (so already-drained alerts aren't re-reported) and emits one JSON line
   per new batch. Tell the operator: "👁️ Watching <CASE> — I'll act within
   ~<N>s of each new alert. Say 'stop watching' to end."

### 2. On each Monitor event
Each event is one JSON line, e.g. `{"status":"ALERTS","new_seqs":[10,11]}`.
Run the **full `/trudi-check-alerts` flow** (its steps 1–9, in order): open/extend
the investigation, then **contain → eradicate → investigate-for-record** —
(4) snapshot + auto-execute the **reversible/low-risk** containment straight off
the alert, before any reasoning; (5) for a confirmed-positive alert, resolve the
kill target with ONE fast pivot and immediately **queue the destructive
eradication for approval** via a popup (`AskUserQuestion`, approve option labelled
with the `ACT-N`) — seconds after containment, NOT after the finding ceremony;
(6) run the full hypothesize → DAIR → findings → report investigation for the
court-record (it never blocks the response, and reverts containment / drops a
still-queued kill if it clears the alerts as benign); then (7–9) handle approvals,
`end_investigation` + ack + update `_last_check_seq.txt`.

**Do NOT re-start the Monitor** — it is still running and will deliver the next
batch on its own. Just finish the investigation and stop; the next event wakes
me again.

## Pausing & approvals

If `/trudi-check-alerts` left an investigation **paused** awaiting approval, the
Monitor keeps running — new unrelated alerts still surface and fold into the
open investigation via `extend_investigation`. The operator's approval arrives
either as a popup selection (`AskUserQuestion`, approve option labelled with the
`ACT-N`) or a typed `approve ACT-N`; either way handle it
(`respond.approve_action` → `respond.execute_action(mode="operator")` →
`monitor.clear_awaiting_approval`), then continue.

## Stopping

Use `TaskStop` on the Monitor task (or the operator says "stop watching" and I
stop it). The detector sidecar keeps running; use `/trudi-stop-watcher` to stop
detection itself.

## Why this is safe to run autonomously

Same guardrails as `/trudi-check-alerts`: the waiter is read-only (it only
watches the alerts directory, never touches evidence), and all response goes
through the gated `respond.*` path — the reversible+low tier auto-executes,
everything destructive still requires an explicit operator approval (a popup
selection or a typed `approve ACT-N`); the agent cannot self-approve.
