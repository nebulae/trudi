---
description: "Event-driven TRUDI live-monitoring loop — wake on a new alert within seconds (no 60s /loop floor) and auto-respond"
argument-hint: "[case_id] [interval_seconds]"
---

# /trudi-watch-alerts

A **second-granularity, event-driven** alternative to `/loop 15s
/trudi-check-alerts`. `/loop` re-fires on the scheduler, which clamps to a
**60s floor**, so a 15s loop really polls ~once a minute. This command instead
arms a lightweight background **waiter** (`bin/trudi-alert-waiter.py`) that
watches the case's `monitoring/alerts/` directory every *N* seconds (default 2)
and **exits the instant a new alert lands**. Its completion fires a harness
task-notification that wakes me immediately — so time-to-response is the poll
interval, not a minute — and I run the same investigation+auto-protect flow as
`/trudi-check-alerts`, then re-arm the waiter. Detection is already real-time
(the Velociraptor sidecar streams alerts as they fire); this closes the gap on
the *agent* side.

The first argument names the case (else read `~/cases/.common/active_case`).
The second, if given, is the waiter poll interval in seconds (default `2`).

## Loop mechanics

This command runs in two situations, distinguished by context:

**(A) Cold start — invoked directly by the operator.**
1. Resolve `CASE` (argument or `cat ~/cases/.common/active_case`).
2. `monitor.list_watchers(CASE)` — confirm a sidecar is alive. If none is
   running, STOP and tell the operator to run `/trudi-start-watcher` first
   (without the sidecar the alerts directory never fills). Do not arm the
   waiter against a dead watcher.
3. **Arm the waiter** as a detached background Bash task (this is the only
   thing this step does, then the turn ends):
   ```
   python3 ~/trudi/bin/trudi-alert-waiter.py --case-id <CASE> --interval <N> --timeout 900
   ```
   Run it with `run_in_background: true`. The waiter reads
   `monitoring/_last_check_seq.txt` itself, so it only fires on alerts newer
   than the last drained tick (and returns immediately if some are already
   pending). Tell the operator: "👁️ Watching <CASE> — I'll act within ~<N>s of
   the next alert. Interrupt and say 'stop watching' to end the loop."
4. End the turn. The harness wakes me when the waiter exits.

**(B) Wake — the background waiter task just completed.**
Read its one-line JSON result:

- `{"status": "ALERTS", "new_seqs": [...]}` — run the **full
  `/trudi-check-alerts` flow** (its steps 1–8: open/extend the investigation,
  hypothesize → dair → tool batch → record findings, then the auto-protect
  stage — auto-execute the reversible+low tier, queue/pause destructive ones
  for `approve ACT-N`, print rollbacks — then `end_investigation` + ack). When
  it finishes, **re-arm the waiter** exactly as in (A) step 3 and end the turn.

- `{"status": "HEARTBEAT"}` — no alert for the timeout window. Do a fast
  liveness check: `monitor.list_watchers(CASE)` (warn + stop re-arming if the
  sidecar died) and `monitor.get_response_state(CASE)` (re-surface any
  `approve ACT-N` still pending). Then **re-arm the waiter** and end the turn.

## Pausing & approvals

If `/trudi-check-alerts` left an investigation **paused** awaiting `approve
ACT-N`, keep re-arming the waiter as normal — new unrelated alerts still
surface, and they fold into the open investigation via
`extend_investigation`. The operator's `approve ACT-N` arrives as a normal
prompt (not a background task); handle it (`respond.approve_action` →
`respond.execute_action(mode="operator")` → `monitor.clear_awaiting_approval`),
then continue the loop.

## Stopping

The loop continues as long as I keep re-arming the waiter on each wake. To
stop: the operator interrupts and says "stop watching" — then I simply do not
re-arm. (The detector sidecar keeps running; use `/trudi-stop-watcher` to stop
detection itself.)

## Why this is safe to run autonomously

Same guardrails as `/trudi-check-alerts`: the waiter is read-only (it only
watches the alerts directory and never touches evidence), and all response goes
through the gated `respond.*` path — the reversible+low tier auto-executes,
everything destructive still requires an operator-typed `approve ACT-N`.
