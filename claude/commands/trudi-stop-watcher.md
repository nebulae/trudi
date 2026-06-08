---
description: "Stop the TRUDI live-monitoring watcher(s) for a case (SIGTERM sidecar, clear event table)"
argument-hint: "[case_id]"
---

# /trudi-stop-watcher

Stops the live-monitoring watcher sidecar(s) for a case: SIGTERMs the
detached `trudi-velo-watcher.py` process(es) and removes the
`Custom.TRUDI.*` artifacts from the client event table so no new alerts
are drained.

The argument, if supplied, names the case. Otherwise read it from
`~/cases/.common/active_case`.

## Steps

### 1. Resolve the case
`case_id` = `$ARGUMENTS` if non-empty, else `cat ~/cases/.common/active_case`.
Refuse if neither is set.

### 2. Ensure an execution log is active (gate prerequisite)
If `core.execution_log.log._path` is unset, call
`misc.start_execution_log(case_id, output_path="~/cases/<case_id>/analysis/<case_id>_trace.json")`
so `monitor.*` calls pass the DAIR cold-start gate.

### 3. Enumerate watchers
```
monitor.list_watchers(case_id)
```
Each record carries the `client_id`, alive/dead state, uptime, and alert
count. If none are alive, print `"No live watchers for <case_id>."` and
exit (nothing to stop).

### 4. Stop each alive watcher
For every watcher reported alive:
```
monitor.stop_watcher(client_id=<from the record>, case_id=case_id)
```
The response reports `killed_pid`, whether the stop was `graceful`, and
`event_table_cleared`. If a `pid_file` lingers for an already-dead
process, note it (it's harmless; `start_watcher` overwrites it).

### 5. Report
List each stopped watcher: `client_id`, killed pid, graceful/forced,
event-table-cleared. State that no further alerts will be drained until
`/trudi-start-watcher` is run again.

## Notes
- Stopping the watcher does **not** clear already-drained alerts,
  investigation traces, or response suggestions — use `/trudi-clear-case`
  for that.
- The victim host itself is untouched — this only stops TRUDI's
  collection of its events.
