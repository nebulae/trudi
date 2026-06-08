---
description: "Start the TRUDI live-monitoring watcher (baseline + detectors + sidecar) for a case"
argument-hint: "[case_id]"
---

# /trudi-start-watcher

Brings a TRUDI live-monitoring case online: resolves the live
Velociraptor client, ensures a baseline exists, renders the
`Custom.TRUDI.*` detectors onto the client event table, and spawns the
watcher sidecar that drains alerts into `monitoring/alerts/`.

The argument, if supplied, names the case. Otherwise read it from
`~/cases/.common/active_case`.

## Steps

### 1. Resolve the case
1. `case_id` = `$ARGUMENTS` if non-empty, else `cat ~/cases/.common/active_case`. Refuse if neither is set.
2. `case_dir` = `~/cases/<case_id>`. Confirm it exists and looks like a live-monitoring case (has `monitoring/` or a `CLAUDE.md` describing Velociraptor). If it has no `monitoring/` scaffold yet, that's fine — `baseline_capture` creates it.

### 2. Ensure an execution log is active (gate prerequisite)
`monitor.*` tools are blocked by the DAIR cold-start gate unless a trace
is configured. If `core.execution_log.log._path` is unset, call:
```
misc.start_execution_log(case_id, output_path="<case_dir>/analysis/<case_id>_trace.json")
```
This (re)establishes the case-wide orchestration trace, which the
`/trudi-check-alerts` loop also expects. Surface the returned
`dashboard_url`.

### 3. Resolve the LIVE client_id (do NOT trust CLAUDE.md)
The victim re-enrolls and rotates its `C.xxx` id (container restarts,
`down -v`). Always resolve it fresh:
```
velo.list_clients()
```
- Pick the client whose `hostname` matches the case's target host
  (see the **Target host** row in `<case_dir>/CLAUDE.md`, typically
  `victim`). If several match, prefer the most recent `last_seen_at`.
- If `velo.list_clients` returns nothing, the stack is down — surface a
  one-line warning ("Velociraptor has no enrolled clients; bring up the
  demo stack first") and exit.
- If the resolved id differs from the **Velociraptor client_id** row in
  `CLAUDE.md`, update that row (move the old id into its history note).

### 4. Ensure a baseline for THAT client_id
Check `<case_dir>/monitoring/baselines/<client_id>.json`.
- If missing (e.g. the client rotated), capture one:
  ```
  monitor.baseline_capture(client_id, case_id)
  ```
  The baseline is the known-good allowlist; only capture it when the host
  is in a clean state (a freshly-restarted/clean victim). If the summary
  shows unexpected `persistence_paths` / `endpoints`, note that the
  baseline may have absorbed pre-existing artifacts.
- Optionally remove stale baseline files for dead clients
  (`baselines/<old_client_id>.json`) so the directory only holds the
  active client.

### 5. Start the watcher
```
monitor.start_watcher(client_id, case_id)            # all four detectors
# or restrict: monitor.start_watcher(client_id, case_id,
#               detectors=["Custom.TRUDI.NewNetwork", ...])
```
`start_watcher` refuses if no baseline exists, or if a watcher is
already alive for this `(case, client)` pair — surface either refusal
verbatim rather than retrying. On success it returns the sidecar `pid`,
the `pid_file`/`log_file`, and the uploaded detector artifacts.

### 6. Confirm + report
- Confirm the sidecar pid is alive (`ps -p <pid>`).
- Report: client_id, the four detectors registered, the watcher pid, and
  the dashboard URL.
- Remind the operator they can now stage activity on the victim and run
  `/loop 15s /trudi-check-alerts` to investigate alerts as they fire.

## Notes
- This is orchestration, not investigation — no `dair_assess` /
  `reason.*` chain is required, only the active execution log from step 2.
- One watcher per `(case, client)`. To restart cleanly after a config or
  detector-template change, run `/trudi-stop-watcher` first, then this.
