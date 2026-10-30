---
name: trudi-watch-alerts
description: Keep a Codex turn watching a TRUDI case for new alerts and run the live investigation workflow when they arrive.
---

Accept a case ID and optional polling interval in seconds, for example
`$trudi-watch-alerts WINDECOY-DEMO 1`. Use one second when the interval is
omitted. Resolve the explicit case first, otherwise the current case directory.

Read the case instructions and $trudi-check-alerts. Confirm a producer with
monitor.list_watchers; use $trudi-start-watcher if the operator requested
startup and none is running. Respect an explicit exercise hold before
draining alerts. Check queued alerts and any open investigation first.

Codex does not provide Claude's Monitor, TaskStop, or /loop workflow. Use the
repository's read-only bin/trudi-alert-waiter.py in one-shot mode:

    python3 <repo>/bin/trudi-alert-waiter.py --case-id <CASE> --cases-root <CASES_ROOT> --since-seq <CURSOR> --interval <SECONDS> --timeout 30

This interval polls the local alert queue. Run the full check-alerts workflow
when work arrives, not once per idle second. Sensor detection, collection, and
investigation have their own latency; a one-second poll is not a promise of
one-second containment or completed findings.

Run it with exec_command, then poll that same session with write_stdin if it
yields. Wait at most 30 seconds per poll so operator input remains responsive.
On ALERTS, execute $trudi-check-alerts. On HEARTBEAT, check producer health and
continue waiting. Keep the turn active; a detached process does not wake an
idle Codex agent automatically. Do not promise monitoring after ending the turn.

Keep the notification cursor separate from the completed-work cursor. Advance
the waiter's in-memory CURSOR to the highest sequence it has surfaced, so a
pending unacknowledged alert does not cause a tight repeat loop. Advance the
case's _last_check_seq.txt only for work actually completed and acknowledged.
On every wake, use monitor.check_alerts and the open investigation state to
retain unfinished work; the notification cursor never acknowledges an alert.
Alert files remain queued during collection, including alerts arriving while
the investigation is running. Keep a pending action attached to its open
investigation; avoid reopening it or issuing duplicate prompts.
Send brief status updates during long waits. When the operator asks to stop,
stop waiting and report pending work; the producer remains running unless the
operator also requests $trudi-stop-watcher.

The signed CEF sidecar can independently apply its configured reversible
containment while the analyst is idle. That is separate from the agent's
investigation loop.
