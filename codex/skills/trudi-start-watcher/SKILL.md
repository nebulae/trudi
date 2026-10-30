---
name: trudi-start-watcher
description: Start or check TRUDI live-monitoring producers for a case, including signed CEF ingest and baseline-backed endpoint watchers.
---

Resolve the explicitly named case, otherwise use the current case directory's
CLAUDE.md. Use the shared active_case file only if neither identifies a case.
Read that case's instructions and monitoring/config.json. Use actual
`trudi-sift` MCP tools; the dotted names here describe their namespaces.

Initialize the case execution log through misc.start_execution_log only if
none is active. Preserve existing traces. If an investigation is open, resume
it with monitor.start_investigation rather than redirecting its trace.

Call monitor.list_watchers. Reuse an already-running producer for the case;
do not stop it merely to make the setup command succeed.

For a case with cef_ingest configuration, start monitor.start_cef_ingest if it
isn't running. Confirm its configured signed sender, source-client binding,
and decoy endpoint. Raw UDP is collection-only. A pure external-detection
case such as WINDECOY-DEMO does not need another host-detector subscription.
Its response source still needs an existing baseline for the current client.

For a host-detector case, resolve the current client using velo.list_clients,
preferring the most recent matching hostname. Reuse its baseline. Capture a
missing baseline only when the host is known clean; never absorb current
attack artifacts to satisfy a setup prerequisite. Start monitor.start_watcher
with the case's intended detectors; surface every returned warning.

Confirm the producer is alive and report its client ID, PID, signing posture,
and dashboard URL. Do not start an attack, acknowledge alerts, or weaken
response policy. Use $trudi-watch-alerts when the operator wants the analyst
loop running; obey an explicit exercise hold.
