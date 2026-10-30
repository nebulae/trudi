---
name: trudi-stop-watcher
description: Stop a TRUDI case's CEF ingest or endpoint watcher producers while preserving alerts, investigations, and evidence.
---

Resolve the explicitly named case, otherwise the current case directory.
Read its instructions. Through trudi-sift MCP, call monitor.list_watchers and
stop the requested live producers:

- client_id cef-ingest: use monitor.stop_cef_ingest(case_id).
- An enrolled endpoint client ID: use monitor.stop_watcher(client_id, case_id),
  which removes that case/client's monitoring subscription.

Report each result. Do not clear alerts, reports, traces, response history,
baselines, Windows logs, or another client's monitoring configuration. Stopping
the analyst's waiting loop alone does not stop these producers.
