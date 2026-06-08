---
description: "Clear a TRUDI case for a fresh run — preview everything, confirm, then wipe outputs + project memory (and live monitoring state)"
argument-hint: "[case_id]"
---

# /trudi-clear-case

Resets a case to a clean slate. Removes the investigation outputs and the
case's Claude project memory, and for a **live-monitoring** case also
stops the watcher and removes the monitoring state (alerts + everything
under `monitoring/`).

**Destructive and irreversible** — `misc.clear_case_run` hard-deletes (no
backup). This command therefore **previews everything it will remove and
requires explicit confirmation before deleting anything.** If the
operator wants a *backup-taking* reset of just the output dirs instead,
point them at `python -m tools.trudi_reset --case-dir <case> --purge-outputs`.

The argument, if supplied, names the case. Otherwise read it from
`~/cases/.common/active_case`.

## What is removed vs. preserved

| Removed | Preserved |
|---|---|
| `analysis/*`, `exports/*`, `reports/*` (except `generate_pdf_report.py`) | `CLAUDE.md` |
| `~/.cache/trudi/session.json` | `.claude/settings.json` (tool allowlist) |
| `~/.claude/projects/<encoded-case-dir>/memory/*` (the case's project memory) | any `evidence/`, mounted images |
| **live:** `monitoring/` (alerts, response, baselines, watchers, artifacts, seq/open-inv state) | top-level case data files (e.g. `ground_truth.json`) |
| **live:** TRUDI cache counter/hook-state (via `trudi_reset`) | `~/.cache/trudi/hash_cache.json` (evidence-hash memo) |

The project-memory deletion is **case-scoped**: `clear_case_run` encodes
the *case dir* (`/home/trin/cases/<case>` → `-home-trin-cases-<case>`),
so it can never touch the global `~/.claude/projects/-home-trin/memory/`.

## Steps

### 1. Resolve the case
1. `case_id` = `$ARGUMENTS` if non-empty, else `cat ~/cases/.common/active_case`. Refuse if neither is set.
2. `case_dir` = absolute path `~/cases/<case_id>` (expand `~`). Confirm it exists. Use the **absolute** path everywhere so the encoded memory path resolves correctly.
3. Detect **live**: the case is live-monitoring if `<case_dir>/monitoring/` exists. Otherwise treat as static-evidence.

### 2. Build the removal preview (read-only — delete NOTHING yet)
Enumerate the *actual* targets so the operator sees exactly what will go.
Use read-only shell (`ls`, `find … | wc -l`, `du -sh`) — no `rm`:
- **Outputs:** list contents of `analysis/`, `exports/`, `reports/`
  (note the `generate_pdf_report.py` exception if present). Show each
  file (or a count + total size if large).
- **Project memory:** compute `encoded = <abs case_dir>` with `/`→`-`;
  list files under `~/.claude/projects/<encoded>/memory/` (state "none"
  if the dir is absent/empty).
- **Cache:** note `~/.cache/trudi/session.json` will be removed (and,
  live, the call-id counter / hook-state reset).
- **Live only:**
  - `monitor.list_watchers(case_id)` — list watchers that will be
    **stopped** (client_id + alive/dead). (Ensure an execution log is
    active first: if `core.execution_log.log._path` is unset, call
    `misc.start_execution_log(case_id, "<case_dir>/analysis/<case_id>_trace.json")`.)
  - Summarize `monitoring/` that will be removed: alert payload count,
    response suggestion/approval/execution counts, baselines present,
    rendered detector artifacts, watcher pid/log files, and the
    `_open_investigation.json` / `_last_check_seq.txt` / `_inv_seq.txt`
    state.

Render this as a clear itemized list to the operator (markdown), grouped
by the table above, with concrete paths and counts — not just
categories.

### 3. Confirm before deleting
After printing the preview, call `AskUserQuestion`:
- **question:** `"Clear case <case_id>? This permanently deletes everything listed above (no backup)."`
- **options:** `"Proceed — clear all listed"` and `"Cancel"`.
  Do **not** mark either as recommended (this is destructive).

If the operator picks **Cancel** (or anything other than an explicit
proceed), stop immediately and delete nothing. Only continue to step 4 on
an explicit "Proceed".

### 4. Execute (only after confirmation)
In order:
1. **(live) stop watchers** — for each watcher from step 2,
   `monitor.stop_watcher(client_id, case_id)` so nothing writes into
   `monitoring/` mid-delete.
2. **clear outputs + project memory** —
   `misc.clear_case_run(case_dir="<absolute case_dir>")`. Surface
   `cleared_count`, `cleared`, and any `errors`.
3. **(live) remove monitoring state** — `rm -rf <case_dir>/monitoring`.
4. **(live) reset cache cleanly** — `python -m tools.trudi_reset --case-dir <case_dir>`
   (resets `call_id.counter` to `{"next": 1}` and clears `hook_state.json`
   under the fcntl lock; never hand-edit cache files). For static cases
   this step is optional — include it only to zero the counter for a
   truly fresh run, and note it touches the **shared** TRUDI cache, so
   avoid it while another case is mid-investigation.

### 5. Report
State the case_id, live vs. static, the count of files removed, whether
`monitoring/` was dropped, and that `CLAUDE.md` / settings / evidence /
`ground_truth.json` were preserved. For a live case, remind the operator
to run `/trudi-start-watcher` to bring monitoring back online (it will
re-baseline against the current victim state).

## Notes
- If the case dir is the operator's *primary* working directory (rare for
  TRUDI cases, which live under `~/cases/<case>`), double-check the
  encoded memory path in the preview before confirming — you never want
  to wipe the global memory index. For standard `~/cases/<case>` layouts
  this is safe.
- This does not reset the **victim host**. After clearing a live case,
  the next baseline captures whatever state the victim is currently in;
  restart/clean the victim separately if you need a pristine known-good.
