# Background jobs for long tools

Status: implemented 2026-09-21. See [delivery notes](resumable-review-jobs-implementation.md)
for the final contracts, defaults and validation. The rationale below records the
pre-implementation behavior.

Scope constraint, as in the sibling plans: rules must generalize across
investigations, evidence types and backends. Historical runs supply regression
fixtures only; no case, artifact, actor or expected conclusion in runtime logic.

## Why

`core/jobs.py` (`start_job` / `job_status` / `list_jobs`) has existed since
`032f426` (2026-08-28) and has **exactly one caller**: `net.tcpxtract_streams`
(`tools/network.py:667`). Every other long tool blocks its turn under a hard
timeout and, on overrun, returns a failure with nothing salvaged:

| Tool | Timeout | On overrun |
|---|---|---|
| EZ tools (`ez_lecmd`, `ez_jlecmd`, …) | `DEFAULT_TIMEOUT` 300s | fail, no partial |
| `ez_evtxecmd`, `ez_recmd_dir`, `ez_recmd_hive` | `VOL_TIMEOUT` 600s | fail, no partial |
| `carve_foremost` | 1h | fail, no partial |
| `carve_bulk_extractor` | 2h | fail, no partial |
| plaso | 6h | fail, no partial |
| `net.tcpxtract_streams` | 30m | **job: partial output retained** |

Observed 2026-09-20 (run 4): `ez_lecmd -d /mnt/<vol>/Users` and
`ez_jlecmd -d /mnt/<vol>/Users` each consumed the full 300s and returned
failures — ten minutes of wall clock, no LNK or jump-list evidence, and an
invitation to read the silence as absence.

The agent contract meanwhile tells the agent that "carve-class tools … **and
other long carves** return a `job_id` immediately" and that "a timed-out carve
still yields usable partials". Both statements are true only of the one wired
tool. The contract must become true, or be corrected.

## What to change

### 1. Which tools run as jobs

Background a tool when its input scope is **unbounded by the call** — a
directory tree, a mounted volume or a whole image — rather than a single named
file, plus the always-long set:

- **carve.\*** — `bulk_extractor`, `foremost`, `scalpel`, `photorec`
- **plaso.\*** — `create_timeline`, `create_targeted`
- **EZ directory mode** — `lecmd`, `jlecmd`, `pecmd`, `mftecmd_dir`,
  `recmd_dir`, `recmd_batch`, `sqlecmd`, `evtxecmd` when given a directory
- **yara.scan_directory**, **misc.readpst_extract** / **pff_export** on a large
  store, **tsk_recover**

Decide per call from the resolved input (directory vs file), not from the tool
name alone: `ez_pecmd -f one.pf` stays synchronous, `-d <Prefetch>` may not.
`hash_directory` already has its own bounded/resumable contract and is out of
scope.

### 2. Inline fast path — do not add a round trip to short runs

`start_job(..., inline_wait=N)` waits up to N seconds (default ~15) for the
complete operation (including fallback parsing and finalization) to finish.
A completed operation returns the ordinary synchronous fields immediately; a
longer operation returns a running `job_id`. Both retain durable ownership state. Most EZ runs over a small tree
finish in under a second; they must not become two-call operations.

### 3. Preserve the originating tool identity (correctness core)

`record_tool_call` stamps `mcp_tool` from `current_mcp_tool`, the ContextVar of
the **tool currently executing** (`core/execution_log.py:37,1355`). A job's
completion entry is written from inside `misc.job_status`
(`core/jobs.py:146`), so it would be stamped `mcp_tool="misc_job_status"` — the
wrong identity — while carrying the right `cmd`.

That breaks exactly what `3700cef` fixed:

- **tiering** — classes granted by tool identity (`mcp_tools` in
  `data/fk/tiering.yaml`) would not apply, so a finding citing the job loses its
  artifact class and cannot reach its proper tier;
- **work_order** — "did the prescribed tool run?" matches on `mcp_tool`, so a
  prescribed tool run as a job reads as never-run and DAIR re-prescribes it;
- any other gate keyed on tool identity.

Required: the job state records the originating tool (and its argument shape),
and the completion `tool_call` is stamped with **that** identity, not the
poller's. Same for `input_call_ids` (the prescribing DAIR call at *start*
time, not at collection time) and `output_path`.

**Identity is not enough — the job must own its investigation run.** State
records the originating **case id, trace path, phase/scope and work
obligation** at start time — and a durable **run identifier**, because case id
and trace path are both reused when the same case is reset. Without it, an old
detached job can write into, or be collected by, the *new* investigation of the
same case at the same path. The run id is minted at `start_execution_log`,
preserved across MCP reconnects, and **changed when the investigation is replaced**.
A cache-only reset retaining the investigation keeps its run id.

Both reset entrypoints refuse while a worker can write, including with
`--force`, and identify jobs the operator must cancel and collect, and it never hands a
reused output directory to a new run while a previous run's worker may still
write into it. Jobs outlive the turn and the operator may switch cases between start and
poll; without ownership, `job_status` collects a carve of case A into case B's
trace, with case B's phase stamped on it. A poll from a different case reports
the job as foreign and collects nothing; the result lands in the trace that
started it, or nowhere.

**Completion must run the tool's own finalization.** A synchronous run does
more than log: `ez_evtxecmd` annotates `coverage_window` and the
`session_artifact` marker from the parsed CSV (`_attach_evtx_coverage`), and
`ez_pecmd` falls back to libscca when PECmd refuses off-Windows. Collection
that skips these produces an entry that is citable but stripped of exactly the
metadata the gates read — a `negative_completeness` check with no coverage
window, a Prefetch job that "succeeded" with an empty CSV. Each job-backed tool
registers a finalizer shared by its synchronous and job paths.

**The finalizer runs in the worker, before completion is published — not at
collection.** The evidence plan requires production-time hashes (§12); a later
poll cannot certify what existed when the process finished, and an output
modified between completion and collection would be hashed as if it were the
original. So the worker, on process exit, runs the finalizer, writes the output
manifest and hashes durably into the job state, and only then publishes
completion. `job_status` collects that durable result; it never computes it.
This also keeps potentially expensive work — a libscca fallback parse over a
whole Prefetch directory — out of the poller's turn.

### 4. A timed-out job is incomplete, never absence

Partial output is real evidence and must stay usable, but the completion entry
must be explicitly incomplete: `timed_out=true`, a scope/coverage marker that
`negative_completeness` reads, and the produced-file count. A negative claim
("no jump lists for this user") cited to a timed-out job is refused, with the
refusal naming the truncated scope. This is the same absence-vs-silence rule the
evidence-access plan applies to refused fetches.

**Making the partial output actually citable takes more than a flag.** Packet
construction rejects a cited call whose `success` is not `True`
(`core/evidence_packets.py`), so a timed-out job — exit non-zero — is refused
as evidence no matter what `timed_out` says, and the files sitting in its
output dir are unreachable. Specify the positive-partial case explicitly:

- a timed-out job with produced output is recorded as a **partial success**,
  and that is **two separate decisions**, never one:
  1. *Are these particular records valid and citable?* Files existing is not
     enough — an interrupted container or a CSV cut mid-record is not evidence.
     Partial output is admitted only after validation (complete records, a
     readable container), carrying `scope_complete=False` and its produced-file
     manifest.
  2. *Was the requested scope completed?* No. `core/phase_routing.reconcile_job`
     (`:229`) currently marks any finished result whose `success` is not
     `False` as **completed work**, so a partial success would release its
     Report blocker with collection unfinished. A partial result must finish
     the *job* while leaving the **work obligation explicitly outstanding** for
     the unmet scope — settled only by a further run, a narrower re-run, or a
     typed disposition;
- the packet builder admits it on that basis and marks every selection from it
  incomplete, so a miss over it can never read as absence;
- a job that produced **nothing** stays a plain failure, and needs the usual
  tool-failure closure (retry, named fallback, or typed disposition).

### 5. Work-order and readiness interaction

- A **started** job satisfies "the prescribed tool is running" — DAIR must not
  re-prescribe it, and must not treat it as complete either.
- `reason.pre_report_check` **blocks** while a started job has never been
  collected: an uncollected job is an unexamined source, not a non-event.
  `list_jobs` supplies the open set.
- **Abandoning a job is a specific lifecycle operation, not a generic tool
  disposition.** A `target_kind="tool"` disposition names a *tool*, while
  Report follow-up obligations identify individual *requests* — and a running
  follow-up cannot be waived at all (`tools/misc.py:1073`). So abandonment is
  settled **by job id and its linked obligation**: cancel the worker (or wait
  for it to finish) first, then release the blocker. Otherwise abandonment
  either leaves reporting blocked forever, or lets an active writer outlive the
  investigation that started it.
- The agent contract's polling instruction stays: poll `misc.job_status`
  between other work, never idle on a running job.

### 6. Concurrency, lifecycle and hygiene

- Cap concurrent jobs (suggest 2–3); a further start returns a typed "queued or
  refused" result naming the running jobs, never a silent serialization.
- Refuse a second job writing into the same `output_dir`.
- Identical `(cmd, output_dir)` already running returns the existing `job_id`
  rather than a duplicate run.
- Jobs are detached and survive an MCP restart; `job_status` must re-attach and
  collect after a reconnect, and `list_jobs` must surface orphans from a prior
  session.
- GC job state files under `~/.cache/trudi/jobs` on a bounded age, never
  deleting one whose output has not been collected.
- `needs_sudo` jobs keep working (the carve path already does this).

### 7. Make the contract match

`claude/CLAUDE.md`, `claude/PILOT.md`, `opencode/AGENTS.md` and
`docs/agent-contract.md` list which tools are job-backed **from one source of
truth** (the same table the code selects from), not a prose list that drifts.
Correct the current claim that all long carves are job-backed. Update the
installed profiles, not only the repository copies.

## Acceptance criteria

1. A registered directory-scope EZ run that exceeds `inline_wait` returns a `job_id`; the
   same tool on a single file returns a synchronous result with no job.
2. A run finishing inside `inline_wait` returns the ordinary synchronous fields and a citable result; durable
   job state is retained so ownership and collection remain recoverable.
3. A collected job's `tool_call` carries the **originating** tool identity:
   tiering grants that tool's artifact class, and the work-order gate counts the
   prescribed tool as run.
4. A started-but-uncollected job: DAIR does not re-prescribe the tool, and
   `pre_report_check` blocks naming the open job. After stopping and collecting it, only a
   job-targeted disposition settles that exact obligation.
5. A timed-out job with validated complete records admits those records as partial evidence; its
   selections are marked incomplete, and a negative claim citing it is refused
   by `negative_completeness`; a timed-out job that produced nothing is a plain
   failure requiring closure.
5a. A poll issued while a different case is active collects nothing and reports
   the job as foreign; the result lands in the trace that started it.
5b. The worker runs the tool's finalizer before publishing completion: a job-backed `ez_evtxecmd` carries the
   same `coverage_window` and `session_artifact` markers as its synchronous
   run, and a job-backed `ez_pecmd` falls back to libscca off-Windows.
5c. A crash between start and collection loses neither the job nor its
   ownership: after restart the job is collected once, into its own case.
5d. **Same case, same path, new run:** resetting a case while its previous job
   is still alive never lets that job write into or be collected by the new
   run; reset refuses, including with `--force`, and lists jobs to cancel.
5e. A validated partial result is citable **and its work obligation stays
   open**; an interrupted container or a CSV cut mid-record is not admitted.
5f. Two jobs of the same tool: abandoning one by job id releases only its own
   obligation, and only after its worker is cancelled or finished.
5g. An output modified between worker completion and collection fails
   verification against the worker-recorded hash.
6. Starting an identical `(run_id, tool, arguments, source_versions, output_roots)` returns the running `job_id`, and a
   second job into the same `output_dir` is refused.
7. Over the concurrency cap, a start returns a typed capacity-refused result (no queue)
   naming the running jobs.
8. A job survives an MCP server restart: `job_status` re-attaches, collects
   once, and `list_jobs` shows it as open beforehand.
9. Collection is exactly once under concurrent polls (two pollers, one
   `tool_call`).
10. Job state files are GC'd by age, never while uncollected.

## Risks

- **A forgotten job is an unexamined source.** Mitigated by the readiness block
  (§5); without it, backgrounding trades a visible timeout for an invisible gap.
- **Resource contention.** Several carves over one mounted image will thrash;
  hence the cap (§6).
- **Disk.** Carve output is large and partial output is retained by design; GC
  must not delete uncollected output, so the case's disk budget is the operator's
  concern — surface produced bytes in `job_status`.
- **Identity drift.** If §3 is skipped, jobs silently degrade tiering and the
  work order — the failure mode `3700cef` already fixed once.
