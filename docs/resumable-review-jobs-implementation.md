# Resumable evidence review and accountable jobs

Implemented 2026-09-21. The existing authorized evidence fetcher and DAIR phase
router remain the execution paths. The new controllers persist unfinished review
and exact work obligations across calls and MCP restarts. There are no case,
artifact-name or model-backend exceptions.

## Review contract

`reason.synthesize(findings, investigation_summary="", input_call_ids=[],
review_session_id="")` automatically resumes the current review, or validates an
explicit session ID. `next_arguments` supplies a valid continuation call.

| Status | Meaning | Next action |
| --- | --- | --- |
| `in_progress` | A bounded slice ended with review still outstanding | Resume synthesis; retain Report unless typed follow-up work routes elsewhere |
| `blocked` | A coverage, access, budget or factual issue needs repair | Address the named blocker; repeating unchanged input does not refill its budget |
| `complete` with `approved=true` | Current factual coverage and every consistency task completed, with no blocking issues | Run `reason.pre_report_check` |

The trace persists session/task identities, queued requests, displayed-evidence
receipts, access failures, issue decisions, cumulative provider calls and tokens.
Checkpoint events do not change the investigation fingerprint. Finding/source
changes replace only dependent tasks; policy/rendering changes invalidate the
corresponding review. Invalidated task usage remains in cumulative totals.

Initial prompts contain complete active claims and a deduplicated source index.
Rows come through the existing fetcher. The 96,000-character guard covers the
assembled system/user input, including provider-specific prompt additions.
Task planning reserves 40,000 characters for fetched evidence and continuation
state. An oversized single task returns an explicit blocker; it never silently
omits an assertion or source.

An exchange retains the three-round/four-request fetch bound. Requests beyond
that slice remain queued, including a finding requiring thirteen sources.
Successful identical versioned requests are cached across tasks after rechecking
the receiving finding's source permissions. Coverage
must name examined assertions and valid displayed receipts. A complete zero-hit
search can support a scoped negative; a refused request or incomplete source
cannot. Empty issues and transport success alone never approve review.

Consistency tasks compare actual descriptions, typed claims, entities, windows
and citations. They reuse completed individual factual review, fetching again
when needed. If one comparison fits, use it; otherwise deterministic blocks and
all block pairs ensure no cross-batch pair is skipped. Open reviewer objections
receive explicit adjudication tasks instead of restarting completed findings.

Defaults: 24 provider requests per task across resumptions, including transport
and format retries; `TRUDI_SYNTHESIS_TASK_CALLS` configures the allowance. Provider
usage counts include failed attempts that report usage. Transient provider failures
leave the checkpoint retryable. An explicitly increased configured allowance can
resume an exhausted task with its existing call count intact; ordinary retries
never replenish it. Existing watchdogs remain.

## Job contract

Every job stores its run ID, trace path, original tool/arguments, working directory,
prescribing lineage, phase, source versions and exact work obligation. The worker
executes the complete registered wrapper, including batches, fallback parsing,
metadata annotation and finalization. It verifies ownership again before execution.
A reconnect retains the run; replacing an investigation creates another run ID.
Legacy traces acquire a stable run ID once. Unverifiable legacy jobs remain listed
for recovery and never attach automatically to a new run.

| Surface | Behavior |
| --- | --- |
| Original long-tool call | Waits up to 15 seconds for complete finalization; otherwise returns `job_id` |
| `misc.job_list` | Lists ownership, lifecycle, live writers and registry-generated adapter policies |
| `misc.job_status(job_id)` | Reads progress or imports the finalized result; never launches fallbacks |
| `misc.job_cancel(job_id, reason)` | Requests process-group shutdown, confirms whether writers stopped, preserves validated records |
| `misc.record_disposition(target_kind="job", target_id=job_id, ...)` | Settles only that collected job's obligation, with its result citation and a reasoned note |

The default capacity is two jobs. Capacity and destination conflicts are refused
with the relevant job IDs; there is no queue. Settings are
`TRUDI_JOB_INLINE_WAIT`, `TRUDI_MAX_JOBS`, and `TRUDI_BACKGROUND_JOBS`.
`core/job_adapters.py` is the authoritative registry for supported long wrappers.

Worker manifests retain file hashes, versions, validation methods, completeness,
wrapper metadata and reproduction recipes. Adapter/finalizer code hashes and loaded parser-library versions are
recorded; external binary version strings are available when emitted by the tool.
First collection verifies hashes. Repeated collection reuses the trace record and
checks immutable file-version metadata, avoiding repeated full-file hashing.
A crash between trace commit and job-state commit recovers the same call ID.

Execution success, typed `result_status` and `scope_complete` are independent.
Interrupted CSV/TSV/JSONL/text outputs can expose separate validated record prefixes;
cut records and unreadable known containers are excluded. Opaque interrupted
formats remain retained for subsequent validation. Completed opaque outputs retain
the adapter's completion assertion, identified as such in their validation method.
YARA workers preserve completed per-file records as they scan.

A partial result ends the worker lifecycle but leaves the original scope open.
A narrower follow-up never silently closes broader work; the remainder needs
justified settlement. Traced reads retain partial-source completeness, so reading
a prefix cannot turn it into negative evidence. Report and DAIR consult the same
obligation ledger. Tool-wide and generic follow-up dispositions cannot settle jobs.

Both reset entrypoints refuse while any relevant worker or child process can
write, even with `--force`. Cache-only resets retaining the investigation keep its
run ID. An explicit cancellation can finalize a dead worker's retained outputs
without restarting extraction. Polling an orphan identifies that recovery action.
Collected terminal registry records expire after 30 days in bounded cleanup;
uncollected jobs, trace records and forensic outputs are retained.

## Validation and measurement

Only synthetic fixtures, mocked provider replies and read-only historical replay
are used. No investigation was started and no live provider was called.

Tests cover continuation/restart, thirteen sources, large finding sets, exhaustive
comparison pairs, zero-fetch refusal, complete zero-match semantics, selective
invalidation, persisted retry budgets, real response parsing, issue adjudication,
citation suggestions, worker ownership, concurrent collection, crash recovery,
reset refusal, exact job cancellation/settlement, output tampering, wrapper
finalization, validated partials and inherited read completeness.

Verification results (2026-09-21):

- Core and tool suite: **2,084 passed**, with the sandbox-sensitive routing
  transport test selected out and verified separately.
- Local dashboard, chain viewer and mounted tool dispatch: **30 passed** outside
  the sandbox; the real MCP routing integration also **passed**.
- Additional scoped-negative zero-match regression: **passed**. Final focused
  synthesis/provider/recovery checks: **260 passed** after adding transient-failure
  recovery and explicit budget-increase handling.
- Python compilation and `git diff --check`: **passed**.

The repository and installed Claude/OpenCode guidance both carry the continuation
and job-settlement contract. Reconnect/restart the MCP server before the next
operator-started investigation so its loaded Python modules and tool schemas use
these changes.

Historical replay command:

```sh
/home/trin/.venv/bin/python scripts/offline_synthesis_replay.py \
  /home/trin/analysis/vanko-run-review-2026-09-21-053409/trace-snapshot.json
```

The previous trace contains 10 active findings, 47 source aliases and 32 physical
sources. Its new source index is 31,724 characters. The largest initial task
prompt measured by the replay is 42,723 characters, or 82,723 with the reserved
40,000-character evidence allowance. This excludes optional investigator narrative
and runtime scope framing; the assembled-input guard checks those too. The earlier
displayed packet was 140,237 characters, beyond the 96,000-character limit.
Replay made zero provider calls and pushed zero initial evidence rows.

Trace/session counters expose maximum prompt size, provider calls/tokens, cached fetches, reused tasks,
elapsed review time and job polling calls. Offline replay establishes bounded
input and retained source access; it does not establish a live speedup or reviewer
accuracy. Compare these counters, finished scope, report completion and factual
quality in the next investigation started by the operator.
