# Finding lifecycle and review workflow

Implemented scope: steps 1–4 of the trace review plan. Evidence packets supply the initial review context; existing bounded evidence fetching remains available for additional rows.

Follow-up: [additional improvements plan](investigation-improvements-plan.md) covers compact actionable guidance, evidence sharing, reviewer corrections, task completion and bounded exploration across evidence capabilities. The [curiosity assessment](curiosity-review.md) documents the baseline reasons for probe underuse. Historical runs supply regression examples, not case-specific runtime rules.

## Follow-up delivery status

The first implementation tranche adds:

- **Bounded guidance:** readiness, pre-report and synthesis responses stay within
  a 6,000-byte application payload budget, leaving transport headroom. Small
  responses retain their existing fields. Larger responses expose counts and
  explicit detail references. `reason.readiness_status(section=..., state_version=...)`
  reads the current projection; `reason.review_details(call_id=..., section=...,
  state_version=...)` reads a saved review without another model call. Join
  `json_chunk` fragments in `next_offset` order, then parse JSON; offsets are
  Unicode characters. Changed snapshots refuse mixed-version paging. Full
  pre-report results remain in the trace. Synthesis now refuses known
  deterministic prerequisites before invoking its model. Failed synthesis is
  reported as failed, rather than “not called.”
- **Shared synthesis evidence:** current finding review packets supply sources
  and selected rows, or are rebuilt when stale. Every active finding has a source
  mapping, including principal and full output path; finding/control entries no
  longer consume a twelve-source inventory limit. Repeated physical-source byte
  spans are shared while preserving citation provenance. The existing bounded
  fetcher remains available. Fetches may specify `finding_call_id` and `path`;
  a mismatch returns a scope error, not an absence result. Source and semantic
  snapshot checks guard final acceptance under the trace writer lock.
- **Reviewer-premise corrections:** a new independent synthesis can resolve an
  earlier issue with `basis="reviewer_error"`, the exact `incorrect_premise`,
  supporting call IDs and exact `evidence_quotes` from the versioned packet or
  actual fetched rows. Earlier evidence is eligible. Source/entry changes reopen
  these resolutions. Genuine contradictions still require evidence; simply
  repeating a review or deleting an objection does not close it.
- **Immediate curiosity repairs:** the grant check uses durable history under
  the same transaction as spending, so long batches and concurrent callers cannot
  lose or double-spend the current allowance. Readiness exposes grant/spend state.
  Absence-mode candidates become optional `exploratory_suggestions`, not binding
  work orders; an empty list does not trigger invented prose-derived tasks.
  DAIR, absence-mode prompts, slim descriptions and all four profiles explain the
  exception and follow the actual question/evidence, including benign alternatives.
- **PECmd path resolution:** `TRUDI_PECMD_DLL` explicitly selects the DLL;
  otherwise the wrapper checks `<TRUDI_EZ_ROOT>/PECmd.dll` and
  `<TRUDI_EZ_ROOT>/PECmd/PECmd.dll`. The root defaults to `/opt/zimmermantools`.
  Missing binaries remain distinct from parser/runtime faults. No binary was
  installed by this change; the default locations were absent at inspection.

**Report follow-up routing is now implemented:** the
[re-entry plan](report-phase-reentry-plan.md) records the delivered behavior and
validation. Validated forensic requests in Report transition before execution in
the same call; typed required review actions can register durable obligations.
Request identity includes exact canonical arguments and source versions, with
matching completion receipts, duplicate-result reuse and explicit refresh.
Production DAIR entry to Report enforces shared readiness and unresolved-work
checks. Permitted retained-output reads and report-local corrections stay in
Report. Packet failures remain repair failures, and independent review gates
remain in force.

This is not the complete roadmap. General task obligations outside Report
follow-up, pre-execution probe reservations, automatic probe-result recording,
starvation prevention, zero-supported-finding closure, and controlled live-agent
comparisons remain later work. The current
curiosity API still logs after execution and a new DAIR grant still resets its
batch allowance. Large synthesis contexts currently return an explicit
`needs-evidence` error above 96,000 serialized characters; automatic partitioned
review is not implemented. These limits must not be described as completed work
or measured speed/accuracy gains.

Tests cover generic source scopes, lossless large-response retrieval, old-evidence
correction, stale/incorrect proof rejection, shared rows, concurrent probe spends,
path resolution and synthetic end-to-end synthesis with a mocked backend. Load
the changed tools/profiles in new or restarted MCP/client sessions; do not hot-swap
code during a comparison investigation.

Validation on 2026-09-20: **1,975** core/tool/regression, Pilot-profile and
OpenCode-registration checks passed. **30** dashboard/chain-view/MCP-registration
checks passed separately with localhost access; the sandbox denied socket binding
for those tests. The new `reason_review_details` mounted name was also verified.
`git diff --check` and documentation link checks passed. No live model run or
paired accuracy/speed benchmark was performed, and existing case traces were not
modified by this implementation.

## Current findings

`core.findings.finding_view` provides active findings, history and lifecycle anomalies. The log index exposes active findings without changing historical `by_type` data. Synthesis, readiness, current coverage, attribution, reports and scorers use this projection. Historical evaluation spending and challenges still use the audit history.

New findings have `finding_id` and `revision`; `supersedes` is the expected current parent. Recording refreshes the trace and checks the parent under the shared writer lock. Missing/stale targets, branches and incompatible declared proposition fields are rejected. This is conservative typed validation, not a semantic equivalence classifier for arbitrary prose. Full descriptions and declared claim fields are sent to synthesis. Provider truncation is a failed review, never a complete result.

Legacy links are projected without rewriting the original trace. Ambiguous branches and incompatible links remain visible and block readiness. Withdraw an incorrect active branch with `misc.retract_finding`, a reason and supporting call IDs. History is retained. Reports append the canonical current finding inventory; trace markdown labels current and retired findings.

## Readiness and audits

Call `reason.readiness_status` before synthesis to aggregate deterministic prerequisites. It neither invokes a model nor requires synthesis. `reason.pre_report_check` runs the same policy with synthesis requirements and persists the report approval snapshot.

Call `reason.audit_findings` explicitly for substantive narration. Successful audits persist a cursor and content/policy/backend fingerprints. Repeating an unchanged audit uses the stored result. New narration is processed incrementally; changed findings, narration content or audit configuration invalidate the applicable cache. Overflow is exposed as `pending_narrations`; invoke again to finish the batch.

Report/export approval is tied to current findings, relevant trace records, evidence output file metadata and policy source hashes. Narration and audit bookkeeping do not expire approval. The final match and write occur under the shared trace writer lock. File metadata changes expire approval; this does not lock external evidence files against a separate process changing them during a write. Existing evidence provenance remains the source of recorded content hashes.

Historical boolean-only report approvals must be refreshed. Legacy synthesis records remain readable through compatibility checks; new synthesis records carry explicit snapshot coverage. Unchanged successful synthesis is cached. A newer failed attempt cannot be bypassed by an older cache entry.

## Structured review

Prompts request one versioned `RESULT` object with concise rationale and role fields. Explicit legacy formats remain adapters. Malformed or truncated responses receive at most one format-repair attempt, then return an explicit failure. DAIR failures are diagnostic reason entries and do not change phase. Pending/failed evaluations cannot authorize a supported finding. Failed or exhausted evidence-fetch loops cannot reuse a preliminary verdict.

Synthesis issues have stable IDs, kinds, finding revisions and evidence references. Omission in a later review does not close an issue. Resolution receipts require new evidence, a reviewed correction, or explicit retraction. Retired revision issues become obsolete; changed findings still require fresh synthesis. Only an evidence gap/unavailable source can become a limitation, with both a reviewed narrower finding and a typed evidence disposition. Contradictions cannot be waived by a round count. Report limitations are always appended, even if the submitted report already has a similarly named section.

## One-call finding submission

`misc.submit_finding` accepts one complete finding, an explicit evidence ID list,
a stable idempotency key, and a `claim` object using the typed `record_finding`
fields. It normalizes the request, checks deterministic prerequisites, runs the
existing independent evaluator, then applies every final record gate. A success
commits the finding; this is not a preview tool. Pilot profiles retain analyst
approval before writing.

```python
misc.submit_finding(
    description="The parsed source contains the Alpha record.",
    confidence="LIKELY",
    input_call_ids=[42],  # replace with actual evidence call IDs
    linked_call_id=42,
    idempotency_key="alpha-presence-v1",
    claim={"claim_kind": "positive", "category": "other", "act": "other",
           "entities": ["Alpha"]},
)
```

Statuses are `recorded`, `needs-evidence`, `contradicted`, `invalid` and
`retryable-review-failure`. Prerequisite refusals include independent issues and
next actions. No tier is silently lowered. Reuse the same key and exact request
after a timeout or lost response; the committed finding is the durable retry
receipt, even if the response was lost. Different content with the same key is
invalid. A review in progress returns a retryable status instead of starting a
second model call; its reservation expires after one hour if the worker dies.

Packets retain the exact observed byte spans, parsed CSV column names, output
SHA-256, producer call/command, recorded provenance/time basis, selected scope,
matching/shown counts, and retention completeness. Unknown source provenance
stays unknown. Invocation logs cannot replace a missing extractor output.
`hash.file` now retains its typed result as citable evidence. Agent-authored
files remain uncitable. An empty match in selected output never proves absence
across the original evidence set.

Optional `selectors=[{"call_id": 42, "path": "/actual/traced/output.csv",
"start_byte": 0, "end_byte": 4096}]` selects half-open byte ranges from that
call's retained output. Paths must belong to the cited call. Defaults select
relevant complete lines/CSV records, bounded by the configured push-row limit
and a 32,000-character packet text budget. A source exceeding 64 MiB, a packet
exceeding 256 MiB of scanned output, or more than 32 discovered sources requires
a narrower traced extraction. Original
extractor coverage is never inferred from output-file completeness. Further
rows can still be fetched during review from the packet's versioned sources.

Review receipts bind the exact description, all typed claim fields, revision
target, evidence versions and reviewer/prompt/policy identity. Unchanged reviews
can be reused after a final-gate refusal. A review already used to record a
finding cannot authorize another submission. Separate legacy evaluate/record calls
use the same packet and receipt checks for new reviews with explicit citations;
older trace entries retain the compatibility matcher. Evidence-free legacy
reviews cannot authorize new CONFIRMED/LIKELY findings.

No trace lock is held during model work. Before commit, the service refreshes
state under the writer lock, verifies the receipt and evidence versions, checks
the expected finding parent, and reruns the final gates. Unrelated narration
does not trigger another review. All existing tier, attribution, completeness,
anti-rewording and sticky-challenge constraints remain in force. Evidence files
are version-checked, not locked against external writers.

## Verification

`tests/tools/test_review_workflow.py` covers branching revisions, concurrent stale-parent writes, qualifiers, retractions, stale report approvals, evidence changes, audit caching, durable issues, malformed DAIR and incomplete fetch reviews. Existing core/tool, coverage, scorer and provider-compatibility tests cover the integration paths. Tests use temporary case paths and mocked model responses.

`tests/tools/test_finding_submission.py` covers exact packet selections and CSV
spans, invalid IDs, unchanged-review caching, concurrent submissions, backend
failures, restart/lost-response recovery, stale evidence, revision races, receipt
spending and complete typed-claim binding. Independent review and all final
gates remain active in submission tests; only model responses are mocked.

Read-only replay against the original traces identifies Bogus Bill's competing successors of finding 999 and CFREDS DeepSeek's incompatible 715→746 and missing-target 707→748 links. No historical case was migrated. The [Vanko DeepSeek 4.1 assessment](/home/trin/analysis/vanko-deepseek41-review-2026-09-20/review.md) documents an uncontrolled live comparison: lower DAIR overhead, higher review input tokens, incomplete coverage and no report. Controlled paired speed, cost and accuracy comparisons remain necessary.
