Investigation success review — 2026-09-21

The synthesis defects in [vanko-synthesis-churn-review.md](vanko-synthesis-churn-review.md)
should be fixed first. Additional code and policy changes are warranted. The
highest priorities below correct false completion, false invalidation and repeated
review. Broader workflow changes should follow as separate increments, retaining
evidence admission, independent review and justified scope settlement.

This review inspected the current working tree, used the previously captured
882-entry trace, and ran isolated in-memory/temporary-directory checks. It did
not change application code or start, stop or modify an investigation. Findings
about code paths below are not all demonstrated causes of the current live run.

**1. Unify all required work under exact scoped obligations. Fix now.**

[work_order.py](/home/trin/trudi/tools/_gates/work_order.py:167) matches prescribed
tools against binary signatures anywhere in the trace. It strips arguments and
also accepts tool-wide dispositions. The newer job/report work ledger tracks
exact requests, so there are two definitions of completion.

Reproduction: a successful `strings.grep` on `alpha.bin` leaves no outstanding
work for `strings.grep(path=beta.bin)`, despite beta never being examined.
[max_pass_cap.py](/home/trin/trudi/tools/_gates/max_pass_cap.py:91) also treats a
matching command and one claim token as verification. An empty strings result
against `archive.bin` matches the challenge “archive.bin contains invoice.”
DAIR can stamp that challenge `verified=true` through its prior-run path.

Give every required DAIR item an obligation ID, source/target, scope, dependencies
and completion criterion. Reuse the existing ledger, extending it to work at
planning time. Record `executed`, `scope_complete`, and the claim's evidential
outcome separately. A successful check can refute a claim; execution alone must
not confirm it. Reuse earlier work only when its coverage satisfies the request.

Acceptance: same tool/different target stays open; equivalent previous coverage
is reused; empty output does not confirm a positive assertion; settling one job
or target does not settle another.

**2. Correct input and output version tracking. Fix now.**

[phase_routing.py](/home/trin/trudi/core/phase_routing.py:44) versions directory
inputs using directory stat metadata. Changing a contained file need not change
that metadata. Conversely,
[finish](/home/trin/trudi/core/phase_routing.py:233) records output-directory
versions alongside exact output files; adding an unrelated file can reopen the
work as stale.

Both directions reproduced: adding an unrelated output changed `completed` to
`stale` while the original CSV was unchanged; modifying a file inside an input
directory did not change `source_versions`.

Use versioned input manifests appropriate to the operation's declared scope.
Use exact produced-output manifests for completion, excluding parent-directory
metadata when membership is not part of the evidence contract. Detect relevant
membership changes without recursively hashing an entire case on each poll.

Protect cited outputs as part of this increment. The saved trace has three
successful extractor invocations targeting the same `evtx_all_e01.csv` (calls
68, 346 and 812); this establishes repeated extraction invocations against one
destination, not that every invocation changed the output bytes. Reuse a completed result when
input scope/version, normalized arguments, parser/configuration and validated
outputs match. A deliberate refresh must publish a new output version and keep
the old cited version readable. Destination protection must cover synchronous
wrappers as well as background jobs. `start_job` currently deduplicates only
unsettled jobs, while middleware reuse depends on tracked work and freshness.

**3. Extend resumability to finding evaluation. Fix next.**

[finding_submission.py](/home/trin/trudi/core/finding_submission.py:149) caches
successful commits and recognizes active leases. A completed failed submission
with the same key/request returns no cached result. Evaluation can therefore
restart, including its evidence exchange and provider allowance.

The isolated check confirmed that an unchanged `needs-evidence` submission is
not returned from cache. The saved run contains 33 evaluation calls for 20 finding
records, although revisions and legitimate evidence changes explain some of that
difference; these counts alone do not establish redundant calls.

Persist evaluation tasks, required requests, receipts and cumulative budgets.
Unchanged factual/access failures should return their existing repair requirement;
transient failures should resume. A changed selector or evidence version should
invalidate only the affected work. Keep factual disagreement, missing evidence,
access failure and provider failure as distinct outcomes in submission responses.

**4. Replace heuristic repetition advice with state-aware progress checks. Fix now.**

[middleware.py](/home/trin/trudi/core/middleware.py:245) keys repetition by tool
and arguments, without run/source version. Its refusal text states that a repeated
negative is evidence of absence. Repetition does not establish scan completeness
or adequate scope; repeating a parser failure establishes neither.

First remove the false absence assertion from the notice/refusal text and add a
focused regression. This small correction should not wait for the full progress
tracking redesign below. Keep the existing negative-evidence gates intact.

Key the check to run, source version and normalized selector. Distinguish repeated
completed reads from failed access, pending work and resumed reviews. State only
what is established: no new observation since the last equivalent operation.
Route absence decisions through the existing completeness checks. Also detect
semantic stalls such as repeated questions with changed wording but unchanged
deciding evidence; respond with a concrete repair or bounded alternative, not an
instruction to manufacture a negative finding.

**5. Supply DAIR with authoritative state and applicable capabilities. Next increment.**

[dair.py](/home/trin/trudi/tools/dair.py:799) constructs the model input from the
agent's summary, supplied phase stack and case context. It does not automatically
include its separate `case_question` argument, active obligations or canonical
evidence/review state in that input. Subsequent server overrides repair parts of
the result, but the planner initially reasons from the supplied account.

Build a bounded planning snapshot from the durable run: question IDs, current
phase/scope, relevant sources, completed and pending obligations, findings and
new contradictions. Treat the caller's summary as supplementary. Keep DAIR
responsible for investigation planning, finding review for evidential support,
and synthesis for cross-finding consistency.

The fallback [lifecycle tool list](/home/trin/trudi/tools/_gates/_lifecycle.py:179)
is Windows-centric. The postfilter in dair.py filters absent memory/pcap tools,
not all incompatible platforms or artifact types. Select fallback work through
declared tool input requirements and the actual inventory. Do not prescribe a
Windows artifact merely because a generic investigation phase is uncovered.

**6. Make inconclusive answers an explicit reportable outcome. Next increment.**

[readiness](/home/trin/trudi/tools/_readiness.py:142) requires a CONFIRMED/LIKELY
finding marked `answers_case_question=True`; DAIR separately refuses Report with
zero findings. A well-supported negative finding can satisfy this, but there is
no separate question-resolution path for an investigation whose available
evidence cannot determine the answer.

Add reviewed question outcomes such as supported, refuted and indeterminate,
with completed scope, remaining uncertainty, unavailable-source dispositions and
supporting receipts. An indeterminate outcome must not waive unfinished feasible
work or erase a contradiction. It should allow an honest final report when the
investigation is complete but the answer remains unknown. Support multiple
question IDs rather than one boolean across an evolving question string.

**7. Separate the full inventory from mandatory case work. Next increment.**

The correspondent check in
[readiness](/home/trin/trudi/tools/_readiness.py:440) can require disposition of
every outbound/chat/roster correspondent when relevant claim classes are present.
The saved trace contains 105 correspondent `out_of_scope` dispositions among 130
total dispositions. That is a measurable administrative burden, not proof that
those checks were all unnecessary.

Keep the full inventory. Define explicit scope by question, time window, source
and relationships; material and ambiguous leads remain required. Allow reviewed
group dispositions with enumerated membership and shared justification. Preserve
near-alias safeguards and exhaustive coverage requirements for claims that assert
global absence. Batch transport already exists; improve scope policy rather than
adding another batching endpoint.

**8. Reuse review at the assertion level and stabilize issue identity. Later increment.**

Findings currently bind a complete description and citation set; synthesis reviews
each finding again. Editing one clause can replace the whole review task. Split
compound findings into typed observations, inferences and supporting assertions
with source receipts and dependencies. Reuse approved unchanged assertions;
review changed relationships and cross-finding consistency independently.

Both [review issue IDs](/home/trin/trudi/core/review_issues.py:71) and
[deterministic requirement IDs](/home/trin/trudi/core/readiness.py:54) depend on
message wording. Existing reviewer IDs can be reused explicitly, but new wording
otherwise creates new identities. Key requirements by stable assertion/scope and
failure category, retaining message history. Deduplicate only when those keys
agree; independent objections must remain separate.

**9. Track timed-out in-process operations honestly. Reliability increment.**

[timeout.py](/home/trin/trudi/core/timeout.py:25) returns failure while its daemon
thread continues, and includes a `killed_after_seconds` field despite not killing
the operation. Accountable detached jobs cover their own workers, not every such
thread. This is an inspected reliability risk, not an observed cause of the latest
synthesis churn.

Register in-flight review operations with run ownership and reconnectable status.
Cooperative cancellation/commit checks should prevent stale operations from
committing to a replacement run. Reset guards should cover all writers. A client
timeout must not invite duplicate work while the original is still active.

**10. Make exploration purposeful and test the complete investigation contract.**

The saved run grants curiosity allowances of two or three in seven early DAIR
assessments but records no curiosity probes. Zero probe records do not prove no
exploration occurred. Integrate a bounded optional discriminating check into the
normal work flow: unresolved question, competing explanations, available source,
expected observation and cost. Link probe intent to the actual result. Do not
require spending a quota or add a mandatory extra model call per phase.

Validation should include raw recorded provider responses, realistic source
formats and the complete chain from client response to the next agent action.
Mocked compliant responses alone missed the provisional-blocker loop. Use
synthetic truth fixtures across mail, tabular output, packet captures, memory,
non-Windows artifacts, partial extraction and benign/indeterminate cases.
Measure report completion, assertion accuracy, false blockers, repeated review,
retrieval success and provider cost together. Replay can verify the controller;
the next user-started run is needed to establish an actual speed/quality gain.

Recommended order: correct the false repetition guidance immediately; then
synthesis handoff/access fixes plus scoped obligations and output protection
(items 1 and 2); then resumable evaluation, authoritative planning and scoped
closure. Defer assertion-level reuse and the broader semantic repeat detector
until these changes have been measured. Keep timeout ownership independently
testable. None of these changes needs a Vanko-specific rule or a backend-specific
exception.

**Peer-review additions and qualifications — Fable review, 2026-09-21.**

The supplied review contains clipped passages. The following incorporates its
identifiable proposals; historical run-specific claims are distinguished from
what was checked in the current code/environment.

- **Failure dispositions:** add a truthful, request-scoped outcome for an
  applicable tool that is unavailable, incompatible or fails to parse its input.
  The current `tool` reasons are only `absent_from_evidence`, `inapplicable` and
  `out_of_scope`. A parser failure must not be labelled inapplicable or become
  a tool-wide waiver. Reference the failed call/job, exact scope, diagnostics and
  attempted/equivalent alternatives. Recording failure leaves the evidence
  obligation open; justified settlement must identify the remaining limitation
  and whether feasible alternatives were exhausted. Preserve validated partial
  observations. This belongs with item 1.
- **Claim-type consistency:** the saved findings 245 and 635 use `category: other`,
  `act: other`, `recipients: []`. The claim checker validates declarations and
  conditional fields but does not establish that their meaning matches the prose.
  Add a structured consistency check during the existing independent evaluation,
  before commit; do not add another model round trip or silently reclassify by
  keywords. A solicitation/agreement is not automatically a completed transfer,
  and the current enum lacks a specific solicitation act. Split mixed assertions
  or supply appropriate generic relationship types when needed. Genuine delivery
  assertions must not bypass recipient/transfer gates through `other`.
- **Tier headroom:** 13 of 20 historical finding records in the saved snapshot
  are LIKELY with `tier_achievable: CONFIRMED`; these include superseded revisions.
  A record-time headroom notice already exists in `tools/misc.py`. Its instruction
  that the tier must match in both directions can itself prompt more revisions.
  Retain an advisory explanation of headroom and any material uncertainty. An
  artifact-class ceiling is not proof that every causal or attribution assertion
  deserves the maximum confidence. Do not auto-upgrade or block reporting solely
  for conservative confidence. Distinguish misclassification from justified
  conservatism.
- **Environment readiness:** verify actual wrapper-resolved executables,
  interpreters, dependencies, rule packs and supported formats with safe startup
  and synthetic parsing fixtures. Feed results to DAIR with known alternatives.
  In the checked environment, `chainsaw` and `capa` are absent from PATH and the
  standard/active-venv executable locations. Hindsight's installed script uses
  `/opt/pyhindsight/bin/python3`; `hindsight.py --help` succeeds and reports
  v2026.01. That does not validate browser parsing, but a blanket current Python
  startup failure was not reproduced. The reviewed Vanko snapshot's USN failure
  is a missing mounted ADS path at call 128; parsing an extracted stream succeeds
  at call 176. A crash or sparse-stream defect from another run needs its own
  fixture. Cover ADS extraction, sparse ranges, parser failures and honest partial
  scope rather than treating all such failures as one dependency problem.
- **Scheduled-task reader:** accepting a single file is a supported improvement;
  the current implementation explicitly requires a directory. Also correct its
  completeness reporting: it reads at most 16,384 bytes per file, returns at most
  8,192 characters per task, and logs `truncated: false` while retaining principally
  a task-name summary. Preserve citable task records/source bindings, distinguish
  parse errors from absence, and mark bounded reads accurately. Test file and
  directory modes, long XML, encoding, partial reads and unreadable files.
- **Legacy job recovery:** current inspection found 94 registry JSON files: 84
  without the current schema (81 labelled running/uncollected, three finished/
  collected) and ten schema-2 complete/collected records. These labels alone do
  not establish whether legacy processes are alive. All files' modification times
  are under 30 days old. `gc_collected` already exists: it removes at most 32 owned,
  collected schema-2 terminal records older than 30 days, retaining forensic
  outputs. Add a recovery/archive path for legacy records after checking process
  ownership and preserving any uncollected results. Never delete an active worker
  or unverified evidence merely to reduce the registry count.

Measurement correction: unique query strings, revision IDs or request keys do
not measure independent investigative progress. Record new source observations,
assertions resolved, required scope completed, reused receipts and repeated
attempts to answer the same question. Retired review usage can include necessary
correction work; classify its cause before reporting it as waste. This qualification
also applies to the distinct-request count in the synthesis review.
