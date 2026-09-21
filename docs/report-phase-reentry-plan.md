# Automatic DAIR re-entry for report follow-up work

Status: implemented, 2026-09-20; isolated validation passed. Live investigation outcomes remain under evaluation.

## Delivery and validation

`core/phase_routing.py` now supplies action classification, durable reservations,
transition/replay, result reuse, explicit refresh, source-version checks and
pending-work projections. Middleware validates the session-visible tool schema
before committing a transition and continues the original invocation through the
normal tool path. Typed synthesis/pre-report actions can register follow-up work;
legacy prose or incomplete action arguments require specification. Packet failures
remain repair failures. Production DAIR entry to Report uses shared readiness and
pending-work checks. Matching async receipts and explicit supported dispositions
settle work; phase movement does not approve findings.

The selected execution-log, middleware, DAIR, reasoning, review, disposition and
guidance suites passed **574 tests**. The real FastMCP integration test separately
passed, including tool-schema discovery, argument validation, same-call execution,
duplicate-result reuse and explicit refresh. A broader sandbox test run timed out;
the broader unsandboxed run was not approved. These results are not a claim that
the full repository suite passed.

Repository client profiles and trace/dashboard rendering are updated. Run-start
profile fingerprints distinguish installed guidance from repository copies.
Installed Claude/OpenCode profiles were synchronized with backups at 21:40 UTC;
no investigation or MCP server was restarted. Deployment hashes and backups are
in `/home/trin/analysis/report-phase-reentry-validation-2026-09-20/`.
Directory input versions currently track directory metadata, not recursive content
hashes; this does not establish immutability of every descendant. Live comparisons
must freeze code/configuration, and packet-selection, source-discovery and response
delivery defects remain separate work. The Vanko run started at 21:14 UTC while
implementation was in progress, so it is not a controlled end-to-end comparison.

## Intended behavior

When a report review identifies required collection or analysis, or the client requests an authorized forensic operation while in Report, transition through DAIR to the appropriate phase **before the operation executes**. Preserve the pending review, perform the required work once, and return to Report only when its prerequisites are satisfied.

Use the same rules across cases, backends and evidence types. Case names, known answers, operating-system paths and particular artifact names must not determine routing.

## Original gaps addressed by this implementation

- `core/middleware.py::_gate_decision` rejects non-allowlisted calls in Report and tells the client to call DAIR. It does not schedule or make the transition.
- `reason_synthesize` checks prerequisites and constructs evidence packets but does not route unresolved collection/analysis work before returning a refusal. Its bounded evidence fetcher reads retained outputs; it is not a forensic execution engine.
- `reason_pre_report_check` directly sets `_current_phase` to Analyze and pops Report. This bypasses a durable transition event; `_rehydrate_phase_state` replays only `dair_call` entries.
- `core/execution_log.py::record_tool_call` marks every Report-phase tool result as a forensic violation, including permitted readers and failed synthesis control calls.
- DAIR can enter Report before the shared deterministic readiness assessment passes. Phase changes and tool-only completion checks therefore cause avoidable backtracking.

The latest Vanko trace demonstrates the blocked-then-retry sequence, but supplies a regression example rather than runtime policy.

## 1. Define action semantics once

Extend the existing tool/capability metadata with a shared classifier used by middleware, DAIR, reasoning and trace auditing. Classification must consider resolved inputs and source provenance as well as the tool name.

| Requested action | Routing |
| --- | --- |
| Read/paginate already-produced evidence; inspect saved review details | Stay in Report |
| Correct a finding, qualify wording, record a supported disposition | Stay in Report; invalidate approvals affected by the change |
| Acquire, extract or parse a new source/scope | Collect |
| Compute a new correlation, comparison or evidentiary conclusion from available artifacts | Analyze |
| Execute a discovery scan | Use the existing Scan phase where its capability requires it |
| Unknown tool, invalid arguments or underspecified target | Return `needs_specification`; do not execute or change phase |
| Source-access, transport or packet-construction defect | Return a typed repair failure; do not invent a collection obligation or repeatedly change phases |

Do not blanket-exempt every `read.*` call: a retained-output read differs from opening an uncollected source. Likewise, a missing reviewer row may require fetching existing output rather than collecting new evidence.

Separate **required work** from optional suggestions. Only an accepted required obligation or an actual authorized tool request triggers re-entry. A suggestion mentioning a forensic tool does not.

## 2. Centralize and persist transitions

Introduce a shared phase-transition service in the execution-log/DAIR layer. Both model-directed DAIR transitions and deterministic report-reentry decisions use it.

- Persist an explicit transition event with old/new phase, case/scope, originating call or issue, obligation/request ID, reason, authority (`model` or `policy`) and the report checkpoint being suspended. Do not fabricate a model assessment for a deterministic transition.
- Update the live phase/stack through the same reducer used for restart replay. Replay historical DAIR entries and new transitions; retain compatibility for historical pre-report entries carrying `phase_returned_to`.
- Resume the appropriate existing frame in the same scope, or create one follow-up frame if needed. Repeated requests for the same work must not keep pushing Report/Collect frames. Preserve genuine child-investigation scope.
- Store transitions and pending-work reservations under the existing transaction lock. Release the lock before model or forensic execution.
- Use a phase revision and pending-work state to prevent another request from returning to Report while collection/analysis is reserved or running. A failed transition cannot allow the operation to run under the old phase.

For clear, already-authorized requests, use deterministic DAIR policy: no additional model call is needed merely to decide that extraction belongs in Collect. Ambiguous investigative choices can still use `dair.assess`.

## 3. Route direct tool requests before invocation

In middleware, validate and classify the request before calling the underlying tool. If Report requires re-entry, commit the transition and link the requested operation to its obligation, then continue that original call once all existing authorization, scope and tool gates pass.

The tool response includes a compact transition notice and identifiers, alongside the normal result. The client should not have to repeat the same call just because its initial phase was Report.

Give each request a stable identity from the case/run, tool, normalized arguments, relevant source versions and obligation. Track reserved/running/completed/failed states using the existing work-order/readiness projections rather than adding an unrelated task queue. Distinguish an intentional refresh from a duplicate delivery.

Handle cancellation and lost responses explicitly. Do not promise exactly-once external execution: reuse a committed result when available; return in-progress for running work; reconcile an unknown outcome before retrying. Async forensic jobs keep their obligation pending until completion or a justified disposition.

Replace the misleading `tool_blocked` event for a successful automatic re-entry with a transition/request event. Genuine refusals remain auditable.

## 4. Route synthesis follow-up before execution

Extend the existing structured review issues with optional action data: required/optional status, capability, proposed tool, target/scope, arguments when known, completion criterion and source/finding dependencies. Resolve these against server metadata and collected evidence; do not execute instructions extracted from free-form reviewer prose.

- Before synthesis: use shared readiness. If an accepted blocker requires new work, persist the obligation, transition to Collect/Analyze and return `status="follow_up_required"` with the pending review and runnable work. Do not spend a synthesis model call first.
- During synthesis: allow bounded, scoped reads of retained outputs without a phase change. If the reviewer establishes a real collection/analysis gap, save its pending review state, register required work and transition before any forensic operation can run.
- Keep forensic execution in the normal tool path. Synthesis may hand off typed work, but must not secretly invoke arbitrary forensic tools inside its model/fetch loop.
- If targets or arguments are incomplete, request specification through DAIR/client guidance rather than guessing. Optional enrichment does not silently become a report blocker.
- A packet-access bug remains a packet-access bug. Transitioning cannot repair a misclassified output path, omitted source rows or an unavailable backend.

On success, link the actual result to the obligation and affected findings. New evidence requires the appropriate renewed review; phase movement alone never approves a finding or resolves a contradiction.

## 5. Make return to Report use the same readiness contract

Guard every entry to Report with `assess_readiness(include_synthesis=False)`, plus unresolved/running follow-up work. Do not require completed synthesis to enter Report: synthesis remains Report work.

Completion receipts must match tool/capability, target, scope and relevant source versions. “A tool with this name ran” does not satisfy a different source or a broader absence claim. Retain a compatibility path for historical traces without treating incomplete legacy receipts as exhaustive coverage.

When follow-up is settled, permit one recorded return to Report with the pending review linked. Rebuild/revalidate affected evidence packets and invalidate stale synthesis/readiness approvals using the existing semantic fingerprint system. Reuse unaffected evidence and successful extraction outputs.

Remove `reason_pre_report_check`'s direct in-memory mutation. It uses the shared router: collection gaps go to Collect, analytical gaps to Analyze, report-local corrections stay in Report. Missing synthesis alone stays in Report and points to synthesis; otherwise the checker would move the investigation out of the only phase where synthesis is allowed.

Repeated synthesis with the same unresolved obligation returns the same bounded handoff state without another model call or transition. No-progress failures expose a concrete repair action or limitation instead of a blind retry instruction.

## 6. Align audit, client guidance and deployment

- Use the action classifier for protocol violations. A failed `reason.synthesize` or permitted evidence read in Report is not forensic execution.
- Recognize synthesis attempts across control and tool-level failure entries. Report “synthesis attempted; blocked by …” accurately.
- Surface pending work, phase revision, transition origin and completion status in bounded guidance and existing trace/dashboard views.
- Update Claude and OpenCode profiles to explain automatic routing, report-local reads and pending review continuation. Verify the installed profiles as well as repository copies; record their fingerprints at run start.
- Update the follow-up roadmap/delivery status only as individual behaviors ship. Keep packet-selection and mail-handoff repairs as separate prerequisites for a reliable end-to-end evaluation.

## Implementation order and acceptance

1. **Classifier, transition reducer and replay:** add generic unit fixtures for all action classes, stack reuse, historical replay and durable restart. Centralize auditing immediately so new transitions cannot create false violations.
2. **Direct request routing:** integrate middleware reservations and continuation. Prove transition is recorded before tool start, the tool executes once on the normal path, other gates remain effective, and concurrent/retried requests do not duplicate work or permit premature Report entry.
3. **Synthesis/readiness handoff:** add typed obligations, pending-review responses and return-to-Report checks. Test real collection gaps, analysis gaps, optional suggestions, source-access errors, missing synthesis, failed jobs and report-local corrections separately.
4. **Client and end-to-end validation:** deploy matched profiles, then run isolated scenarios across disk, memory, network, cloud and documentary capabilities using different source/subject names. Freeze code/configuration during each comparison.

Required outcomes: no authorized forensic operation starts in Report; permitted report reads stay there; no redundant model call just for an unambiguous transition; no extra caller retry for automatic direct-call re-entry; restart and live state agree; equivalent repeated requests do not inflate the stack; unrelated tool success cannot close an obligation; unchanged failures do not cause synthesis loops; and final reports still require current, independent review approval.

Measure phase refusals, unnecessary DAIR/synthesis calls, repeated extraction, time from review gap to completion, stale-approval rejection and factual quality. A completed phase transition or shorter failed run is not evidence of a successful investigation.
