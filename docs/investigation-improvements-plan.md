# General investigation guidance and efficiency improvements

Status: implementation in progress, 2026-09-20. The design below includes later
increments; see the delivery status in [the workflow review](investigation-review.md)
for the subset actually implemented and validated. Do not treat this document as
a claim that the full roadmap has shipped.

Basis: [current workflow](investigation-review.md), [curiosity mechanism assessment](curiosity-review.md), prior trace assessments, and the [original implementation plan](/home/trin/analysis/trace-review-2026-09-19/implementation-plan.md). Steps 1–4 of the original plan are implemented. This follow-up repairs their integration before expanding the task/phase work in steps 5–6. Account for the already-landed live fixes; do not implement them again.

**Scope constraint:** every runtime rule and acceptance criterion must generalize across investigations. Derive work from the user's questions, actual evidence capabilities, observed results and unresolved alternatives. Never special-case a case name, known answer, actor, artifact filename, operating system or backend. Historical cases may supply regression examples, but do not define required artifacts or expected conclusions. Support disk, memory, network, mobile, cloud, live-endpoint and documentary evidence through capabilities; do not impose a host-forensics checklist on unrelated evidence. Benign and inconclusive outcomes are valid.

## Objective

Make valid guidance easy to consume and execute, recognize when its work is complete, and correct faulty guidance without sacrificing supported findings. Reduce repeated model work while preserving independent review, provenance, confidence rules, coverage and honest uncertainty.

We cannot guarantee that an unconstrained agent follows every instruction. We can make required state transitions depend on verified results, deliver actionable guidance at those transitions, and measure whether agents use it. Prompts explain the workflow; server checks enforce the applicable contract.

The design addresses general failure classes:

| Failure | Observed example | Required change |
|---|---|---|
| Guidance was inaccessible | A control response exceeds the client's usable context | Compact summaries, typed result retrieval and pagination |
| Guidance was mistaken | A reviewer searches a different source or subject and contradicts supported evidence | Finding-scoped source selection and a reviewer-error correction path |
| Completed work was not recognized | Equivalent completed work is requested again | Tool/target/scope completion receipts |
| Useful guidance was not completed | Relevant coverage remains open despite a completion claim | Prioritized obligations, closure checkpoints and truthful completion status |
| Exploration was suppressed or untracked | Optional probes wait behind expanding work orders; allowances expire from a short log window | Explicit exploration opportunities, durable budgets and linked results |

Adding more instructions to the existing large profiles would leave these problems in place.

## Guidance contract

Use three explicitly different classes throughout readiness, DAIR, tool results and profiles:

- **Invariant:** evidence must remain read-only; cited outputs must exist; a stale receipt cannot approve a changed claim. Enforced where the action occurs.
- **Required obligation:** a case-specific, accepted coverage or review requirement with an owner, target, completion condition and supporting reason. Blocks its dependent transition until satisfied, adjudicated or legitimately dispositioned.
- **Suggestion:** optional enrichment or an exploratory lead. It can be declined or deferred without creating a hidden report blocker.

Model suggestions become obligations only after validation against the evidence capabilities and existing policy/task state. A tool name alone is an underspecified proposal. Requests with missing targets or arguments return `needs_specification`; they must not force the agent to guess a command. A model-generated obligation can be challenged with evidence; it cannot become mandatory merely through repetition.

The same obligation ID must appear in the guidance, tool completion receipt and report-readiness result. Identify it by rule, target, source scope and finding revision, rather than hashing the entire changing English message. Keep the previous text and any scope changes in the audit history.

## Delivery sequence

### Added maintenance item: PEDmd / PECmd path

Track the requested “PEDmd path” fix as the PECmd Prefetch parser path unless
the operator identifies a different tool. Resolve configured deployments and
standard flat/nested installation layouts without searching evidence directories
or guessing a different executable. Expose a missing binary distinctly from a
parser/runtime failure. Test path selection, explicit override precedence and
genuine absence. At inspection, no PECmd DLL was found at the configured default
or standard nested path; correcting resolution does not install a missing parser.

### 0. Freeze the reproduction and instrumentation

Before runtime changes, preserve representative failures as isolated regression fixtures: source/subject confusion, omitted deciding rows, correction using pre-existing evidence, readiness overflow, completed-task mismatches, missed applicable coverage and lost exploration budgets. Parameterize source types, subjects, filenames, call IDs and ordering. Include unrelated and unavailable sources so that success requires selecting the relevant evidence, not memorizing a known answer.

Record run-level code/contract/prompt/config fingerprints, orchestrator model, each backend role/model, evidence versions and decoding settings. A code/policy change during a run must be reported as a policy change, not “evidence changed.” Mark such runs unsuitable for paired comparison. Keep answer keys outside the investigating agent's accessible case inputs and tools; use them only in the grading process.

Instrument requests at their entry point, including failures before trace reservation. Count submission attempts, deterministic refusals, model attempts, fetch/repair legs, cache reuse, response bytes, phase durations, scan timeouts and completed obligations. Do not treat fewer `finding_refused` events as fewer retries when refusals have moved to another event type. Separate backend and orchestrator token accounting; do not sum overlapping concurrent durations as elapsed time.

Exit: the selected failure classes can be reproduced without touching original cases, and every actual submission attempt is measurable.

### 1. Make guidance readable and immediately actionable

Extend the current readiness implementation with a versioned compact response. Keep complete internal assessment and evidence metadata in the trace. Initial engineering budgets: **8 KiB for the normal serialized control response, 2 KiB for an inline progress notice**, including common middleware metadata. These are configurable transport limits, not semantic truncation rules. If a field cannot fit, return an explicit stable reference and cursor; never silently cut a claim, error or completion condition.

The normal response should contain:

- Current state and semantic state version; `ready_for_synthesis`, `ready_to_report`, or an explicit failed/blocked status.
- Counts of required obligations, suggestions and pending review/audit work.
- Up to three prioritized runnable actions, each with obligation ID, reason, affected finding/source, canonical tool and validated arguments when known, and the exact completion condition.
- Structured pagination and detail references for remaining actions, evidence and inventories. The server evaluates the whole obligation set even when the client sees only its first page.

Use a supported typed read interface for persisted review results and readiness sections. Prefer extending existing reasoning/read APIs; settle names during implementation. The agent must not need to search a huge trace, read an internal MCP cache through Bash, or rerun a model to recover a verdict. Detail retrieval stays bounded and model-free. Old tool names remain available; migrate the response shape through an advertised workflow contract and client/profile tests.

Run the cheap readiness projection automatically before synthesis and a Report transition. Return unmet deterministic prerequisites before spending a synthesis call. Refresh or reuse its cached projection after material finding/task changes. Include small changed-state notices in relevant tool results. This removes dependence on remembering a separate readiness ritual; unchanged logging must not produce more model calls or repeated notices.

Files: `tools/_readiness.py`, `core/readiness.py`, `tools/reasoning.py`, `core/middleware.py`, result retrieval and client/profile tests.

Exit: large control responses remain consumable below the configured client budget; applicable coverage obligations are visible before synthesis and discretionary broad scanning; overflow and backend failure are distinguishable from a factual objection.

### 2. Give synthesis the same evidence the finding reviewer had

Build synthesis context from active finding revisions and their review receipts. Supply a source index grouped by finding, host/principal, full artifact path, producer and searched scope. Finding/control entries do not consume evidence-source slots. Every finding must have a visible evidence/receipt reference even when rows require paginated retrieval. For unusually large cases, explicitly partition the review and complete the cross-finding joins before declaring coverage complete.

Deduplicate identical physical source versions and overlapping row selections while retaining every originating call and claim link. Do not turn duplicate citations into independent corroboration. Keep full provenance in stored packets; pass the model only the metadata and rows needed for the current check.

The reviewer requests deciding rows by finding/source identity. A request for another principal's source returns an explicit scope mismatch where deterministically detectable; cross-principal comparisons remain possible when named as such. A zero match must identify the exact source and search completeness. It cannot establish absence in an omitted or different source.

Synthesis continues to assess relationships, time/identity joins and case-question coverage independently. A valid atomic review receipt can be reopened for a specific contradictory dependency or demonstrated review defect, with affected clauses identified. Merely failing to see omitted rows is an evidence-access problem that should trigger retrieval, not a factual contradiction.

Files: `core/evidence_packets.py`, `tools/reasoning.py` inventory/fetch/synthesis paths, `tools/_output_reader.py`.

Exit: all active findings receive evidence coverage; another subject's source cannot silently substitute for the cited source; repeated references to a physical source retain their provenance without duplicating its content in the prompt.

### 3. Let independent review correct its own mistakes

Add a distinct resolution basis for an **incorrect reviewer premise**. Require the original issue, the exact rebutted statement, existing evidence IDs plus versioned selectors, and an independent adjudication accepting the correction. Existing evidence is allowed; its call ID need not be newer than the objection. Retrieval receipts may establish what rows were newly shown, but do not manufacture new independent evidence.

Keep the adjudication narrowly scoped. Establishing that an identifier is present in a source does not identify its human operator or settle separate attribution gaps. A changed source invalidates the resolution. Agent disagreement, repeated review, renamed issues or an empty later blocker list never closes a material issue by itself. Preserve the issue and its resolution history, including any remaining obligations.

Separate transport/schema errors from evidence insufficiency and contradiction. Check response schemas before updating issue state. Allow deterministic compatibility normalization only where it preserves the documented meaning—for example, a list of plain query terms when the fetch protocol explicitly defines that list as an OR search. Otherwise use the bounded repair path and return an actionable failure. Show “synthesis failed validation” instead of “synthesis was not called.”

Files: `core/review_issues.py`, `tools/_llm_parse.py`, `tools/reasoning.py`, `tools/_readiness.py`.

Exit: a false unsupported-evidence objection can be corrected using a versioned earlier source without rerunning acquisition; a genuine contradiction still cannot be waived or hidden by a failed review. One rejected resolution cannot silently discard the provenance of other adjudications.

**First checkpoint:** deliver 1–3 together, replay the generic failure fixtures, then run isolated smoke investigations spanning different evidence capabilities on a fixed build. Resolve any evidence/accuracy regressions before broadening orchestration. No single case's expected finding list defines success.

### 4. Track accepted guidance through completion

Implement a thin projection over the existing execution log for accepted obligations and task receipts. This is the bounded first part of original step 5; a separate database or a second phase engine is unnecessary.

Each accepted task needs: ID, owning question/issue, proposal source, canonical tool, normalized arguments and target, evidence version/scope, prerequisites, required output/completeness condition, status and completion/disposition receipt. Support proposed/needs-specification, pending, running, satisfied, failed, unavailable and inapplicable states. Report eligibility follows the underlying coverage and disposition rules, not the task status label alone.

Use successful target- and scope-matched receipts to settle work automatically. Existing work can satisfy a newly proposed equivalent task. A successful empty search is distinct from an unread source, an invocation-only log, truncated output or timeout. A failed parse must never satisfy a negative assertion. Legacy traces with insufficient argument/result metadata stay explicitly ambiguous; do not invent complete receipts from matching tool names.

DAIR, hypothesis discriminators and deterministic coverage checks feed one accepted task set. Return its next small runnable batch instead of competing prose work orders. Different queries/windows/hosts stay separate. Server policy remains authoritative for transitions; caller phase declarations cannot clear obligations. Keep unrelated, permitted evidence gathering available while an obligation is blocked.

Before an expensive discretionary scan, prioritize pending work that can decide a case question or close a required gap. Require a stated scan question, relevant roots, resource bounds and a continuation strategy. A timeout returns partial coverage and an explicit narrowed/resumable action; it does not automatically repeat the same broad scan. Initial optional-scan budgets should be configurable and tested against the wrappers. Required exhaustive collection remains available when the claim's scope needs it.

Files: `core/execution_log.py`, `core/middleware.py`, existing `work_order`/`max_pass_cap` gates, `tools/dair.py`, `tools/tool_capabilities.py`, relevant scan wrappers and an obligation projection if needed.

Exit: completed work is recognized only with valid target/result receipts; applicable earlier work is reused; different-source work is not falsely reused; decisive applicable coverage precedes low-value broad scanning. Restart reconstructs the same pending obligations.

### 4a. Make bounded curiosity usable and observable

Curiosity is a way to test a plausible alternative or unexplored source, not a quota of additional findings. The [mechanism assessment](curiosity-review.md) distinguishes rare recorded probes from unmeasured exploratory tool use. Raising the budget alone will not fix scheduling, recording or instruction conflicts.

1. **Persist the actual allowance.** Replace the 30-entry lookup with an indexed, durable grant keyed to its investigation and batch. Expose granted, reserved, spent and remaining units, plus explicit expiry/replacement semantics. Reconstruct after restart; unrelated trace traffic cannot revoke a grant. Reserve atomically before execution and consume once per actual exploratory execution. Transport retries of an existing execution do not spend again. A dispatched failed/partial probe remains accounted for; validation failure before dispatch releases its reservation. Phase changes explicitly close/reconcile grants; repeated DAIR calls must not create unlimited exploration by refreshing an allowance. Apply an overall configurable exploration resource cap as well as batch limits.
2. **Create an opportunity that cannot be starved by an expanding work order.** Keep batches finite. At batch completion or a material contradiction, new entity, unexplained observation or coverage gap, expose a small exploration decision alongside required work. A cheap, independent probe may run while unrelated long work is pending if its prerequisites and resource policy permit it. Urgent required work retains priority; new suggestions do not postpone exploration indefinitely. Preserve pending obligations and explain deferral when dependencies or resources prevent a probe. Report generation itself does not launch probes; a material new lead reopens investigation and invalidates approval through the existing lifecycle.
3. **Make candidates executable, conditional and case-neutral.** Use the unresolved question, inspected source scopes and available capabilities to suggest at most a few high-information checks, with rationale, target/tool arguments, expected discriminating result and cost bound. Include benign alternatives and contradictory evidence, not just another actor or another transfer channel. The investigator can propose its own hunch. Already examined sources are candidates only for a materially different question or incomplete scope. No candidate is required merely because it appears in a generic checklist.
4. **Use one accepted task set, with explicit optionality.** Absence-mode output must not silently turn every suggested probe into binding `priority_tools`. Tag proposals as exploratory suggestions; only validated obligations block their dependent transitions. Choosing a probe schedules an exploratory task; a significant result may create a separately validated required follow-up. Deduplicate equivalent proposals across DAIR and reasoning while retaining their origins.
5. **Attach recording to execution.** Reuse the task/receipt mechanism: accept a probe with its rationale and budget reservation, associate the normal forensic tool execution, then attach its output/completeness and outcome automatically. Avoid a mandatory second logging call after every probe or a new unrestricted tool dispatcher. Keep the existing recording API as a compatibility adapter with explicit historical-only semantics when no pre-execution reservation exists; it must not manufacture prior authorization. Distinguish seed evidence from the probe's result evidence. A probe entry is control metadata; findings cite the actual versioned forensic outputs and pass the unchanged review gates.
6. **Review gaps only when state changes.** Cache the exploration decision against unresolved questions, inspected scopes and evidence versions. Use existing DAIR/hypothesis output when sufficient; do not add a model call at every phase or tool event. A reasoned “no useful candidate,” “already tested,” “out of scope,” or “deferred for cost” is valid. Do not force expenditure of all budget or make an optional skipped probe a report blocker. A known material coverage gap still follows the required-obligation policy.

Files: `tools/_gates/curiosity_budget.py`, `core/execution_log.py`, `tools/misc.py`, task receipts/middleware, `tools/dair.py`, `tools/reasoning.py`, `core/slim_descriptions.py`, all supported agent profiles and their behavioral tests.

Exit: a grant survives more than 30 unrelated entries and restart; concurrent/duplicate execution cannot overspend; results attach to their seed and actual evidence; an expanding work order does not silently starve an eligible probe. With an informative available candidate, the agent tests it or gives a valid reason to defer; with no useful candidate, it finishes without manufactured exploration. No finding is accepted on a probe rationale alone.

### 5. Align agent guidance and the user-visible finish

Shorten the always-loaded contract to a small operational spine: establish scope, follow the returned required batch, consider bounded exploration at relevant checkpoints, submit findings, resolve or adjudicate issues, and finish through a validated report or explicit blocked status. Move long examples and conditional forensic guidance to targeted tool descriptions and retrievable documentation. Update Claude, OpenCode and both Pilot profiles together, including slim tool descriptions. Pilot's analyst approval requirement for finding writes remains in force; server recommendations do not supply that approval.

Remove conflicting “nothing outside priority_tools” instructions while preserving the explicit bounded-exploration exception. Make absence mode discoverable in every client. Replace assumptions that every investigation starts with a confirmed positive detection or seeks a second actor/exfiltration channel with the user's actual question and capability-driven coverage. Provide the same guidance contract to all backends; do not add model- or case-specific shortcuts. Define a reviewed no-supported-finding/inconclusive completion path so a zero-finding gate cannot incentivize inventing a finding; an uninvestigated case must still remain incomplete.

Emit relevant reminders at the point of action:

| Situation | Guidance / expected behavior |
|---|---|
| Deterministic submission refusal | Return every independently checkable prerequisite and a concrete repair; no unnecessary model evaluation |
| Review lacks deciding rows | Retrieve by finding/source; preserve the proposition while obtaining evidence |
| Transport timeout | Retry the same exact submission key/request; no new draft unless the claim changes |
| Reviewer cites the wrong source | Use the incorrect-premise adjudication path; do not retract a supported observation just to clear the gate |
| Real unsupported clause | Correct that clause or collect deciding evidence; preserve other supported clauses |
| Scan timeout | Treat coverage as partial; narrow/resume or disposition appropriately |
| Readiness false | Show unresolved obligations and the next action; do not announce a completed investigation |

Keep exploratory suggestions visibly optional. Remove conflicting guidance that requires separate evaluate/confidence/citation calls before every submission. Keep the compatibility preview path for analysts who want to inspect a review before recording.

Track substantive narration audits incrementally and surface pending coverage as part of closure. Include relevant imported investigation narration as well as explicit agent messages, deduplicated by source identity. Trigger an audit only for changed material, not from every pre-report request. Do not restore repeated full-history audit loops.

Render the canonical final report from the approved active-finding snapshot and explicit limitations. If closure cannot be reached, allow a clearly labelled **incomplete investigation status** containing validated observations and unresolved issues, without claiming final-report approval. Preserve retracted claims as history. Where Vera export or transcript capture is integrated, carry lifecycle and completion status through that adapter; do not treat free-form Vera notes as an approved TRUDI report.

A server can control its own exports and tool results, but cannot guarantee the wording of an external agent's final chat message. Add end-of-run/profile checks where the client supports them, and a behavioral evaluation that fails if final prose claims completion or revives a withdrawn claim. Document any client enforcement gap rather than claiming that prompts eliminate it.

Files: the four agent profiles, `docs/agent-contract.md`, `tools/reasoning.py` audit path, reporting/export integration and behavioral tests.

Exit: the agent finishes with a valid report or an honest blocked status; it cannot obtain approved report output by moving unapproved claims into narrative text. Required dispositions remain evidence-backed and specific.

### 6. Validate guidance use and end-to-end results

Test at three levels:

1. **Deterministic regressions:** wrong-subject source, omitted cited output, duplicate packet source, old-evidence reviewer correction, stale source, overlarge response, canonical target receipt, partial scan, restart and final-report snapshot integrity. Include long batches, grant reset/revocation, concurrent reservations, lost responses and exploratory-result lineage. Parameterize failures across evidence types; test behavior and invariants, not just helper output shapes.
2. **Agent behavior scenarios:** real tool interactions under each supported client/backend profile. Give the agent large inventories, faulty reviewer objections, already-completed tasks, missing applicable coverage, unavailable artifacts, transport failures and a stale snapshot. Include a useful unexpected lead, an expanding work order, a deliberately irrelevant suggestion, a benign explanation, no useful remaining probe, a genuine unresolved contradiction, and a fully reviewed zero-supported-finding outcome. Assess actions and resulting state, not whether the agent repeats instructions or spends its whole budget.
3. **Frozen paired investigations:** baseline and changed builds on isolated copies of the same evidence, same backend roles/settings, at least three repeats per configuration for an initial pilot. Select by capability strata across supported disk, memory, network, mobile, cloud/live and documentary workflows; include mixed evidence, sparse evidence and benign/inconclusive cases. Use synthetic fixtures for strata without a suitable real case, and disclose coverage limits. Reserve unseen cases for holdout evaluation; never choose thresholds or prompts from their answers. Pin available provider versions; record mutable aliases and treat results descriptively. No mid-run code changes. Blind claim adjudication to configuration where practical.

Acceptance measures:

| Measure | Initial acceptance criterion |
|---|---|
| Guidance delivery | No unreadable default control responses; all required guidance reachable through bounded retrieval |
| Valid guidance uptake | At least 90% of presented runnable required actions satisfied or legitimately adjudicated/dispositioned within the next relevant batch; report denominator and exceptions |
| Faulty guidance handling | Wrong-source and incorrect-premise fixtures corrected without deleting supported findings; genuine contradictions remain blocking |
| Completion recognition | No “never run” for a valid equivalent receipt in fixtures; no reuse across different target/scope/version |
| Report integrity | Zero stale approvals, revived retracted claims, or false completion in the evaluated client workflows |
| Factual quality | No new material unsupported attribution, mechanism or negative assertion; no lost required question coverage; supported observations retained with appropriate qualification across capability strata |
| Exploration accounting | Every scheduled probe links rationale, durable grant, actual execution and outcome; long batches/restarts do not lose allowance; no duplicate spending or unsupported findings from probe metadata |
| Exploration usefulness | Measure eligible opportunities, selected/deferred probes and reasons, useful coverage or hypothesis changes per unit of cost, and unlogged exploration separately; no minimum probe count or mandatory budget utilization |
| Efficiency | Target at least 25% fewer backend attempts and 20% lower median active elapsed time than the frozen comparator, while also reducing finding-review input tokens; report end-to-end time and all failures separately |
| Retry efficiency | Track attempts per committed finding, model-free repairs, duplicate evaluations and cache reuse; no success claim from legacy refusal counts alone |

The percentages are engineering targets, not promised gains. Guidance uptake must not reward blind compliance with invalid advice or penalize necessary safety/correctness work. Show wall time, active-time methodology, scan time, provider-specific tokens and accuracy side by side. An unfinished run is an unfinished result, not a fast successful sample.

## Recommended scope now

Start with reproduction plus changes **1–3**: compact actionable responses, shared synthesis evidence, and correctable reviewer premises. Include generic curiosity failure fixtures in the baseline. Then measure the first checkpoint. Advance to **4, 4a and 5** together for accepted-task execution, durable exploration and consistent agent guidance. The bounded-window budget defect and conflicting descriptions can be repaired independently earlier, provided their tests preserve existing semantics; do not introduce a separate temporary task framework. Keep the larger hypothesis/planning merger and broader event-driven DAIR redesign deferred until this bundle demonstrates accurate completion across evidence capabilities.

Review concrete interfaces, invariants and tests per increment. Runtime work must
preserve historical case data, model routing and existing analyst approval requirements.
