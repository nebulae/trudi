# Returning to a collection phase when Report-phase work needs evidence

Status: behaviour contract, revised 2026-09-20 after two reviews.
**Partly implemented** — see "What exists today".

Revision note: reviewed twice —
[report-phase-return-review.md](report-phase-return-review.md) and
[investigation-plan-peer-review.md](investigation-plan-peer-review.md) §7. Both
sets of points are folded in.

**This document names no new interface.** The router shipped as
`core/phase_routing.py` with the typed events `phase_transition` and
`phase_work`, replay in `core/execution_log.py`, and Report-entry readiness
enforcement. Earlier drafts here proposed a `record_phase_return` helper and a
`phase_return` event; those names are withdrawn — a second event family or
writer must not be created to satisfy stale wording. The implementation
sequence lives in
[report-phase-reentry-plan.md](report-phase-reentry-plan.md); this is the
behaviour contract it is measured against.

Basis: the VANKO-2016-DEEPSEEK41 run of 2026-09-20 (trace archived under the
case's `.trace-backups/`). Historical runs supply regression fixtures only —
every rule below must generalize across investigations, evidence types and
backends. No case name, artifact, actor or expected conclusion may appear in
runtime logic.

## The problem

When Report-phase work discovers that it needs evidence, the investigation has
no typed way back to a collection phase. The agent finds out by attempting a
forensic tool and being refused, and the phase only changes if the agent then
chooses to call `dair_assess` and the director happens to transition.

Observed in that run (times UTC):

| Time | Event |
|---|---|
| 19:32:56 | DAIR transitions to Report (dair_call 311) |
| 19:33:38 | `reason_synthesize` refused, gate `synthesis_prerequisites` (call 312). Phase stays Report |
| 19:34:16 | `misc_parse_scheduled_tasks` attempted and blocked, `tool_blocked` 318 |
| 19:34:44 | agent calls `dair_assess`; DAIR pushes Report → Collect (dair_call 320) |
| 19:42:33 | DAIR returns to Report (358); synthesis refused again (359, 367, 369) |
| 19:45:35 | `pre_report_check` returns not-ready (370) |
| 19:46:49 | DAIR returns to Report (376); synthesis refused again (380, 382) |

The round trip cost a wasted tool attempt, a model-backed `dair_assess`, and
several agent turns, each time. The agent's own narration at 19:34 shows it
reasoning about how to get back to collection rather than collecting.

## What exists today

Two snapshots: what the motivating run ran on, and what has since shipped.

**At the time of the run (the behaviour this contract was written against):**

- `core/middleware.py::_gate_decision()` blocked any non-allowlisted tool while
  `log._current_phase` was outside `_DAIR_ACTIVE_PHASES`, telling the client to
  "call dair_assess to return to a collection phase"; the refusal was recorded
  by `ExecutionLog.record_tool_blocked`.
- `reason_pre_report_check` performed a partial, untyped return by rewriting
  `_current_phase` and popping the Report frame inline.
- `reason_synthesize` had no equivalent; its refusals left the phase in Report.
- Phase mutation was reachable only from a `dair_call`
  (`ExecutionLog._apply_dair_transition`).

**Shipped since (align to these, do not duplicate them):**

- `core/phase_routing.py` — `action_phase()` classifies the required action,
  `transition()` / `apply_return()` move the phase, `reserve()` / `finish()`
  carry request identity and work state, `work_state()` / `pending_work()`
  expose obligations, `route_issues()` routes review issues, and
  `append_event()` writes the typed entries.
- Typed events `phase_transition` and `phase_work`, replayed by
  `core/execution_log.py` alongside `dair_call`.
- Report-entry readiness enforcement and follow-up routing in the middleware.

**Verified implementation map (2026-09-20):**

| Requirement | Existing implementation / checks |
| --- | --- |
| Action classification, same-call execution, dedup and refresh | `core/phase_routing.py`, `core/middleware.py`; `tests/core/test_phase_routing.py` |
| Shared audit classifier and `mcp_tool` | `core/execution_log.py::record_tool_call`, `core/phase_routing.py::action_phase` |
| Missing synthesis stays in Report; typed evidence follow-up returns | `tools/reasoning.py`, `route_issues`; routing tests |
| Durable state replay and Report-entry readiness | `core/execution_log.py`, `tools/dair.py`, routing tests |
| Profiles and fingerprints | `profile_fingerprints`, four repository profiles; deployment record in `~/analysis/report-phase-reentry-validation-2026-09-20/` |

The current implementation does not need another phase router. Trigger origin
uses existing `request_id`/`trigger_call_id` metadata. Directory version checks
remain shallow; precise historical output ownership is addressed separately by
the reviewer-access source contract. The following gap list describes the
**motivating run**, not an outstanding implementation checklist.

## Gaps to close

1. **A refusal that needs evidence does not change phase.** Only
   `pre_report_check` returns, and it does so as a side effect rather than a
   typed, auditable transition.
2. **The agent learns the phase is wrong by being refused.** The block is
   correct but late: the attempt is spent, and nothing moves the investigation
   to where the attempt would succeed.
3. **`pre_report_check`'s return is untyped.** It mutates `_current_phase` and
   the stack directly, writes no transition record, and leaves
   `_last_dair_cid` pointing at the Report-phase director call, so the next
   batch has no refreshed work order.
4. **Re-entry to Report is unconditioned.** DAIR pushed Report three times in
   14 minutes while the same blocker stood, because nothing records that the
   previous Report entry ended in an unmet evidence requirement.

## Design

### 1. One typed transition, one writer

Phase state is mutated by exactly one writer. That writer shipped as
`core/phase_routing.py`: `transition()` / `apply_return()` move the phase and
`append_event()` records the typed `phase_transition` (and `phase_work`)
entries that `core/execution_log.py` replays. It:

- moves to the phase the **required action** needs (below), popping only the
  Report frame it is leaving and preserving unrelated nested scope;
- records the transition, its trigger and the obligation that caused it;
- leaves the work order to DAIR.

Nothing else may mutate phase state. `reason_pre_report_check`'s former inline
mutation goes through the same writer, so its return is typed and auditable
like any other.

Implemented routing uses this writer from synthesis and middleware. Audit and
deployment coverage is mapped above; retain the acceptance tests below for
regression checking.

`trigger` is an enum: `blocked_tool` | `synthesis_gate` | `readiness_gate`.

**The phase is chosen from the required action, not from stack proximity.**
Classify the obligation first — acquisition/parsing of a source that does not
yet exist (Collect), reasoning over collected output (Analyze), scoping a
surfaced lead (Scan) — then resume a suitable frame **in the same scope** if
one exists, else create one follow-up frame. The nearest active frame may be
Scan or Analyze when the work needs Collect, and a genuine nested
investigation must not be collapsed to reach it. The chooser reads typed
fields only, never prose.

### 2. Trigger A — a blocked forensic tool returns the phase

One behaviour, in order, in the middleware's routing path:

1. **Validate** the request (schema, arguments, authorization) and keep every
   normal gate.
2. **Reserve** request identity durably, so a duplicate delivery after a
   timeout cannot run the work twice.
3. **Transition** to the phase the action requires, recording the transition
   and its obligation.
4. **Execute the original call** through the remaining gates.
5. **Return the result** together with the transition notice.

No block record, no instruction to re-run, no requirement for another
`dair_assess` before the work proceeds. Earlier drafts said all three
immediately before requiring continuation; following both recreated the
duplicate attempt this change exists to remove.

Re-plan only on an actual planning dependency: when the request needs a new
planning decision rather than a position fix, return that specific dependency
instead of executing. A reviewer's suggestion is not tool authorization.

### 3. Trigger B — a review refusal returns the phase only for accepted collection/analysis work

The outer gate id is **not** sufficient to decide this. `synthesis_evidence`,
`finding_lifecycle` and a not-ready pre-report each cover several different
required actions, and they are not interchangeable:

| Required action | Where it must be done |
|---|---|
| Acquire or parse a source that does not exist yet | Collect |
| Reason over output already collected | Analyze / Scan |
| **Run synthesis that has not run** | **stays in Report** — synthesis is only callable there |
| Repair an output-resolution or parser defect | stays in Report; it is a repair, not collection |
| Correct or retract a finding (`supersedes`, retraction) | stays in Report |
| Model or transport failure (`review_schema`, malformed RESULT, 502) | retry in place |

So the gate result must carry a **typed action/repair reason** inside it, and
only an accepted collection/analysis obligation routes a return. A pre-report
check that demands synthesis must never move the investigation out of the phase
where synthesis can run — that was the sharpest defect in the first draft of
this plan.

The returned result carries `phase_returned_to` and the transition entry's
call id when a return happened, and the specific dependency when it did not.

The returned result carries `phase_returned_to` and the transition entry's
call id, so the agent sees one unambiguous instruction instead of inferring
from a gate message.

### 4. What must not trigger a return

- Allowlisted reads of already-produced output (`read.output`, `read.mail`).
  Reading retained evidence is legitimate Report work and is how a reviewer's
  gap gets checked; it collects nothing new.
- `misc.record_disposition`, narration, finding corrections carrying
  `supersedes` — already exempt at `core/middleware.py:604`.
- `misc.export_execution_log` / `misc.write_final_report`.

### 5. Loop control

**Obligations are closed by matching evidence, never by calling DAIR.** The
first draft cleared the pending flag on any `dair_assess` and counted any new
tool, finding or disposition as progress. Both are too weak: that permits
Report → refusal → return → DAIR → Report indefinitely, and an unrelated or
failed tool would satisfy the requirement.

A return records a durable **obligation**: a stable id, the required action, its
target and scope, and the source version it depends on. It is settled only by

- a completed result **matching that target and scope** (a failed or unrelated
  run does not count), or
- a reviewed correction that removes the need, or
- a justified typed disposition (`misc.record_disposition`) naming it.

`dair_assess` may **acknowledge or re-plan** an obligation — it still owns the
work order — but acknowledgement is not completion and never clears it.

**Re-entry to Report is guarded, not advisory.** Entering Report requires the
deterministic readiness contract to pass with synthesis itself excluded (so
"synthesis has not run" cannot bar the phase where synthesis runs), and no
pending or running follow-up work outstanding. A blocked re-entry names the
open obligations.

### 5a. Replay and concurrency

A typed event alone does not survive a restart. `_rehydrate_phase_state`
currently replays only `dair_call`, so a `phase_transition` would be lost and the
resumed session would believe it is still in Report.

- Replay `phase_transition` / `phase_work` events and reconstruct the pending obligations from
  them, through **one reducer** used by both live and replayed state, with a
  compatibility path for traces written before this change.
- Reserve request identity so a duplicate delivery after a timeout does not
  execute the same forensic request twice; handle running, completed and
  unknown outcomes explicitly.
- Do not hold the trace writer lock across forensic or model execution. Take it
  to read state and to commit the transition, not for the work in between.
- Test a concurrent attempt to enter Report while evidence work is reserved or
  running — not only a concurrent finding write.

### 6. Surfacing

- `phase_transition` / `phase_work` entries appear in the trace and are rendered by the dashboard
  (`dashboard/trace_viewer.html`) like a DAIR transition, with the trigger and
  the requirement.
- `tools/_readiness.py` counts unmet obligations from `phase_work` entries
  so `readiness_status` can state plainly why Report was left.
- **Audit labels use the same classifier as execution routing.**
  `record_tool_call` currently stamps every Report-phase result as a forensic
  violation, including permitted reads of retained output and failed synthesis
  control calls. Recognize synthesis attempts recorded under `mcp_tool`, not
  only `tool`, so a refused `<py>:reason_synthesize` is not filed as forensic
  work outside its phase.
- **Deployment is part of the change.** The installed profiles, not only the
  repository copies, carry the agent-facing contract; the inspected installed
  Claude profile lacks the newer submission/detail-retrieval guidance. Update
  and fingerprint the installed profiles, and verify the running server exposes
  the new behaviour before judging a run against it.
- `docs/agent-contract.md`, `claude/CLAUDE.md`, `claude/PILOT.md` and
  `opencode/AGENTS.md` describe the new behaviour: a Report-phase refusal that
  needs collection or analysis transitions the phase and continues the call;
  the result carries the transition notice. Remove the instruction to call
  `dair_assess` purely to get back to a collection phase, and the instruction
  to re-run a blocked tool — neither is the behaviour any more.

## Acceptance criteria

Each is a test; none may reference a case, actor or artifact by name.

1. A non-allowlisted forensic tool attempted in Report records a
   `phase_transition` with `trigger="blocked_tool"`, leaves `_current_phase` in
   the phase the action requires, and **the original call executes** in the
   same exchange — no block record and no re-run instruction (§2). A duplicate
   delivery of the same reserved request executes once.
2. The same tool attempted in an active phase records no `phase_transition`.
3. `reason_synthesize` refused with a typed **collection** action reason
   records a `phase_transition` with `trigger="synthesis_gate"` and returns
   `phase_returned_to`.
4. No `phase_transition` for: `review_schema`, a backend transport error, a
   packet-resolution/parser repair, a report-local finding correction, or a
   pre-report result whose only unmet requirement is that synthesis has not
   run — that last case stays in Report and directs synthesis.
5. `pre_report_check` with an accepted collection obligation produces a typed
   `phase_transition`, replacing the inline mutation; with `ready_to_report=true`
   it produces none.
6. An allowlisted read of retained output in Report produces no `phase_transition`
   and is not audited as a forensic phase violation.
7. An obligation is not cleared by `dair_assess`, by a failed run, or by an
   unrelated tool/finding/disposition; it is cleared by a completed result
   matching its target and scope, a reviewed correction, or a justified typed
   disposition naming it.
8. Report entry is refused while an obligation is pending or follow-up work is
   running, and the refusal names the open obligations. Readiness for that
   guard excludes synthesis itself.
9. The target phase follows the required action: a Collect-class obligation
   resumes or creates a Collect frame even when Analyze or Scan sits nearer the
   top, and a genuine nested investigation is preserved.
10. Restart replays `phase_transition` / `phase_work` events through the same reducer as live
    state and reproduces phase, scope, pending obligations and the review
    checkpoint; a pre-change trace still loads.
11. Concurrency: a Report re-entry attempted while evidence work is reserved or
    running is refused; the trace writer lock is not held across forensic or
    model execution.

## Risks and dependencies

- **Auto-return cannot fix an impossible requirement.** In the run that
  motivated this, synthesis was blocked by a packet-builder defect (`-o` read
  as an output flag, fixed separately) that no amount of collection would
  clear. The obligation contract in §5 bounds the loop, but the companion fix
  is to make `core/synthesis_evidence.build_synthesis_packet` degrade per
  finding instead of refusing the whole synthesis.

  **Constrained per review:** partial synthesis supports partial *diagnostic*
  review only. It must never yield a complete SUPPORTED synthesis or report
  approval. Every affected active finding keeps a typed unresolved
  source-access issue, and the three cases stay distinguishable — bytes
  unavailable, bounded rows omitted, and an actual no-match result. Repairing
  the parser defect remains a separate repair, and independent review is not
  weakened to get a report out.
- **Phase oscillation** if action classification leaks beyond accepted
  collection/analysis obligations. Mitigated by typed action reasons (§3) and
  evidence-closed obligations (§5), not by gate ids alone.
- **Director authority.** The return changes position and records an
  obligation; it never prescribes tools. DAIR remains the single planner and
  may re-plan any obligation.
- **Two mechanisms.** The greatest risk to this work is building the transition
  twice. This document is the behaviour contract;
  [report-phase-reentry-plan.md](report-phase-reentry-plan.md) carries the
  implementation sequence and interfaces. One reducer, one writer, one set of
  typed events.

## Resolved: execution semantics

Previously an open question — after an automatic return, should the blocked
tool run, or be refused with a retry instruction? **Resolved in favour of
continuing the call** (§2): for a validated, already-authorized request,
persist the transition, attach the obligation and proceed through the normal
gates, with request identity reserved so a duplicate delivery cannot re-run the
work. A request needing a new planning decision returns that dependency
instead.

## Acceptance additions from review

- Missing synthesis alone stays in Report and directs synthesis.
- A packet-resolution failure, model failure or report-local correction creates
  no collection work.
- Real collection or analysis is preceded by its durable transition; reads of
  retained output stay in Report.
- Repeated DAIR calls, failed tools and unrelated evidence cannot clear an
  obligation or authorize Report entry.
- Restart reproduces phase, scope, pending work and review checkpoint.
- Concurrent calls cannot re-enter Report while follow-up work runs, and
  duplicate delivery does not execute a reserved request twice.
- An unresolved source prevents full synthesis and report approval even when
  other findings receive a partial review.
- A permitted report reader, or a failed synthesis control call, is not marked
  as a forensic phase violation.

## Implemented continuation and job contract

The delivery contract is now specified in
[resumable-review-jobs-implementation.md](resumable-review-jobs-implementation.md).
Synthesis progress alone never approves Report: current finding coverage, all
required consistency comparisons and resolved blocking issues are necessary.
An exchange is a bounded slice of a persisted review task. Provider retries
consume the same cumulative 24-call allowance.

Job wrappers finalize and validate in the worker, including the inline fast
path. Polling only observes/imports a finalized result. Job abandonment uses
`target_kind="job"` after the worker stops and its result is collected; neither
a generic tool disposition nor cancellation alone settles its work obligation.
Both reset entrypoints refuse active writers, including with `--force`.
