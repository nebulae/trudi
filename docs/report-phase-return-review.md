# Review of the proposed Report-phase return plan

Decision: **request changes before implementation**. Reviewed 2026-09-20 against
`report-phase-return-plan.md`, the current middleware/phase replay/readiness code,
and the September 20 investigation trace. The centralized typed transition and
case-independent scope are sound. The following details need revision.

## Required revisions

1. **P1 — Classify the required action, not just the outer gate.** Design §3
   treats all `synthesis_evidence`, `finding_lifecycle` and not-ready results as
   collection/analysis needs. They are not equivalent. An output-resolution
   defect needs repair; a finding correction can remain in Report; missing
   synthesis must remain in Report because synthesis is only callable there.
   Otherwise a pre-report check can move the investigation out of the very
   phase needed to satisfy its blocker. Add typed action/repair reasons inside
   the gate result and route only accepted collection/analysis obligations.

2. **P1 — Close obligations with evidence, not a DAIR call.** Design §5 clears
   the pending flag whenever DAIR runs and explicitly permits re-entry with
   unmet work. That allows Report → refusal → return → DAIR → Report forever.
   Any new tool/finding/disposition is also too broad a progress criterion; an
   unrelated or failed tool can satisfy it. Track stable obligations and their
   target/scope/source-version dependencies. DAIR may acknowledge or re-plan
   them; only matching completion, supported correction or a justified typed
   disposition settles them. Guard Report entry with deterministic readiness
   excluding synthesis itself and with pending/running follow-up work.

3. **P1 — Specify replay and in-flight concurrency.** A typed event alone does
   not fix restart: `_rehydrate_phase_state` currently processes only
   `dair_call`. Replay the new events and reconstruct pending requirements.
   Use one reducer for live/replayed state and retain a historical compatibility
   path. Test a concurrent attempt to enter Report while evidence work is
   reserved/running, not just a concurrent finding write. Do not hold the trace
   lock throughout forensic or model execution.

4. **P1 — Constrain the partial-synthesis recommendation.** The Risks section
   proposes continuing with unavailable finding sources. That can support
   partial diagnostic review, but must not yield a complete SUPPORTED synthesis
   or report approval. Preserve a typed unresolved source-access issue for every
   affected active finding; differentiate unavailable bytes, bounded omitted
   rows and an actual no-match result. Resolving a parser defect remains a
   separate repair. Do not weaken independent review merely to get a report.

5. **P2 — Choose the needed phase before choosing a stack frame.** The nearest
   active frame can be Scan or Analyze even when the operation requires Collect.
   Classify the capability/action first, then resume a suitable frame in the same
   scope or create one follow-up frame. Preserve genuine nested investigations.
   Do not use stack proximity as a substitute for work semantics.

6. **P2 — Resolve execution semantics in favor of fewer round trips.** For a
   validated, already-authorized forensic request, persist the deterministic
   DAIR transition, associate its obligation and continue the original call
   through all normal gates. There is no need to fail merely so the client can
   send the same request again. If the request needs a new planning decision,
   return that specific dependency instead. Reviewer suggestions are not tool
   authorization. Reserve request identity and handle running, completed and
   unknown outcomes without blindly repeating work after timeouts.

7. **P2 — Fix audit classification and verify deployment.**
   `record_tool_call` currently stamps all Report-phase results as forensic
   violations, including failed synthesis and permitted reads. Use the same
   classifier for execution routing and audit labels. Recognize synthesis
   attempts recorded under `mcp_tool`, not only `tool`. Update and fingerprint
   installed profiles as well as repository files; the inspected installed
   Claude profile lacks the newer submission/detail-retrieval guidance.

## Acceptance additions

- Missing synthesis alone stays in Report and directs synthesis.
- A packet-resolution failure, model failure or report-local correction does
  not create collection work.
- Actual new collection/analysis is preceded by its durable phase transition;
  reads of retained outputs stay in Report.
- Repeated DAIR calls, failed tools and unrelated evidence cannot clear a
  pending obligation or authorize Report entry.
- Restart reproduces phase, scope, pending work and review checkpoint.
- Concurrent calls cannot re-enter Report while follow-up work runs, and
  duplicate delivery does not execute the same reserved request twice.
- An unresolved source prevents full synthesis/report approval even if other
  findings receive a partial review.
- A permitted report reader or failed synthesis control call is not marked as
  a forensic phase violation.

The implementation sequence and detailed interfaces proposed in
[report-phase-reentry-plan.md](report-phase-reentry-plan.md) cover these changes.
Consolidate into one implementation plan rather than building two transition
mechanisms. No runtime changes were made during this review.
