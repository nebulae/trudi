# Implementation-readiness review

Reviewed 2026-09-20: the revised `reviewer-evidence-access-plan.md` and
`report-phase-return-plan.md`, current code and the focused regression tests.

**Decision: ready to implement in stages, using the concrete decisions below.**
The earlier architectural objections are addressed. I would retain the existing
router, evidence/receipt machinery and detail pager. The remaining decisions are
implementation work, not reasons to commission another redesign.

This is approval of the direction and delivery sequence, not a statement that
all specified behavior already exists. No runtime code was edited in this review.

## Verified and still pending

- The wrapper resolver now follows `reason_call_id`, with no nearest-review
  fallback. The failed-wrapper reproduction, explicit-link and interleaving
  tests pass. A failed review with a valid link should remain retrievable as a
  failed diagnostic result; “failed wrapper returns none” means a call that
  failed before creating any review, not suppression of its own failure record.
- Finding-review fetches accept the irrelevant synthesis field, null paths no
  longer exclude all file sources, and prompts distinguish the review types.
- **Scope hardening remains partly pending.** The current resolver still tests
  the truthiness of `finding_sources`, whereas the revised acceptance contract
  requires explicit packet purpose/schema and rejection of malformed synthesis
  packets. Refusal hints also need to use the packet's permitted sources, not
  the current directory contents. Thus “§1 delivered” describes the immediate
  bug fix, not completion of the strengthened acceptance criteria.
- The Report contract still lists already implemented work as missing:
  transition replay, action-based audit classification, missing-synthesis
  handling, profile updates and fingerprints. These have code and tests or a
  deployment record. Build a requirement-to-code/test checklist before using
  that document as a work list. Keep genuinely unmet acceptance details visible;
  do not replace the router to satisfy obsolete status text.

Validation: **93 tests passed** with
`python -m pytest --no-cov -q tests/tools/test_guidance_improvements.py tests/tools/test_evidence_request.py`.
These verify the delivered fixes; they do not validate the planned features or
establish that the full repository suite passes.

## Implementation decisions I would use

### 1. Compact at the client boundary; keep the internal review complete

`core/finding_submission.py` calls the evaluator body directly and reads its
verdict, error, conclusion and discriminators before committing. Replacing its
return with a generic compact summary would risk changing transactional behavior.

Keep one complete, persisted internal review result. Produce a dedicated client
envelope at the MCP boundary, with required fields selected explicitly:
`review_call_id` (and the existing `_trudi_call_id`), success/status, factual
verdict when final, receipt, concise next actions and the versioned detail route.
Every normal/failed/cached evaluation path uses the same serializer. Refused
transactional submissions also need a usable reference to their saved review.

Apply the final response budget after enrichment, keeping structured and text
representations consistent. Define and test a byte ceiling on the actual client
envelope, including duplicated text/structured content and Unicode escaping;
retaining the existing 6,000-byte application target alone is not that proof.
Large blocker sets become counts plus lossless detail references, not silent
truncation. The stable ID, status, receipt and retrieval route must always fit.

Acceptance includes a real MCP serialization path and direct internal submission
on the same large review: the client gets a bounded response while submission
still sees the complete result and exact receipt binding.

### 2. Give evidence requests identity and explicit outcomes

“Unresolved required request” needs a lifecycle. The current request schema has
no request ID or required/optional state; counting returned rows cannot supply it.

For the first implementation, treat reviewer-issued evidence requests as required
by default. Assign server request IDs and retain the original selectors, permitted
scope, repair relationship and per-source outcomes. A corrected request explicitly
replaces the rejected attempt; the old rejection is not a permanent blocker once
its correction succeeds. A final prose verdict cannot silently discard an
unresolved request. Keep optional exploratory suggestions outside this mechanism.

A valid completed search with zero matches is a successful access operation.
A scope refusal, missing source or I/O failure is not. Partial selection and
partial source retention remain separately described; neither becomes proof of
absence merely because a read succeeded.

Use one repair allowance per review and an independent absolute model-call and
elapsed-time budget. Specify mixed batches: retain successful receipts and repair
only failed requests; do not repeat successful reads. Persist `review_pending`
or an incomplete state while the review is in progress, then atomically finalize
its outcome. Incomplete reviews produce no approval receipt and no sticky
factual verdict; provisional prose remains diagnostic only. Restart must preserve
this distinction, including a crash between the initial answer and finalization.

### 3. Make output manifests a tool-completion contract

This is the widest change in the plan. The executor currently records stdout
and sometimes `output_path`; many extractors identify outputs through arguments
or an output directory. The packet builder cannot reconstruct exact historical
ownership from whatever files happen to be in that directory later.

Use one retained-source record containing source identity, producer call ID,
kind, exact path or inline-output identity, version, completeness and any targeted
read selector. File, stdout-sidecar and inline sources use the same interface.
Distinguish a reader's selected view from ownership of the underlying file.

Have wrappers register exact produced paths at completion. For directory-producing
tools, use explicit manifests or attributable per-invocation outputs; an unscoped
directory diff is insufficient when calls run concurrently or overwrite a file.
If attribution is uncertain, record that limitation rather than claiming ownership.
Async jobs publish completed manifests only when their outputs are usable.

New manifests are authoritative. Legacy discovery remains a labeled compatibility
path and must not rewrite old calls or silently certify a later sibling file.
Reuse existing source-version and packet binding checks, with an explicit policy
version for the changed source contract. Do not treat a partial retained hash as
a hash of the entire original evidence file.

### 4. Separate candidate matching, citation and proof

Use the shared retained-source records for bounded uncited-source discovery,
including inline output. Report scan coverage and candidate matches as advisory
metadata. A term match establishes neither support nor contradiction.

Put automatically discovered candidates in a separate `candidate_source_ids` or
suggestion field on a self-correction. Do not automatically insert them into its
evidentiary citations. This resolves the remaining tension between §8a's
“never cite as proof” wording and its requirement to put every match “in its
evidence.” The investigator may cite a source after inspecting it.

An empty or capped candidate search means “no candidate found within this scan,”
not “collection is required.” Keep narrowing a claim available. For source
selection, deduplicate physical spans and preserve targeted selectors before
tuning row caps; measure relevance and per-source budget allocation as well as
prompt size.

## Small document corrections to make with the first increment

- Evidence plan §1 should refer to explicit packet purpose/schema, consistently
  with the later acceptance section; label its strengthened checks as pending.
- §8a test 2 still says an empty suggestion should direct collection. Replace
  that with coverage-qualified guidance; the later acceptance criterion already
  states the correct behavior.
- §8a's automatically matched sources belong in advisory metadata, not evidence
  citations. Preserve an explicit investigator decision to cite them.
- §9's older test says both raw and rendered quotes always pass. Restrict that to
  representations actually shown. The newer displayed-proof rule takes precedence.
- Reconcile Report-plan status with existing implementation. Map requested trigger
  metadata to the existing event schema; any missing origin field is an additive
  change, not another event family. Treat reviewed-correction settlement and other
  acceptance details as explicit checks rather than assuming every clause shipped.

## Delivery sequence and stopping criteria

| Increment | Implementation boundary | Required exit checks |
| --- | --- | --- |
| 1. Review delivery and access protocol | Evaluator/MCP envelope, saved details, packet-purpose validation, fetch receipts and request finalization | Large results stay deliverable; submission is unchanged; mixed access failures and restart cannot yield approval; exact wrapper linkage remains intact |
| 2. Provenance and selection | Executor/wrapper output registration, retained-source adapter, packet/fetch selection | Concurrent directory writers and overwritten outputs remain distinct; targeted late sources receive rows; duplicates do not exhaust the budget; legacy limitations are explicit |
| 3. Citation assistance | Bounded suggestions on review/refusal/citation/confidence surfaces | Inline output is found; authored/reviewer prose is excluded; no automatic citations or verdict changes; capped scans remain honest |
| 4. Optional presentation | CSV rendering and displayed-proof receipts, then dashboard display | Hidden/clipped text cannot satisfy a quote; stale renderer/source versions are detected; total prompt and response budgets hold |

Keep the existing Report router as the integration boundary throughout. Review
access defects remain repair failures, not collection obligations. Verify the
installed tools/profiles, then freeze code/configuration for comparison runs.

For the first release, success means fewer scope refusals, zero oversized review
responses, no guessed review IDs, fewer repeated evaluations and more findings
accepted on their first submission **with independent approval intact**. Final
validation still requires completed reports and factual checks across different
evidence types. A quicker incomplete run is not sufficient evidence of improvement.
