# Peer review of the revised investigation plans

Decision: **request changes before approving the complete plans**. Reviewed
2026-09-20 against [reviewer-evidence-access-plan.md](reviewer-evidence-access-plan.md),
the latest [report-phase-return-plan.md](report-phase-return-plan.md), current
code and the captured 21:14 UTC run. The narrow packet-specific scope repair is
sound. The remaining changes below address delivery, provenance and correctness;
none requires a case-specific rule.

Some evidence-access code has already changed despite the plan's “Not
implemented” status. This review includes that partial implementation where it
demonstrates a design risk. It does not modify runtime code or claim that the
whole implementation has been validated.

## Required revisions

### 1. P1 — Bound the original review response before improving detail lookup

**Location:** evidence-access plan [§6](reviewer-evidence-access-plan.md#6-reasonreview_details-accepts-the-ids-the-agent-actually-holds),
lines 100–112; sequencing, lines 302–307.

The plan treats failed lookup primarily as an ID-resolution problem. The observed
driver was that every completed evaluation response overflowed the client and
the ordinary result—including its correct review ID—was diverted to a file.
Adding suggestions, rendered evidence or another lookup route will not make that
initial result deliverable. `reason_evaluate_finding` still returns the full
result, including the large `inputs` prompt.

Make a bounded initial evaluation response a first delivery item: stable review
ID, verdict/access status, receipt, actionable blockers and an exact versioned
detail route. Store full prompts, packets, audits and suggestions in the saved
review. Preserve these essential fields deliberately rather than relying on the
generic compact response's scalar-selection order. Measure the actual serialized
MCP response after middleware enrichment; a packet character cap alone is not a
transport limit.

**Acceptance:** a large review reaches the client without cache-file fallback;
its ID retrieves the same saved result; the receipt still binds the exact claim;
detail paging is lossless and rejects mixed versions.

### 2. P1 — Link wrapper IDs explicitly; never select a nearby review

**Location:** evidence-access plan §6, lines 107–112.

“Resolve the wrapped reason call” needs a persisted relationship. The partial
implementation `_resolve_reason_entry` selects the nearest preceding same-tool
review. A failed wrapper or interleaved calls can therefore return another
claim's review. Read-only reproduction: successful reviews 10 and 11, followed
by failed wrapper 12, returned review 11 with `success=true` for request 12.

Persist the originating request/review ID when a wrapper is emitted. Resolve
only that link; ambiguous historical entries should return candidates as guidance,
not silently select one. Readiness details retain their own retrieval route.
Do not invent a `call_id` argument for tools whose detail endpoint does not take it.

**Acceptance:** concurrent same-tool calls resolve to their own reviews; validation
failure before review creation resolves to none; an unlinked historical wrapper
cannot borrow a prior success.

### 3. P1 — Treat failed access to deciding evidence as incomplete review even when other rows were shown

**Location:** evidence-access plan §3, lines 57–67; acceptance 4–5, lines 284–289.

The prose requires both all-refused requests **and no initially pushed rows**.
That does not cover review #67: registry and unrelated event rows were shown,
but all twelve requests for deciding rows failed. Acceptance criterion 5 omits
the initial-row condition, so the plan also contradicts itself.

Define the outcome around unresolved evidence-access requests, not a total row
count. After the bounded repair attempt, an unresolved required request produces
an incomplete/access-failure result. Partial factual observations may be retained
as diagnostics; they must not become complete approval or a sticky factual
challenge caused solely by inaccessible evidence. Specify mixed batches as well
as all-refused rounds. Persist failure state so the initial provisional verdict
cannot survive in the trace or influence gates after restart.

**Acceptance:** unrelated pushed rows plus failed deciding requests; mixed
successful/refused requests; one repair succeeds; repair limit is exhausted;
replayed trace does not turn an access failure into a substantive verdict.

### 4. P1 — Include retained inline output in uncited-source discovery

**Location:** evidence-access plan §8, lines 141–160; §8a, lines 185–205.

The proposed candidate scan names artifact files and stdout sidecars, omitting
complete inline stdout. The motivating configuration read (#98) is a successful
390-character inline result with **no `stdout_path`**. A literal implementation
would miss the very evidence this feature is intended to find.

Use the shared retained-source abstraction, including inline output with its
completeness and call identity. Exclude reviewer prose by requesting primary
row sources explicitly (`for_rows=True`), as well as excluding authored files.
Keep suggestions outside the review's evidence/receipt until the client cites
them and independent review covers them.

The zero-match-only term rule also cannot detect missing relationships when the
same account, path or number appears in an unrelated cited source. Treat it as
a limited retrieval heuristic, not a completeness test. Report candidate matches
and bounded search coverage; an empty result cannot establish that collection is
needed. Remove §8a's rule that narrowing is correct **only** when neither remedy
applies: a candidate containing the terms may contradict the claim or fail to
support its causal interpretation. Suggestion matches do not justify retaining
an unsupported assertion or automatically citing it as proof in self-correction.

**Acceptance:** complete inline output; the same identifiers in unrelated cited
rows; candidate rows that contradict the claim; partial/capped search; optional
narrowing remains possible; suggestions never alter citations or approval.

### 5. P1 — Fix source selection and attribution before raising row caps

**Location:** evidence-access plan §5, lines 89–98.

More rows proportional to match count does not address the observed selection
failure. A broad year token matched all 6,100 event rows; duplicate citations to
the same CSV consumed the shared budget; later targeted reads received no rows.
Raising the first source's cap can intensify that starvation.

Preserve targeted read selectors, prioritize discriminating matches, deduplicate
physical spans while retaining all citation links, and allocate the bounded
budget across required sources. Test that adding an irrelevant early source or
another citation to the same file cannot hide the decisive later selection.

The plan also omits retrospective source attribution: a later file added to a
shared output directory becomes a source of an earlier extraction when the
directory is rediscovered. Record exact produced-output manifests and versions;
do not attribute every current sibling file to every historical call. Legacy
directory discovery needs an explicit provenance limitation.

**Acceptance:** repeated physical sources, broad terms, a late targeted source,
and two tools writing different files into one directory. Measure the serialized
prompt including metadata and rendered labels, not only selected raw text.

### 6. P2 — Bind quotes to the actual displayed representation

**Location:** evidence-access plan §9, lines 240–252.

Accepting either the complete raw row or a freshly rendered version is broader
than “quote what the reviewer saw.” If presentation omits columns or clips a
field, hidden raw text must not qualify as displayed proof. Re-rendering later
also depends on the renderer version and projection settings.

Keep canonical raw spans and store the exact displayed text/projection or a
versioned, reproducible display receipt tied to the same source and row. Accept
only text actually exposed to that reviewer. Preserve source/claim version checks;
rendered quotation is not a route around them. Add tests for hidden columns,
clipped values, multiline/quoted CSV, renderer changes and stale source versions.
This presentation change can follow the access/delivery fixes.

### 7. P1 — Remove conflicting Report-return instructions and align with the implemented router

**Location:** Report-return plan §1 lines 85–92, §2 lines 111–124,
§6 lines 230–234, and status/current-state sections.

The contract still instructs the implementation to record a block, tell the
client to **re-run**, and require another DAIR assessment, immediately before
requiring continuation of the original invocation. Its client-profile section
repeats the re-run instruction. Following both recreates duplicate attempts and
the round trip the change is intended to remove. Likewise “pop until an active
phase is on top” conflicts with choosing the required phase while preserving
unrelated nested scope.

Rewrite these sections as one final behavior: validate the request; retain normal
gates; durably reserve and transition; execute the original call; return the
result and transition notice. Re-plan only when there is an actual planning
dependency. Pop only the appropriate Report frame and preserve other scope.

The repository already has `core/phase_routing.py`, `phase_transition` and
`phase_work`, replay and Report-entry readiness enforcement. The document still
describes them as missing and specifies a new `record_phase_return`/`phase_return`
interface. Align the contract to the existing implementation and list remaining
gaps explicitly. Do not introduce a second event family or writer to satisfy
stale wording. The earlier review's core design concerns are otherwise addressed.

## Acceptance details to retain

- Choose scope validation by explicit packet purpose/schema. A malformed
  synthesis packet must not silently fall back to finding-review semantics just
  because its source map is absent or empty. Keep the original operator decision:
  genuinely out-of-scope requests are refused with permitted-source guidance.
- Scope-error guidance lists only sources allowed by the versioned packet;
  dynamically discovered sibling files are not valid alternatives.
- `searched=true` is necessary but insufficient for absence. Preserve separate
  matched/shown counts, scan completeness, retained-source completeness and
  requested scope. An empty complete source may legitimately have zero total
  rows; a partial or budget-limited scan cannot prove absence.
- Every retry, including the one format-repair retry, counts toward an explicit
  total model-call/time budget. Repeated unchanged access failure should expose
  a repair requirement rather than encourage another entire evaluation.
- Keep full independent review and exact receipt binding. The uncited-source
  feature remains advisory. No synthetic or live speed gain is established by
  obtaining a lower-tier finding through an access failure.

## Suggested delivery order

1. Packet-purpose-aware scope repair, accurate failure records, bounded initial
   evaluation responses and explicit review-ID linkage.
2. Required-access failure semantics, versioned produced-output manifests and
   fair selection of targeted evidence.
3. Bounded uncited-source suggestions across every retained source kind.
4. Optional CSV presentation with displayed-proof receipts.

Use generic fixtures throughout, then compare runs with code/configuration
frozen. Do not bundle the optional presentation work into the urgent protocol fix.

Validation for this peer review: inspected plans/current implementations and
retained trace evidence; ran the isolated in-memory wrapper-ID reproduction.
No investigation was restarted and no runtime code was edited by this review.
