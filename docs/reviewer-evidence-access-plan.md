# Reviewer evidence access: fix plan

Status: first release implemented 2026-09-20: delivery/access protocol, source
provenance/selection and citation assistance. The §9 CSV presentation
increment is now implemented as well. See [implementation and validation](reviewer-evidence-access-implementation.md)
for exact coverage, limitations and replay measurements.

Revision note: reviewed in
[investigation-plan-peer-review.md](investigation-plan-peer-review.md), which
requested changes before approval. Its points are folded in below. One defect
it found in the shipped §6 code — a wrapper resolving to a *neighbouring*
review — is fixed; §6 now resolves only a persisted link.

Findings and measurements this plan addresses:
[review-evidence-access-findings.md](review-evidence-access-findings.md).
Companion: [report-phase-return-plan.md](report-phase-return-plan.md).

Scope constraint, as in the other plans: every rule must generalize across
investigations, evidence types and backends. Historical runs supply regression
fixtures only. No case, artifact, actor, platform or expected conclusion may
appear in runtime logic.

Operator decision recorded 2026-09-20: an out-of-scope evidence request is
**refused, and the refusal returns the valid source list so the model can retry
within the same round** (option c). It is not silently redirected to another
source, and it does not silently succeed.

## Objective

A reviewer must be able to reach the rows that decide the claim it was asked
about, and the trace must record honestly whether it ever saw them. Today a
finding review is shown a 6-row sample, its requests for more are refused by a
check meant for synthesis, and the refusal is recorded in a shape that reads
like a search that found nothing.

## 0. Bound the evaluation response itself, before improving lookup

**This is the first delivery item.** The observed driver of the lookup failures
was not ID resolution: a completed evaluation response overflowed the client,
so the ordinary result — *including its own review ID* — was diverted to a
file. No amount of extra lookup routes, suggestions or rendering makes that
first result deliverable. `reason_evaluate_finding` still returns the whole
result, including its large `inputs` prompt.

Return a bounded initial evaluation response carrying, deliberately (not by the
generic compact response's scalar-selection order):

- the stable review id;
- verdict **or** access status;
- the receipt;
- actionable blockers;
- an exact, versioned detail route.

Full prompts, packets, evidence audits and suggestions live in the saved
review, reachable through that route.

**Submissions are in scope, not only direct evaluations.** The run that
motivated this used `misc.submit_finding`, whose failure path appends full
citation suggestions *after* the compact review reference has been built; one
captured response measured **8,684 bytes before the MCP envelope**. The size
boundary therefore lives at the middleware, covering every response including
transactional submissions, and the tests measure those enriched responses — not
just the evaluation path.

**Measure the serialized MCP response after middleware enrichment.** A packet
character cap is not a transport limit; the enrichment layer adds fields after
the cap is applied.

**Acceptance.** A large review reaches the client with no cache-file fallback;
its id retrieves the same saved result; the receipt still binds the exact
claim; detail paging is lossless and rejects mixed versions.

## 0a. An empty backend response is a transport fault, not a review outcome

**Observed** across runs 2, 3 and 4 (four occurrences, two in run 4 alone):
the openai-compat backend returns `finish_reason=tool_calls` with **no
content**. `tools/reasoning.py` classifies it as
`Model returned empty response (finish_reason=tool_calls)` (:819) and the call
fails — correctly, but expensively: in run 4 it killed one
`reason_evaluate_finding` (cid 121) and one `misc.submit_finding` review
(cid 124, the first time the one-call submission path had ever reached review).

The request builder (:733-745) sends `model`, `messages` and `max_tokens` and
**never sends `tools`**. The model is selecting a tool call unprompted, so
nothing in the answer can be repaired and no re-wording helps.

1. **Suppress tool selection on the wire.** Send `tool_choice: "none"` on the
   openai-compat path. Verify the target server accepts the field rather than
   rejecting the request — Ollama and vLLM differ here — and fall back to
   omitting it when the server 400s, recording which behaviour was used.
2. **Classify it as a transport fault with its own single re-ask.** The
   existing format-repair path is the wrong remedy: a format repair re-asks
   with "FORMAT REPAIR: <error>" appended, but there is no malformed content to
   repair. An empty response gets **one** plain re-ask of the same prompt, and
   that re-ask counts against the same total model-call budget as any other
   retry.
3. **A transport fault never becomes a verdict**, by §3: if the re-ask also
   returns empty, the review ends as a typed retryable failure naming the
   backend condition — never SUPPORTED, CHALLENGED or UNVERIFIABLE, and never a
   sticky challenge against the claim.
4. Keep the two conditions distinguishable in the trace: an empty response is
   not a `finish_reason=length` budget exhaustion, which has a real remedy
   (raise the thinking budget) and a different message (:812-817).

**Tests.** `tool_choice` is sent on the compat path and omitted after a server
rejection, with the fallback recorded; an empty first response plus a good
re-ask yields the normal result; two empty responses yield a typed retryable
transport failure with no verdict and no sticky challenge; the re-ask counts
toward the model-call budget; a `finish_reason=length` result still produces
the budget-exhaustion message, not the transport one.

## 1. Scope checks apply only where their inputs exist

`tools/reasoning.py::_resolve_evidence_requests` (from :1464).

1. **`finding_call_id`** — validate explicit packet purpose and the synthesis
   source-map schema before searching. Cross-finding packets carry
   `finding_sources` from `core.synthesis_evidence.build_synthesis_packet`;
   malformed maps are refused, never treated as unrestricted finding packets. A finding-review packet
   (`core.evidence_packets.build_packet`) has no such key; there the field is
   ignored, never grounds for refusal.
2. **`path` (:1532)** — treat as a filter only when it is a non-empty string.
   A present-but-null `path` must not filter out every file-backed source.
3. **Instruction text (`_evidence_request_instruction`, :345)** — the
   finding_call_id/path guidance is emitted only for the synthesis prompt. The
   finding-review prompt describes only the fields that packet supports.

## 2. A refusal returns what the reviewer may ask for (option c)

When a request is refused for scope reasons, the appended block must carry the
**valid sources for that cited call**: each `call_id`, its retained paths (or
"stdout"), and the matching-row count the packet already computed. The reviewer
can then reissue a correct request immediately.

A round in which **every** request was refused for scope reasons and **no rows
were returned** does not consume one of `COMPAT_EVIDENCE_ROUNDS` (:249). Cap
the free retries at one per review so a mis-formatting model cannot loop; a
second all-refused round ends the review under §3.

The instruction that accompanies the refusal states plainly: a refused request
searched nothing, so it is not evidence of absence.

## 3. Failed access to deciding evidence is an incomplete review

`_evidence_round_trip` (:1690) keeps whatever verdict the final round produced.
The first draft of this section required **both** all-refused requests and no
initially pushed rows — which does not cover the motivating case: unrelated
registry and event rows *were* shown, and all twelve requests for the deciding
rows failed. (Acceptance criterion 5 also contradicted that prose.)

Define the outcome around **unresolved required evidence-access requests**, not
a total row count:

- after the bounded repair attempt (§2), any unresolved required request
  produces an incomplete / access-failure result, whatever else was shown;
- partial factual observations may be retained as **diagnostics**; they must
  not become a complete approval, nor a sticky factual challenge caused solely
  by inaccessible evidence;
- mixed batches (some requests resolved, a required one not) are specified the
  same way as all-refused rounds;
- the failure state is **persisted**, so a provisional verdict from an earlier
  round cannot survive in the trace or influence gates after a restart.

This matters because a substantive verdict sticks to the claim through
`challenge_sticky`: a tooling failure must not become a lasting judgement about
the evidence.

**Acceptance.** Unrelated pushed rows plus failed deciding requests; mixed
successful/refused requests; one repair succeeds; the repair limit is
exhausted; a replayed trace does not turn an access failure into a substantive
verdict.

## 4. The fetch record distinguishes refusal from an empty search

Today `rec` is created with `"file": ""` (:1491) and filled only when a source
is actually scanned (:1603), so a refused request is recorded with
`rows_returned: 0`, `total_rows: 0` and an empty `file` — indistinguishable
from a completed search that matched nothing, except by its `status` string.
In the run that motivated this, 19 of 28 evaluate requests were recorded that
way.

1. Add an explicit `searched: bool` to the record. False for every status that
   never opened a source (`scope_mismatch`, `out_of_scope`, `missing`,
   `not_evidence`).
2. Any consumer that treats 0 rows as absence must require `searched: true`.
3. Record per-source results instead of last-writer-wins: `file` and
   `total_rows` are assigned inside the per-source loop while `rows_returned`
   and `bytes` accumulate across sources, so a call with several outputs
   reports one file's `total_rows` beside all files' row count. Replace with a
   `sources: [{path, kind, total_rows, rows_returned, complete}]` list and keep
   the scalar fields as totals, or as the single entry when there is one.

## 5. Fix selection and attribution before raising row caps

`COMPAT_PUSH_ROWS_PER_CID` is 6 (:258), and a source matching thousands of rows
is sampled at 6 — but raising that cap first would make things worse, not
better. The observed failure was **selection**, not volume: a broad year token
matched all 6,100 event rows, duplicate citations to the same CSV consumed the
shared budget, and later targeted reads received nothing. A bigger first cap
intensifies that starvation.

In order:

1. **Preserve targeted read selectors** and prioritize discriminating matches
   over broad-token matches.
2. **Deduplicate physical spans** while retaining every citation link to them.
3. **Allocate the bounded budget across required sources**, so an early
   irrelevant source or a second citation of the same file cannot hide a
   decisive later selection.
4. Only then scale the initial row count with the match count, still bounded by
   the character budget, with per-source totals (shown, matched, scanned,
   complete) stated where the model cannot miss them.

**Three demonstrated failures that fair selection does NOT fix.** Each needs
its own regression fixture before the next investigation; none is repaired by
better ranking or by carved extracts (§11).

- **Raw-storage limits are not display limits.** A 94-character column
  projection was rejected because the *raw* row it came from exceeded 6,400
  characters. The cap belongs to what is displayed, not to what may be read:
  separate the two limits so a small projection of a large row is deliverable.
- **`read.mail` message bodies must be persisted** with their source locators
  (store path, message id, part), not summarized in passing. A recipient or
  dissemination claim rests on body text, and today that text is not retained
  where a reviewer or a later fetch can reach it.
- **A review that says it is requesting evidence but emits no structured
  request must be repaired**, like any other malformed answer: one repair pass
  that asks for the request block, then an explicit failure. Today the prose
  intent is lost and the round is spent.

**Produced-output attribution.** A file added later to a shared output
directory currently becomes a source of an earlier extraction when the
directory is rediscovered. Record exact produced-output manifests and versions
per call; do not attribute every current sibling file to every historical call.
Legacy directory discovery keeps an explicit provenance limitation.

**Acceptance.** Repeated physical sources; broad terms; a late targeted source;
two tools writing different files into one directory. Measure the serialized
prompt including metadata and rendered labels, not only the selected raw text.

## 6. Wrapper ids resolve by an explicit link, never by proximity

*Implemented 2026-09-20, after the peer review found a defect in the first
version.*

`reason_review_details` accepted only `reason_call` entries, while the agent
commonly holds the `<py>:` wrapper `tool_call` id the middleware writes, or the
id of a `reason_readiness_status` call whose details come from a different
tool. Five of six calls in the motivating run were refused.

The first fix resolved a wrapper to the nearest preceding same-tool review.
That is wrong: proximity is not identity. Reproduced by the reviewer —
successful reviews 10 and 11, then a failed wrapper 12 returned review 11 with
`success=true` for request 12, i.e. another claim's verdict.

1. **Persist the originating review id** when the wrapper is emitted
   (`reason_call_id` on the baseline entry, stamped in
   `core/middleware.py::_trace_success_baseline`).
2. **Resolve only that link.** An unlinked wrapper, or one whose call failed
   before any review existed, resolves to nothing.
3. **Ambiguous historical entries return candidates as guidance**, never a
   silent selection.
4. The refusal names the entry type passed and the valid ids, and routes a
   readiness id to `reason.readiness_status(section=…)`. Readiness keeps its
   own retrieval route: **do not invent a `call_id` argument** for a tool whose
   detail endpoint does not take one.

**Acceptance.** Concurrent same-tool calls resolve to their own reviews; a
validation failure before review creation resolves to none; an unlinked
historical wrapper cannot borrow a prior success.

## 7. `<py>:` entries record their arguments

`core/middleware.py::_trace_success_baseline` (:493) records
`cmd = "<py>:<tool>"` with no arguments, so an input-validation failure cannot
be diagnosed from the trace. Record the bounded, redacted shape already
available via `_arg_shapes` (:438). Paths and identifiers only, never file
contents.

## 8. A refusal names the uncited call that already holds the missing facts

**Observed.** In the run of 2026-09-20 the agent asserted the contents of a
configuration file, citing the event logs, prefetch and an MFT listing — but
not the one call that had read that file. The review returned UNVERIFIABLE,
saying the deciding facts "are not present in any cited row". The agent
re-evaluated (cids 113 then 125), added four more corroborating sources, and
still did not cite the deciding call. Two reviews, roughly ten minutes, and
fourteen fetch requests were spent on a citation error.

The refusal told it to "collect the evidence the review names and evaluate
again". The evidence was already collected. Only the citation was missing, and
the server can tell the difference.

**Change.** When a finding is refused because its review was not SUPPORTED, and
when a review itself closes non-SUPPORTED, compute deterministically — no model
call — whether the claim's distinctive terms appear in a **successful evidence
call that was not cited**, and name it.

1. Terms: the claim identifiers plus the description terms already derived for
   packet selection (`_cited_query_terms`,
   `tools/_output_reader.py:107`, as used at
   `core/evidence_packets.py:153-157`). Terms **may overlap** with cited
   output: the same account, path or number appearing in a cited source does
   not establish the missing *relationship*, so restricting the search to
   zero-match terms would hide exactly the candidates that matter. (An earlier
   draft required zero matches; that restriction is withdrawn, and the
   implementation already allows overlap — keep it.)
2. Candidates: entries passing `_is_evidence_entry(..., for_rows=True)`
   (`tools/reasoning.py:1414`) that are not cited, scanned through the
   **shared retained-source abstraction** — artifact files, stdout sidecars
   **and complete inline stdout**, each with its completeness and call
   identity. Inline output is not optional: the read that motivated this
   feature is a successful 390-character inline result with **no
   `stdout_path`**, so a file-and-sidecar-only scan would miss precisely the
   evidence the feature exists to find. `for_rows=True` excludes reviewer
   prose; `agent_authored_paths`
   (`tools/_gates/_evidence_calls.py:38`) excludes authored files; evidence
   images are never opened.
3. Report typed, on the refusal and the reason entry:
   `uncited_sources: [{call_id, path, terms_found, rows_matched}]`, plus one
   sentence naming the call ids to add to `input_call_ids` and re-evaluate.
4. **Never auto-cite.** The gate still refuses; the agent decides. Suggesting a
   source is not evidence that the source supports the claim. Suggestions stay
   **outside** the review's evidence and receipt until the client cites them
   and independent review covers them.
5. **A limited retrieval heuristic, not a completeness test.** A term match
   cannot detect a missing *relationship*, whether or not the same account,
   path or number also appears in a cited source. Report
   candidate matches and the bounded search coverage; an empty result does not
   establish that collection is needed.

**Bounds.** Run on the refusal path and on a non-SUPPORTED review's own result,
never per call. Cap the number of candidate calls scanned and the bytes read
per call, reusing the packet scan budget; report when the scan was capped so an
empty suggestion is not read as "no such source exists".

### 8a. Surface it before the claim is narrowed, not only after refusal

**Observed, same run.** Three reviews of one claim (110, 120, 130), none citing
the call that had read the file whose contents the claim asserted. Between the
second and third the agent self-corrected (cid 128) and **permanently dropped
two assertions** — including one that an uncited call could have supported.
The third review then reported the same problem about a different file's
contents. Roughly twenty minutes and thirty fetch requests went into a citation
error, and the investigation lost facts it had already collected.

Narrowing a claim to fit the citations is the expensive failure here: the
refusal-time suggestion arrives after the agent has already given ground.

**Change.** Attach `uncited_sources` (§8) to the **review result itself**
whenever the verdict is not SUPPORTED, not only to a later recording refusal.
The reviewer's own answer then carries, as typed data beside its rationale:
the facts it could not find in cited rows, and the uncited evidence calls whose
retained output contains those terms.

`reason.confidence_score` and `reason.cite_check` should surface the same
field, since both run before a claim is recorded or narrowed and both already
take the claim and its citations.

The accompanying text must distinguish the two remedies explicitly, because
they are opposite actions and the current message only offers the first:

- collect new evidence, when nothing in the trace holds the fact; or
- **cite what is already there**, when an uncited call does — naming it.

Narrowing the claim with `misc.record_self_correction` **remains a legitimate
option at any time** — the first draft said it was correct only when neither
remedy applied, which is too strong. A candidate source containing the terms
may contradict the claim, or fail to support its causal interpretation; a
suggestion match never justifies keeping an unsupported assertion, and must not
be cited as proof inside the self-correction. What it does require is a record:
a self-correction that drops a fact while a matching uncited source exists
names that source id in advisory `candidate_source_ids`, separate from evidence
and citation IDs, so the choice is auditable without treating a match as proof.

**Tests.**
1. A non-SUPPORTED review whose missing terms appear in an uncited evidence
   call returns `uncited_sources` naming it, before any recording attempt.
2. The same review with no such call returns an empty `uncited_sources`, and
   the text reports bounded scan coverage and leaves narrowing available; an
   empty search does not establish that new collection is required.
3. `cite_check` and `confidence_score` return the field on the same inputs.
4. A self-correction that narrows a claim while a matching uncited source
   exists is recorded with that source id in advisory `candidate_source_ids`.
5. The field never causes a citation to be added automatically, and never
   changes a verdict.

**Tests.**
1. Claim terms present in an uncited evidence call → the refusal names that
   call id and the matched terms, **including when the same terms also appear
   in a cited source**.
2. A candidate match never establishes a missing fact or relationship. Terms
   may overlap with cited output; suggestions remain advisory and exclude
   already cited call IDs.
3. An agent-authored file containing the terms → never suggested.
4. A capped scan reports that it was capped.
5. The suggestion does not cite anything: recording stays refused until a new
   review covers the updated citation set.
6. Deterministic — same trace, same suggestion, no model call, no evidence
   image opened.

## 9. CSV output is rendered readably, without changing what a quote must match

**Today.** A CSV row reaches the reviewer as the raw line it occupies in the
file — every column, in file order, comma-separated, including the empty ones —
and the header is carried separately in the selection's `columns`
(`core/evidence_packets.py:99-130`). Fetch blocks append the same raw lines
(`tools/reasoning.py:1599`). An EVTX or MFT export runs to dozens of columns,
so the fields that decide the claim sit inside a long comma run that the reader
has to align against a header printed elsewhere. The dashboard shows the same
raw text in its stdout-excerpt block (`dashboard/trace_viewer.html:820`).

**Change.** When a source is tabular — by extension (`.csv`, `.tsv`) or by a
successful header parse — render each row as labelled fields rather than a bare
line:

- one `column: value` pair per populated column, empty columns omitted;
- the row's file position retained (`row_number`, byte range) exactly as now;
- per-field width capped, with the truncation marked in the field, and the
  existing `columns`/projection behaviour unchanged;
- the same rendering for packet spans and for fetch blocks, so a row looks
  identical wherever the reviewer meets it.

**Constraint that governs the design.** A reviewer-error resolution must quote
text that was actually shown, and the check is a substring match against the
stored span text (`core/review_issues.py:110-124`). If the rendering replaces
the stored text, every quote the model copies from a rendered row will fail to
match the raw line, and §8's term scan will drift from what the reviewer saw.
So:

1. The **stored** `span['text']` and `source_selections[].text` remain the raw
   bytes of the row — canonical, byte-anchored, unchanged.
2. Rendering is a presentation layer applied when the prompt is built, and the
   **exact displayed text and projection** are stored with it — or a versioned,
   reproducible display receipt tied to the same source and row.
3. Quote matching accepts **only text actually exposed to that reviewer**. The
   first draft accepted either the raw row or a freshly rendered version; that
   is broader than "quote what the reviewer saw". If the presentation omitted a
   column or clipped a field, the hidden raw text must not qualify as displayed
   proof, and re-rendering later depends on renderer version and projection
   settings.
4. Source and claim version checks still apply. Rendered quotation is not a
   route around them.

This keeps provenance byte-anchored while letting the model read and cite what
it was shown.

**Tests to add for this:** hidden columns, clipped values, multiline/quoted
CSV, a renderer change between review and resolution, and a stale source
version. This presentation work follows the access and delivery fixes; it is
not bundled with them.

**Dashboard.** The stdout-excerpt and packet blocks render a tabular excerpt as
a table with its header when the content parses as CSV/TSV, falling back to the
current `<pre>` when it does not, with a toggle to see the raw text. Display
only; it reads the same stored bytes.

**Tests.**
1. A CSV row with many columns renders as labelled fields, omitting empty
   columns, and keeps its `row_number` and byte range.
2. A quote qualifies only when that exact representation was displayed;
   hidden raw fields and clipped suffixes cannot satisfy reviewer-error proof.
3. Stored span text is byte-identical to the file's row after rendering is
   introduced (provenance hashes unchanged).
4. A non-tabular source is unaffected.
5. A file whose header fails to parse falls back to raw lines and is labelled
   as such rather than mis-rendered.
6. Per-field truncation is visible in the field and does not silently shorten a
   value the reviewer might quote.

## 10. Synthesis pulls its evidence instead of packing it

**Observed 2026-09-20 (run 4).** All 16 `reason_synthesize` attempts failed, 12
of them — including the last three — with

> Synthesis source context exceeds the bounded review budget; use narrower
> traced evidence selections.

`core/synthesis_evidence.build_synthesis_packet` rebuilds a packet for every
active finding and refuses when the total exceeds `MAX_CONTEXT_CHARS`
(96,000). The run reached Report with 27 findings (10 active after
supersessions) and could not synthesize at all, so no report was reachable —
and the agent had no lever, because "narrow the evidence of all findings
collectively" is not an action it can take. The better the investigation, the
more certain the failure.

Measured composition of that packet (209,591 chars against a 96,000 cap):

| Component | Chars | |
|---|---|---|
| Row spans | 93,616 | what pull mode removes |
| Provenance | 29,886 | 59 source entries, **47 unique** |
| Identities + file versions | 7,162 | must stay |
| `finding_sources` index | 8,460 | repeats full source dicts per finding |

Removing rows alone leaves ~116,000 — still over. Rows **and** deduplication
together land near 25–30k.

**Change.** The synthesis packet becomes an **index**, and the reviewer pulls
what it needs through the `EVIDENCE_REQUEST` machinery that already exists,
is already restricted to the packet's sources, and whose results already feed
reviewer-error quote matching via `source_selections`.

The packet carries:

- **unique sources, once each** — id, `call_id`, path, output hash, byte size,
  retained completeness, matched/scanned totals, tool, truncated command,
  timestamp, artifact classes;
- **findings** — claim, tier, revision, review id, and **source ids by
  reference**, never repeated source dicts;
- **identities and file versions in full** — quote binding and
  `packet_current` depend on them;
- **no row spans.**

Four conditions keep this from trading one failure for another:

1. **A pull-mode round 1 legitimately has zero rows.** That is not the access
   failure of §3, which keys on unresolved *required* requests, never on a row
   count. Say so explicitly in both the prompt and the failure classifier.
2. **No rows pulled, no factual assertion.** A reviewer that never fetches may
   raise structural issues only; a contradiction or unsupported-claim issue
   must cite a row it actually pulled.
3. **A zero-fetch review cannot approve either.** Prohibiting only
   contradictions leaves `issues: []` — a clean bill issued without looking —
   and today's readiness has no evidence-coverage requirement that would reject
   it. Synthesis therefore **persists a coverage record** tied to the current
   finding revisions: which findings had rows examined, from which sources, and
   which required factual review is still unfinished. Readiness treats
   unfinished required review as an open obligation, so a complete synthesis
   approval is impossible while it stands. Partial coverage is a legitimate
   *interim* result, never an approval.
4. **Bounded execution, not an open-ended pull.** The fetcher allows three
   rounds of four requests; removing pushed rows makes that ceiling load-
   bearing, while claims, source metadata, reproduction records (§12) and file
   versions all still grow with case size. Specify:
   - **bounded batches** — findings are reviewed in batches sized to the
     prompt budget, not all at once;
   - **durable progress** — each batch's coverage and issues persist, so a
     later batch resumes rather than restarting, and a crash loses one batch;
   - **a final cross-finding consistency pass that receives the findings
     themselves** — each active finding's actual assertions, entities, time
     windows and evidence references — with bounded fetching available. The
     accumulated issue lists and coverage records are not enough: two batches
     can each pass locally while holding mutually contradictory findings, and
     two clean issue lists cannot expose that. Issues and coverage go in as
     context; the assertions are what get compared;
   - **durable continuation within a single finding.** Batching findings does
     not help a finding whose review needs more source requests than one
     exchange allows (three rounds of four): its review persists the fetched
     receipts and the still-unfinished requests, and continues from them in a
     further exchange, under the same overall budget. Without this, one
     evidence-rich finding can never finish regardless of batch size;
   - **one budget covering the entire model prompt** — index, claims, fetched
     rows and instructions together — not a per-component cap, so the failure
     cannot migrate from packet construction to exhausted fetching or
     accumulated context.

**Acceptance.** A case whose packed packet exceeds the cap synthesizes under
pull mode; the index stays under budget as findings grow (10, 30, 100
findings) and, where it cannot, batches deterministically rather than
refusing; a source cited by many findings appears once; a fetched row satisfies
reviewer-error quote matching; a zero-fetch review may neither assert a
contradiction **nor return `issues: []` as an approval**; partial coverage is
recorded and blocks complete approval while required review is unfinished;
batch progress survives a restart; **two deliberately contradictory findings
placed in different batches are caught by the final pass**, which receives
their assertions, entities and time windows rather than only their batch
results; **a single finding needing thirteen distinct source requests
completes through durable continuation** without exceeding the overall budget;
`packet_current` still invalidates on a changed source.

## 11. Carve the exact evidence, do not point at the whole artifact

Today a finding cites the call that produced `mft.csv` or parsed `Amcache.hve`,
and every reviewer round then searches that whole output for the handful of
rows that matter. The reviewer should instead be handed — and the finding
should cite — a **derived extract containing exactly the supporting rows**.

**The extract must be produced by a tool, never written by the agent.** An
agent-authored file is not evidence (`agent_authored_source`,
`tools/_gates/_evidence_calls.py:38`), and that rule must not be weakened. So
this needs a traced extraction tool — `read.output` currently returns rows to
the caller but writes nothing (`tools/read_output.py`) — that writes a derived
artifact under the case output dirs and records, in a manifest beside it:

- the **source call id**, source path and source `sha256` at extraction time;
- the **selector** used (query terms, columns, row numbers or byte ranges);
- **byte ranges and row numbers** of every extracted row in the source;
- the source's **matched/scanned totals** for that selector — so the extract
  states how much it left behind;
- the extractor version.

**Lineage and authorization contract.** Recording a parent in a manifest does
not, by itself, let anyone read that parent: a fetch is permitted only for a
call/path present in the packet's source map, so "the reviewer may still fetch
the parent" is false unless the parent is registered. Specify:

- **transitive parent registration** — citing an extract registers its parent
  chain (and each ancestor's path) in the permitted source map for that review,
  so the parent is genuinely fetchable;
- **version checks along the chain** — an ancestor whose version changed
  invalidates the extract exactly as a changed source invalidates a packet;
- **citation aliases** — an extract and its parent are the *same* evidence.
  Two extracts of one source, or an extract plus its parent, must never count
  as independent corroboration; the corroboration logic dedupes on the
  originating source identity, not on the citing path.

Consequences that must hold:

- **Artifact class is inherited from the source call**, not invented by the
  extractor, so tiering is unchanged: an extract of a Prefetch CSV is still
  Prefetch evidence, and an extract of a reviewer's prose is still nothing.
  Class inheritance alone is **not** sufficient — the origin identity above is
  what prevents double-counting.
- **An extract can never ground a negative.** Absence claims continue to
  require the complete source under `negative_completeness`; a carved subset
  is evidence of presence only. State this in the manifest and enforce it in
  the gate.
- **Cherry-picking is the risk.** The manifest's matched/scanned totals and the
  recorded selector make the omission visible, and contradiction checks still
  run against the **source**, which the reviewer may still fetch. An extract
  narrows the reading path; it must not narrow the evidence.
- **An extract is invalidated by a source change** — the recorded source hash
  and version are checked exactly as `packet_current` checks a packet.

This composes with §10: the index points at extracts where they exist and at
full outputs otherwise, and pulls are cheaper because the extract is small.
It also serves §8 — a suggestion can name the extract rather than a 500 MB
parent.

**Acceptance.** An extract is tool-produced and citable; an agent-written file
with identical content is still refused; citing an extract makes its parent
fetchable in the same review; a changed ancestor invalidates the extract; two
extracts of one source (and an extract plus its parent) count once, not twice,
for corroboration; the extract's artifact class equals the source's; a negative claim citing only an extract is refused while the same
claim citing the complete source is allowed; a changed source invalidates the
extract; the manifest's totals report what was left behind; a finding citing an
extract reaches the same tier as one citing the parent.

## 12. Every evidence entry carries a reproduction record

A reader of the finished report must be able to take any piece of evidence
behind a finding, **re-run the command that produced it and verify the result
by hash**, without access to this session. Today that chain is partial: a
packet entry carries `tool`, `command`, `call_timestamp`, `artifact_classes`
and `producer_call_id` (`core/evidence_packets.py:268,356`), the output hash is
computed at packet-build time rather than persisted on the call, and
`source_hashes` is populated only by `hash.file` (`tools/hashing.py:70`) — so
for most entries the *input* side of the derivation is unrecorded.

**Each evidence entry in the index (§10), each extract manifest (§11) and each
report appendix row carries:**

- **originating source** — the path(s) the command actually read, each with its
  `sha256`. For a file on a mounted image, the originating record is the
  acquisition hash of the image (from `hash.verify_evidence_hash`) **plus** the
  mount offset and the path within the volume, because hashing a 40 GB image
  per row is not viable and the acquisition hash is the custody anchor anyway.
- **the exact command** that produced the output, as recorded.
- **the output** — path, `sha256`, byte size, row count — persisted **on the
  tool_call entry at production time**, not recomputed later. A hash computed
  at read time cannot prove the output has not changed since. For a
  background job (see [long-tool-jobs-plan.md](long-tool-jobs-plan.md)),
  "production time" means **when the worker finishes**, not when a later poll
  collects it: the worker writes the manifest and hashes before publishing
  completion, and collection reads that durable record.
- **tool identity and version** (`mcp_tool` plus the binary/library version),
  since a different parser version legitimately yields different bytes.
- **the parent link** (`producer_call_id`), so a chain reconstructs:
  image → mount → extractor → CSV → extract.

**Determinism, stated honestly.** Many forensic tools embed run timestamps,
ordering or temp paths, so a re-run is not always byte-identical. The record
carries the raw `sha256` of the bytes and, where the output is tabular, a
**stable row-set digest**.

That digest needs a sharper definition than "sorted canonical rows", which does
not deliver the guarantee: sorting removes ordering differences but leaves an
embedded run timestamp inside a row, while generically ignoring timestamp-
looking fields would hide changes to real forensic times — the evidence itself.
Specify instead:

- **versioned, tool-specific normalization** of known *exporter* metadata
  (the header line a parser stamps with its run time, a temp path in a source
  column), declared per tool and versioned with it — never a generic
  "ignore anything date-shaped";
- **duplicate-row multiplicity preserved** — a row appearing twice is not the
  same evidence as appearing once;
- **evidentiary fields never normalized** — timestamps that are the artifact's
  own data are part of the digest.

Keep the two ideas apart in the record and in the report: byte-for-byte
reproduction, and semantic equivalence under a named normalization version. A
raw mismatch that matches semantically is reported as *reproducible under
normalization vN*, never as tampering; where no normalization exists for a
tool, only the raw hash is claimed and the record says so.

**Legacy outputs and non-command tools.** Two populations cannot satisfy the
record as stated, and neither may become a new report blocker:

- **Pre-existing outputs** cannot acquire a trustworthy production-time hash
  retrospectively — a hash computed now proves only that the file has not
  changed *since now*. They carry an explicit **provenance limitation**
  ("verified from <date>, production-time hash unavailable"), which the report
  prints; they are not refused, and they are not silently presented as
  reproducible.
- **Python-implemented tools** record a description, not an executable command
  line (`<py>:<tool>`, and the libscca Prefetch path writes
  `pyscca prefetch parse …`). For these the record carries a **structured
  reproduction recipe** — tool identity, arguments, tool and library versions,
  and the dependency that must be present — rather than a shell string a reader
  would paste and have fail.

**Rendering.** `misc.write_final_report` emits an **evidence reproduction
appendix**: one row per cited evidence entry — finding, source + hash, command,
output + hash, tool version — so the chain is in the delivered document, not
only in the trace. `misc.export_execution_log` carries the same records.

**Acceptance.** Every evidence entry in a synthesis index resolves to a source
path with a hash, a reproduction recipe (command line or structured recipe),
and an output hash recorded at production time; a legacy entry carries its
provenance limitation and does not block the report; a Python-tool entry
carries a structured recipe with versions rather than an unrunnable string; a
file read from a mounted image records the image's acquisition hash, offset and
in-volume path; an output modified after production fails verification; a
benign re-run that differs only in embedded timestamps matches on the row-set
digest and is reported as reproducible; the report appendix lists every cited
entry with no gaps; a chain of three derivations reconstructs end to end from
the appendix alone.

## Acceptance criteria

Tests; none may name a case, actor or artifact.

1. A large evaluation response reaches the client with no cache-file fallback,
   carries its review id, and that id retrieves the same saved result (§0).
   Measured on the serialized response **after** middleware enrichment.
2. Finding-review packet + request carrying `finding_call_id` → rows returned.
3. Synthesis packet + request whose `finding_call_id` does not match its
   sources → refused, listing that finding's valid sources. A malformed
   synthesis packet is refused by purpose, not silently treated as a
   finding-review packet.
4. `"path": null` → rows returned; a wrong non-empty path → refused with the
   valid path list drawn from the versioned packet only.
5. An all-refused round does not decrement the round budget; the free retry is
   capped at one per review. Every retry counts toward the total
   model-call/time budget.
6. **Any unresolved required request** yields an incomplete/access-failure
   result — including when unrelated rows were pushed, and in mixed batches —
   with no SUPPORTED / CHALLENGED / UNVERIFIABLE verdict and no sticky
   challenge against the claim (§3).
7. A replayed trace does not turn a persisted access failure into a
   substantive verdict.
8. A refused request's record has `searched: false`; a completed search that
   matched nothing has `searched: true`. `searched: true` alone never
   establishes absence: scan completeness, retained-source completeness and
   requested scope are checked too.
9. A cited call with several output files reports per-source rows and totals;
   the scalar totals equal the sum of the per-source entries.
10. Selection fairness: an early irrelevant source, and a second citation of
    the same file, cannot hide a decisive later targeted selection. A broad
    token does not consume the budget ahead of discriminating matches.
11. Two tools writing different files into one output directory are attributed
    per call from the produced-output manifest, not by directory rediscovery.
12. Uncited-source discovery finds a candidate whose retained output is
    **complete inline stdout with no sidecar**; reviewer prose and authored
    files are never candidates; a capped scan reports that it was capped; an
    empty result does not assert that collection is needed.
13. Suggestions never alter citations, evidence, receipts or approval, and a
    narrowing self-correction records any matching uncited source id.
14. `review_details` with a **linked** wrapper id returns that review; with an
    unlinked or failed wrapper it returns none and lists candidates; concurrent
    same-tool calls resolve to their own reviews.
15. A `<py>:` tool_call entry for a failed call records an argument shape
    containing the offending parameter names and no values beyond paths/ids.
16. Rendered-CSV quoting accepts only text actually displayed: hidden columns
    and clipped values do not qualify, and renderer or source-version changes
    are detected.

## Acceptance details to retain

- Scope validation keys on **explicit packet purpose/schema**. A malformed
  synthesis packet must not fall back to finding-review semantics merely
  because its source map is absent or empty. Genuinely out-of-scope requests
  stay refused, with permitted-source guidance (the operator decision).
- Scope-error guidance lists only sources allowed by the **versioned packet**;
  dynamically discovered sibling files are not valid alternatives.
- `searched=true` is necessary but **not sufficient** for absence. Keep
  matched/shown counts, scan completeness, retained-source completeness and
  requested scope separate: an empty complete source may legitimately have zero
  rows, while a partial or budget-limited scan proves nothing.
- Every retry, including the single format-repair retry, counts toward an
  explicit total model-call/time budget. Repeated unchanged access failure
  should expose a **repair requirement**, not encourage another full
  evaluation.
- Full independent review and exact receipt binding stay. The uncited-source
  feature is advisory. No speed gain is established by obtaining a lower-tier
  finding through an access failure.

## Sequencing

Delivery order (from the peer review; generic fixtures throughout, then compare
runs with code and configuration frozen):

1. Packet-purpose-aware scope repair (§1), accurate failure records (§4),
   **bounded initial evaluation responses (§0)**, **empty-response transport
   handling (§0a)** and explicit review-id linkage (§6).
2. Required-access failure semantics (§3), versioned produced-output manifests
   and fair selection of targeted evidence (§5).
3. **Pull-mode synthesis (§10)** — it is the current hard blocker: no report
   is reachable at all while the packed packet exceeds its cap. Then bounded
   uncited-source suggestions across every retained source kind (§8, §8a).
4. Carved evidence extracts (§11), which make every later pull cheaper, with
   their reproduction records (§12). §12's production-time output hashing is a
   prerequisite for §11's manifests, so land them together.
5. Optional CSV presentation with displayed-proof receipts (§9).

Do not bundle the optional presentation work into the urgent protocol fix.
§1 and §6 are already delivered.

## Risks

- **Prompt growth (§5).** The character budget must remain the binding limit,
  or a large source pushes a review into truncation — which the reviewer
  reports as an incomplete review, not a verdict.
- **Free retries (§2).** Capped at one per review; without the cap a model that
  keeps mis-formatting requests would never finish.
- **Shape changes (§4).** `sources` is additive; keep the scalar fields
  populated for existing consumers until they are migrated in the same change.

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
