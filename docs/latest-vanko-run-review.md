# Latest Vanko run review — 2026-09-20

The run collected and recorded substantial evidence, but failed to produce a
report. The decisive failure was the synthesis packet's size accounting and
recovery contract. Repeated attempts to repair that failure changed citations,
reopened already supported findings, and eventually changed a confidence tier
for a tooling reason. The Report-to-Collect router worked for the recorded
forensic follow-ups.

This was a Claude pilot (`claude-opus-5` in the session transcript) using
`deepseek-v4.1-flash:cloud` for DAIR and independent reasoning. The synthesis
failures happened in TRUDI before a synthesis request reached that model.

## Scope and outcome

Reviewed `/home/trin/cases/vanko-deepseek41/analysis/VANKO-2016-DEEPSEEK41_trace.json`
and the matching Claude session `56bdbaa8-47aa-47b0-bb93-246aa68f775b`.
Trace times are 2026-09-20 23:39:41 through 2026-09-21 02:23:03 UTC
(September 20, 16:39–19:23 Pacific). The pilot's final response at 02:23:26 UTC
explicitly acknowledged that it could not produce the gated report.

| Measurement | Observed |
| --- | ---: |
| Trace duration | 2 h 43 m 22 s |
| Trace entries | 854 |
| Tool-call entries | 255 |
| Finding review calls | 46 |
| Review outcomes | 22 supported, 20 unverifiable, 4 failures |
| Finding records, including revisions | 27 |
| Active logical findings at end | 10: 7 confirmed, 3 suspected |
| Synthesis attempts / model synthesis reviews | 16 / 0 |
| Synthesis size refusals | 12 |
| Recorded Report → Collect transitions | 5 |
| Fetch events / individual requests | 57 / 159 |
| Final report artifacts | None in `reports/` |

The 125 `finding_submission` events are state transitions, not 125 independent
submissions. They contain 75 distinct idempotency keys, with some keys retried.
Likewise, 27 finding records include 17 revisions of the ten logical findings.

## 1. The terminal failure was synthesis metadata growth

Call **556** first failed on citation **297**: SQLECmd had printed unrecognized
argument errors while returning exit code zero, so the trace marked it successful
despite no usable artifact output. The finding was re-cited. Beginning at **559**,
the remaining synthesis attempts repeatedly hit:

> Synthesis source context exceeds the bounded review budget; use narrower traced evidence selections.

The 12 size refusals were **559, 561, 562, 613, 628, 632, 676, 686, 719, 748,
821, 841**. The other four failures were two wrong-phase calls (**551, 669**),
the missing output (**556**), and a deterministic prerequisite (**682**).

Offline reconstruction of the input immediately before call **841** produced:

| Serialized component | Characters |
| --- | ---: |
| Compact displayed synthesis packet | 140,237 |
| Same packet with every evidence span's text emptied | 121,624 |
| Contribution of evidence text, including JSON escaping | 18,613 |
| Builder limit | 96,000 |

There were **59 source records for 32 distinct source paths**. About 87% of the
packet was structure, provenance, selectors, references and other metadata.
Even removing all row text would leave it over budget.

`core/synthesis_evidence.py:28` deduplicates repeated spans, but appends each
finding's complete source record at line 58 and repeats source references in
`finding_sources`. It caps row content at 32,000 characters, then checks the
entire serialized object at line 93. The size failure includes neither the
actual size nor its contributors and labels the problem `needs-evidence`.

This sent the pilot toward file sizes instead of prompt composition. Narrations
**563, 620, 679, 694, 724, 755** show successive attempts to replace MFT, mailbox,
event-log and prefetch citations with smaller files. Only at **846**, near the
end, did the pilot identify aggregate source/metadata count as the actual limit.
The period from first reaching Report to the final failed submission was roughly
62 minutes. Some new useful evidence appeared during that period, so it would be
incorrect to label every minute wasted, but none of the re-citation cycles
produced a synthesis review.

There is a second capacity defect: row allocation is global and greedy across
findings. In the reconstructed packet, the first finding received 26 rows;
F-224 and F-547 received **no rows and no shared-row references**. Raising the
96,000-character limit alone would expose this next evidence-access problem.
Additionally, `_ask` measures ordinary `json.dumps` output and subsequently
includes system instructions and the finding narrative, whereas the builder
measures compact JSON. These are different budgets in practice.

## 2. CSV projection still pays for hidden raw fields

The new CSV renderer was active: its receipt version matches the installed
renderer. However, `core/evidence_packets.py:169` rejects oversized raw rows
before applying column projection. Lines 333–339 also charge the larger of raw
and displayed length against the source's allocation.

The last review, **852**, demonstrates the consequence precisely:

| Source 793: VeraCrypt Setup prefetch row | Characters |
| --- | ---: |
| Raw row, including fields the reviewer did not request | 6,479 |
| Allocated share for this source | 6,400 |
| Requested nonempty displayed fields | 94 |

The row existed, matched, and was returned by the investigator's traced read.
Its packet nevertheless contained **zero spans**. Review 852 therefore rejected
the revised finding as unverifiable. The same claim had been supported at **801**.
The final attempt also removed targeted UserAssist read **614**, leaving **360**,
whose ranked lines showed names/counts without their adjacent timestamps.

Raw retention and displayed context need separate limits. Plain-text evidence
also needs record/context-aware selection: isolated UserAssist lines and XML
fields repeatedly separated identifiers from the timestamps that explained them.

## 3. The investigator and reviewer saw different mail evidence

`read.mail` returns message bodies to its caller, but
`tools/read_output.py:417` persists only `from -> to | subject` lines. Its response
still tells the investigator to cite that call because body evidence lives there.

For calls **97, 100, 317**, review packets instead discovered a handful of
`Contact.txt` and `Appointment.txt` files beneath the export directory. Reviews
**108, 127, 260, 322** consequently could not verify the mail bodies the pilot had
read. Call **633** had the same general problem: the review selected message
metadata files, without the decisive bodies. Re-extracting as mbox at **646**
made more of that evidence accessible, at the cost of another collection cycle.

This is a persisted-output/provenance contract defect. A mail reader needs to
retain the exact returned records and their source locators, so the reviewer can
inspect the same evidence without rediscovering arbitrary directory members.

## 4. Missing rows did not always trigger fetching

Eight unverifiable reviews had **no fetch event**:
**214, 286, 339, 601, 607, 797, 827, 852**. Reviews **797** and **852** even said in
their rationale that they requested additional rows, but supplied no structured
`evidence_request`. The server accepted the terminal verdict after one provider
call and left the investigator to start another submission.

The evidence-access instruction describes `RESULT.evidence_request`, but the
final example in `tools/reasoning.py:866` omits that field. Validation permits
`UNVERIFIABLE` without a request. This is a likely contributor to the model's
inconsistent behavior, rather than evidence that a well-formed request was
silently discarded. Repairs should distinguish an unresolved presentation gap
from an exhausted search or actual evidentiary limitation.

All **159 parsed fetch requests** recorded status `ok`; none recorded the prior
scope-mismatch refusal. Ten requests returned no rows, so `ok` means the search
executed, not that it resolved the question. Cross-finding fetch behavior was not
tested by this run because synthesis never reached the model.

## Consequences and additional friction

- **Confidence became a size workaround.** Finding F-348 changed from LIKELY
  (**667**) to SUSPECTED (**681/684**). The saved description explicitly says this
  was solely because including a citation broke the synthesis budget. Capacity
  should not determine an evidentiary confidence tier. This review does not
  independently endorse either tier or the finding's stronger delivery language.
- **Noisy correspondent obligations added work.** Check **391** blocked on 104
  purportedly engaged correspondents, including the literal string `address type`.
  Call **97** registered that string with 18 recipient occurrences. The trace
  contains 116 dispositions overall, 93 marked out of scope. This shows malformed
  address data reaching a mandatory gate; it does not establish that every
  disposition was unnecessary.
- **Transactional responses bypass the transport cap.** Failed submissions copy
  full citation candidates back onto the response after creating the compact
  review link (`core/finding_submission.py:277`). Middleware compaction covers
  direct review tools, not `misc.submit_finding`. One captured submission response
  was 8,684 UTF-8 bytes before the MCP envelope; the repository's conservative
  two-copy wire estimator gives a maximum of 18,067 bytes, with 36 of 78 parseable
  submission responses above 8,192. This is a separate size-contract gap; there
  is no evidence here that client truncation caused the terminal synthesis failure.
- **Backend format failures were secondary.** Reviews **121/143** returned empty
  content with `finish_reason=tool_calls`; **538** failed result parsing, and
  **332** exceeded the review context budget during evidence fetching. These
  caused retries but do not explain the 12 deterministic synthesis refusals.
- **Curiosity probes remained unused.** There are no probe tool entries. This run
  therefore supplies no evidence of improved probe utilization.

## What improved, and what to fix first

The five Report-to-Collect transitions (**645, 688, 721, 759, 830**) preceded the
associated forensic execution. All eleven recorded routed work items completed
in Collect. CSV labelled displays and receipts were present, and the recorded
fetches did not exhibit the old scope mismatch. Those improvements did not
translate into successful end-to-end report generation.

The next fixes should apply to every case:

1. Make synthesis capacity a server-owned concern: compact shared source records,
   reserve coverage per finding, retain exact source/quote bindings, and use
   bounded review batches when the complete task cannot fit. Include the entire
   prompt in one consistent budget. Return measured capacity diagnostics as a
   presentation/repair issue rather than suggesting new evidence collection.
2. Separate raw evidence storage from displayed context accounting; preserve
   record context and the successful fetched rows required to verify a finding.
3. Persist each reader's actual returned evidence, particularly mail bodies,
   with precise original source locators.
4. Make missing-display recovery explicit in the result schema and validator;
   keep evidence-access failures separate from factual confidence. Require
   measurable progress before repeating the same failed synthesis operation.
5. Apply final response limits to transactional submissions as well as direct
   reviews, and validate addresses before creating correspondent obligations.

The previous passing tests covered individual packets, rendering, quote receipts,
and selected transport/routing paths. They missed this multi-finding synthesis
workload, raw-versus-projected allocation boundary, and transactional response
path. A useful regression fixture is this saved run, with specific assertions
for synthesis capacity and evidence coverage; a higher limit alone is insufficient.

## Reproduction and limits

The immutable review snapshot and measurements are under
`/home/trin/analysis/vanko-run-review-2026-09-21-053409/`:

- `trace-snapshot.json` — SHA-256
  `e498d4ecf14cf2278df245deefdef9df4da2f170b2ab4185de32689675fdf8a7`.
- `timeline.tsv` and `review-tool-results.json` — event index and captured client
  responses from the matching pilot session.
- `synthesis-size-diagnostic.json` and `synthesis-prompt-offline.json` — offline
  reconstruction before call 841. The seven active reviewed packets pass their
  entry/file-version checks under the stored run policy; the other three
  findings' packets are rebuilt from existing outputs. Only the size guard was
  lifted in the diagnostic process to measure the rejected object. No provider
  request or investigation event was generated.
- `submission-delivery-sizes.json` — captured response lengths and conservative
  estimated MCP envelope sizes, not packet captures of actual wire traffic.

This is a workflow and implementation review, not a fresh factual investigation
or ground-truth accuracy grade. No investigation was started, no provider calls
were made, and no case trace, evidence, findings, or application code was changed.
