# Reviewer evidence access: implementation and validation

Implemented 2026-09-20 against the approved revised plan. This release covers
increments 1–4 in the implementation-readiness review, including CSV display
and dashboard tables (§9). Exact displayed-quote checks remain in force; hidden
raw text cannot be used as proof.

## Delivered

| Area | Behavior | Implementation |
| --- | --- | --- |
| Initial review delivery | Compact after MCP enrichment; stable review ID, verdict/access status, receipt and versioned detail route. Text and structured copies agree. Complete internal results remain available to transactional submission. | `core/review_delivery.py`, `core/middleware.py` |
| Lossless details | Saved results and Unicode pages respect a conservative 8,192-byte wire budget, including both MCP representations. Validation refusals receive their own retrievable review identity. | `core/control_response.py`, `reason.review_details` |
| Required evidence access | Server request IDs, explicit replacement IDs, one all-refused repair allowance, bounded provider-call count and outer watchdog. Successful requests are reused. Unresolved access fails review with no approval receipt or sticky factual verdict. | `tools/reasoning.py` |
| Scope and outcomes | Explicit packet purpose; malformed synthesis maps are refused. Finding reviews ignore the irrelevant synthesis finding ID. Refusals name permitted sources and searched=false. Receipts retain per-source outcomes, match/display counts and scan/retention completeness. | `core/evidence_packets.py`, `core/execution_log.py`, `tools/reasoning.py` |
| Output ownership | Exact declared targets are captured at tool completion, with source versions and producing IDs. Same-target cooperating writers are serialized, including across processes. Async execution registers only completed outputs. | `core/output_manifest.py`, `core/executor.py` |
| Read provenance | Traced reads store full selectors and observed source versions, separately from producer ownership. Replaced artifacts/sidecars cannot be silently reused. Original stdout length survives retention caps. | `tools/read_output.py`, `tools/_output_reader.py`, `core/execution_log.py` |
| Selection | Targeted reads first, rare-term ranking with common years downweighted, per-physical-source budget shares, repeated spans represented by references. Byte-anchored source text is preserved. | `core/evidence_packets.py` |
| CSV presentation | Packet and fetch rows use labelled nonempty fields, with visible field clipping, original byte ranges and versioned display receipts. Dashboard excerpts and packet rows use tables with raw-text toggles. | `core/evidence_display.py`, `core/review_issues.py`, `dashboard/trace_viewer.html` |
| Citation assistance | Bounded advisory search over uncited retained outputs, including inline stdout. Review/refusal/citation/confidence responses carry candidates and scan coverage. Self-corrections store candidate IDs separately from evidence citations. | `core/citation_candidates.py`, `tools/reasoning.py`, `tools/misc.py` |

This retains evidence fetching: packets improve the first evidence selection;
the existing fetcher obtains additional rows when needed. Independent review,
exact claim/receipt binding and finding gates remain required.

Candidate searches deliberately permit terms also present in cited output: a
missing relationship cannot be detected solely by term absence. They exclude
cited call IDs and authored/reviewer prose, identify matching sources without
changing a verdict, and leave narrowing available. No candidate becomes a
citation automatically. The bounds are 256 calls, 128 sources, 1 MiB per source,
16 MiB total, eight suggestions and a 1.5-second scan deadline checked between
sources. Capped/partial searches cannot establish absence or a need to collect.

## Validation

**696 tests passed**, covering review access/delivery, packet/submission,
executor/logging, middleware, Report routing, reasoning, DAIR, EZ wrappers,
citation and output reading. The separate previously approved real MCP routing
test also passed: **697 checks in total**. This is a focused regression suite,
not a claim that the entire repository suite ran.

New regressions include an actual MCP client/envelope with a large review;
lossless escaped-Unicode paging; a large internal transactional review with the
same receipt; failed and repaired access across restart; mixed-batch read reuse;
malformed synthesis scope; concurrent producers; stale output/sidecars; fair
selection and span sharing; inline candidates and candidate/citation separation.

Offline replay used the saved 184-entry previous trace and ten cached initial
evaluation responses. The reusable script is `scripts/replay_review_access.py`.
No model calls were made and no case artifacts were changed.

| Measurement | Previous trace | Offline replay |
| --- | --- | --- |
| Initial review delivery | 10 cached JSON payloads, 82,999–145,647 bytes | All 10 conservative full MCP envelopes fit: 3,766–7,304 bytes |
| Stored scope refusals replayed | 20 scope mismatches | 20 searches execute successfully |
| Targeted read #60 in review #67 | 0 rows | 6 rows |
| Targeted read #63 in review #67 | 0 rows | 3 rows + 1 shared span |
| Targeted read #85 in review #87 | 0 rows | 1 row + 5 shared spans |
| Serialized packet characters, ten reviews combined | 546,659 | 364,837; 33.3% fewer |
| Inline output #98 | Omitted from relevant claims' citations | Suggested in reviews #110, #120 and #143 |

The old fetch records did not retain the erroneous finding ID. Their scope
replay uses the stored call/query/columns and an explicitly irrelevant synthesis
ID to reproduce the defect; it is not an exact replay of lost wire arguments.

Measurements and source hash:
`/home/trin/analysis/reviewer-access-validation-2026-09-20/replay.json`.
The snapshot SHA-256 remains
`f852be510c48b14a0f9a1bb84dd92cdf73675f594a36ba23c7c9358bca5deb32`.

These checks establish transport, access and selection improvements. They do
not measure model token savings, total investigation time, first-submission
acceptance, completed-report rate or factual accuracy on a new investigation.

## Deployment and remaining boundaries

- Repository and installed Claude/OpenCode guidance describe review IDs, paging,
  access repair and advisory candidates. Installed copies are backed up with
  hashes under the validation directory. Pilot profiles retain analyst approval
  rules. Core changes load in a fresh/restarted MCP process; active investigations
  were not restarted.
- The trace viewer now selects FETCH by default and gives Phase return and
  Follow-up the existing filter badge layout. Reload the page to apply defaults.
- Manifests are authoritative for newly declared exact outputs, including EZ
  directory+filename pairs and redirected stdout. Directory-only tools with no
  attributable filename record the limitation instead of claiming siblings;
  use a traced read or an explicit wrapper `produced_paths` registration. Legacy
  discovery is marked unverified, and historical ownership is not reconstructed.
- Output writer locks coordinate TRUDI executors. They do not make a claim about
  unrelated external writers; file-version checks still reject changed evidence.
- Selection is bounded: unusually large rows can still require a targeted fetch.
  CSV rendering and display receipts now reject hidden/clipped-field proof and
  stale renderer/source versions. Oversized or malformed views are explicitly
  bounded or labelled as raw fallbacks.
- The existing Report router is retained. Its status is reconciled in the
  companion plan; no second transition mechanism was introduced.


## CSV presentation increment

The stored packet spans and fetch selections retain their original row text and
byte positions. Only the separately receipted display enters the reviewer prompt.
CSV and TSV display nonempty `column: value` lines, retain embedded quoted values,
indent multiline values and mark fields shortened at 400 characters. Projection
is case-insensitive and keeps the requested column order. Plain text stays plain;
malformed table headers fall back to explicitly labelled raw lines. Inline
stdout uses the same renderer as files.

Reviewer-error adjudication validates the saved displayed text, source identity,
byte positions and renderer receipt. Omitted columns, clipped suffixes and raw
CSV syntax that was never shown cannot satisfy a quote. Source/renderer changes
invalidate the receipt; a stale adjudication reopens the issue. Canonical rows
are not reconstructed from rendered strings.

The dashboard handles quoted commas, escaped quotes, multiline fields and TSV,
with bounded table previews, escaped HTML, and a raw-text disclosure. Packet rows
also expose the exact reviewer display for comparison. FETCH remains selected by
default and the Phase return / Follow-up filter styling is retained.

Historical presentation verification used the ten packets embedded in the saved
trace: all displayed packets fit the 96,000-character context ceiling
(36,376–62,636 characters). The source files referenced by that snapshot were no
longer available at their recorded paths, so this is a saved-selection display
check, not a rebuilt-source or factual-review replay. Results are in
`~/analysis/reviewer-access-validation-2026-09-20/csv-presentation-replay.json`.

Tests exercise byte-preserving CSV/TSV/multiline rendering, empty fields,
projection/order, BOM/whitespace headers, inline output, clipping, hidden/raw
quote rejection, source/renderer changes, context budgets and dashboard parsing
and HTML escaping. No live investigation was started or restarted.

Final CSV verification: **715 regression tests passed**, plus the separate real
MCP routing test (**716 total**). The dashboard JavaScript checks also passed,
including parsing, projection, clipping, HTML escaping and whole-page syntax.
Use a fresh MCP session for the backend changes and reload the dashboard.
