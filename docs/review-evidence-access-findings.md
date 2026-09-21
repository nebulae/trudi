# Reviewer evidence access: defects observed in a live run

Status: findings, 2026-09-20. Not fixed. Companion to
[report-phase-return-plan.md](report-phase-return-plan.md).

Basis: VANKO-2016-DEEPSEEK41 run 3 (2026-09-20 21:14 UTC onward), which ran the
finding-lifecycle/readiness batch plus the parser, mount and packet fixes.
Historical runs are regression fixtures only; nothing below may be keyed to a
case, artifact, actor or expected conclusion.

Summary: the reviewer is not ignoring the evidence it is sent. It is shown a
small sample, and its attempts to pull the deciding rows are being rejected by a
scope check that does not apply to the packet type it was given.

## 1. Evidence requests are rejected as `scope_mismatch` in finding review

**Observed.** Across the run's four `reason_evaluate_finding` calls:

| Review | Fetch requests | Rejected `scope_mismatch` | Rows returned | Verdict |
|---|---|---|---|---|
| 50 | 9 | 7 | 23 (last 2 requests) | SUPPORTED |
| 55 | 3 | 0 | 51 | decided |
| 67 | 12 | **12** | **0** | UNVERIFIABLE |
| 72 | — | — | — | — |

Review 67 asked twelve times, received nothing, and returned UNVERIFIABLE. That
verdict then blocked the finding through
`confirmed_requires_supported_evaluate`. Review 50 shows the shape of the bug:
seven rejections, then the model dropped the extra request fields and the next
two requests succeeded immediately.

**Cause.** `tools/reasoning.py::_resolve_evidence_requests` gained two filters:

- a `finding_call_id` must resolve inside `evidence_packet['finding_sources']`;
- a `path` key filters the retained sources.

`finding_sources` exists only in a **synthesis** packet
(`core/synthesis_evidence.build_synthesis_packet`). A finding-review packet
(`core/evidence_packets.build_packet`) has no such key, so any request carrying
`finding_call_id` can never match and is rejected. The rejection text then tells
the model to "choose its exact source in finding_sources", which does not exist
in that packet.

The request instruction feeds this: `_evidence_request_instruction` tells every
reviewer, including finding review, "For synthesis include `finding_call_id` and
the exact `path` from `finding_sources`". The model complies and is refused.

Second trigger: the path filter applies whenever the `path` key is **present**,
so an explicit `"path": null` filters out every file-backed source and yields
the same rejection.

**Fix.**
1. Apply the `finding_call_id` check only when the packet actually carries
   `finding_sources`; otherwise ignore the field.
2. Treat `path` as a filter only when it is a non-empty string.
3. Emit the finding_call_id/path guidance only in the synthesis prompt.
4. Make the rejection name what is available for that packet type, and say
   plainly that a rejected request returned no rows, so absence cannot be
   inferred from it.

**Tests.** A finding-review packet plus a request carrying `finding_call_id`
returns rows; the same request against a synthesis packet with a
non-matching finding still rejects; `"path": null` returns rows; a wrong
non-empty path still rejects; a review whose every request is rejected must not
be recorded as a verdict on the evidence (see §2).

## 2. A review that received no rows should not return a substantive verdict

Review 67 returned UNVERIFIABLE after twelve rejected requests and zero rows.
Whatever the cause of the rejection, "I was shown nothing" and "the evidence
does not support this" must not be the same outcome: the first is a tool
failure, the second is a judgement that sticks to the claim via
`challenge_sticky`.

When every request in a round is rejected (`scope_mismatch`, `missing`,
`out_of_scope`) and no rows were pushed for the cited sources, the review
should fail with a typed, retryable error naming the rejected requests, not
produce a verdict.

## 3. The push budget makes a fetch round mandatory

`COMPAT_PUSH_ROWS_PER_CID` is 6 (`tools/reasoning.py:258`). In this run the
event-log source matched **6,100** rows and the packet showed 6 of them; the
registry source matched 24 and showed 6. The selection is honestly labelled
(`selection_complete: false`), so this is not a correctness bug, but with a
6-row sample nearly every review must spend fetch rounds to reach a decision —
which is exactly where §1 breaks.

Consider scaling the initial push with the source's match count (with the
existing character budget as the real bound), and stating the totals in the
packet header where the model cannot miss them.

## 4. `reason.review_details` rejects the call ids the agent has

**Observed.** Six calls, five rejected with "call_id must name a saved reason
result" (cids 77, 78, 79, 81, 82, 83; only 80 succeeded).

**Cause.** The tool accepts only an entry whose type is `reason_call`
(`tools/reasoning.py::reason_review_details`). The ids the agent holds are
often the `<py>:` wrapper `tool_call` ids the middleware writes for
Python-implemented tools, or the id of a `reason_readiness_status` call — whose
details are retrieved through `reason.readiness_status(section=…)`, a different
route with a similar name.

**Fix.**
1. When the id names a `tool_call` that wrapped a reason call, resolve to that
   reason call instead of refusing.
2. Make the refusal actionable: state the entry type that was passed, name the
   correct retrieval route for it, and list the most recent valid reason call
   ids.
3. Have every control response that can be paged carry its own
   `details.arguments.call_id`, so the agent never has to derive one.

## 5. `<py>:` tool_call entries record no arguments

The middleware baseline entry records `cmd = "<py>:<tool>"` and no arguments
(`core/middleware.py::_trace_success_baseline`). When such a call fails on its
input — as in §4 — the trace shows the failure but not what was passed, so the
defect cannot be diagnosed from the trace alone. Record a bounded, redacted
argument shape on the entry.
