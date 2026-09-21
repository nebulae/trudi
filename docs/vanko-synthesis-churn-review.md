Vanko synthesis churn — observed 2026-09-21, 19:59 UTC (12:59 PDT)

The live run is cycling through evidence requests and finding revisions. The
resumable review session survives, but provisional objections escape as public
blockers before their review task has finished. The investigator responds by
changing findings, which invalidates the corresponding review tasks. Evidence
presentation problems repeatedly provoke those objections.

Read-only snapshot: [trace-snapshot.json](/home/trin/analysis/vanko-synthesis-review-2026-09-21/trace-snapshot.json),
882 entries, captured at 19:54:55 UTC. Live follow-up through call 886 at
19:59:06 UTC. Run ID: `240e6b5a1ddc45e6b60b23a3be84c891`;
review session: `RS-5e0cb1a556ae0321e71f278b`.
The reasoning backend reports `deepseek-v4.1-flash:cloud` through openai-compat.

| Measurement | Observed value |
| --- | --- |
| First synthesis checkpoint | 18:45:16 UTC, call 505 |
| Last completed synthesis slice | 19:52:29 UTC, call 868 |
| Current coverage at that checkpoint | 2 of 9 tasks: eight individual findings plus one consistency comparison |
| Synthesis provider calls, including schema repairs | 33 |
| Synthesis reason-call records | 31 |
| Reported synthesis usage | 289,872 input / 258,719 output tokens |
| Usage attached to superseded task versions | 21 provider calls; 183,523 input / 170,247 output tokens |
| Synthesis evidence retrieval | 23 fetch events; 78 requests; 77 distinct call/path/query/column combinations |
| Cache hits across all observed task versions | 1 |
| Largest recorded synthesis prompt across task versions | 49,913 characters; below the 96,000-character limit |
| Accumulated elapsed time inside synthesis slices | 1,666 seconds, approximately 27.8 minutes |

The 77 distinct request combinations measure selector variation, not distinct
investigative questions or progress. Reworded searches can repeatedly pursue the
same missing relationship. Likewise, retired-task usage is not wholly wasted:
some earlier review identifies a valid correction. Distinguish new deciding
observations, resolved requirements and retained review coverage from syntax-level
uniqueness when comparing runs.

About 67 minutes elapsed between the first and last completed synthesis slices.
Much of that interval was spent outside synthesis repairing/reviewing findings
and performing follow-up work. The final comparison task has not started.
This is not the previous oversized-packet refusal: evidence retrieval and model
calls are running, and individual tasks have completed.

**1. Provisional objections become actionable blockers.**

Call 866 returns `status: in_progress`, `approved: false`, an empty
`review_issues` array, and `next_action: resume_reason.synthesize`. At the same
time, its public `blockers` array contains two mail-attribution objections. The
task still has four pending evidence requests, so those objections have not
passed task completion and issue normalization.

In [synthesis_session.py](/home/trin/trudi/core/synthesis_session.py:390),
`last_response` saves blockers/directives before the pending-request branch;
the final payload spreads them back into the public response at line 445.
[control_response.py](/home/trin/trudi/core/control_response.py:75) can additionally
treat those legacy blockers as required guidance when the response is large.
The earlier system instruction says only the final answer counts, but the
controller exposes intermediate conclusions anyway.

This pattern appears in calls 536, 567, 607, 659, 724 and 866. After call 866,
the investigator reads more mail, runs strings searches, transitions to Analyze
at call 872, and submits another revision at call 879. The live trace at call
884 is inside that finding evaluation, not final report writing. At 19:58:39,
submission 885 finishes as `needs-evidence`: the reviewer acknowledges that the
quoted text, dates, recipient and subject were found, but says attachment and
sender-to-message binding remain unshown. Call 886 then searches the MFT for an
attachment filename. Synthesis coverage remains 2/9 at the 19:59 follow-up.

**2. Mail requests cannot recover the message structure being demanded.**

Finding 635 has already consumed five provider calls, eleven fetched requests,
and still has four requests queued. Fetches 849, 855 and 862 search the original
mbox files as ranked text lines. Requests for `Date`, `From`, `To`, `Subject`,
`Message-ID` or `has_attachment` return `columns_ignored: true`.

The reviewer sees the sentence “This is a VeraCrypt encrypted container.” and
other isolated thread lines without a message record binding body, headers and
attachments. Call 866 consequently asks for those same relationships again.
Changing search terms cannot reliably establish message boundaries or ownership.
The synthesis index prefers underlying files over the structured read operation's
presentation; see [synthesis_evidence.py](/home/trin/trudi/core/synthesis_evidence.py:58)
and the line-based fallback in
[evidence_display.py](/home/trin/trudi/core/evidence_display.py:178).

There is an additional request-validation defect: call 862 contains `columns`
as a comma-separated string. It becomes a list of individual characters in
`missing_columns`. The controller consumes raw `result_block.evidence_request`
before the parsed request list and only checks call ID/query types. This wastes
requests and should be repaired centrally.

**3. The compact source index drops deciding provenance and schema.**

The model-facing projection in
[evidence_display.py](/home/trin/trudi/core/evidence_display.py:107) retains tool
name, output path, size and selector, but omits the recorded command and input
target. For inline stdout, several sources become `strings_grep`, `path: null`.
The saved packet retains their commands, but the reviewer does not receive them
in that index or obtain them through the row-search interface.

Call 536 searches call 96 for FTP configuration and calls 123/181 for archive
members. Their actual commands identify call 96 as the archive strings, 123 as
smallftpd.exe strings, and 181 as ftpd.ini strings. The reviewer interprets its
wrong-source misses as missing evidence. Later, call 567 calls the archive
listing unattributed even though its originating command names the archive.

A separate false objection is independently verified: fetches 520, 526, 532,
551 and 563 request `DeletedTime`. The actual recycle-bin CSV field is
`DeletedOn`, and its matching row already contains `2016-06-18 22:22:09`.
Call 567 nevertheless says the deletion timestamp is absent from the collected
evidence. Missing requested columns must lead to schema correction, not absence
claims. The compact index does not provide the available CSV columns.

**4. Revisions consume the benefit of continuation.**

The same session ID persists throughout. Finding 135's completed task survives,
and revised FTP finding 581 eventually completes. Selective invalidation works.
However, five different task-set snapshots appear as finding revisions replace
prior versions. Twenty-one of the 33 provider calls belong to those retired
versions. Their usage is counted, but their pending review no longer advances
the current findings. The cache only catches exact versioned selectors; changing
queries and citations gets little benefit.

Not every follow-up is unnecessary. For example, later RDP research adds
authentication corroboration and a client workstation name. This review does not
establish that all finding changes were wrong. It establishes concrete false
objections and an avoidable loop that mixes unfinished review with investigator
correction.

**5. The old final-review prompt increases the work inside each task.**

Each individual finding gets the broad final logic/missing-investigation prompt
plus directives and the new continuation instructions. The system RESULT example
omits the coverage/comparison fields required by the task instruction. Calls 841
and 845 explicitly note that discrepancy in recorded backend diagnostics. There
are two extra schema-repair provider calls, and call 859 records an output-limit
event. Calls commonly generate thousands of output tokens while evidence access
is still unfinished. This compounds the loop; provider latency alone does not
explain the hour.

Recommended correction order, applicable to every case and backend:

1. Make `in_progress` a continuation-only response. Retain tentative objections
   internally; expose actionable blockers only after validation or an explicit
   access/work handoff. Add an integration fixture for mixed issues plus pending
   evidence requests, including the bounded control response.
2. Restore concise source identity and discoverable schema: input target/command,
   available columns, and typed selector capabilities. Correct missing-column
   requests before accepting any absence conclusion.
3. Fetch semantic evidence units. Mail needs a bounded message record with its
   headers, body excerpt, attachment metadata and source binding. Plain text needs
   bounded adjacent context. Preserve receipts and completeness restrictions.
4. Unify and validate the resumable RESULT schema. Separate evidence-request,
   factual-review and consistency instructions; avoid a full provisional verdict
   and investigative directive set on each fetch turn.
5. Keep the durable session and selective invalidation. Measure reuse across
   legitimate revisions, and reuse prior factual review only where its assertions,
   policy and evidence receipts are demonstrably equivalent. Do not weaken report
   approval to hide these failures.

No investigation was started, no running work was interrupted, and no application
code or live trace was changed for this analysis.
