# Agent contract — worked examples

Illustrative call shapes referenced by `claude/CLAUDE.md`. These are examples,
not new rules; every rule they demonstrate is stated in the contract and
enforced by the gates. Placeholders (`<PID>`, `<C2_IP>`, …) are generic.

## `_note` narration on a parallel batch

Add `_note="<narration>"` to exactly ONE tool call per parallel batch; the
middleware logs it as an `agent_message` before the tools run. Same text you
write to the user. Opening narration before the first tool call goes through
`misc_record_agent_message` directly.

```
# three parallel calls, one carries the narration
vol_pstree(image=..., _note="Pre-plan reads complete. Starting memory analysis.")
vol_netscan(image=...)
vol_cmdline(image=...)
```

## `input_call_ids` lineage — the trace as a causal DAG

```python
# tool results from the prior batch had cids 17, 18, 19
dair.assess(
    tool_results_summary="vol.pstree showed orphaned PID <PID>; vol.netscan flagged a beacon to <C2_IP>:<PORT>",
    phase_stack="[{\"phase\": \"Triage\", \"depth\": 0}]",
    input_call_ids=[17, 18, 19],
)

# Prerequisites (including DAIR) must be current. The tool reviews and records
# this one finding only if the evidence and every final gate support it.
misc.submit_finding(
    description="<process>.exe (PID <PID>) is a C2 beacon (T1055)",
    confidence="CONFIRMED",
    idempotency_key="c2-beacon-v1",
    linked_call_id=24,                    # 1:1 primary evidence
    input_call_ids=[24, 31],              # N:M evidence lineage
    claim={"claim_kind": "positive", "category": "other", "act": "c2",
           "actor_kind": "process", "actor": "<process>.exe",
           "entities": ["<process>.exe", "<C2_IP>"], "techniques": ["T1055"]},
)

# an attribution finding — bound to a person by a session artifact (cid 57 = ez.evtxecmd 4624/4778 rows)
misc.submit_finding(
    description="<account> was operated by <person> during the exfil window",
    confidence="LIKELY", linked_call_id=57, input_call_ids=[57, 61],
    idempotency_key="account-attribution-v1",
    claim={"claim_kind": "positive", "category": "identity", "act": "attribution",
           "actor_kind": "human", "actor": "<person>", "principal": "<account>",
           "session_binding_call_ids": [57], "answers_case_question": True},
)

# an egress finding — needs the transfer artifact call (cid 73 = USN $J write on the removable volume)
misc.submit_finding(
    description="<archive> was written to the removable volume <label>",
    confidence="CONFIRMED", linked_call_id=73, input_call_ids=[73, 80],
    idempotency_key="removable-egress-v1",
    claim={"claim_kind": "positive", "category": "exfil", "act": "egress", "channel": "removable",
           "transfer_call_ids": [73], "entities": ["<archive>", "<label>"]},
)
```

`linked_call_id` (1:1 primary) and `input_call_ids` (N:M lineage) are
complementary — supply both.

Use the same key and exact request after a timeout; a successful retry returns
the original finding. If the claim changes, use a new key (and `supersedes` for
a correction). The existing evidence fetcher can obtain more rows during
review. See [the submission contract](investigation-review.md#one-call-finding-submission)
for statuses and byte selectors. Pilot workflows require analyst approval before
calling this tool because success records the finding.

Separate `reason.evaluate_finding` and `misc.record_finding` remain available.
Pass identical finding text, all typed claim fields, evidence IDs and revision
target to both; new receipts cannot approve a broader or reworded claim.

Review responses carry `review_call_id`, verdict or access status, and a
versioned `details` route. Read the named blocker sections with
`reason.review_details` before retrying; never guess IDs or rerun an evaluation
to retrieve it. `access_failure` means required evidence was not reached: repair
the request/source, rather than treating it as a factual challenge or collecting
new evidence automatically. Fetch repairs use `replaces_request_id` and retain
successful reads. `uncited_sources` are optional leads from retained outputs,
including inline stdout: inspect them before citing, and obtain a new independent
review after changing citations. Empty/capped suggestions do not require new
collection. Narrowing the claim remains available.

## Finding capture — narration that states facts must carry findings

`misc.record_agent_message` is for reasoning and direction, not facts. A
paragraph that states a conclusion must be accompanied by structured findings —
separate `misc.submit_finding(...)` calls, or legacy recording after matching
reviews. The legacy `findings=[…]` shape below does not perform the reviews:

```python
misc.record_agent_message(
    content="<HOST> memory shows a C2 beacon on <process>.exe (PID <PID>) and an archiver staging data.",
    input_call_ids=[821, 822, 823],
    findings=[
        {"description": "<process>.exe (PID <PID>) is a C2 beacon implant on <HOST> (C2: <C2_IP>:<PORT>)",
         "confidence": "CONFIRMED", "linked_call_id": 821, "source": "vol.netscan",
         "input_call_ids": [821, 823], "claim_kind": "positive", "category": "other", "act": "c2"},
        {"description": "<archiver>.exe archived data on <HOST> in the incident window",
         "confidence": "CONFIRMED", "linked_call_id": 822, "source": "vol.cmdline",
         "input_call_ids": [822, 823], "claim_kind": "positive", "category": "other", "act": "other"},
    ],
)
```

Batched findings pass the same gates as `misc.record_finding` (recent
`dair_call`; CONFIRMED/LIKELY need a SUPPORTED `reason.evaluate_finding` for the
same typed claim). Per-finding gate failures return in the response; the
narration entry is written either way.

## Report follow-up routing

Required forensic work discovered in Report uses a durable DAIR transition before
execution: new acquisition/extraction goes to Collect, new analysis to Analyze,
and discovery scans to Scan. A validated, already-authorized tool request continues
in the same call after that transition; do not repeat it just to change phase.
This does not authorize new work beyond the analyst's instructions in pilot mode.

Reads of traced, produced outputs and finding corrections remain in Report.
Synthesis may return `follow_up_required` with typed work and a `request_id`;
execute that work through normal MCP tools. Optional suggestions are not duties.
`repair_required` means an output-access/software problem, not a reason to collect
more evidence. Missing synthesis alone also stays in Report.

Pending/running/failed work appears in `reason.readiness_status().follow_up` and
blocks return to Report. A DAIR call or unrelated tool success does not settle it.
Completed duplicate requests reuse their result. For a deliberate repeat of a
completed/failed request, or after reconciling an unknown outcome, pass `_refresh=true`;
never refresh an operation merely because its response was delayed. Poll background
jobs with `misc.job_status`; do not restart them. A justified unavailable/inapplicable
request can be dispositioned with `target_kind="follow_up"`, its exact request ID,
a reasoned note and its result/trigger evidence call IDs. This settles the task,
not the underlying finding or independent review issue.

Return through DAIR after required work is settled, then rerun synthesis against
the updated evidence. Report publication still requires a current pre-report approval.

## Resumable review and accountable jobs

`reason.synthesize` returns `status: in_progress | complete | blocked` and a
`review_session_id`. For `in_progress`, call it again with `next_arguments` and
normal lineage; the server resumes unfinished requests and reuses current review
receipts. Stay in Report unless a typed follow-up routes actual evidence work.
A successful call or `issues: []` does not approve a report. Wait for `complete`
and `approved: true`, then run `reason.pre_report_check`. A budget blocker retains
the checkpoint; unchanged retries do not replenish its allowance.

Long tools wait up to 15 seconds for the complete operation, including fallback
parsing and validation. Otherwise they return a durable `job_id`. There are two
concurrent slots and no queue. `misc.job_list` supplies the current adapter
policies and active jobs. Poll `misc.job_status` between useful work; do not
restart a running operation. Jobs belong to a run, not merely a case/path.

Execution success, `result_status`, and `scope_complete` are separate. Cite only
validated outputs from a partial/cancelled job. Its original scope remains open,
and a partial search cannot prove absence. Traced reads preserve that incomplete
scope. Unsupported interrupted containers require subsequent validation.

To abandon work, call `misc.job_cancel(job_id, reason)` and collect the stopped
job. Then use `misc.record_disposition(target_kind="job", target_id=job_id,
reason="out_of_scope"|"inapplicable"|"evidence_unavailable", note=...,
evidence_call_ids=[<this job's collected call_id>])` when justified. This settles
only that job's obligation; a generic tool disposition cannot settle jobs.
Cancellation alone never settles scope. An orphan's explicit cancellation can
finalize retained partial output without re-running extraction. Both reset
entrypoints refuse while workers can write, including with `--force`.
