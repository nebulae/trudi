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
