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
vol_vol_pstree(image=..., _note="Pre-plan reads complete. Starting memory analysis.")
vol_vol_netscan(image=...)
vol_vol_cmdline(image=...)
```

## `input_call_ids` lineage — the trace as a causal DAG

```python
# tool results from the prior batch had cids 17, 18, 19
dair.dair_assess(
    tool_results_summary="vol.pstree showed orphaned PID <PID>; vol.netscan flagged a beacon to <C2_IP>:<PORT>",
    phase_stack="[{\"phase\": \"Triage\", \"depth\": 0}]",
    input_call_ids=[17, 18, 19],
)

reason.evaluate_finding(
    finding="<process>.exe (PID <PID>) is a C2 beacon",
    supporting_evidence="vol.malfind PID=<PID> yields injected DLL; vol.netscan PID=<PID> → <C2_IP>:<PORT>",
    input_call_ids=[24, 31],
)

misc.record_finding(
    description="CONFIRMED C2 beacon on PID <PID> (T1055)",
    confidence="CONFIRMED",
    linked_call_id=24,                    # 1:1 primary evidence
    input_call_ids=[24, 31, 42],          # N:M complete lineage incl. supporting reason calls
    claim_kind="positive", category="other", act="c2",          # typed claim — mandatory
    actor_kind="process", actor="<process>.exe",
    entities=["<process>.exe", "<C2_IP>"],            # who/what the claim is about
    techniques=["T1055"],
)

# an attribution finding — bound to a person by a session artifact (cid 57 = ez.evtxecmd 4624/4778 rows)
misc.record_finding(
    description="<account> was operated by <person> during the exfil window",
    confidence="LIKELY", linked_call_id=57, input_call_ids=[57, 61],
    claim_kind="positive", category="identity", act="attribution",
    actor_kind="human", actor="<person>", principal="<account>",
    session_binding_call_ids=[57], answers_case_question=True,
)

# an egress finding — needs the transfer artifact call (cid 73 = USN $J write on the removable volume)
misc.record_finding(
    description="<archive> was written to the removable volume <label>",
    confidence="CONFIRMED", linked_call_id=73, input_call_ids=[73, 80],
    claim_kind="positive", category="exfil", act="egress", channel="removable",
    transfer_call_ids=[73], entities=["<archive>", "<label>"],
)
```

`linked_call_id` (1:1 primary) and `input_call_ids` (N:M lineage) are
complementary — supply both.

## Finding capture — narration that states facts must carry findings

`misc.record_agent_message` is for reasoning and direction, not facts. A
paragraph that states a conclusion must be accompanied by structured findings —
separate `misc.record_finding(...)` calls or atomically via `findings=[…]`:

```python
misc.record_agent_message(
    content="<HOST> memory shows a C2 beacon on <process>.exe (PID <PID>) and an archiver staging data.",
    input_call_ids=[821, 822, 823],
    findings=[
        {"description": "<process>.exe (PID <PID>) is a C2 beacon implant on <HOST> (C2: <C2_IP>:<PORT>)",
         "confidence": "CONFIRMED", "linked_call_id": 821, "source": "vol.netscan"},
        {"description": "<archiver>.exe archived data on <HOST> in the incident window",
         "confidence": "CONFIRMED", "linked_call_id": 822, "source": "vol.cmdline"},
    ],
)
```

Batched findings pass the same gates as `misc.record_finding` (recent
`dair_call`; CONFIRMED/LIKELY need a SUPPORTED `reason.evaluate_finding` for the
same typed claim). Per-finding gate failures return in the response; the
narration entry is written either way.
