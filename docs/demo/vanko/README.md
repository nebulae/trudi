# Demo bundle — VANKO-2016 ("Case of the Abducted Zebrafish")

This is the case shown in the **[demo video](https://youtu.be/Dbx5DcH6V5E)**. It is
committed here in full so a reviewer can follow the exact run end to end without
the SIFT Workstation: the execution trace, the final report, a key structured
artifact, and the terminal transcript.

- **Case:** SANS FOR500 "Case of the Abducted Zebrafish" student scenario (full
  ~42 GB Surface 3 physical image + CyLR collection). Evidence is **not** committed
  here (read-only, and far too large); only TRUDI's outputs are.
- **Case question:** was Anthony Vanko involved in disseminating classified Stark
  research to a Chinese university server, did he bulk-copy the classified data,
  and what was done with it?

## Files

| File | What it is |
|------|------------|
| [`VANKO-2016_trace.json`](VANKO-2016_trace.json) | Full execution trace — every tool call, DAIR call, reason call, curiosity probe, and finding, each with a `_trudi_call_id`, UTC timestamp, and lineage (`input_call_ids`). This is the Agent Execution Log (submission component #8). |
| [`VANKO-2016_final_report.md`](VANKO-2016_final_report.md) | The structured analyst report: case-question answers, attack narrative, tiered findings register (F1–F10), ATT&CK coverage, indicators. |
| [`device_install_inventory.csv`](device_install_inventory.csv) | The complete USB device-install table from `setupapi.dev.log` that surfaced the BadUSB (`ATMEL Ducky_Storage`) initial-access device. |
| [`console.log`](console.log) | Full terminal transcript of the run (~7,850 lines): the agent's narration, every tool call, the DAIR/reason exchanges, and the adversarial-review CHALLENGES — the raw record behind the trace. |

## View the trace in the dashboard

```bash
./dashboard.sh        # serves the repo's cases on http://127.0.0.1:8765
```

Or open `dashboard/trace_viewer.html` (chain and graph views too) and point it at
`VANKO-2016_trace.json`.

## Traceability spot-check (submission component #5 / #8)

Every finding in the report links back to the tool execution that produced it.
For example, finding **F4** (CONFIRMED — classified `temp.zip` FTP-exfiltrated to
`173.73.166.249` on 2016-06-18, then deleted) is grounded in the recovered
`$RZQSNFO.zip` (SHA-256 `8d95f450…`), the FTP `transfers.log`, and a Security 4624
logon — each citable to its `_trudi_call_id` in `VANKO-2016_trace.json`.

## Self-correction sequences (for the demo / submission component #1)

The run contains real, autonomous self-corrections — captured in the trace and
summarized in the report:

- **F4 exfil downgrade → recover → re-confirm:** `reason.evaluate_finding`
  CHALLENGED the "classified" framing; the agent recovered `temp.zip`, confirmed
  its contents, resolved a timezone discrepancy, and re-recorded the finding as
  CONFIRMED.
- **F8 recipient downgrade:** after a CHALLENGED verdict noted Titan Biotech's
  SMTP is a US ARIN range, the agent downgraded "foreign buyers" to "solicitors
  (nationality self-reported, unverified)."

## Reproducing the console transcript

The transcript was captured straight from the Claude Code terminal during the
run. To regenerate for a fresh recording:

```bash
script -q -c "claude" docs/demo/vanko/console.log     # plain transcript
# or, for a replayable cast:  asciinema rec docs/demo/vanko/console.cast
```

> **Note:** trace, report, and console here are from the Vanko run on the current
> engine. If you re-record the demo, refresh all three together so the bundle
> stays internally consistent.
