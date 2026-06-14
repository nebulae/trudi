# VANKO-2016 — demo-video case ("Case of the Abducted Zebrafish")

This is the case shown in the **[demo video](https://youtu.be/Dbx5DcH6V5E)**, and the
Agent Execution Logs artifact for the submission. The full run is committed here so a
reviewer can follow it end to end without the SIFT Workstation — and the installer
copies this whole `cases/` tree into `~/cases/`, so it shows up in the trace dashboard.

- **Case:** SANS FOR500 "Case of the Abducted Zebrafish" (full ~42 GB Surface 3
  physical image + CyLR collection). **Evidence is not committed** (read-only and far
  too large); only TRUDI's outputs are.

## Files

| File | What it is |
|------|------------|
| [`analysis/VANKO-2016_trace.json`](analysis/VANKO-2016_trace.json) | Full execution trace — every tool / DAIR / reason call, curiosity probe, and finding, each with a `_trudi_call_id`, UTC timestamp, and lineage. The dashboard's input and the Agent Execution Log (submission #8). |
| [`reports/VANKO-2016_final_report.md`](reports/VANKO-2016_final_report.md) | Structured report: case-question answers, attack narrative, tiered findings F1–F10, ATT&CK, indicators. |
| [`analysis/device_install_inventory.csv`](analysis/device_install_inventory.csv) | The USB device-install table from `setupapi.dev.log` that surfaced the BadUSB (`ATMEL Ducky_Storage`). |
| [`console.log`](console.log) | Full ~7,850-line terminal transcript of the run — agent narration, every tool call, the DAIR/reason exchanges, and the adversarial-review CHALLENGES. |
| [`CLAUDE.md`](CLAUDE.md) | The case brief TRUDI was given. |

## View it in the dashboard

```bash
./dashboard.sh        # serves ~/cases on http://127.0.0.1:8765, pick VANKO-2016
```

## Traceability spot-check

Finding **F4** (CONFIRMED — classified `temp.zip` FTP-exfiltrated to `173.73.166.249`
on 2016-06-18, then deleted) is grounded in the recovered `$RZQSNFO.zip` (SHA-256
`8d95f450…`), the FTP `transfers.log`, and a Security 4624 logon — each citable to its
`_trudi_call_id` in `analysis/VANKO-2016_trace.json`.

## Self-correction sequences (submission criterion #1)

- **F4 exfil downgrade → recover → re-confirm:** `reason.evaluate_finding` CHALLENGED
  the "classified" framing; the agent recovered `temp.zip`, confirmed its contents,
  resolved a timezone discrepancy, and re-recorded CONFIRMED.
- **F8 recipient downgrade:** after a CHALLENGED verdict noted Titan's SMTP is a US
  ARIN range, "foreign buyers" was downgraded to "solicitors (nationality
  self-reported)."

> Accuracy of this run vs. the official SANS answer key is scored in
> [docs/accuracy-report.md](../../docs/accuracy-report.md) (§ Ground-truth comparison).
