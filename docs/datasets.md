# Dataset Documentation

*Find Evil! Hackathon — submission component #5.*

TRUDI was developed and validated against real, mostly-public DFIR datasets. Each
case TRUDI has run is bundled in this repo under [`cases/<CASE>/`](../cases/) — the
**execution trace, the reports, the case brief, and (where one exists) the
ground-truth file**. The installer copies the whole `cases/` tree into `~/cases/`, so
after `./install.sh` you can browse every run in the trace dashboard
(`./dashboard.sh` → `http://127.0.0.1:8765`).

**Evidence is deliberately not included.** The raw images/PCAPs are large (40–195 GB
for several cases) and, for the public datasets, are better obtained from their
authoritative source. Each case below links to where the evidence comes from. What is
committed is TRUDI's *output* — enough to read the findings and replay the trace, not
to re-image a disk.

## What's bundled per case

```
cases/<CASE>/
├── CLAUDE.md                     ← the case brief TRUDI was given
├── analysis/<CASE>_trace.json    ← full execution trace (dashboard input, Agent Execution Log)
├── analysis/dashboard.url        ← the live dashboard link
├── analysis/ground_truth.json    ← machine-readable answer key (CFReDS, DEMO-LIVE only)
└── reports/                      ← final report(s) + exported trace (.json/.md)
```

Bulk tool output (multi-hundred-MB MFT/event-log CSVs, carved-file dumps, extracted
hives) is intentionally excluded to keep the repo light and GitHub-safe — regenerate
it by re-running the case against the evidence.

> **Trace provenance.** The bundled trace for each case is its report-time export
> (the authoritative investigation log). SCHARDT-2002 ships with its report and brief
> only — its trace is pending a clean re-run — so the dashboard will show seven cases.

## Cases

| Case | Dataset / provenance | Evidence (not committed) | What TRUDI concluded | Answer key |
|------|----------------------|--------------------------|----------------------|------------|
| **VANKO-2016** | SANS FOR500 "Case of the Abducted Zebrafish" (course scenario) — **the demo-video case** | ~42 GB Surface 3 physical image + CyLR | Witting insider: BadUSB-planted `defaultprinter` + FTP exfil, then a deliberate StarkResearch bulk copy for Bulgakov/Titan. [report](../cases/vanko/reports/VANKO-2016_final_report.md) · [bundle](../cases/vanko/README.md) | SANS instructor solution (scored in [accuracy report](accuracy-report.md)) |
| **CFREDS-LEAK** | **NIST CFReDS** Data Leakage Case (public) | PC E01 + RM#1/RM#2 USB + RM#3 CD-R — [cfreds-archive.nist.gov](https://cfreds-archive.nist.gov/data_leakage_case/) | Sole insider `informant` leaked "Secret Project Data" to `spy.conspirator` across 5 channels with per-device anti-forensics. [report](../cases/cfreds-leak/reports/CFREDS-LEAK_final_report.md) | **Machine-readable** `ground_truth.json` + NIST Q&A key |
| **SCHARDT-2002** | **NIST "Hacking Case"** (Greg Schardt / "Mr. Evil"), public | Dell CPi notebook — EnCase E01 + raw `dd` (CFReDS) | Laptop bound to Greg Schardt = Mr. Evil = admin; hacking toolset + a wireless-interception capture of a third party. [report](../cases/schardt/reports/SCHARDT-2002_report.md) | NIST 31-question key (scored in [accuracy report](accuracy-report.md)) |
| **NITROBA-2008** | Nitroba University Harassment Scenario (public network forensics PCAP) | `nitroba.pcap` (~54 MB) | Harassing web-mail traced to a single dorm device and roster member Johnny Coach (`jcoachj@gmail.com`); device-level CONFIRMED, person-level LIKELY. [report](../cases/nitroba/reports/NITROBA-2008_expert_report.md) | Published scenario solution |
| **M57-JEAN** | M57.biz / NPS scenario family (Garfinkel) — digitalcorpora | `nps-2008-jean.E01` Windows XP image (~2.9 GB) | Spreadsheet-exfil via spoofed-recipient social engineering; Jean deceived (no on-host insider collusion). [report](../cases/m57-jean/reports/M57-JEAN_report.md) | Published scenario notes |
| **SRL-2018-ENTERPRISE** | Enterprise APT scenario ("CRIMSON OSPREY", SRL universe) — 8 hosts | Per-host memory + disk + event logs (~195 GB) | Cobalt Strike beacon (`p.exe`) under a stolen Domain Admin token, WMI→PowerShell→cmd chain, lateral movement; briefed IOCs refuted against raw evidence. [report](../cases/srl-2018-enterprise/reports/SRL-2018-ENTERPRISE_rd01_report.md) | — (self-assessed) |
| **ROCBA** | SANS FOR500 Windows Forensic Analysis — "Fred Rocba" workstation | Windows workstation image (~40 GB) | NTLM network brute-force (not RDP) + intrusion reconstruction. [report](../cases/rocba/reports/ROCBA_final_report.md) | — (self-assessed) |
| **DEMO-LIVE** | Synthetic Velociraptor live-monitoring demo — **experimental, not part of the submission** | Live endpoint (Docker bring-up) | Per-alert investigations from baseline drift (auto-protect). [reports](../cases/DEMO-LIVE/reports/) | `ground_truth.json` |

## Reproducing a run

1. Obtain the evidence from the source above and place it in `~/cases/<CASE>/evidence/`.
2. Open `~/cases/<CASE>/CLAUDE.md` (already bundled) — it has the evidence paths and case question.
3. `cd ~/cases/<CASE> && claude`, then ask TRUDI to investigate.
4. Compare against the committed trace/report here, or — for CFReDS / DEMO-LIVE —
   score automatically with `accuracy.accuracy_compare` against `ground_truth.json`.
