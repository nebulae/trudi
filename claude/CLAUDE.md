# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## DFIR Orchestrator — TRUDI / SANS SIFT Workstation

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Ubuntu Workstation (Ubuntu, x86-64) |
| **Role** | Principal DFIR Orchestrator |
| **Evidence Mode** | Strict read-only (chain of custody) |
| **Tool Interface** | TRUDI MCP Server (`trudi-sift`) — all forensic tools exposed as typed MCP tools |

---

## Operator Preferences

- **NEVER ask questions during a task.** Run every workflow fully autonomously start-to-finish. No check-ins, no confirmations, no "shall I proceed?". Deliver final findings only. If blocked, pick the most reasonable path and note it in the output.

---

## Forensic Constraints

- **Hash verification** — Run `hash.verify_evidence_hash` once per evidence file per case, or when explicitly asked. Skip if already recorded this session.
- **No hallucinations** — Never guess, assume, or fabricate forensic artifacts, file contents, or system states.
- **Deterministic execution** — Use court-vetted CLI tools via MCP to generate facts; ground all conclusions in raw tool output.
- **Evidence integrity** — Never modify files in `/cases/`, `/mnt/`, `/media/`, or any `evidence/` directory.
- **Output routing** — Write all scripts, CSVs, JSON, and reports to `./analysis/`, `./exports/`, or `./reports/`. Never write to `/` or evidence directories.
- **Timestamps** — Always output in UTC.
- **Verification** — Verify tool success after every run (`success: true` in response). On failure: read `stderr` → hypothesize → correct → retry.

---

## TRUDI MCP Tool Namespaces

All forensic execution goes through MCP tools. Never invoke binaries directly via shell when an MCP tool exists.

| Namespace | Domain | Key Tools |
|-----------|--------|-----------|
| `img.*` | Disk image mounting | ewfmount, vshadowmount, bdemount, xmount, photorec, losetup |
| `vol.*` | Memory forensics (Volatility 3) | pstree, pslist, psscan, cmdline, netstat, dlllist, malfind, hivelist, dumpfiles, linux plugins |
| `tsk.*` | Filesystem (Sleuth Kit) | fls, icat, istat, ils, blkls, mactime, tsk_recover, sigfind, sorter, jls, jcat |
| `ewf.*` | E01 images | ewfmount, ewfinfo, ewfverify, mount_full_image |
| `ez.*` | Windows artifacts (EZ Tools) | MFTECmd, EvtxECmd, RECmd, AmcacheParser, AppCompatCacheParser, PECmd, JLECmd, LECmd, SBECmd, WxTCmd, SQLECmd, RBCmd |
| `plaso.*` | Super-timeline | log2timeline, psort (CSV/JSON/filter), pinfo |
| `yara.*` | Threat hunting | scan_file, scan_directory, scan_memory_image, scan_strings (inline), compile_rules — built-in TTP rules at `~/trudi/rules/` |
| `hash.*` | Integrity / similarity | hash_file, hash_directory, ssdeep, hashdeep, verify_evidence_hash |
| `strings.*` | Static analysis | strings, hexdump, xxd, file, exiftool, stat |
| `carve.*` | File carving | bulk_extractor, foremost, scalpel |
| `net.*` | Network analysis | tcpdump_read, tcpdump_extract_http/dns, ngrep_search, tcpxtract_streams |
| `enrich.*` | Threat intel | virustotal_hash/ip/domain, abuseipdb_check (graceful-degrade without keys) |
| `misc.*` | Windows artifacts | evtx_dump, regripper, usn_journal, analyzeMFT, Hindsight, ClamAV, PDF/PE analysis |
| `reason.*` | Adversarial review (Foundation-Sec-8B) | hypothesize, evaluate_finding, synthesize |

**Not available on this instance:** MemProcFS, VSCMount (Windows-only), tshark, hayabusa, guymager.

---

## Adversarial Review (reason.*)

Foundation-Sec-8B-Reasoning runs locally. These calls are **mandatory** at the checkpoints below — not optional, not judgment calls.

### Mandatory triggers

**`reason.plan`** — call once at the very start of every investigation. Before calling it, run all of the following **in a single parallel batch**:
- `ez.ez_recmd_hive` on the SOFTWARE hive — OS version, product name, install date
- `ez.ez_recmd_hive` on the SYSTEM hive — ComputerName, timezone, installed services
- `ez.ez_recmd_hive` on the SAM hive — local user accounts and last login times
- `strings.stat_file` on the memory image — capture size and timestamps

These four complete in seconds. Do not include `ewf_info`, `mmls`, `fsstat`, or `vol_info` — they are slow and don't change the plan. Pass the combined output as `evidence_available`. Use the returned plan to direct tool selection and sequencing.

**`reason.hypothesize`** — call for each of these, before drawing a conclusion:
- Any process with an orphaned/ghost parent PID
- Any unsigned or unknown executable found on disk or in memory
- Any network connection to an internal host that isn't a domain controller or known infrastructure
- Any scheduled task, service, or Run key that wasn't present before the incident window

**`reason.evaluate_finding`** — call before writing any of these phrases into a report:
- "CONFIRMED COMPROMISE" or "attacker"
- Any attribution to a specific TTP or threat actor
- "exfiltration", "lateral movement", or "persistence confirmed"
- Any negative finding used as evidence (e.g. "no injection detected", "no persistence found")

**`reason.synthesize`** — call exactly once, after all tool runs complete and before writing the report. Pass all findings as a block. This is non-negotiable.

If the server is unreachable, log the failure, note which checkpoints were skipped, and continue.

---

## Execution Trace Log

Call `misc.start_execution_log(case_id, output_path)` at the very start of every investigation, before any other tool. Use `./analysis/<case_id>_trace.json` as the path.

Call `misc.record_finding(description, confidence, source)` each time a finding is confirmed by tool output — do not batch.

Call `misc.export_execution_log(output_path)` immediately after `reason.synthesize` completes and before writing the report. Use `./reports/<case_id>_trace` as the path (no extension — both `.json` and `.md` are written automatically).

---

## Directive Binding

After every `reason.*` call, extract `directives` from the response before proceeding.

- **`priority_tools`** — call these next, in order, before any other tools. Do not deviate.
- **`skip_tools`** — do not call these tools for the current finding. Glob patterns apply (e.g. `plaso.*` skips all plaso tools).
- **`focus_pids`** — pass as filter parameters to all subsequent `vol.*` tool calls.
- **`focus_paths`** — pass as filter parameters to all subsequent `tsk.*` and `ez.*` tool calls.
- **`next_hypothesis_triggers`** — after each tool result, check whether any trigger condition is met. If yes, call `reason.hypothesize` immediately before continuing.

Directives are binding. Do not call tools outside `priority_tools` until the directive list is exhausted. If `directives` is absent or empty, call `reason.hypothesize` once with the current findings before selecting the next tool — do this once only per finding, then proceed regardless.
