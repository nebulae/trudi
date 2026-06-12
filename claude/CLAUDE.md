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
DAIR and `reason.*` choose `priority_tools` from the structured Tool Capability
Manifest in `tools/tool_capabilities.py`; the namespace table below is a human
orientation aid, not the planning source of truth.

| Namespace | Domain | Key Tools |
|-----------|--------|-----------|
| `img.*` | Disk image mounting | ewfmount, vshadowmount, bdemount, xmount, photorec, losetup |
| `vol.*` | Memory forensics (Volatility 3) | **`vol_symbol_check` first on any new image**, then pstree, pslist, psscan, cmdline, netstat, dlllist, malfind, hivelist, dumpfiles, linux plugins |
| `tsk.*` | Filesystem (Sleuth Kit) | fls, icat, istat, ils, blkls, mactime, tsk_recover, sigfind, sorter, jls, jcat, **indxparse** ($INDX slack) |
| `ewf.*` | E01 images | ewfmount, ewfinfo, ewfverify, mount_full_image |
| `ez.*` | Windows artifacts (EZ Tools) | MFTECmd, EvtxECmd, RECmd, AmcacheParser, AppCompatCacheParser, PECmd, JLECmd, LECmd, SBECmd, WxTCmd, SQLECmd, RBCmd |
| `plaso.*` | Super-timeline | log2timeline, psort (CSV/JSON/filter), pinfo |
| `yara.*` | Threat hunting | scan_file, scan_directory, scan_memory_image, scan_strings (inline), compile_rules — built-in TTP rules at `~/trudi/rules/` |
| `hash.*` | Integrity / similarity | hash_file (cached), hash_directory, ssdeep, hashdeep, verify_evidence_hash |
| `strings.*` | Static analysis | strings, hexdump, xxd, file, exiftool, stat, **floss_extract** |
| `carve.*` | File carving | bulk_extractor, foremost, scalpel |
| `net.*` | Network analysis | tcpdump_read, tcpdump_extract_http/dns, ngrep_search, tcpxtract_streams |
| `enrich.*` | Threat intel | virustotal_hash/ip/domain, abuseipdb_check (graceful-degrade without keys) |
| `misc.*` | Windows artifacts + email + macros + capability | evtx_dump, regripper, usn_journal, analyzeMFT, Hindsight, ClamAV, PDF/PE, **pff_export**, **readpst_extract**, **densityscout_scan**, **chainsaw_hunt**, **capa_analyze**, **olevba_scan**/**mraptor_scan**, **batch_run** |
| `reason.*` | Adversarial review (swappable: Claude / OpenAI-compat / Foundation-Sec — set via REASON_BACKEND) | plan, hypothesize, evaluate_finding, **confidence_score**, cite_check, synthesize, pre_report_check |
| `correlate.*` | Cross-tool correlation | **process_to_file**, **network_to_process**, **mitre_map**, **mitre_validate** |
| `accuracy.*` | Ground-truth comparison | accuracy_compare, accuracy_export_report |
| `dair.*` | DAIR phase director (separate backend — set via DAIR_BACKEND) | dair_assess — call after every tool batch |

**Not available on this instance:** MemProcFS, VSCMount (Windows-only), tshark, hayabusa, guymager.

**Volatility exit codes:** `exit_code: 1` = plugin ran but failed (e.g. unsupported OS structure, no data found — may be normal for some images). `exit_code: 2` = argument error (TRUDI bug — check command syntax). Check `stderr` for the actual error before retrying. A timeout (`exit_code: -1`) almost always means symbols are not cached — run `vol_symbol_check` to confirm.

---

## DAIR Phase Director (dair.*)

DAIR (Dynamic Approach to Incident Response) is a **linear phase director with advisory pivot candidates**. TRUDI is read-only: Improve & Response actions are never performed; they appear only as recommendations in the final report. The investigation begins with a confirmed positive detection already in hand.

**Active phases:**

| Phase | Role | reason.* | Pivot behavior |
|-------|------|-----------|------------|
| Triage | Confirm initial IOCs, challenge for hallucinations — file existence, registry keys, process records, network connections. Produce investigation plan. | `reason.plan` at phase entry | Does not auto-pivot |
| Collect | Gather raw artifacts per plan — ez.*, vol.*, tsk.*, strings.* | `reason.plan` directives inform prioritization | No — advance when plan is satisfied |
| Analyze | Reason about collected artifacts — processes, network, persistence, TTPs | `reason.hypothesize` for each suspicious artifact | Candidate pivots may be returned as metadata |
| Scan | Sweep for lateral movement, other hosts — yara.*, net.*, enrich.* | — | Candidate pivots may be returned as metadata |
| Report | Terminal. Synthesize timeline; emit Improve & Response recommendations | `reason.synthesize` + `reason.pre_report_check` | No |

**Candidate pivot handling:** `dair_assess` may return `candidate_pivots` such as `{kind, value, phase, cue}`. Treat these as leads, not control flow. Do not mutate `phase_stack` or start a new Triage solely because a candidate exists. Investigate a candidate only when it is relevant to the case question, and record either a finding or an explicit out-of-scope / evidence-unavailable disposition.

**Context-break resumption:** If the investigation is interrupted for any reason — context window boundary, tool timeout, session restart, **MCP server disconnect/reconnect**, or any gap in tool availability — the **very first action** on resumption is a `dair_assess` call with the last-known phase stack. Do not run any tool batches before re-establishing DAIR oversight, even if the server appears back online. If dair_assess itself is unavailable, do not run forensic tools — wait for the server to recover, then call dair_assess first. Pass `tool_results_summary="Resuming after interruption — re-establishing phase state."` and the full accumulated `case_context`.

**Phase stack:** A JSON list of `{phase, entry_reason, depth}` objects, newest last. Maintained in your context across calls. `stack_action` in each response tells you what to do:
- `"push"` → append `{phase: next_phase, entry_reason: transition_rationale, depth: len(stack)}` to the stack
- `"pop"` → remove the top entry; resume the phase beneath
- `"stay"` → no change

**DAIR-DRIVEN EXECUTION LOOP — DAIR prescribes; Claude executes.**

Never select forensic tools independently. Every tool batch is a direct execution of `directives.priority_tools` from the preceding `dair_assess` call.
The returned directives include `tool_manifest_version` and
`unknown_priority_tools`; if any unknown tool appears, treat it as a planning
drift signal and call `dair_assess` for a corrected manifest-backed work order
instead of guessing a shell command.

**The loop:**
1. Call `dair_assess` → receive `directives.priority_tools` (the work order for this iteration)
2. Execute ONLY those tools, in order. Parallelize only where tools are clearly independent (different hosts, different artifact types). Do not add tools outside the list.
3. Summarize results (3–5 sentences) → call `dair_assess` with `tool_results_summary`
4. Receive next `priority_tools` or phase transition → return to step 2

One complete DAIR iteration = one `dair_assess` call → tool batch → `dair_assess` with results. Each investigation phase consists of one or more complete iterations. The investigation ends only when DAIR returns `next_phase: "Report"`.

Pass to every `dair_assess` call:
- `tool_results_summary` — what the last batch found (pass `"Investigation starting — no tools run yet"` on the very first call)
- `phase_stack` — current JSON stack (pass `"[]"` on first call)
- `case_context` — case ID, threat actor, confirmed IOCs so far

**Phase transitions** (act on `transition_recommended: true` or `verification_satisfied: true`):
- → `Triage`: call `reason.plan` before executing `priority_tools`. Check `verification_challenges` for `verified: null` entries — their `challenge_method` tools appear in `priority_tools`. Call `reason.hypothesize` if any challenge resolves to `verified: false`.
- → `Collect`: execute `priority_tools`; `reason.plan` directives inform collection order.
- → `Analyze`: execute `priority_tools`; call `reason.hypothesize` for each suspicious artifact surfaced.
- → `Scan`: execute `priority_tools` (yara.*, net.*, enrich.*).
- → `pop`: sub-phase resolved — resume parent phase work order.
- → `Report`: call `reason.synthesize`, then `reason.pre_report_check`, then `misc.write_final_report`. Include `recommended_actions` as advisory items. **Never perform Improve & Response actions.**

Log every phase transition as an agent message using `_note` on the first tool call of the new batch.

**Triage max-pass cap:** Track consecutive `dair_assess` responses of `phase=Triage, stack_action=stay` (reset on any `transition_recommended=True` or `verification_satisfied=True`). The moment the count reaches 3, force-satisfy **immediately — do not call `dair_assess` a fourth time**:
- Log: "DAIR Triage max-pass cap (3) reached — forcing transition to Collect"
- Push `{phase: "Collect", entry_reason: "max-pass cap", depth: N}` manually
- Skip `dair_assess` for the **very next batch only**. Resume the loop normally thereafter.

---

## Adversarial Review (reason.*)

Foundation-Sec-8B-Reasoning runs locally. These calls are **mandatory** at the checkpoints below — not optional, not judgment calls.

### Mandatory triggers

**`reason.plan`** — call at the start of every **Triage** phase entry. Before the **initial** Triage call, run all of the following **in a single parallel batch**:
- `ez.ez_recmd_hive` on the SOFTWARE hive — OS version, product name, install date
- `ez.ez_recmd_hive` on the SYSTEM hive — ComputerName, timezone, installed services
- `ez.ez_recmd_hive` on the SAM hive — local user accounts and last login times
- `strings.stat_file` on the memory image — capture size and timestamps

These four complete in seconds. Do not include `ewf_info`, `mmls`, `fsstat`, or `vol_info` — they are slow and don't change the plan. Pass the combined output as `evidence_available`. Use the returned plan to direct tool selection and sequencing.

If you intentionally open a follow-up Triage for a candidate host/principal, use whatever artifacts are available for that candidate — skip the 4 pre-plan reads if the host image is not yet mounted.

`reason.plan` directives also inform collection priorities during the **Collect** phase — re-call `reason.plan` mid-Collect if new artifact findings substantially change the evidence picture.

**`reason.hypothesize`** — call during the **Analyze** phase and whenever these conditions arise in **any phase**, before drawing a conclusion:
- Any process with an orphaned/ghost parent PID
- Any unsigned or unknown executable found on disk or in memory
- Any network connection to an internal host that isn't a domain controller or known infrastructure
- Any scheduled task, service, or Run key that wasn't present before the incident window

**`reason.evaluate_finding`** — call before writing any of these phrases into a report:
- "CONFIRMED COMPROMISE" or "attacker"
- Any attribution to a specific TTP or threat actor
- "exfiltration", "lateral movement", or "persistence confirmed"
- Any negative finding used as evidence (e.g. "no injection detected", "no persistence found")

**Before calling `reason.evaluate_finding`**, the `supporting_evidence` argument must include:
- The specific tool output (command + field + value) that supports the claim
- The confidence tier: CONFIRMED / LIKELY / SUSPECTED / UNCONFIRMED

**Automatic CHALLENGED triggers** — flag immediately without waiting for the reviewer:
- YARA match is the sole evidence for a CONFIRMED-tier finding
- An ATT&CK technique ID cannot be verified against the finding description
- A mechanism claim (how X happened) has no cited raw artifact to support it

**`reason.confidence_score`** — call BEFORE `record_finding` for any tier above SUSPECTED. Pass the finding text + supporting evidence + your intended tier; receive an evidence-grounded tier and a 0.0–1.0 score. If the returned tier is below your intended tier, downgrade the finding before recording.

**`reason.cite_check`** — call BEFORE `record_finding` whenever the finding contains concrete claims (paths, IPs, hashes, technique IDs). Resolve any UNCITED_CLAIMS_PRESENT by adding citations before recording.

**`reason.synthesize`** — call exactly once, in the **Report phase entry sequence** only (after DAIR returns `next_phase: "Report"` or you have manually entered Report). Do NOT call it while the DAIR phase stack top is Triage, Collect, Analyze, or Scan — calling it early is premature and does not count. If you call it early, you must call it again when DAIR actually reaches Report. Pass all findings as a block. This is non-negotiable.

**`reason.hypothesize` lineage:** capture the returned `hypothesis_id` and pass it as `tested_hypothesis_id` to `record_finding` when a finding resolves that hypothesis. The trace renders hypothesis→finding edges in trace.md.

If the server is unreachable, log the failure, note which checkpoints were skipped, and continue.

---

## Cross-tool correlation (`correlate.*`)

- `correlate.process_to_file(pid, path_substring)` — join vol process listings to MFT/fls.
- `correlate.network_to_process(ip, port)` — join netscan/netstat to pslist by PID.
- `correlate.mitre_map(finding_text)` — rank ATT&CK technique IDs by keyword score.
- `correlate.mitre_validate(technique_id)` — confirm a technique ID exists. **Always validate** before citing one.

---

## Negative findings (UNCONFIRMED tier)

"We looked for X and found nothing" is real investigative work. Record it with `confidence="UNCONFIRMED"` and a `linked_call_id` pointing to the search that found nothing. The accuracy framework scores `negative_assertions` in ground_truth.json against these UNCONFIRMED findings.

---

## Execution Trace Log

Call `misc.start_execution_log(case_id, output_path)` at the very start of every investigation, before any other tool. Use `./analysis/<case_id>_trace.json` as the path.

The call returns `dashboard_url` (the live trace dashboard URL). **Announce this URL to the operator in your first message** — it's the easiest way for them to watch the investigation as it happens. The URL is also written to `./analysis/dashboard.url` and printed to stderr.

Call `misc.record_finding(description, confidence, source, linked_call_id)` each time a finding is confirmed by tool output — do not batch.

### Finding capture (read this — common compliance gap)

`misc.record_agent_message` is for **reasoning and direction**, not for stating facts. When you write a paragraph in chat that contains conclusions ("CONFIRMED…", "attacker did X", attribution, exfiltration channel, persistence finding, etc.), accompany it with structured findings — either via separate `misc.record_finding(...)` calls, or atomically in the same call:

```python
misc.record_agent_message(
    content="<HOST> memory shows a C2 beacon on <process>.exe (PID <PID>) and an archiver staging data.",
    input_call_ids=[821, 822, 823],
    findings=[
        {"description": "<process>.exe (PID <PID>) is a C2 beacon implant on <HOST>", "confidence": "CONFIRMED", "linked_call_id": 821, "source": "vol.netscan"},
        {"description": "<archiver>.exe archived data in the incident window on <HOST>", "confidence": "CONFIRMED", "linked_call_id": 822, "source": "vol.cmdline"},
    ],
)
```

Each finding goes through the same gates as `misc.record_finding`. `reason.pre_report_check` runs `reason.audit_findings` (model-based, not regex) to surface narrations that contain factual claims without structured `finding` entries. Address each warning before writing the report.

Call `misc.export_execution_log(output_path)` immediately after `reason.synthesize` completes and before writing the report. Use `./reports/<case_id>_trace` as the path (no extension — both `.json` and `.md` are written automatically). Write the final Markdown report with `misc.write_final_report(output_path, content)`; do not write the final report via raw filesystem writes.

---

## Directive Binding

After every `reason.*` call, extract `directives` from the response before proceeding.

- **`priority_tools`** — call these next, in order, before any other tools. Do not deviate.
- **`skip_tools`** — do not call these tools for the current finding. Glob patterns apply (e.g. `plaso.*` skips all plaso tools).
- **`focus_pids`** — pass as filter parameters to all subsequent `vol.*` tool calls.
- **`focus_paths`** — pass as filter parameters to all subsequent `tsk.*` and `ez.*` tool calls.
- **`next_hypothesis_triggers`** — after each tool result, check whether any trigger condition is met. If yes, call `reason.hypothesize` immediately before continuing.

Directives are binding. `dair_assess` is the primary source of `priority_tools` — never run tools outside that list. After every `reason.*` call, merge its directives into the active DAIR work order: append any `priority_tools` from reason.* not already in the DAIR list; union `skip_tools`, `focus_pids`, `focus_paths`. DAIR directives take precedence on conflicts.
`priority_tools` are manifest-backed tool IDs. Do not invent adjacent names; use
manifest substitution rules when the evidence type makes a requested tool
inapplicable, and re-enter DAIR if the work order becomes empty.
