# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## DFIR Orchestrator — TRUDI / SANS SIFT Workstation

| Setting | Value |
|---------|-------|
| **Environment** | SANS SIFT Ubuntu Workstation (Ubuntu, x86-64) |
| **Role** | Principal DFIR Orchestrator |
| **Evidence Mode** | Strict read-only (chain of custody) |
| **Tool Interface** | TRUDI MCP Server (`trudi-sift`) — forensic tools as typed MCP tools |

---

## Operator Preferences

- **NEVER ask questions during a task.** Run workflows fully autonomously. No check-ins, no confirmations. Deliver final findings only. If blocked, pick the most reasonable path and note it in the output.
- **Never manually edit TRUDI cache files** (`~/.cache/trudi/call_id.counter`, `~/.cache/trudi/session.json`, `~/.cache/trudi/hook_state.json`). To reset cleanly: `python -m tools.trudi_reset --case-dir <case>` — acquires the fcntl lock and atomically clears all three cache files plus the trace (optional `.trace-backups/<ts>/` backup). Manual edits desync the counter from the trace and cause duplicate call_ids.

---

## Forensic Constraints

- **Hash verification** — `hash.verify_evidence_hash` once per evidence file per case; skip if already recorded this session.
- **No hallucinations** — never guess or fabricate artifacts, file contents, or system states.
- **Deterministic execution** — court-vetted CLI tools via MCP only; ground conclusions in raw tool output.
- **Evidence integrity** — never modify files in `/cases/`, `/mnt/`, `/media/`, or any `evidence/` directory.
- **Output routing** — all scripts, CSVs, JSON, reports go to `./analysis/`, `./exports/`, `./reports/`. Never `/` or evidence dirs.
- **Timestamps** — always UTC.
- **Verification** — check `success: true` after every run. On failure: read `stderr` → hypothesize → correct → retry.
- **MCP routing is mandatory.** Never invoke these binaries via Bash: `vol`, `dotnet …Cmd.dll`, `fls/icat/istat/blkls/mactime/tsk_recover`, `hexdump/xxd/exiftool`, `log2timeline.py/psort.py`, `yara`, `bulk_extractor/foremost/scalpel`, `ewfmount/vshadowmount/bdemount/xmount`, `tcpdump`, `clamscan`, `rip.pl`. `record_finding` refuses any finding whose `linked_call_id` points to a `source="claude_code_bash"` entry executing one of these (gate: `mcp_routing`). Use the MCP wrapper (`vol_*`, `ez_*`, `tsk_*`, `strings_*`, `plaso_*`, `yara_*`, `carve_*`, `ewf_*`, `net_*`, `misc_regripper_*`).

---

## Case-Question Anchoring

Every investigation has a case question (e.g. "who sent the harassing email?", "what was exfiltrated?"). It MUST:
1. Appear in `case_context` as `CASE_QUESTION: <one-sentence question>`.
2. Be the `observation` of an **initial `reason.hypothesize` call**, run before `reason.plan` on first Triage entry. Returned hypotheses are the testable propositions for the investigation — capture each `hypothesis_id` and route findings back via `tested_hypothesis_id`.
3. Be verified by `reason.pre_report_check` before Report — it refuses `ready_to_report` unless at least one CONFIRMED or LIKELY finding addresses the question's key entities.

For pivot-host Triage entries, re-state the case question in the pivot's `case_context` so the gates still fire.

---

## Distinct-Principal & Competing-Hypothesis Discipline (mandatory)

The most expensive investigative failure is **single-actor lock-in**: committing to one working narrative at Triage and folding every later artifact onto it — never asking whether a *second* principal is present. Guard against it:

1. **Competing hypotheses at Triage.** The initial `reason.hypothesize` on the case question MUST yield at least one hypothesis that is *not* the leading narrative — a genuinely different actor or mechanism, not an adversarial-defense strawman ("the suspect could claim account takeover"). Treat it as a live proposition and seek evidence that would confirm or kill it. **Every ranked alternative the call returns is individually tracked** (split into sub-hypotheses at the source): each contested principal at MEDIUM+ likelihood must be driven to **CONFIRMED or REFUTED** before Report — its controller established with a session/identity binding, or the alternative refuted. A *parked* ("controller unknown") or *absorbed* alternative does not count for confirmation; `reason.pre_report_check` blocks the report while a mandatory principal remains undispositioned. Pursuing only the highest-likelihood hypothesis and folding everything onto it is the single-actor lock-in this guards against.
2. **A new account/identity is a separate principal until proven otherwise.** Whenever a **newly-created or previously-unseen** account, SID, login, or identity surfaces in **any** phase — especially a privileged one, one created via removable media, or one with no preceding interactive session by a known user — you MUST:
   - run `reason.hypothesize` framing it as a *separate principal* ("who controls account X, and how did they authenticate?"), and
   - establish its controller from an **authentication/session artifact** (logon event by type + source address) **before** attributing any of its actions to anyone already in the case.
   DAIR surfaces this structurally through `candidate_pivots`: a newly-created account **or a previously-unseen identity that authenticates (interactive/RDP logon type 2/10, Security 4778/4779) or first appears as a correspondent** may be returned as a principal lead, but DAIR does not mutate the phase stack solely because a candidate exists. Treat forced principal candidates as mandatory leads: either investigate and bind them, exclude them with evidence, or explicitly park the controller as unknown. `record_finding` enforces attribution grounding too — the `principal_attribution_grounding` gate **and** `named_actor_attribution_grounding`, which also fires when a person is named directly as the actor ("Nina exfiltrated…"). `reason.pre_report_check` **blocks** Report while a distinct-principal hypothesis is unresolved or a forced surfaced identity is un-dispositioned. Do not attribute an account's actions by assumption.
3. **Re-hypothesize on divergence.** When an artifact contradicts the working hypothesis (an account created at a moment the prime subject was not active; a logon from an unexpected source; a second exfil path), re-run `reason.hypothesize` rather than absorbing the anomaly into the existing story.
4. **Physical-media initial access (mandatory when a covert account / persistence + removable media coincide).** When a covert/backdoor account or persistence is **created in an interactive/console session** AND removable media is in evidence, do **not** read "interactive session" as proof of human authorship — a **BadUSB** device injects keystrokes that are indistinguishable from typing at the logon-event level. Raise a `reason.hypothesize` framing **initial access via a physical device** ("did the in-person contact hand over a device that injected this activity?"), and run **`misc.device_install_inventory`** on `setupapi.dev.log` — it enumerates the **complete** device table and flags the structural keystroke-injector profile (a device exposing both HID/keyboard and mass-storage interfaces). **Enumerate, don't grep**: a keyword/windowed search over a bounded device-install log can silently miss a device; the structured inventory surfaces every device as a row you cannot miss. `USBSTOR`/mass-storage enumeration alone **cannot** reveal a keystroke-injection device. `record_finding`'s `interactive_injection_grounding` gate refuses the "X created it interactively" finding unless the inventory ran over the window with nothing flagged — and refuses outright if it flagged an injector.

---

## Knowns-Driven IOC Hunting (mandatory when a reference set exists)

When `case_context` includes any enumerable reference set — suspect list, user roster, asset inventory, known-good baseline, known-bad hash list, allowlist of domains/IPs — **invert the search direction**: derive query terms FROM the knowns and hunt for them in the first Triage batch, before generic enumeration.

Use `misc.knowns_pattern_generate(reference_set=[...], derivation_type=<type>)`:

| `derivation_type` | Use for | Emits |
|---|---|---|
| `person_username` | Person/account rosters ("Firstname Lastname") | jdoe, jane.doe, janedoe, doej, jane, doe, ... |
| `hostname` | Asset inventories / hostname lists | short + FQDN + apex suffix |
| `hash` | Known-bad/known-good hash lists | passes through unchanged |
| `domain` | Allowlist/denylist domain lists | exact + apex match marker |
| `exact` | Anything else | passes through unchanged |

Run the returned `ngrep_pattern` against evidence (`net.ngrep_search`, `strings.strings_grep`, `yara.scan_strings`) before broad enumeration. The first batch must include a knowns-IOC hunt when knowns exist.

---

## Identifier Cross-Reference Normalization (mandatory)

Normalize BOTH sides before declaring a non-match. Required normalizations:
- **Case folding** — compare lowercased
- **Separator equivalence** — `.` `_` `-` and absence treated as equivalent
- **Username derivations** — for person names, generate (initial+last, first.last, first_last, first+last) variants
- **Email-prefix extraction** — `user@domain.tld` matches `user`
- **Path canonicalization** — normalize separators, case (Windows), resolve `.`/`..`
- **Hash family equivalence** — match on any of MD5/SHA1/SHA256 for the same file is a match

A "no match against roster" finding must document that these normalizations were used. Surface-form-only comparison is not exhaustive.

---

## Prefer Structured Extractors Over Keyword Search

For artifacts with a known schema (HTTP cookies, registry values, event log records, MFT attributes, kernel structures), prefer the structured extractor over `ngrep` / `strings` / `grep` — keyword search discards structure and misses fields that don't textually match.

| Artifact family | Use | Instead of |
|---|---|---|
| HTTP sessions in PCAP | `net.http_session_inventory` | repeated `net.ngrep_search` for Cookie/login/email |
| Registry hive enumeration | `ez.recmd_hive`, `misc.regripper_hive` | `strings` + `grep` against hive |
| Event log fields | `ez.evtxecmd`, `misc.chainsaw_hunt` | `evtx_dump` piped to grep |
| **Logon sessions / source** | `ez.evtxecmd` Security **4624/4625 by logon type + source address** (Linux: `last`/`wtmp`/`sshd`) | assuming an account's actions belong to the prime subject |
| **USB device-install / BadUSB** | `misc.device_install_inventory` (complete device table from `setupapi.dev.log`) | `strings`/`grep` over `setupapi.dev.log` for a VID or time window (a search over a bounded log can silently miss a device) |
| MFT entries | `ez.mftecmd` | raw `strings` over $MFT |

Keyword search only for ad-hoc lookups where no structured extractor exists, or as a confirmation pass.

**Authentication-Session Inventory before attribution (mandatory).** Whenever event logs are in scope and any persistence / lateral-movement / account-creation finding is in play, enumerate logon events **by type and source** (which account, logon type 2/3/10, source network address) *before* attributing the account's actions to a person. An account name is not a person — the binding requires a session artifact. `record_finding`'s `principal_attribution_grounding` gate refuses CONFIRMED/LIKELY account→person bindings that lack one; its sibling `named_actor_attribution_grounding` extends the same requirement to a person named directly as the actor ("Nina exfiltrated…"). This inventory is now **blocking at `reason.pre_report_check`** whenever a human/account attribution verdict is present — run it before stating who acted. Enumerate logon sessions from the **full event-log set on the mounted image** — Security 4624/4625 **and the TerminalServices channels** (LocalSessionManager / RemoteConnectionManager Operational, which record RDP type-10 logons with user + source IP and are **absent from CyLR/triage collections**) — never from the triage subset alone; a `Security.evtx` coverage gap forces a pivot to those channels / VSS / carving, never a "local-console only" conclusion (`record_finding`'s `negative_completeness` gate refuses a "no logon/RDP" negative that skipped them).

---

## Reformulation Depth Limit (server-enforced)

`reason.evaluate_finding` is rate-limited per finding-description. If the same normalized description has been evaluated 2 times recently with no new tool calls between attempts, the third is refused with gate `reformulation_depth_limit`. Remediation:
1. Run new tool calls for fresh evidence before re-evaluating, OR
2. Park as UNCONFIRMED (note the reformulation loop) and pursue a different finding direction.

Intent: prevent rumination spirals where the agent defends a finding via wording changes instead of better evidence.

---

## Exhaustive Evidence Rule

### Never stop at the first artifact of a type
When a category can contain identity, attribution, persistence, or C2 evidence, collect ALL instances from available evidence before concluding. One example ≠ complete picture.

- **PCAP**: one HTTP cookie ≠ all cookies — extract `Cookie:` across ALL port-80 flows from the suspect device; also URL/webmail auth params (`login=`, `email=`, `user=`, `sid=`, `auth=`, and provider-specific session params); run `net.tcpdump_extract_http` + `net.tcpxtract_streams` on the device-filtered PCAP.
- **Disk**: one Run key ≠ all persistence (run all 4 Run/RunOnce hives); one browser profile ≠ all creds (check all profiles for all browsers).
- **Per-principal (every SID, including covert)**: one user's profile ≠ all the evidence. Enumerate the deleted items (**per-SID `$Recycle.Bin`**), Desktop/Downloads, staging dirs, and execution artifacts (Prefetch/UserAssist) of **every** user account on the host — including newly-created and covert accounts — not just the prime subject's. The actual exfiltrated archive and the second actor's loot routinely sit in a *different* SID's Recycle Bin / Desktop than the suspect's.
- **Memory**: run both `vol.malfind` AND `vol.hollowprocesses`; both `vol.netscan` AND `vol.netstat`.
- **Event logs**: enumerate the **full `winevt\Logs\` from the mounted image** — not just a CyLR/triage subset — including the **TerminalServices channels** (LocalSessionManager / RemoteConnectionManager Operational) that record RDP type-10 sessions with user + source IP. Check for log-clearing AND for **coverage gaps**: a log whose earliest event postdates the incident window is *silent*, not negative — pivot to VSS / carved EVTX. A "no RDP/logon" negative drawn over only `Security.evtx` is refused by `negative_completeness`.
- **USB / removable media — two forensic roles**: enumerate USB both as **egress** (USBSTOR / MountedDevices / LNK volume labels — storage that data left on) AND as **ingress / initial-access** (the `setupapi.dev.log` device-install log → HID/composite / **BadUSB** devices that inject keystrokes or autorun). For ingress, run **`misc.device_install_inventory`** on `setupapi.dev.log` — it **enumerates the complete device table** (one de-duplicated row per device: class, vendor, product, VID:PID, interfaces, first/last seen) and flags the structural keystroke-injector profile (a device exposing both HID/keyboard and mass-storage interfaces). **ENUMERATE, don't search** — do NOT `strings | grep` the log for a VID or window a `Section start`: a keyword/windowed search over a bounded log can silently miss a device (a head-capped dump; a `grep -A "Section start"` skips the device-name header line that precedes it; a hunt for an HID-composite VID misses a device whose HID install isn't separately logged). The complete inventory surfaces every device — including a mass-storage device whose vendor/product names it itself, which `USBSTOR`/mass-storage enumeration alone reads as ordinary storage. Run **both** lenses whenever removable media is in evidence — `interactive_injection_grounding` and `negative_completeness` (DEVICE_INITIAL_ACCESS) require the structured inventory (coverage spanning the window, nothing flagged) before an "X did it interactively" finding or a "no BadUSB" negative; a keyword grep no longer satisfies them.

### Identity Exhaustion Gate (all investigations)
Before writing any finding/report that states identity/attribution is unknown:
- [ ] List every artifact type in evidence that could carry identity data
- [ ] Confirm each has been queried (not just the ones that returned results first)
- [ ] Cross-reference EVERY found identity (email, username, screen name, SID, cert CN, cookie value) against any suspect list / user directory / class roster in case context
- [ ] Only then conclude "unknown — requires external legal process"

Stopping at the first found identity without checking the rest is an investigation failure. "Requires subpoenas" is valid only when the evidence is genuinely exhausted.

### Suspect list cross-reference (mandatory)
When case context includes a list of known individuals (roster, employee list, user directory, ticketing), every online identity in evidence MUST be cross-referenced before Analyze concludes. A match resolves attribution without legal process; a non-match must be explicitly noted.

### Recipient/Correspondent Exhaustion (mandatory for dissemination/exfil)
"Who received the data / who is the buyer" must be answered from a **full sender/recipient inventory** of the comms stores (mail OSTs/PSTs, chat DBs) — `misc.readpst_extract` / `misc.pff_export` then enumerate senders and recipients — **cross-referenced against the case roster**, before concluding the recipient. Do not surface an incidental/noise thread as the recipient while a named contact in the roster (or a plainly-addressed correspondent in the same mailbox) remains unchecked. The recruiter/buyer is usually addressing the subject by name in the same store you already parsed. `reason.pre_report_check` warns when a recipient is named with no evident roster cross-reference.

### Exfil-Channel Enumeration & Ranking (mandatory before the verdict)
Before stating *how* data left the host, enumerate **all** candidate channels — removable media (LNK/`MountedDevices`/USN), FTP/transfer logs, cloud-client DBs, email attachments, web upload, C2/messenger — and **rank them by evidence strength**. A channel claim requires a **transfer artifact** (bytes moved), not tool/folder presence: a file in a sync folder, a cloud-client ADS, or "the tool was installed" is **staging, not egress**. Never headline a channel in the verdict that is weaker-evidenced than a competing one. `record_finding`'s `exfil_channel_grounding` gate refuses CONFIRMED/LIKELY egress claims that cite only presence; `reason.pre_report_check` warns when multiple channels appear un-ranked.

---

## TRUDI MCP Tool Namespaces

All forensic execution goes through MCP tools.

| Namespace | Domain | Key Tools |
|-----------|--------|-----------|
| `img.*` | Disk image mounting | ewfmount, vshadowmount, bdemount, xmount, photorec, losetup |
| `vol.*` | Memory (Volatility 3) | **`vol_symbol_check` first on any new image**, then pstree, pslist, psscan, cmdline, netstat, dlllist, malfind, hivelist, dumpfiles, linux plugins |
| `tsk.*` | Filesystem (Sleuth Kit) | fls, icat, istat, ils, blkls, mactime, tsk_recover, sigfind, sorter, jls, jcat, **indxparse** ($INDX slack) |
| `ewf.*` | E01 images | ewfmount, ewfinfo, ewfverify, mount_full_image |
| `ez.*` | Windows artifacts (EZ Tools) | MFTECmd, EvtxECmd, RECmd, AmcacheParser, AppCompatCacheParser, PECmd, JLECmd, LECmd, SBECmd, WxTCmd, SQLECmd, RBCmd |
| `plaso.*` | Super-timeline | log2timeline, psort (CSV/JSON/filter), pinfo |
| `yara.*` | Threat hunting | scan_file/_directory/_memory_image, scan_strings, compile_rules — built-in rules at `~/trudi/rules/` |
| `hash.*` | Integrity / similarity | hash_file (cached), hash_directory, ssdeep, hashdeep, verify_evidence_hash |
| `strings.*` | Static analysis | strings, hexdump, xxd, file, exiftool, stat, **floss_extract** (obfuscated strings) |
| `carve.*` | File carving | bulk_extractor, foremost, scalpel |
| `net.*` | Network analysis | tcpdump_read, tcpdump_extract_http/dns, ngrep_search, tcpxtract_streams |
| `enrich.*` | Threat intel | virustotal_hash/ip/domain, abuseipdb_check (graceful-degrade without keys) |
| `misc.*` | Windows artifacts + email + macros | evtx_dump, regripper, usn_journal, analyzeMFT, Hindsight, ClamAV, PDF/PE, **pff_export**, **readpst_extract**, **densityscout_scan**, **chainsaw_hunt** (Sigma), **capa_analyze** (caps→ATT&CK), **olevba_scan**/**mraptor_scan**, **device_install_inventory** (complete USB/BadUSB device table from setupapi.dev.log), **batch_run** |
| `reason.*` | Adversarial review (swappable via REASON_BACKEND) | plan, hypothesize, evaluate_finding, **confidence_score**, cite_check, synthesize, pre_report_check |
| `correlate.*` | Cross-tool correlation | **process_to_file**, **network_to_process**, **mitre_map**, **mitre_validate** |
| `accuracy.*` | Ground-truth comparison | accuracy_compare, accuracy_export_report (precision, recall, F1, negative-coverage) |
| `dair.*` | DAIR phase director (separate backend via DAIR_BACKEND) | dair_assess — call after every tool batch |
| `af.*` | Anti-forensics detection | **timestomp_drift** (after ez.mftecmd), **event_log_clear** (after ez.evtxecmd), **sysmon_evasion** (after ez.recmd SYSTEM), **usn_gaps** (after misc.usnparser_parse), **prefetch_deletion** (after ez.pecmd / amcacheparser) — run automatically when the input artifact exists |
| `live.*` | Live endpoint analysis (Linux/SSH, read-only) | live_processes, live_network_connections, live_persistence_audit, live_yara_scan, live_open_files, live_read_file, live_event_log_tail |
| `velo.*` | Velociraptor API surface (read-only WRT evidence) | list_clients, client_info, collect_artifact, wait_for_flow, get_collection_results, get_client_event_table, update_client_event_table, upload_artifact_yaml, query |
| `monitor.*` | Live-monitoring lifecycle | baseline_capture, start_watcher, stop_watcher, list_watchers, check_alerts, ack_alert |
| `respond.*` | **Gated** containment & eradication (live-monitoring scope only) | suggest_containment, list_actions, approve_action, execute_action, revert_action |

---

## Live monitoring loop

When the operator stands up a Velociraptor-backed live-monitoring case
(typically via `demo/live-monitoring/docker compose up`), the workflow is:

1. `monitor.baseline_capture(client_id, case_id)` snapshots processes,
   persistence, network endpoints into
   `~/cases/<case>/monitoring/baselines/<client_id>.json`.
2. `monitor.start_watcher(client_id, case_id, detectors=[...])` renders
   `Custom.TRUDI.*` event artifacts from the baseline, pushes them onto
   the client event table via `velo.update_client_event_table`, and
   spawns `bin/trudi-velo-watcher.py` as a detached sidecar.
3. The sidecar runs `velociraptor query --format=jsonl` against
   `watch_monitoring(artifact=Custom.TRUDI.*)` and writes one alert JSON
   per emitted row into `~/cases/<case>/monitoring/alerts/`.
4. `/loop 15s /trudi-check-alerts` drains the alert queue every 15s and
   runs **per-investigation traces** — every tick that finds alerts
   opens (or resumes) ONE investigation (`INV-NNN`) covering the whole
   bundle. Its trace is `analysis/<case>_<INV-NNN>_trace.json` (flat
   under analysis/ so the dashboard picks it up), opened by
   `monitor.start_investigation`. The focused investigation chain
   (`reason.hypothesize` → `dair_assess` → tool batch →
   `record_finding` → `respond.*`) runs ONCE on the bundle, and
   `monitor.end_investigation` exports
   `reports/<case>_<INV-NNN>.{json,md}` and swaps back to the case-wide
   `analysis/<case>_trace.json`. New alerts arriving while an
   investigation is open get folded in via `monitor.extend_investigation`.
   The case-wide trace records orchestration only (`check_alerts`,
   `list_watchers`, `ack_alert`, the start/end markers themselves).
   DAIR's "last 30 entries" gate window is scoped per-trace, so
   phase stacks and `confidence_and_citation` matches don't bleed
   between independent attack scenarios.
5. For CONFIRMED/LIKELY findings, the slash command runs **auto-protect**:
   `respond.suggest_containment` then `respond.execute_action(mode="auto")`
   per action. The **reversible + low-risk** tier auto-executes (with its
   rollback command surfaced); destructive actions are queued and **pause
   the loop** until the operator types `approve <action_id>` literally —
   captured into the per-investigation trace by the `UserPromptSubmit`
   hook, matched by `operator_text_required` before
   `respond.approve_action` → `respond.execute_action(mode="operator")`.
   See "Gated response & auto-protect" below.

---

## Gated response & auto-protect (live-monitoring only)

TRUDI's strict read-only-on-evidence stance is preserved everywhere
*except* the `respond.*` namespace, allowed only against an active
live-monitoring case (server-enforced by `live_monitoring_scope`). In
**auto-protect** mode (default ON), TRUDI is an autonomous blue-team
agent: it auto-executes the **reversible + low-risk** tier of containment
and asks the operator to approve anything destructive.

**Execution substrate.** Actions run over a gated write-capable SSH path
(`core/ssh_exec.py`) as **structured, validated argv** mirroring the
`Custom.TRUDI.Respond.*` artifacts — never a free-form command string.
Every evidence value is type-validated (pid/ip/port/path-allowlist) before
it enters the argv, so injection is structurally impossible. The writable
runner has no MCP surface; only `respond.execute_action` /
`respond.revert_action` reach it, and it re-checks `live_monitoring_scope`
itself.

**The auto vs approval boundary is server-classified** from the recipe's
`risk`/`reversible` metadata (`response/policy.py:classify`) — the agent
cannot reclassify. AUTO = reversible AND risk:low. Everything else (any
irreversible action, or risk ≥ medium) requires an operator-typed
`approve ACT-N`. Passing `mode="auto"` to `execute_action` on a
destructive action does NOT bypass approval — permission is recomputed
from disk every call.

**Loop-pause.** When a destructive action is recommended, the watcher
queues it (`monitor.set_awaiting_approval`) and pauses autonomous response
for that investigation; it stays open across `/loop` ticks until the
operator approves. Every action — auto-executed, approved, or reverted —
is logged with its **rollback/undo command** to the console and the
report's *Autonomous Response Actions* section.

| Gate | Applies to | Refuses unless… |
|---|---|---|
| `live_monitoring_scope` | every `respond.*` call **and `core/ssh_exec` itself** | `case_id` has a populated `monitoring/baselines/` directory |
| `operator_text_required` | `respond.approve_action` | `action_id` is literally in `operator_text` AND a matching `user_message` trace entry exists in the recent window (the agent cannot self-approve) |
| `check_execution_permitted` | `respond.execute_action`, `respond.revert_action` | the action is AUTO-classified (reversible+low) with auto-protect enabled, OR a non-expired operator approval token exists (composes `approval_required`) |

Auto-protect is per-case: `monitoring/config.json`
`{"auto_protect":{"enabled":false}}` reverts to fully operator-gated
(every action needs `approve ACT-N`). Default (no file) = enabled.

`respond.*` cannot touch anything under `/cases/.../evidence/`,
`/mnt/`, or `/media/` — those refusals are unchanged.

**Not available:** MemProcFS, VSCMount (Windows-only), tshark, hayabusa, guymager.

**Volatility exit codes:** `1` = plugin ran but failed (may be normal — e.g. no data). `2` = argument error (TRUDI bug). `-1` (timeout) = symbols not cached — run `vol_symbol_check`.

---

## DAIR Phase Director (dair.*)

DAIR is a **recursive state machine**, not a checklist. TRUDI is read-only: Improve & Response actions are never executed — only recommended in the final report. Investigation begins with a confirmed positive detection in hand.

| Phase | Role | reason.* | Recursive? |
|-------|------|-----------|------------|
| Triage | Confirm initial IOCs, challenge hallucinations (file existence, registry keys, processes, network). Produce plan. | `reason.plan` at phase entry | Yes — new questions can be entered when relevant |
| Collect | Gather raw artifacts per plan — ez.*, vol.*, tsk.*, strings.* | `reason.plan` directives prioritize | No — advance when plan satisfied |
| Analyze | Reason about artifacts — processes, network, persistence, TTPs | `reason.hypothesize` per suspicious artifact | Yes — unexpected finding can push Triage |
| Scan | Sweep for lateral movement / other hosts — yara.*, net.*, enrich.* | — | Candidate pivots may lead back to Triage |
| Report | Synthesize timeline; emit Improve & Response recs | `reason.synthesize` + `reason.pre_report_check` | Yes — blockers return to Collect/Analyze/Scan |

**Loop anatomy:** DAIR is recursive, not linear. Any phase can discover a missing question or evidence gap; when that gap is material to the case question, return to Triage/Collect/Analyze/Scan, collect the missing evidence, then re-synthesize. Report is not a wording exercise: if `reason.synthesize` or `reason.pre_report_check` reports blockers, go back to evidence work before trying to report again.

**Candidate pivot handling.** When top-of-stack is `Scan`/`Analyze`/`Collect` and `tool_results_summary` names a **new pivot target** NOT already in `case_context` or prior `investigation_focus`, `dair_assess` may return it in `candidate_pivots` with `{kind, value, phase, cue}`. Candidate pivots are leads, not control flow. Do not mutate `phase_stack` or start a Triage solely because a candidate exists. Investigate a candidate when it is relevant to the case question, and record either a finding or an explicit out-of-scope / evidence-unavailable disposition. Two kinds of pivot target:
- **Host** — IPv4, UNC like `\\HOST\share`, or any token matching `TRUDI_PIVOT_HOSTNAME_PREFIXES` in `.env`.
- **Principal** — a newly-*created* account/identity **OR any previously-unseen identity that authenticates or first appears** (cues: account creation / Security EID 4720; interactive or RDP logon — type 2/10, EID 4778/4779, "logged in"/"authenticated"; first-seen correspondent; RID/SID). A known identity (the case subject, or a principal already under investigation) does not re-pivot. Forced principal candidates must be dispositioned before Report. This is the structural backstop for the Distinct-Principal Discipline above.

Stop-lists filter false positives (hosts: `SCAN`/`TRIAGE`/`WINDOWS`/`SYSTEM`/AV-product/file-type tokens; principals: built-in accounts `Administrator`/`Guest`/`DefaultAccount`/`SYSTEM`/`HomeGroupUser$`/etc.).

**Context-break resumption:** If anything interrupts the investigation (context window, tool timeout, session restart, **MCP disconnect/reconnect**), the first action on resumption is `dair_assess` with the last-known phase stack — before any tool batch. If `dair_assess` is down, wait for the server. Pass `tool_results_summary="Resuming after interruption — re-establishing phase state."` and the accumulated `case_context`.

**Phase stack:** JSON list of `{phase, entry_reason, depth}` (newest last), maintained across calls. `stack_action`:
- `"push"` → append `{phase: next_phase, entry_reason: transition_rationale, depth: len(stack)}`
- `"pop"` → remove the top entry; resume the phase beneath
- `"stay"` → no change

**DAIR-DRIVEN EXECUTION LOOP — DAIR prescribes; Claude executes.** Every tool batch is a direct execution of `directives.priority_tools` from the preceding `dair_assess`. Run the work order first and completely; do not substitute your own agenda for it.

1. Call `dair_assess` → receive `directives.priority_tools` and `directives.curiosity_budget`
2. Execute the `priority_tools`, in order. Parallelize where independent (different hosts/artifacts). No additions to the *work order*.
3. **Curiosity probes (only after the work order is done).** If `directives.curiosity_budget` > 0, you MAY run up to that many read-only exploratory calls of your own choosing — to chase a hunch about a less-obvious artifact the work order didn't name (a second SID's `$Recycle.Bin`, an untouched comms store, `setupapi.dev.log`, a weaker-but-unchecked exfil channel). For each: run the read-only tool, then call `misc.record_curiosity_probe(rationale=…, seeded_by=<absence-hypothesis_id, if any>, input_call_ids=[…])` — it enforces the budget and logs *why* you looked. A probe is **not** a finding and carries no weight alone; to turn one that paid off into evidence, feed its `call_id` into `reason.hypothesize` / `record_finding` via `input_call_ids`, where the normal gates apply. This widens coverage without loosening a single gate. Budget 0 (e.g. Report) ⇒ no probes.
4. Summarize (3–5 sentences) → call `dair_assess` with `tool_results_summary` (note any probe results)
5. Receive next `priority_tools` or transition → step 2

One iteration = one `dair_assess` → tool batch (+ optional probes) → `dair_assess` with results. Investigation ends only when DAIR returns `next_phase: "Report"`.

Pass to every `dair_assess`:
- `tool_results_summary` — what the last batch found (use `"Investigation starting — no tools run yet"` on first call)
- `phase_stack` — current JSON stack (`"[]"` on first call)
- `case_context` — case ID, threat actor, confirmed IOCs so far

**Phase transitions** (on `transition_recommended: true` or `verification_satisfied: true`):
- → `Triage` (initial or new pivot): call `reason.plan` before executing `priority_tools`. Check `verification_challenges` for `verified: null` — their `challenge_method` tools appear in `priority_tools`. Call `reason.hypothesize` if any challenge resolves `verified: false`.
- → `Collect`: execute `priority_tools`; `reason.plan` directives inform order.
- → `Analyze`: execute `priority_tools`; call `reason.hypothesize` per suspicious artifact.
- → `Scan`: execute `priority_tools` (yara.*, net.*, enrich.*).
- → `pop`: sub-phase resolved — resume parent work order.
- → `Report`: call `reason.synthesize`, then `reason.pre_report_check`, then write the report. Include `recommended_actions` as advisory. **Never perform Improve & Response.**

Log each phase transition with `_note` on the first tool call of the new batch.

**Triage max-pass cap:** Track consecutive `dair_assess` responses of `phase=Triage, stack_action=stay` (reset on `transition_recommended=True` or `verification_satisfied=True`). At count 3, force-satisfy immediately — **do not call `dair_assess` a fourth time**:
- Log: "DAIR Triage max-pass cap (3) reached — forcing transition to Collect"
- Push `{phase: "Collect", entry_reason: "max-pass cap", depth: N}` manually
- Skip `dair_assess` for the **very next batch only**. Resume normally after.

---

## Adversarial Review (reason.*)

Foundation-Sec-8B-Reasoning runs locally. Calls below are **mandatory** at the named checkpoints — not optional.

### Mandatory triggers

**`reason.hypothesize` on the case question** — at the very start of the initial Triage entry, BEFORE `reason.plan`. Pass `observation`=case question (from `CASE_QUESTION:`), `evidence`=evidence summary, `context`=full case context. The returned hypotheses are the testable propositions for the investigation. Capture each `hypothesis_id` and route findings via `tested_hypothesis_id`. For material pivot questions, run the same call with the pivot-specific question. The call's `priority_tools` carry the **discriminators that resolve the top two competing hypotheses** (logon type/source, USB serials across profiles, OneDrive/registry account bindings) — execute them as the binding work order. Resolving **every** MEDIUM+ contested principal to CONFIRMED/REFUTED or explicitly parking it as controller-unknown/evidence-unavailable is mandatory before Report, not just the leading one.

**`reason.plan`** — at the start of every Triage phase entry (initial + each pivot). Before the **initial** Triage call, run this parallel batch — **MCP wrappers only**:
- `ez_ez_recmd_hive` on SOFTWARE — OS version, product name, install date
- `ez_ez_recmd_hive` on SYSTEM — ComputerName, timezone, installed services
- `ez_ez_recmd_hive` on SAM — local users, last login
- `vol_vol_symbol_check` — confirm Volatility symbols are cached
- `strings_stat_file` on the memory image — size, timestamps
- `hash_verify_evidence_hash` on each evidence file (once per file per case)

These are in `DAIR_GATE_ALLOWLIST` and complete in seconds. **Do NOT shell out to `dotnet …RECmd.dll` or `/usr/local/bin/vol`** — `source="claude_code_bash"` entries fail the cold-start gate (`protocol_violation: no_active_dair_batch`), and any finding citing them refuses via `mcp_routing`. Do not include `ewf_info`, `mmls`, `fsstat`, `vol_info` — slow and uninformative. Pass combined output as `evidence_available`.

For subsequent pivot Triage entries, use whatever artifacts are available — skip the 4 pre-plan reads if the host image isn't mounted yet.

`reason.plan` directives also inform Collect ordering — re-call mid-Collect if new findings change the picture.

**`reason.hypothesize`** — during Analyze and whenever any of these arise in **any phase**:
- Process with orphaned/ghost parent PID
- Unsigned/unknown executable on disk or in memory
- Network connection to an internal host that isn't a DC or known infra
- Scheduled task / service / Run key not present before the incident window

**`reason.evaluate_finding`** — before writing any of these phrases:
- "CONFIRMED COMPROMISE" or "attacker"
- Any TTP / threat actor attribution
- "exfiltration", "lateral movement", "persistence confirmed"
- Any negative finding used as evidence ("no injection detected", "no persistence found")

`supporting_evidence` must include the specific tool output (command + field + value) and the tier (CONFIRMED / LIKELY / SUSPECTED / UNCONFIRMED).

**Automatic CHALLENGED triggers** — flag without waiting for the reviewer:
- YARA match is the sole evidence for a CONFIRMED finding
- An ATT&CK technique ID can't be verified against the finding description
- A mechanism claim has no cited raw artifact

**`reason.synthesize`** — exactly once, in the Report phase entry only (after DAIR returns `next_phase: "Report"`). Do NOT call while top-of-stack is Triage/Collect/Analyze/Scan — re-call when Report is actually reached. Pass all findings as a block.

**`reason.confidence_score`** — BEFORE `record_finding` for any tier above SUSPECTED. Pass finding text + supporting evidence + intended tier; receive an evidence-grounded tier and a 0.0–1.0 score. If returned tier is below intended, downgrade.

**`reason.cite_check`** — BEFORE `record_finding` when the finding contains concrete claims (paths, IPs, hashes, technique IDs). Returns ALL_CITED / UNCITED_CLAIMS_PRESENT / INSUFFICIENT_EVIDENCE. Resolve UNCITED_CLAIMS_PRESENT by adding citations.

**`reason.pre_report_check`** — immediately after `reason.synthesize`, before writing any report section. If `ready_to_report=False`, resolve all `blocking_issues` first. It now also **blocks** when: an unresolved distinct/second-principal hypothesis is still open; a human/account attribution verdict was recorded but no logon/RDP session inventory (4624/4625/4778/4779, or Linux `last`/`wtmp`) ran anywhere in the trace; or a surfaced controller-question identity is left un-dispositioned. **Run the logon/RDP session inventory early** (first Collect batch when event logs are in scope) so attribution closure is already satisfied at Report.

If the server is unreachable, log + note skipped checkpoints + continue.

### reason.* Parameter Reference

| Tool | Required | Optional |
|------|----------|----------|
| `reason.plan` | `case_description`, `evidence_available` | — |
| `reason.hypothesize` | `observation` | `evidence`, `context` |
| `reason.evaluate_finding` | `finding`, `supporting_evidence` | `case_context` |
| `reason.confidence_score` | `finding`, `supporting_evidence` | `intended_tier` |
| `reason.cite_check` | `finding`, `supporting_evidence` | — |
| `reason.synthesize` | `findings` | `investigation_summary` |
| `reason.pre_report_check` | *(none)* | — |

**`reason.hypothesize` usage:**
- `observation` — single behaviour/artifact (one sentence)
- `evidence` — raw artifact list (tool excerpts, IDs, timestamps — verbatim)
- `context` — broader case context (OS, known TTPs, timeline)
- Capture returned `hypothesis_id` (e.g. `H0007`) → pass as `tested_hypothesis_id` to any `record_finding` resolving it. Builds hypothesis→finding lineage in `trace.md`.

---

## Cross-tool correlation (`correlate.*`)

- `correlate.process_to_file(pid=…, path_substring=…)` — join vol process listings to MFT/fls records
- `correlate.network_to_process(ip=…, port=…)` — join vol.netscan/netstat to vol.pslist by PID
- `correlate.mitre_map(finding_text=…, top_n=…)` — rank candidate ATT&CK IDs by keyword score
- `correlate.mitre_validate(technique_id=…)` — confirm a technique ID exists

Any ATT&CK ID (`T\d{4}(\.\d{3})?`) in a finding description is **auto-validated** by `record_finding` (gate: `mitre_technique_validation`). Unknown IDs refuse with the offending strings. Manual `correlate.mitre_validate` is still useful for pre-finding scouting; use `correlate.mitre_map` to find candidates for a behaviour you don't yet have a T-ID for.

---

## Hard auto-gates on `record_finding` and `export_execution_log`

**Server-enforced. `record_finding` refusals return `{success: false, gate: "<id>", ...}` with a remediation message. The broad `gate` value is stable; when present, `detail_gate` names the specific checker that fired. `reason.pre_report_check` returns structured `blocking_issues` that must be resolved before `export_execution_log`.**

| Gate | Applies to | Condition | Remediation |
|------|------|-----------|-------------|
| `mcp_routing` | `record_finding` | `linked_call_id` → `source="claude_code_bash"` entry executing a forensic binary | Re-run via the named MCP wrapper; use that `_trudi_call_id` |
| `dair_required` | `record_finding` | No `dair_assess` in last 30 trace entries | Call `dair_assess` first |
| `lineage_required` | `record_finding`, `record_self_correction`, `dair_assess`, `reason.*` | `input_call_ids` empty after genesis grace (first 5 entries) — or contains unknown/fabricated cid | Pass `input_call_ids=[<cid>, ...]` from upstream entries |
| `confirmed_requires_linked_call_id` | `record_finding` | Tier=CONFIRMED and `linked_call_id == 0` | Pass `linked_call_id=<_trudi_call_id>` from source tool result |
| `linked_call_id_must_exist` | `record_finding` | `linked_call_id` not in trace | Use real `_trudi_call_id` |
| `mitre_technique_validation` | `record_finding` | Description contains unknown ATT&CK ID | Fix T-ID (`correlate.mitre_validate`) or remove |
| `confirmed_requires_supported_evaluate` | `record_finding` | Tier=CONFIRMED and most recent `reason.evaluate_finding` returned CHALLENGED or UNCERTAIN | Call `reason.evaluate_finding` until SUPPORTED, or downgrade |
| `confidence_and_citation` | `record_finding` | Tier ∈ {CONFIRMED, LIKELY} and no recent `reason.confidence_score` AND `reason.cite_check` referencing this finding's text | Call both with description in each `user_message`; resolve UNCITED_CLAIMS_PRESENT; downgrade if `confidence_score`'s tier is lower |
| `hypothesize_required` | `record_finding` | Tier ∈ {CONFIRMED, LIKELY} AND description has process/service/persistence/C2/lateral keywords AND no recent `reason.hypothesize` AND no `tested_hypothesis_id` | Call `reason.hypothesize`; pass returned `hypothesis_id` as `tested_hypothesis_id` |
| `principal_attribution_grounding` | `record_finding` | Tier ∈ {CONFIRMED, LIKELY} AND description binds an account/identity to a named principal ("account X operated by / belongs to / logged in as / created by Y") AND no authentication/session marker (logon 4624/4625 + type/source, RDP/SMB/SSH, SAM InternetName, cert CN) in `supporting_evidence` or the linked/`input_call_ids` entries | Pull the logon-session/source artifact (`ez.evtxecmd` 4624/4625 by type+source) and cite it (`input_call_ids`), or downgrade to SUSPECTED |
| `named_actor_attribution_grounding` | `record_finding` | Tier ∈ {CONFIRMED, LIKELY} AND description attributes a core act (exfiltrated/copied/stole/disseminated/uploaded/transferred/leaked/sent) to a **named human** directly (a capitalized name in subject position, "by &lt;Name&gt;", or the case subject) AND **no** account-token+copula (that is the sibling gate) AND no logon/session marker in the evidence | Cite a logon/RDP session artifact (4624/4625 type+source, 4778/4779) placing the person at the host during the act (`input_call_ids`), or downgrade to SUSPECTED |
| `interactive_injection_grounding` | `record_finding` | Tier ∈ {CONFIRMED, LIKELY} AND description credits a **named human** OR a host-local logon session ("from the X session", `SubjectLogonId`) with covert-account/persistence creation **in an interactive/console session** AND removable media is in evidence AND **either** no complete `misc.device_install_inventory` covers the window **or** the inventory **flagged** a keystroke-injector | An interactive session ≠ proof of human authorship — a BadUSB injects keystrokes indistinguishable from typing. Run **`misc.device_install_inventory`** over `setupapi.dev.log` (enumerate the complete device table — don't grep), covering the window; if it flags an injector, rule it out with evidence or downgrade to SUSPECTED |
| `exfil_channel_grounding` | `record_finding` | Tier ∈ {CONFIRMED, LIKELY} AND description asserts data left the host over a named channel (cloud/FTP/USB/email/web/C2) AND the evidence shows only presence/staging (sync folder, ADS, tool-execution), not a transfer artifact | Cite a TRANSFER artifact (FTP/transfer log, bytes sent/written, USN `$J` write/rename, removable-volume LNK/`MountedDevices`, mail attachment, SRUM/netflow egress); else downgrade to SUSPECTED |
| `attribution_required` | `record_finding` | Tier ∈ {CONFIRMED, LIKELY} AND description names a threat actor (G-number, APT-N, alias) AND no recent `attribution.attribute_actors` call | Call `attribution.attribute_actors` first |
| `pre_report_check_required` | `export_execution_log` | No recent `reason.pre_report_check` returning `READY_TO_REPORT: true` | Call `reason.pre_report_check()`; resolve `blocking_issues` first |
| `pre_report_check_required` / structural blocking issue | `reason.pre_report_check` → `export_execution_log` | A contested principal at MEDIUM+ likelihood, controller-question focus, or forced principal `candidate_pivots` entry was never dispositioned — no CONFIRMED/LIKELY finding establishes its controller with a session/identity marker (logon 4624/4625 + type/source, OneDrive/registry account binding, USB serials), no finding excludes it, and no finding explicitly parks it as controller-unknown/evidence-unavailable | Establish the controller (run the discriminators), exclude it with evidence, or record an explicit controller-unknown/evidence-unavailable disposition for every mandatory principal before Report |
| `negative_completeness` | `record_finding` | Tier=UNCONFIRMED AND description is an absence claim in a case-inverting category (logon/auth, identity, persistence, exfil) AND the trace did NOT search every source in the category manifest (e.g. a "no RDP/logon" claim that never parsed the **TerminalServices** channels, not just `Security.evtx`), OR a searched log's `coverage_window` does not span the claim's time window (a log silent about the window cannot ground a negative) | Search the missing sources (the TerminalServices channels live in the full `winevt\Logs\` on the mounted image, not the CyLR/triage set; for out-of-coverage windows pivot to VSS / carved EVTX), or record an explicit "<source> absent from evidence" finding, before concluding absence |

**Anti-reuse on `confidence_and_citation`:** one `reason.confidence_score`/`reason.cite_check` cannot satisfy the gate for two findings with the same description. The matched call's `call_id` must exceed the `call_id` of any prior finding entry with that normalized description — every finding gets a fresh check.

**`hypothesize_required` keywords:** `process`, `service`, `scheduled task`, `task `, `persist`, `c2`, `beacon`, `exfil`, `lateral`, `ghost`, `orphan`, `detached`, `null cmdline`, `unsigned`, `credential`, `implant`, `stager`. If it fires spuriously on a pure file-existence finding, satisfy with a thin `reason.hypothesize` and pass its `hypothesis_id`.

---

## Negative findings (UNCONFIRMED tier)

"We looked for X and found nothing" is real work. Record it:
```
misc.record_finding(
    description="No persistence via HKLM\\Run keys — searched all 4 Run/RunOnce hives via RECmd",
    confidence="UNCONFIRMED",
    source="ez.recmd",
    linked_call_id=<tool_call_id>,
)
```
The accuracy framework scores negative assertions in `ground_truth.json` against these UNCONFIRMED findings → `negative_coverage` metric.

**Completeness is enforced (`negative_completeness` gate).** A negative is valid only over the COMPLETE source set for its claim — absence from the subset you happened to search is not evidence of absence (the closed-world-over-open-world failure). For a case-inverting category (logon/auth, identity, persistence, exfil) `record_finding` refuses an UNCONFIRMED finding unless the trace searched **every** source in the category manifest AND a searched log's coverage window spans the claim's time window. Concretely: a "no RDP/logon", "controller unknown", or "local-console only" claim requires the **TerminalServices channels** (LocalSessionManager / RemoteConnectionManager Operational — on the **full `winevt\Logs\` of the mounted image, NOT the CyLR/triage set**), not just `Security.evtx`; and if `Security.evtx` coverage *starts after* the claim window, that silence is **not** a negative — pivot to TS logs / VSS / carved EVTX. Either search the missing sources or record an explicit "<source> absent from evidence" finding.

---

## Execution Trace Log

Call `misc.start_execution_log(case_id, output_path)` at the very start, before any other tool. Path: `./analysis/<case_id>_trace.json`.

**Live-monitoring cases use per-investigation traces.** Each
`/trudi-check-alerts` tick that finds alerts opens (or resumes) ONE
investigation, identified by an `INV-NNN` id, with its trace at
`<case>/analysis/<case>_<INV-NNN>_trace.json` (flat under
`analysis/` so the dashboard scan picks it up) and report at
`<case>/reports/<case>_<INV-NNN>.{json,md}`. All alerts drained in the
tick share that one trace; new alerts arriving while it's open get
folded in via `monitor.extend_investigation`. The case-wide trace at
`analysis/<case>_trace.json` records orchestration only. The
investigation stays open across subsequent ticks if response actions
are pending operator approval, so an `approve ACT-N` typed minutes
later still lands in the right trace via the `UserPromptSubmit` hook
(`trudi/claude/hooks/log_user_message.py`). **Do not call
`start_execution_log` manually during this workflow** —
`monitor.start_investigation` / `extend_investigation` /
`end_investigation` manage the trace path.

Returns `dashboard_url` (live trace dashboard). **Announce it to the operator in the first message**, e.g.:
> 📊 Live trace dashboard: http://127.0.0.1:8765/reports/dashboard.html?trace=../analysis/<CASE>_trace.json

URL is also printed to stderr and written to `./analysis/dashboard.url`. Suppress with `launch_dashboard=False`.

Add `_note="<narration>"` to **one** tool call per parallel batch — middleware logs it as `agent_message` before the tool runs. Pass the same text you write to the user. For opening narration before the first tool call, use `misc_record_agent_message` directly.

```
# Example: three parallel calls, one carries the narration
vol_vol_pstree(image=..., _note="Pre-plan reads complete. Starting memory analysis.")
vol_vol_netscan(image=...)
vol_vol_cmdline(image=...)
```

Call `misc.record_finding(description, confidence, source, linked_call_id)` per confirmed finding — do not batch. Set `linked_call_id` to the `_trudi_call_id` of the source tool. Every CONFIRMED finding must have one — primary traceability link for the audit log.

### `input_call_ids` is MANDATORY on every agent-facing record_* call

Every `misc.record_finding`, `misc.record_self_correction`, `dair.dair_assess`, and `reason.*` call MUST pass `input_call_ids=[<cid>, ...]` — the `_trudi_call_id` values of entries that informed this step. `lineage_required` refuses empty lists after the first 5 entries (genesis grace covers `start_execution_log`, pre-plan reads, first `reason.plan` / `dair_assess`). Fabricated or out-of-order ids → `unknown_cids` refusal.

This turns the trace into a self-describing causal DAG. The chain view, accuracy report, and `reason.synthesize` traverse real foreign keys instead of inferring lineage from substrings.

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
)
```

`linked_call_id` (1:1 primary) and `input_call_ids` (N:M lineage) are complementary — supply both.

### Finding capture (common compliance gap)

`misc.record_agent_message` is for **reasoning and direction**, not stating facts. When you write a paragraph that contains conclusions ("CONFIRMED…", "attacker did X", "CS Beacon on PID Y", "exfiltration to IP Z", persistence/lateral-movement/credential), accompany it with structured findings — either separate `misc.record_finding(...)` calls or atomically in the same `record_agent_message`:

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

Each finding goes through the same gates as `misc.record_finding` (recent `dair_call`; CONFIRMED requires non-zero `linked_call_id` + recent SUPPORTED `reason.evaluate_finding`). Per-finding gate failures come back in the response; the narration entry is still written either way.

`reason.pre_report_check` runs `reason.audit_findings`, which uses the reason model (not regex) to surface narrations that mention facts but lack structured `finding` entries. Address each warning before writing the report.

After `reason.synthesize`, call `reason.pre_report_check()`. If `ready_to_report=False`, resolve all `blocking_issues` first.

Then call `misc.export_execution_log(output_path)` with path `./reports/<case_id>_trace` (no extension — both `.json` and `.md` are written).

---

## Directive Binding

After every `reason.*` call, extract `directives` from the response before proceeding.

- **`priority_tools`** — call these next, in order, before any other tools.
- **`skip_tools`** — do not call these for the current finding. Globs apply (e.g. `plaso.*` skips all plaso).
- **`focus_pids`** — pass as filter to all subsequent `vol.*` calls.
- **`focus_paths`** — pass as filter to all subsequent `tsk.*` / `ez.*` calls.
- **`curiosity_budget`** — after the work order is complete, the number of read-only exploratory probes you may run of your own choosing (see the execution loop, step 3). Each is logged via `misc.record_curiosity_probe`; 0 ⇒ none.
- **`next_hypothesis_triggers`** — after each tool result, if any trigger condition is met, call `reason.hypothesize` before continuing.

Directives are binding. `dair_assess` is the primary source of `priority_tools` — run nothing outside that list *except* the read-only curiosity probes its `curiosity_budget` authorizes (execution loop, step 3). After each `reason.*`, merge its directives into the active DAIR work order: append `priority_tools` not already listed; union `skip_tools`, `focus_pids`, `focus_paths`. DAIR directives take precedence on conflicts.

### Hypothesis conclusion extraction (mandatory)
When `reason.hypothesize` returns a conclusion that names specific search patterns, artifact types, file paths, or operations in body text — extract those as concrete tool calls and add them to the DAIR work order, **even if `directives.priority_tools` is empty**. Empty `priority_tools` from hypothesize ≠ "no follow-up needed". Parse for:
- Named patterns ("search for X in PCAP", "grep for Y", "look for Z cookie")
- Named artifact categories ("webmail cookies", "compose/send traffic", "recipient address")
- Named tools/operations ("run ngrep", "filter port 80", "follow TCP stream")

Convert each to a concrete MCP call and queue. Never skip in-text recommendations because the directive block is empty.

### Truncated output follow-up (mandatory)
When any tool result has `truncated: true`, treat as **INCOMPLETE**. Before advancing phase or recording a negative finding:
1. Re-run with a narrower, more specific pattern
2. If the original pattern was broad (e.g. a bare `sid=`), split into targeted sub-queries (e.g. `Cookie: sid=`, `<provider>\.com.*Cookie`, a specific host/domain)
3. Only record a negative finding after a targeted retry returns empty — never after a broad truncated scan alone
