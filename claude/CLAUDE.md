# TRUDI Orchestrator

This file directs the coding agent running a TRUDI investigation — installed as
`~/.claude/CLAUDE.md` for Claude Code and as `AGENTS.md` for OpenCode.

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
- **Tool calls are made ONLY through the tool-calling interface.** NEVER write a tool invocation as text or inside a code block — written calls execute nothing. If you catch yourself describing a call (`net.ngrep_search(...)`, "run vol..."), STOP and execute it as a real tool call instead. A turn that ends with a plan instead of executed tool calls stalls the investigation: keep calling tools until the phase's work order is done.
- **Never manually edit TRUDI cache files** (`~/.cache/trudi/call_id.counter`, `~/.cache/trudi/session.json`, `~/.cache/trudi/hook_state.json`, `~/.cache/trudi/session_owner.json`). To reset cleanly: `python -m tools.trudi_reset --case-dir <case>` — acquires the fcntl lock and atomically clears all three cache files plus the trace (optional `.trace-backups/<ts>/` backup). Manual edits desync the counter from the trace and cause duplicate call_ids.

---

## Forensic Constraints

- **Hash verification** — `hash.verify_evidence_hash` once per evidence file per case; skip if already recorded this session.
- **No hallucinations** — never guess or fabricate artifacts, file contents, or system states.
- **Deterministic execution** — court-vetted CLI tools via MCP only; ground conclusions in raw tool output.
- **Evidence integrity** — never modify files in `/cases/`, `/mnt/`, `/media/`, or any `evidence/` directory.
- **Output routing** — all scripts, CSVs, JSON, reports go to `./analysis/`, `./exports/`, `./reports/`. Never `/` or evidence dirs. **`reports/` is written only by `misc.write_final_report`** (gated on `reason.pre_report_check` `ready_to_report=true`); raw `Write`/`Edit`/`MultiEdit` and Bash redirects / `tee` / `cp` into `reports/`, **`exports/` and `analysis/.tool_output/`** are refused at PreToolUse — those directories hold tool output only. **An agent-authored file is never evidence**: writing "verbatim excerpts" of a mailbox or CSV into a file and citing a `read.*` of it is refused by `record_finding` (gate `agent_authored_source`) and shown to the reviewer as `not evidence`; when the reviewer missed rows, issue/let it issue another `EVIDENCE_REQUEST` over the tool-produced file with better terms. Reasoning and notes go in the trace via `misc.record_agent_message` — the agent has NO raw-write capability to `analysis/`, `exports/` or `reports/` (all three hold tool output only; a raw write there is refused at PreToolUse).
- **Timestamps** — always UTC.
- **Verification** — check `success: true` after every run. On failure: read `stderr` → hypothesize → correct → retry.
- **Control-plane notices** — a tool result carrying `dair_notice` or `finding_notice` is an instruction: make the named call (exact shape included in the notice) before any further forensic tool calls. Ignoring it escalates to a refusal (`dair_engagement_gate`).
- **Background jobs** — carve-class tools (`net.tcpxtract_streams`, and other long carves) return a `job_id` immediately instead of blocking the turn. Poll `misc.job_status(job_id)` between other work — never sit idle on a running job; a timed-out carve still yields usable partials in its output dir. The finished `job_status` result carries the citable `_trudi_call_id` for findings from the carve.
- **MCP routing is mandatory.** Never invoke these binaries via Bash: `vol`, `dotnet …Cmd.dll`, `fls/icat/istat/blkls/mactime/tsk_recover`, `hexdump/xxd/exiftool`, `log2timeline.py/psort.py`, `yara`, `bulk_extractor/foremost/scalpel`, `ewfmount/vshadowmount/bdemount/xmount`, `tcpdump`, `clamscan`, `rip.pl`. `record_finding` refuses any finding whose `linked_call_id` points to a `source="claude_code_bash"` entry executing one of these (gate: `mcp_routing`). Use the MCP wrapper (`vol_*`, `ez_*`, `tsk_*`, `strings_*`, `plaso_*`, `yara_*`, `carve_*`, `ewf_*`, `net_*`, `misc_regripper_*`).

---

## Case-Question Anchoring

Every investigation has a case question (e.g. "who sent the harassing email?", "what was exfiltrated?"). It MUST:
1. Be **declared typed**: `reason.plan(case_question="<one-sentence question>")` and `dair_assess(case_question=...)` (prose `CASE_QUESTION:` markers in `case_context` are no longer read).
2. Be the `observation` of an **initial `reason.hypothesize(hypothesis_kind="case_question")` call**, run before `reason.plan` on first Triage entry. Returned hypotheses are the testable propositions for the investigation — capture each `hypothesis_id` and route findings back via `tested_hypothesis_id`.
3. Be **answered by a typed finding**: the CONFIRMED/LIKELY finding that answers it passes `answers_case_question=True`. `reason.pre_report_check` refuses `ready_to_report` until one exists (wording is not matched).

For pivot-host Triage entries, pass the case question to the pivot's `dair_assess(case_question=...)` so the gate still fires.

---

## Distinct-Principal & Competing-Hypothesis Discipline (mandatory)

The most expensive investigative failure is **single-actor lock-in**: committing to one working narrative at Triage and folding every later artifact onto it — never asking whether a *second* principal is present. Guard against it:

1. **Competing hypotheses at Triage.** The initial `reason.hypothesize` on the case question MUST yield at least one hypothesis that is *not* the leading narrative — a genuinely different actor or mechanism, not an adversarial-defense strawman ("the suspect could claim account takeover"). Treat it as a live proposition and seek evidence that would confirm or kill it. Declare it: `reason.hypothesize(hypothesis_kind="distinct_principal", contested_principals=["<account>", ...])`. **Every principal you type in `contested_principals` is individually tracked** and must be driven to **CONFIRMED or REFUTED** before Report; a principal only the reviewer listed (`RESULT.hypotheses[].principals`) is mandatory when it is a forced DAIR candidate or matches the case roster (`misc.knowns_pattern_generate`), otherwise it is carried as report inventory with a warning — its controller established by a CONFIRMED/LIKELY finding with `principal=` + `session_binding_call_ids=`, or the alternative refuted by a finding with `tested_hypothesis_id=` + `resolves="refuted"` or `misc.record_disposition(target_kind="principal", target_id=<account>, reason="refuted"|"excluded", evidence_call_ids=[...])`. When the contested identity turns out to be the **same person/account as the prime subject** (an alias, the registered-owner string, the account they use), say so honestly with `reason="same_as"` (+ `evidence_call_ids`) — never a backwards `refuted`. A *parked* (`controller_unknown`) or *absorbed* alternative does not count for confirmation — with one grounded exception: `reason="evidence_unavailable"` is accepted as a **report caveat (warning, not blocker)** when a typed `source` disposition records that the logon/session sources are absent from the evidence (e.g. XP with auditing off, no Security/TerminalServices logs) — the report must then state that the binding rests on documentary artifacts, not a session. Role placeholders (`unknown`, `attacker`, `external actor`) are never contested principals. `reason.pre_report_check` blocks the report while a mandatory principal remains undispositioned. **Prose never counts** — "refuted"/"ruled out"/"controller unknown" in a description is not read. Pursuing only the highest-likelihood hypothesis and folding everything onto it is the single-actor lock-in this guards against.
2. **A new account/identity is a separate principal until proven otherwise.** Whenever a **newly-created or previously-unseen** account, SID, login, or identity surfaces in **any** phase — especially a privileged one, one created via removable media, or one with no preceding interactive session by a known user — you MUST:
   - run `reason.hypothesize` framing it as a *separate principal* ("who controls account X, and how did they authenticate?"), and
   - establish its controller from an **authentication/session artifact** (logon event by type + source address) **before** attributing any of its actions to anyone already in the case.
   DAIR surfaces this structurally through `candidate_pivots`, from what YOU declare: `dair_assess(observed_principals=[{"name": "<account>", "cue": "created"|"interactive_logon"|"network_logon"|"correspondent"|"other", "call_ids": [<cid>]}])`. A `created` / `interactive_logon` cue on a previously-unseen principal is a **forced** candidate (DAIR does not read principals out of your summary prose, and it does not mutate the phase stack because a candidate exists). Treat forced principal candidates as mandatory leads: bind them with a session artifact (a CONFIRMED/LIKELY finding with `principal=`, `actor_kind="human"`, `session_binding_call_ids=[...]`), exclude them with evidence (`misc.record_disposition(target_kind="principal", target_id=..., reason="excluded"|"not_a_principal", evidence_call_ids=[...])`), or park them (`reason="controller_unknown"|"evidence_unavailable"`). `record_finding` enforces attribution grounding too — `principal_attribution_grounding` (a `principal` bound to a human) **and** `named_actor_attribution_grounding` (`actor_kind="human"` on a core act). `reason.pre_report_check` **blocks** Report while a `distinct_principal` hypothesis is unresolved or a forced surfaced identity is un-dispositioned. Do not attribute an account's actions by assumption.
3. **Re-hypothesize on divergence.** When an artifact contradicts the working hypothesis (an account created at a moment the prime subject was not active; a logon from an unexpected source; a second exfil path), re-run `reason.hypothesize` rather than absorbing the anomaly into the existing story.
4. **Physical-media initial access (mandatory when a covert account / persistence + removable media coincide).** When a covert/backdoor account or persistence is **created in an interactive/console session** AND removable media is in evidence, do **not** read "interactive session" as proof of human authorship — a **BadUSB** device injects keystrokes that are indistinguishable from typing at the logon-event level. Raise a `reason.hypothesize` framing **initial access via a physical device** ("did the in-person contact hand over a device that injected this activity?"), and run **`misc.device_install_inventory`** on `setupapi.dev.log` — it enumerates the **complete** device table and flags the structural keystroke-injector profile (a device exposing both HID/keyboard and mass-storage interfaces). **Enumerate, don't grep**: a keyword/windowed search over a bounded device-install log can silently miss a device; the structured inventory surfaces every device as a row you cannot miss. `USBSTOR`/mass-storage enumeration alone **cannot** reveal a keystroke-injection device. `record_finding`'s `interactive_injection_grounding` gate (trigger: `session_type="interactive"` + `act="account_creation"|"persistence_install"`) refuses the "X created it interactively" finding unless the inventory ran over `window=` with nothing flagged — and, if it flagged an injector, until the device is ruled out with evidence: `rule_outs=[{"what": "injector", "call_ids": [...]}]` or `misc.record_disposition(target_kind="device", target_id="<VID:PID>", reason="ruled_out", evidence_call_ids=[...], window={...})`.

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

**Reading parsed output — use `read.*`, not Bash.** After an extractor writes its output (an EZ `--csv`, `misc.readpst_extract`/`pff_export` mail dir, `misc.chat_db_export` CSVs, a plaso/chainsaw/capa file), read that output with **`read.read_output`** (CSV/JSON/TXT — supports `query`, `columns`, `where`) and **`read.read_mail`** (extracted mbox/.eml — `field=sender|recipient|subject|body`, returns message BODIES), **not** `cat`/`jq`/`grep`/`python` in Bash. Bash reads are `source="claude_code_bash"` with no `_trudi_call_id`, so a finding cannot cite them and the reviewer cannot re-verify them — a finding grounded only in a Bash read is uncitable and will not hold; **bash reads of produced output are now refused at PreToolUse** (guard_pretooluse). The `read.*` tools are traced and return a `_trudi_call_id` to pass as `linked_call_id`/`input_call_ids`. In particular, a **recipient / dissemination** claim (who received the data; whether X was the recipient) MUST cite `read.read_mail` message bodies (To/Cc + body) — and the chat stores via `misc.chat_db_export` — never a mail-extraction or `strings` call alone; a subject-line-only read cannot establish or exclude a recipient.

**Authentication-Session Inventory before attribution (mandatory).** Whenever event logs are in scope and any persistence / lateral-movement / account-creation finding is in play, enumerate logon events **by type and source** (which account, logon type 2/3/10, source network address) *before* attributing the account's actions to a person. An account name is not a person — the binding requires a session artifact. `record_finding`'s `principal_attribution_grounding` gate refuses CONFIRMED/LIKELY account→person bindings (`principal=` + `actor_kind="human"`) that lack `session_binding_call_ids=[...]` pointing at a logon/session artifact call (`ez.evtxecmd` / `misc.evtx_filter` on 4624/4625/4778/4779, `net.pcap_identity_timeline`, `net.http_session_inventory`, `live.live_recent_logins` — these stamp the `session_artifact` marker); its sibling `named_actor_attribution_grounding` extends the same requirement to `actor_kind="human"` on a core act. This inventory is now **blocking at `reason.pre_report_check`** whenever a human/account attribution verdict is present — run it before stating who acted. Enumerate logon sessions from the **full event-log set on the mounted image** — Security 4624/4625 **and the TerminalServices channels** (LocalSessionManager / RemoteConnectionManager Operational, which record RDP type-10 logons with user + source IP and are **absent from CyLR/triage collections**) — never from the triage subset alone; a `Security.evtx` coverage gap forces a pivot to those channels / VSS / carving, never a "local-console only" conclusion (`record_finding`'s `negative_completeness` gate refuses a "no logon/RDP" negative that skipped them).

---

## Reformulation Depth Limit (server-enforced)

`reason.evaluate_finding` is rate-limited per finding — matched by its **typed claim** (`claim_kind|category|act` + overlapping `entities`/`principal`), falling back to the normalized description. If the same claim has been evaluated 2 times recently with no new tool calls between attempts, the third is refused with gate `reformulation_depth_limit` — re-wording the description does not reset the count. Remediation:
1. Run new tool calls for fresh evidence before re-evaluating, OR
2. Park as UNCONFIRMED (note the reformulation loop) and pursue a different finding direction.

Intent: prevent rumination spirals where the agent defends a finding via wording changes instead of better evidence.

---

## Attack-Lifecycle Coverage (the investigation's goals)

A forensic investigation must try to establish — or rule out — the five phases of the cyber attack lifecycle; these are the goals that should drive collection and analysis:

1. **Persistence** — scheduled tasks (`\System32\Tasks`, TaskScheduler 106/200/201), Run/RunOnce keys, services (7045), Startup folder, WMI subscriptions.
2. **Privilege Escalation** — 4672 special privileges, 4728/4732 privileged-group additions, process masquerading (unusual parent), UAC/token elevation.
3. **Lateral Movement** — 4624/4625 by logon type (network 3 / RDP 10), PsExec (4697/7045 PSEXESVC), WinRM/PS-remoting (4104), TerminalServices 21/22/25, share access (5140).
4. **Evidence of Execution** — Prefetch, Shimcache, Amcache, UserAssist, SRUM.
5. **Exfiltration** — netflow/proxy/PCAP, archiver/cloud-sync tools (7-Zip/WinRAR/Rclone), DNS tunnelling, browser upload history, USB history, FTP/transfer logs.

`reason.pre_report_check` computes per-phase coverage from the trace (`tools/_gates/_lifecycle.py`) and **warns** (never blocks) on any phase whose artifact sources were never examined; `misc.write_final_report` renders an **Attack-lifecycle coverage** table. A phase is covered by establishing it (a positive finding in its category/act — including the new `category=privilege_escalation`), ruling it out with a grounded negative, or examining its sources. Symmetric: proving a phase absent counts as much as finding it; a phase left unexamined is a blind spot, not a clean bill.

---

## Exhaustive Evidence Rule

### Never stop at the first artifact of a type
When a category can contain identity, attribution, persistence, or C2 evidence, collect ALL instances from available evidence before concluding. One example ≠ complete picture.

- **PCAP**: one HTTP cookie ≠ all cookies — extract `Cookie:` across ALL port-80 flows from the suspect device; also URL/webmail auth params (`login=`, `email=`, `user=`, `sid=`, `auth=`, and provider-specific session params); run `net.tcpdump_extract_http` + `net.tcpxtract_streams` on the device-filtered PCAP.
- **Disk**: one Run key ≠ all persistence (run all 4 Run/RunOnce hives); one browser profile ≠ all creds (check all profiles for all browsers).
- **Per-principal (every SID, including covert)**: one user's profile ≠ all the evidence. Enumerate the deleted items (**per-SID `$Recycle.Bin`**), Desktop/Downloads, staging dirs, and execution artifacts (Prefetch/UserAssist) of **every** user account on the host — including newly-created and covert accounts — not just the prime subject's. The exfiltrated archive or a second actor's loot may sit in any SID's Recycle Bin / Desktop — the prime subject's or another's — so enumerate every SID's before concluding where it is.
- **Memory**: run both `vol.malfind` AND `vol.hollowprocesses`; both `vol.netscan` AND `vol.netstat`.
- **Event logs**: enumerate the **full `winevt\Logs\` from the mounted image** — not just a CyLR/triage subset — including the **TerminalServices channels** (LocalSessionManager / RemoteConnectionManager Operational) that record RDP type-10 sessions with user + source IP. Check for log-clearing AND for **coverage gaps**: a log whose earliest event postdates the incident window is *silent*, not negative — pivot to VSS / carved EVTX. A "no RDP/logon" negative drawn over only `Security.evtx` is refused by `negative_completeness`.
- **USB / removable media — two forensic roles**: enumerate USB as **egress** (USBSTOR / MountedDevices / LNK volume labels) AND as **ingress / initial-access** (the `setupapi.dev.log` device-install log → HID/composite **BadUSB** devices that inject keystrokes or autorun). For ingress, run **`misc.device_install_inventory`** on `setupapi.dev.log` — it enumerates the complete device table (one de-duplicated row per device: class, vendor, product, VID:PID, interfaces, first/last seen) and flags the structural keystroke-injector profile (a device exposing both HID/keyboard and mass-storage). **ENUMERATE, don't `strings | grep`**: a keyword/windowed search over a bounded log can silently miss a device, and `USBSTOR`/mass-storage enumeration alone reads a self-naming mass-storage device as ordinary storage. Run **both** lenses whenever removable media is in evidence — `interactive_injection_grounding` and `negative_completeness` (DEVICE_INITIAL_ACCESS) require the structured inventory (coverage spanning the window, nothing flagged) before an "X did it interactively" finding or a "no BadUSB" negative; a keyword grep no longer satisfies them.

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
"Who received the data / who is the buyer" must be answered from a **full sender/recipient inventory** of the comms stores (mail OSTs/PSTs **and** chat DBs) — `misc.readpst_extract` / `misc.pff_export` for mail, `misc.chat_db_export` for Skype/WhatsApp sqlite (messages + the Transfers file-transfer trail) — then enumerate senders and recipients (`read.read_mail`, `read.read_output`), **cross-referenced against the case roster**, before concluding the recipient. Enumerate every correspondent in the parsed store against the roster before concluding a recipient — do not surface an incidental/noise thread as the recipient while a named or plainly-addressed contact remains unchecked; a named contact may be addressing the subject directly, or the store may contain no such contact, neither assumed. Declare the recipient typed (`recipients=[...]`, `act="delivery"|"possession"`, `receipt_call_ids=[...]`); `reason.pre_report_check` blocks while an **engaged or roster-matched** correspondent (one the subject WROTE TO, a chat participant, or a match against the `misc.knowns_pattern_generate` roster — inbound-only senders, however many messages, go to the report inventory, never blocking) is referenced by no finding's `entities`/`recipients` and no `misc.record_disposition(target_kind="correspondent", ...)`; every other registry identity is rendered into the report's **Evidence registry inventory** by `write_final_report` — shown, never a blocker, never a disposition. Run `misc.knowns_pattern_generate` on the case roster early: it is the relevance model.

### Exfil-Channel Enumeration & Ranking (mandatory before the verdict)
Before stating *how* data left the host, enumerate **all** candidate channels — removable media (LNK/`MountedDevices`/USN), FTP/transfer logs, cloud-client DBs, email attachments, web upload, C2/messenger — and **rank them by evidence strength**. A channel claim requires a **transfer artifact** (bytes moved), not tool/folder presence: a file in a sync folder, a cloud-client ADS, or "the tool was installed" is **staging, not egress**. Never headline a channel in the verdict that is weaker-evidenced than a competing one. `record_finding`'s `exfil_channel_grounding` gate refuses a CONFIRMED/LIKELY `act="egress"` claim whose `transfer_call_ids=[...]` do not name a transfer artifact call; `reason.pre_report_check` warns when multiple `channel`s appear un-ranked and blocks when a declared channel's source set was never examined (or settled with `misc.record_disposition(target_kind="source", ...)`).

---

## TRUDI MCP Tool Namespaces

All forensic execution goes through MCP tools.

| Namespace | Domain | Key Tools |
|-----------|--------|-----------|
| `img.*` | Disk image mounting | ewfmount, vshadowmount, bdemount, xmount, photorec, losetup |
| `vol.*` | Memory (Volatility 3) | **`vol_symbol_check` first on any new image**, then pstree, pslist, psscan, cmdline, netstat, dlllist, malfind, hivelist, dumpfiles, linux plugins |
| `tsk.*` | Filesystem (Sleuth Kit) | fls, icat, istat, ils, blkls, mactime, tsk_recover, sigfind, sorter, jls, jcat, **indxparse** ($INDX slack) |
| `ewf.*` | E01 images | ewfmount, ewfinfo, ewfverify, mount_full_image |
| `ez.*` | Windows artifacts (EZ Tools) | MFTECmd, EvtxECmd, RECmd (**`ez_recmd_batch` runs per hive file by default — `-d <Users tree>` ran to the 1800 s timeout; one citable call per NTUSER/UsrClass/SAM/SYSTEM/SOFTWARE hive**), AmcacheParser, AppCompatCacheParser, PECmd, JLECmd, LECmd, SBECmd, WxTCmd, SQLECmd, RBCmd |
| `plaso.*` | Super-timeline | log2timeline, psort (CSV/JSON/filter), pinfo |
| `yara.*` | Threat hunting | scan_file/_directory/_memory_image, scan_strings, compile_rules — built-in rules at `~/trudi/rules/` |
| `hash.*` | Integrity / similarity | hash_file (cached), **hash_directory (bounded: `max_files`/`max_bytes`/`max_seconds`/`skip_larger_than_mb`; returns a PARTIAL manifest with `truncated=True` + `next_start_path` — resume with `start_after=`; never point it at a whole profile/AppData tree in one call)**, ssdeep, hashdeep, verify_evidence_hash |
| `strings.*` | Static analysis | strings, hexdump, xxd, file, exiftool, stat, **floss_extract** (obfuscated strings) |
| `carve.*` | File carving | bulk_extractor, foremost, scalpel |
| `net.*` | Network analysis | tcpdump_read, tcpdump_extract_http/dns, ngrep_search, tcpxtract_streams |
| `enrich.*` | Threat intel | virustotal_hash/ip/domain, abuseipdb_check (graceful-degrade without keys) |
| `misc.*` | Windows artifacts + email + macros | evtx_dump, regripper, usn_journal, analyzeMFT, Hindsight, ClamAV, PDF/PE, **pff_export**, **readpst_extract**, **densityscout_scan**, **chainsaw_hunt** (Sigma), **capa_analyze** (caps→ATT&CK), **olevba_scan**/**mraptor_scan**, **device_install_inventory** (complete USB/BadUSB device table from setupapi.dev.log), **chat_db_export** (Skype/WhatsApp sqlite → messages/transfers/participants CSVs, strict read-only), **batch_run** |
| `read.*` | Produced-output reads (traced + citable) | **read_output** (CSV/JSON/TXT under analysis / exports / reports — query, columns, where), **read_mail** (extracted mbox/.eml — message BODIES, sender/recipient roster). Use these instead of bash `python`/`jq`/`cat`/`mailbox` — bash reads are untraced/uncitable and now refused at PreToolUse |
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

## Live monitoring & gated response (live-monitoring cases only)

Velociraptor-backed live-monitoring cases (`monitor.*` / `respond.*`) use a
per-investigation trace, auto-protect containment (reversible+low-risk actions
auto-execute; destructive actions need an operator-typed `approve ACT-N`), and
a server-classified auto/approval boundary. Static forensic investigations never
use this subsystem. **Full detail: `docs/live-monitoring.md`.**

**Not available:** MemProcFS, VSCMount (Windows-only), tshark, hayabusa, guymager.

**Volatility exit codes:** `1` = plugin ran but failed (may be normal — e.g. no data). `2` = argument error (TRUDI bug). `-1` (timeout) = symbols not cached — run `vol_symbol_check`.

---

## DAIR Phase Director (dair.*)

DAIR is a **recursive state machine**, not a checklist. Outside the gated
live-monitoring `respond.*` namespace, TRUDI is read-only: static-case Improve
& Response actions are never executed — only recommended in the final report.
Investigation begins with a confirmed positive detection in hand.

| Phase | Role | reason.* | Recursive? |
|-------|------|-----------|------------|
| Triage | Confirm initial IOCs, challenge hallucinations (file existence, registry keys, processes, network). Produce plan. | `reason.plan` at phase entry | Yes — new questions can be entered when relevant |
| Collect | Gather raw artifacts per plan — ez.*, vol.*, tsk.*, strings.* | `reason.plan` directives prioritize | No — advance when plan satisfied |
| Analyze | Reason about artifacts — processes, network, persistence, TTPs | `reason.hypothesize` per suspicious artifact | Yes — unexpected finding can push Triage |
| Scan | **Scoping** — pursue each new IOC to depth, in TWO senses: (i) other hosts / network propagation (yara.*, net.*, enrich.*) AND (ii) DEEPER investigation of the SAME host driven by a newly-discovered IOC (a covert account's $Recycle.Bin/Desktop/LNKs/autoruns, a flagged injector-payload task's payload + author, an unexpected inbound logon source). A new IOC is followed, not ticked and passed. | — | Candidate pivots + flagged IOCs are scoping leads; each driven to a finding or typed disposition before Report (open ones surface as a pre_report warning) |
| Report | Synthesize timeline; emit Improve & Response recs | `reason.synthesize` + `reason.pre_report_check` | Yes — blockers return to Collect/Analyze/Scan |

**Loop anatomy:** DAIR is recursive, not linear. Any phase can discover a missing question or evidence gap; when that gap is material to the case question, return to Triage/Collect/Analyze/Scan, collect the missing evidence, then re-synthesize. Report is not a wording exercise: if `reason.synthesize` or `reason.pre_report_check` reports blockers, go back to evidence work before trying to report again.

**Candidate pivot handling (typed).** When top-of-stack is `Scan`/`Analyze`/`Collect`, DECLARE what the batch surfaced — `dair_assess(observed_hosts=["10.0.4.6", "\\\\HOST\\share", "wkstn-15"], observed_principals=[{"name": "svc_x", "cue": "created", "call_ids": [<cid>]}])` — and `dair_assess` diffs them against what the trace already knows (prior declarations, findings' `principal`/`entities`, the identity registry) and returns the new ones in `candidate_pivots` with `{kind, value, phase, cue, call_ids}`. Nothing is read out of `tool_results_summary` prose. Candidate pivots are leads, not control flow. Do not mutate `phase_stack` or start a Triage solely because a candidate exists. Investigate a candidate when it is relevant to the case question, and record either a finding or a typed disposition (`misc.record_disposition(target_kind="host"|"principal", ...)`).
- **Host** — IPv4, UNC `\\\\HOST\\share`, or a hostname (validated by shape; malformed values come back in `typed_input_errors`).
- **Principal** — cue `created` or `interactive_logon` ⇒ **forced** (must be dispositioned before Report); `network_logon` / `correspondent` / `other` ⇒ appearance. Built-in accounts (`Administrator`/`Guest`/`SYSTEM`/…) and already-known principals do not re-pivot. This is the structural backstop for the Distinct-Principal Discipline above.

**Report is refused server-side while the trace holds zero findings** (`server_override: report_refused_zero_findings`, `misc.record_finding` put at the head of the work order) — record findings from a collection phase, then re-assess. **Report is also refused until the full DAIR cycle has run** (`server_override: report_refused_phase_coverage`): the trace's own dair history must show Collect AND Analyze were entered (Scan too when host candidate pivots exist) — a Triage→Report shortcut skips the systematic enumeration the phases exist for, and `reason.pre_report_check` blocks on the same trace-derived computation.

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

**Triage max-pass cap:** Track consecutive `dair_assess` responses of `phase=Triage, stack_action=stay` (reset on `transition_recommended=True` or `verification_satisfied=True`). At count 3 the cap MAY fire — **only if the third response carries no `verification_challenges` with `verified: null`**. A challenge whose `challenge_method` **already ran successfully** anywhere in the trace is verified server-side by that run (`verified: true`, `verified_basis="prior_run"`, `verified_by_call_id`) — do not waive such challenges. While a concrete challenge is open you must run its `challenge_method` tool (it is in `priority_tools`) — or settle it typed: `misc.record_disposition(target_kind="tool", target_id="<method>", reason="inapplicable"|"absent_from_evidence")` (prose "inapplicable" is not read) — and call `dair_assess` again; the cap is never a way past a verification the backend asked for. Server-enforced: `misc.record_self_correction(trigger="dair_max_pass_cap")` is refused (gate `max_pass_cap`) while an open challenge exists, and `reason.pre_report_check` **blocks** on any challenge that was never run. When the cap legitimately fires:
- Log: "DAIR Triage max-pass cap (3) reached — forcing transition to Collect" via `record_self_correction(trigger="dair_max_pass_cap")`
- Push `{phase: "Collect", entry_reason: "max-pass cap", depth: N}` manually
- Skip `dair_assess` for the **very next batch only**. Resume normally after.

---

## Adversarial Review (reason.*)

The adversarial reviewer runs on a local or Claude reasoning model. Calls below are **mandatory** at the named checkpoints.

### Mandatory triggers

**`reason.hypothesize` on the case question** — at the very start of initial Triage, BEFORE `reason.plan`. Pass `observation`=case question, `evidence`=evidence summary, `context`=full case context. Returned hypotheses are the testable propositions; capture each `hypothesis_id`, route findings via `tested_hypothesis_id`. Run again per material pivot question. Its `priority_tools` carry the **discriminators resolving the top two competing hypotheses** (logon type/source, USB serials across profiles, OneDrive/registry account bindings) — execute them as the binding work order. **Every** MEDIUM+ contested principal must reach CONFIRMED/REFUTED/SAME-AS or be parked controller-unknown/evidence-unavailable before Report — not just the leading one.

**The tier is arithmetic, not an opinion (Phase J).** `record_finding` computes `tier_achievable` from the **artifact classes** the cited calls carry (`data/fk/tiering.yaml`: per act, and per channel for egress; two classes from the SAME tool run count once). Asking above it is refused by gate `tier_contract` with `tier_path` naming the exact missing classes and the tools that produce them (e.g. "CONFIRMED for act=execution needs 1 more of execution_primary: Prefetch [ez.pecmd], Amcache [ez.amcacheparser]"). Collect and cite those tools, or record at the reachable tier with the gap documented — the tier must match the evidence in both directions; asking lower is accepted with a symmetric `tier_headroom` note. `reason.confidence_score(act=, channel=, input_call_ids=[...])` is a deterministic preview of the same lookup. `reason.evaluate_finding` is a **fact-checker only**: SUPPORTED (stated facts are in the cited rows) / CONTRADICTED (a row contradicts a fact — sticky CHALLENGED) / UNVERIFIABLE (deciding rows not visible — UNCERTAIN); it is told the server-computed tier (`TIER CONTRACT`), does not judge it, and `intended_tier` is ignored. Cite the **extractor run** (the `ez.*`/`misc.*` call that wrote the CSV), not only a `read.read_output` subset — the reviewer fetches columns from what you cite, and a `read.*` inherits the extractor's artifact class.

**`reason.plan`** — at the start of every Triage entry (initial + each pivot). Before the **initial** call, run this parallel batch — **MCP wrappers only** (all in `DAIR_GATE_ALLOWLIST`, seconds each):
- `ez_ez_recmd_hive` on SOFTWARE / SYSTEM / SAM — OS+install / ComputerName+timezone+services / local users+last login
- `vol_vol_symbol_check`; `strings_stat_file` on the memory image; `hash_verify_evidence_hash` on each evidence file (once per file per case)

**Do NOT shell out to `dotnet …RECmd.dll` or `/usr/local/bin/vol`** — `source="claude_code_bash"` entries fail the cold-start gate (`protocol_violation: no_active_dair_batch`) and any finding citing them refuses via `mcp_routing`. Skip `ewf_info`/`mmls`/`fsstat`/`vol_info` (slow, uninformative). Pass combined output as `evidence_available`. For pivot Triage entries use whatever artifacts exist (skip the pre-plan reads if the image isn't mounted). `reason.plan` directives inform Collect ordering — re-call mid-Collect if findings change the picture.

**`reason.hypothesize`** — during Analyze and whenever any arise in **any phase**: process with orphaned/ghost parent PID; unsigned/unknown executable on disk or in memory; network connection to an internal host that isn't a DC or known infra; scheduled task / service / Run key not present before the incident window.

**`reason.evaluate_finding`** — before writing any of: "CONFIRMED COMPROMISE"/"attacker"; any TTP / threat-actor attribution; "exfiltration"/"lateral movement"/"persistence confirmed"; any negative used as evidence ("no injection detected"). `supporting_evidence` must include the specific tool output (command + field + value) and the tier.

**Reviewer evidence access (push-then-pull).** The reviewer sees an **EVIDENCE INVENTORY** of the cited calls with the rows matching the claim's terms **pushed** in round 1 ("showing K of M matching; N scanned; source COMPLETE|PARTIAL" — a selection with its totals), and pulls more via `EVIDENCE_REQUEST` (resolved from the cited call_ids only, ≤3 rounds, each logged as `reason_evidence_fetch`). Therefore:
1. **Cite the calls whose OUTPUT FILES hold the discriminating rows** (`input_call_ids`) — rows are pushed/fetched only from what you cite; cite the extractor run, not a summary. Complete stdout is persisted (`analysis/.tool_output/<cid>.txt`, `stdout_path`) so stdout-only tools are pushed in full; a legacy 600-char-excerpt entry is labelled **PARTIAL** and a miss over it is not absence (challenge stamped `verdict_basis="partial_source"`, does not stick — re-run the tool).
2. **Declare `entities`/`principal` on the evaluate** — the finding's nouns are the push terms; round-1 coverage is stamped `evidence_pushed`.
3. **LIKELY needs a SUPPORTED evaluate too** (gate `confirmed_requires_supported_evaluate`, covers CONFIRMED+LIKELY). Pass the SAME typed claim (`claim_kind=, category=, act=, entities=, principal=, channel=`) you will record — matched by claim key + entities; a mismatch is refused (`claim_mismatch`).
4. **CHALLENGED/UNCERTAIN is sticky** (gate `challenge_sticky`, keyed by claim — re-wording does not shed it): CONFIRMED/LIKELY refused until a NEW evidence tool call runs AND a later evaluate returns SUPPORTED. SUSPECTED is the honest downgrade; the refusal lists the discriminators to collect.
5. **Refusals are ledgered** (`finding_refused`); re-recording the same claim key + entities with no new evidence tool call since is refused (`refusal_rewording`).
6. **Reviewer answers carry a `RESULT` JSON block** (verdict/blockers/hypotheses/directives), parsed first; each reason/dair entry records `parse_path`.

**Automatic CHALLENGED triggers** — flag without waiting: YARA match is the sole evidence for a CONFIRMED finding; an ATT&CK id can't be verified against the description; a mechanism claim has no cited raw artifact.

**`reason.synthesize`** — Report phase only (callable when DAIR returns `next_phase: "Report"` with `stack_action` push or pop; refused earlier). Pass your narrative as `findings`; the server appends the **RECORDED FINDINGS** block (typed tiers, claim keys, cids) which the reviewer judges — wording cannot over/under-state a recorded tier. Tier-only objections are demoted to `under_tiered`/`tier_blockers_demoted` advisories, never blockers. **Depth limit:** a third synthesize with no new evidence tool call since the previous is refused (gate `synthesize_depth_limit`). After round 2 without new evidence, `reason.pre_report_check` carries remaining synthesize blockers as warnings (`synthesize_blockers_unresolved`) and `misc.write_final_report` appends them under "Reviewer limitations"; structural checks (principals, sources, challenges, blocked tools) stay blocking. If a blocker names collectable evidence, collect it and synthesize again — do not re-word.

**`reason.confidence_score`** — BEFORE `record_finding` for any tier above SUSPECTED. Deterministic tier + 0.0–1.0 score; if below intended, downgrade.

**`reason.cite_check`** — BEFORE `record_finding` when the finding has concrete claims (paths, IPs, hashes, technique IDs). ALL_CITED / UNCITED_CLAIMS_PRESENT / INSUFFICIENT_EVIDENCE — resolve UNCITED by adding citations.

**`reason.pre_report_check`** — immediately after `reason.synthesize`, before writing any report section. If `ready_to_report=False`, resolve all `blocking_issues` first (evidence or typed dispositions, never wording). Keyed on declared claims / typed dispositions / server-stamped registries, it **blocks** when: a `distinct_principal` hypothesis or a contested principal is unresolved; a human/account verdict (`actor_kind="human"|"account"`) exists with no logon/RDP session inventory (4624/4625/4778/4779, or Linux `last`/`wtmp`) anywhere in the trace; a forced principal candidate is un-dispositioned; an `act="account_creation"` principal has no controller; a `RESULT.blockers` item is open; a verification challenge never ran; a declared recipient leaves observed correspondents unreferenced; a declared egress channel's sources were never examined; a blocked tool was never re-run or dispositioned. **Run the logon/RDP session inventory early** (first Collect batch when event logs are in scope). The result is stamped typed (`ready_to_report`, `blocking_issues`); `misc.export_execution_log` / `misc.write_final_report` read that boolean. If the server is unreachable, log + note skipped checkpoints + continue.

### reason.* Parameter Reference

| Tool | Required | Optional (typed) |
|------|----------|----------|
| `reason.plan` | `case_description`, `evidence_available` | `case_question` |
| `reason.hypothesize` | `observation` | `evidence`, `context`, `mode`, `hypothesis_kind` (`case_question`\|`distinct_principal`\|`mechanism`\|`coverage_gap`\|`other`), `contested_principals=[...]` |
| `reason.evaluate_finding` | `finding`, `supporting_evidence` | `case_context`, `claim_kind`, `category`, `act`, `entities`, `principal`, `channel`, `actor_kind`, `actor` (the SAME claim you will record); verdict is a fact-check only — SUPPORTED / CONTRADICTED / UNVERIFIABLE |
| `reason.confidence_score` | `finding`, `supporting_evidence`, `input_call_ids`, `act` (+ `channel`) | `intended_tier` (returns `downgrade_reasons` + `tier_path` when the cited classes fall short) — deterministic, no model call |
| `reason.cite_check` | `finding`, `supporting_evidence` | claim kwargs as above |
| `reason.synthesize` | `findings` | `investigation_summary` |
| `reason.pre_report_check` | *(none)* | — |

**`reason.hypothesize` usage:** `observation` = single behaviour/artifact (one sentence); `evidence` = raw artifact list (tool excerpts, IDs, timestamps, verbatim); `context` = broader case context (OS, known TTPs, timeline). Capture the returned `hypothesis_id` (e.g. `H0007`) → pass as `tested_hypothesis_id` to any `record_finding` resolving it (builds hypothesis→finding lineage in `trace.md`).

---

## Cross-tool correlation (`correlate.*`)

- `correlate.process_to_file(pid=…, path_substring=…)` — join vol process listings to MFT/fls records
- `correlate.network_to_process(ip=…, port=…)` — join vol.netscan/netstat to vol.pslist by PID
- `correlate.mitre_map(finding_text=…, top_n=…)` — rank candidate ATT&CK IDs by keyword score
- `correlate.mitre_validate(technique_id=…)` — confirm a technique ID exists

Any ATT&CK ID (`T\d{4}(\.\d{3})?`) in a finding description is **auto-validated** by `record_finding` (gate: `mitre_technique_validation`). Unknown IDs refuse with the offending strings — unless the local table is incomplete (< 600 techniques), in which case the id is recorded on the finding as `unvalidated` (`reason=table_incomplete`) and the record proceeds; rebuild the table with `python -m tools.mitre.build_mitre_cache`. Manual `correlate.mitre_validate` is still useful for pre-finding scouting; use `correlate.mitre_map` to find candidates for a behaviour you don't yet have a T-ID for.

---

## Hard auto-gates on `record_finding` and `export_execution_log`

The gates below are **server-enforced in code** (`tools/_gates/`), not by this
prose. Each refusal returns `{success:false, gate:"<id>", ...}` with a
remediation message (and `detail_gate` naming the focused checker). The typed
claim, dispositions and the tier contract (see below) are what they key on.
**Full gate-by-gate reference: `docs/gates.md`.** The gates you hit most:

- `tier_contract` — the tier a CONFIRMED/LIKELY finding asks for must be reachable from the ARTIFACT CLASSES its cited calls carry (`data/fk/tiering.yaml`). Refusal carries `tier_achievable` + `tier_path`.
- `confirmed_requires_supported_evaluate` — CONFIRMED/LIKELY need a SUPPORTED `reason.evaluate_finding` (a fact-check) for the same typed claim; CHALLENGED/UNCERTAIN is sticky.
- `typed_claims` — declare `claim_kind`/`category`/`act` (+ conditional fields); gates key on the declared structure, never wording.
- `mcp_routing` / `dair_required` / `lineage_required` / `agent_authored_source` — routing, an active DAIR batch, `input_call_ids`, and never citing an agent-authored file.
- `negative_completeness` — a negative needs the complete source manifest for its category and coverage over the window.
- grounding gates (`principal_attribution_grounding`, `exfil_channel_grounding`, `interactive_injection_grounding`, …) — attribution needs a session artifact; egress needs a transfer artifact.
- `pre_report_check_required` — `reason.pre_report_check` must return `ready_to_report=true` before export/report.


## Typed claims (every CONFIRMED / LIKELY / UNCONFIRMED finding)

The control plane keys on what you **declare**, never on your wording. `misc.record_finding` (and `record_agent_message(findings=[…])`) take:

| Field | Values | Required when |
|---|---|---|
| `claim_kind` | `positive` \| `negative` | always |
| `category` | `exfil` \| `logon_auth` \| `identity` \| `persistence` \| `device_initial_access` \| `execution` \| `delivery` \| `destruction` \| `attribution` \| `privilege_escalation` \| `other` | always |
| `act` | `presence` \| `execution` \| `timeline` \| `account_creation` \| `persistence_install` \| `logon` \| `egress` \| `delivery` \| `possession` \| `c2` \| `lateral_movement` \| `credential_access` \| `privilege_escalation` \| `destruction` \| `attribution` \| `other` | always |
| `channel` | `removable` \| `cloud` \| `email` \| `web` \| `ftp` \| `chat` \| `c2` \| `other` | `act="egress"` |
| `transfer_call_ids` | cids of the transfer artifact calls | `act="egress"` at CONFIRMED/LIKELY |
| `recipients` / `receipt_call_ids` | who received it / destination-side receipt calls | `act` delivery/possession |
| `actor_kind` / `actor` | `human` \| `account` \| `process` \| `device` \| `system` \| `unknown` / the name | `actor_kind="human"` ⇒ `actor`; `act="attribution"` ⇒ `actor_kind` (use `unknown` when no session binds a person) |
| `principal` / `session_binding_call_ids` | the account bound to the actor / the logon-session artifact calls | binding a principal to a human |
| `session_type` | `interactive` \| `remote_interactive` \| `network` \| `service` \| `unknown` | interactive account creation / persistence |
| `window` | `{"start": "YYYY-MM-DD", "end": "YYYY-MM-DD"}` | negatives in logon_auth / device_initial_access; device rule-outs |
| `rule_outs` | `[{"what": "injector"\|"automation"\|"second_principal", "call_ids": [...]}]` | a flagged injector must be ruled out |
| `entities`, `scope`, `threat_actor`, `techniques`, `artifacts`, `resolves` (`confirmed`\|`refuted`), `answers_case_question` | optional / situational | — |

Pass the same `claim_kind`/`category`/`act`/`entities`/`principal`/`channel` to `reason.evaluate_finding` — the SUPPORTED verdict is matched to the finding by that claim. SUSPECTED needs no claim. Every refusal names the missing field and its enum.

---

## Dispositions (`misc.record_disposition`)

The only way to settle a lead, source, tool, challenge, principal, correspondent, device or hypothesis **without a finding**. Prose ("absent from evidence", "inapplicable", "ruled out", "controller unknown") is never read.

```
misc.record_disposition(target_kind=..., target_id=..., reason=..., evidence_call_ids=[...], note="", window={...})
```

| `target_kind` | `target_id` | allowed `reason` |
|---|---|---|
| `source` | manifest source id from the refusal (`terminalservices`, `chat_messenger`, `device_inventory`, …) | `absent_from_evidence` \| `inapplicable` \| `out_of_scope` |
| `tool` | the MCP tool (`ez.pecmd`) | `absent_from_evidence` \| `inapplicable` \| `out_of_scope` |
| `challenge` | `"<dair_call_id>:<challenge claim>"` | `absent_from_evidence` \| `inapplicable` \| `out_of_scope` |
| `principal` | the account/identity (any spelling) | `excluded`\* \| `not_a_principal`\* \| `refuted`\* \| `same_as`\* (same person/account as an established principal — an alias or the prime subject's own account) \| `controller_unknown` \| `evidence_unavailable` \| `out_of_scope` |
| `correspondent` | the address | `noise` \| `out_of_scope` \| `excluded`\* |
| `device` | `VID:PID` | `ruled_out`\* (`window` REQUIRED + ≥1 cited call carrying the device's OWN record classes — `device_install` / `usb_storage`; session/transfer/mail evidence describes how an account was USED, not how it was created, and is refused: `disposition_evidence_relevance`) \| `absent_from_evidence` |
| `hypothesis` | `H0002` | `refuted`\* \| `excluded`\* \| `evidence_unavailable` |
| `host` | host / IP | `out_of_scope` \| `evidence_unavailable` \| `excluded`\* |
| `destruction_scope` | the destruction finding's call_id | `undetermined` |

\* asserts a fact about the evidence — `evidence_call_ids` must name successful evidence tool calls.

---

## Closure duties the server enforces (Phase K)

- **Verification challenges persist.** A DAIR challenge is verified only by a run that **touches its claim** (a claim token in the run's cmd, stored output, or sidecar — hive-family rule included); an unrelated run of the same tool family no longer verifies it. Unrun challenges from EVERY dair call block at `reason.pre_report_check` until run or challenge-dispositioned.
- **Failed tools need closure.** A FAILED MCP forensic tool (e.g. exit `tool_unavailable`) must be retried, replaced by a named fallback, or settled with `misc.record_disposition(target_kind="tool", ...)` — else `pre_report_check` blocks, exactly like a gate-blocked tool.
- **Comms stores present in evidence must be examined** whenever a delivery/dissemination/egress claim exists at ANY tier: a chat-store family visible in collected output (skype/whatsapp/telegram/signal) must be parsed (`misc.chat_db_export`) or source-dispositioned. Parsing may equally exonerate.
- **Correspondent exhaustion attaches to the claim class, not the tier** — a SUSPECTED delivery claim engages it too. Recipient claims should rest on a **queried BODY read** (`read.read_mail mode=messages` with a query — the cmd records mode/field/query); a roster listing cannot establish or exclude a recipient. Near-alias addresses (one character apart, same domain) are surfaced as a typed lead — never auto-merged; resolve with evidence in either direction.
- **Zero-match answers disclose siblings.** The evidence resolver appends the match counts of every other call over the same artifact to any "0 rows match" answer — a non-empty sibling prevents a false absence; all-empty siblings strengthen a true one.
- **Tier–evidence concordance (audit note).** `pre_report_check` notes any finding recorded below its `tier_achievable`. The tier must match the evidence in both directions; the note is arithmetic, not an instruction to strengthen.

---

## Negative findings (UNCONFIRMED tier)

"We looked for X and found nothing" is real work. Record it:
```
misc.record_finding(
    description="No persistence via HKLM\\Run keys — searched all 4 Run/RunOnce hives via RECmd",
    confidence="UNCONFIRMED",
    source="ez.recmd",
    linked_call_id=<tool_call_id>,
    claim_kind="negative", category="persistence", act="persistence_install",   # typed claim — mandatory
    scope=["run_keys", "services", "scheduled_tasks", "startup_wmi_amcache"],
)
```
The accuracy framework scores negative assertions in `ground_truth.json` against these UNCONFIRMED findings → `negative_coverage` metric.

**Completeness is enforced (`negative_completeness` gate).** A negative is valid only over the COMPLETE source set for its claim — absence from the subset you happened to search is not evidence of absence (the closed-world-over-open-world failure). For a case-inverting category (logon/auth, identity, persistence, exfil) `record_finding` refuses an UNCONFIRMED finding unless the trace searched **every** source in the category manifest AND a searched log's coverage window spans the claim's time window. Concretely: a "no RDP/logon", "controller unknown", or "local-console only" claim requires the **TerminalServices channels** (LocalSessionManager / RemoteConnectionManager Operational — on the **full `winevt\Logs\` of the mounted image, NOT the CyLR/triage set**), not just `Security.evtx`; and if `Security.evtx` coverage *starts after* the claim window, that silence is **not** a negative — pivot to TS logs / VSS / carved EVTX. Either search the missing sources or — only when a source is genuinely not in the evidence — settle it typed: `misc.record_disposition(target_kind="source", target_id="<source id from the refusal>", reason="absent_from_evidence")`.

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

Add `_note="<narration>"` to **one** tool call per parallel batch — logged as an `agent_message` before the tools run; pass the same text you write to the user. Opening narration (before the first tool call) goes through `misc_record_agent_message`. (example: docs/agent-contract.md)

Call `misc.record_finding(description, confidence, source, linked_call_id)` per confirmed finding — do not batch. `linked_call_id` = the `_trudi_call_id` of the source tool; every CONFIRMED finding must have one (primary traceability link).

### `input_call_ids` is MANDATORY on every agent-facing record_* call

Every `misc.record_finding`, `misc.record_self_correction`, `dair.dair_assess`, and `reason.*` call MUST pass `input_call_ids=[<cid>, ...]` — the `_trudi_call_id`s of the entries that informed this step. `lineage_required` refuses empty lists after the first 5 entries (genesis grace covers `start_execution_log`, pre-plan reads, first `reason.plan` / `dair_assess`); fabricated or out-of-order ids → `unknown_cids` refusal. This makes the trace a self-describing causal DAG the chain view / accuracy report / `reason.synthesize` traverse by real foreign keys. `linked_call_id` (1:1 primary) and `input_call_ids` (N:M lineage) are complementary — supply both. (example call shapes, incl. attribution/egress findings: docs/agent-contract.md)

### Finding capture (common compliance gap)

`misc.record_agent_message` is for **reasoning and direction**, not stating facts. When a paragraph states a conclusion ("CONFIRMED…", "attacker did X", C2/exfil/persistence/lateral-movement/credential), accompany it with structured findings — separate `misc.record_finding(...)` calls or atomically via `record_agent_message(findings=[…])`. Batched findings pass the same gates (recent `dair_call`; CONFIRMED/LIKELY need a SUPPORTED `reason.evaluate_finding` for the same typed claim); per-finding gate failures return in the response, the narration is written either way. (example: docs/agent-contract.md)

`reason.pre_report_check` runs `reason.audit_findings`, which uses the reason model (not regex) to surface narrations that mention facts but lack structured `finding` entries. Address each warning before writing the report.

After `reason.synthesize`, call `reason.pre_report_check()`. If `ready_to_report=False`, resolve all `blocking_issues` first (evidence or typed dispositions — never wording).

Then call `misc.export_execution_log(output_path)` with path `./reports/<case_id>_trace` (no extension — both `.json` and `.md` are written) and write the report with `misc.write_final_report(...)`. Both read the typed `ready_to_report` flag on the latest pre-report entry; raw writes into `reports/` are refused at PreToolUse. A refused export/report call is logged as a **failed** `<py>:` tool_call carrying the gate id.

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
