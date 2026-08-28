# TRUDI Orchestrator (OpenCode)

Directs the coding agent running a TRUDI investigation under OpenCode. This is the
condensed orchestrator — every rule here is backed by a server-enforced gate; the
full rationale lives in `~/trudi/claude/CLAUDE.md` and `~/trudi/docs/gates.md`.

## Ground rules

- **Run fully autonomously.** Never ask questions, never check in, never end a turn
  with a plan or "next steps" text. Deliver final findings only. If blocked, pick the
  most reasonable path and note it in the trace.
- **Tool calls happen ONLY through the tool-calling interface.** Never write an
  invocation as text or a code block — written calls execute nothing. If you catch
  yourself describing a call, STOP and execute it. Keep calling tools until the
  phase's work order is done.
- **Evidence is strict read-only** (`/cases/*/evidence/`, `/mnt`, `/media`). All
  output goes to `./analysis/`, `./exports/`, `./reports/`. `reports/` is written
  ONLY by `misc.write_final_report` (gated on `reason.pre_report_check`
  `ready_to_report=true`); raw writes and bash reads of produced output in those
  dirs are refused at execution time. An agent-authored file is never evidence.
- **MCP routing is mandatory.** Never invoke forensic binaries via bash (`vol`,
  `fls/icat/…`, EZ `dotnet …Cmd.dll`, `log2timeline.py`, `yara`, `bulk_extractor`,
  `tcpdump`, `hexdump/xxd/exiftool`, `rip.pl`, `clamscan`, mount tools). Findings
  citing bash runs of these are refused (gate `mcp_routing`).
- **Read produced output with `read.read_output` / `read.read_mail`** — never
  bash `cat`/`jq`/`python`. Bash reads are untraced and uncitable; `read.*` returns
  a `_trudi_call_id` you can cite. Recipient/dissemination claims MUST cite
  `read.read_mail` message BODIES (To/Cc + body), never subject lines alone.
- Timestamps always UTC. Check `success: true` after every run; on failure read
  stderr, correct, retry. A result with `truncated: true` is INCOMPLETE — re-run
  narrower before recording any negative.
- **Control-plane notices are instructions.** A tool result carrying a
  `dair_notice` or `finding_notice` field is the control plane telling you the
  next required call — act on it (call the named tool with the given shape)
  BEFORE any further forensic tool calls.
- **Background jobs:** carve-class tools (e.g. `net.tcpxtract_streams`)
  return a `job_id` immediately — poll `misc.job_status(job_id)` between other
  work; never sit idle waiting on a running job. The finished job_status
  result is the citable record.
- Never manually edit `~/.cache/trudi/*` files; reset with
  `python -m tools.trudi_reset --case-dir <case>`.

## Investigation start (exact order)

1. `misc.start_execution_log(case_id, "./analysis/<CASE_ID>_trace.json")` — announce
   the returned `dashboard_url` to the operator.
2. `hash.verify_evidence_hash` once per evidence file per case.
3. `reason.hypothesize(hypothesis_kind="case_question", observation=<the case
   question>)` — BEFORE reason.plan. Capture each `hypothesis_id`; route findings
   back via `tested_hypothesis_id`.
4. Pre-plan parallel batch (evidence-type dependent): registry hives via
   `ez.ez_recmd_hive` (SOFTWARE/SYSTEM/SAM), `vol.vol_symbol_check` on any memory
   image, `strings.stat_file` on evidence. PCAP-only cases: `net.tcpdump_read` +
   `net.tcpdump_extract_ips`/`list_connections` + `net.http_session_inventory`.
5. `reason.plan(case_description, evidence_available, case_question=…)`.
6. `dair.dair_assess` — then follow the DAIR loop below for the whole investigation.

## DAIR execution loop (DAIR prescribes; you execute)

Phases: Triage → Collect → Analyze → Scan → Report (recursive, not linear — any
phase can push back to an earlier one when a material gap appears).

1. `dair_assess(tool_results_summary, phase_stack, case_context, input_call_ids)` →
   receive `directives.priority_tools` + `curiosity_budget`.
2. Execute `priority_tools` in order, completely. No substituting your own agenda.
3. After the work order: up to `curiosity_budget` read-only probes of your own
   choosing, each logged via `misc.record_curiosity_probe(rationale, input_call_ids)`.
4. Summarize results (3–5 sentences) → call `dair_assess` again. Repeat.
5. Investigation ends only when DAIR returns `next_phase: "Report"`.

`phase_stack` is a JSON list of `{phase, entry_reason, depth}` maintained across
calls (`push`/`pop`/`stay` per the response). Pass
`"Investigation starting — no tools run yet"` + `"[]"` on the first call. On ANY
interruption/reconnect, the first action is `dair_assess` with the last-known stack.

Declare what a batch surfaced, typed: `observed_hosts=[…]`,
`observed_principals=[{"name", "cue": "created"|"interactive_logon"|"network_logon"|
"correspondent"|"other", "call_ids"}]`. A `created`/`interactive_logon` cue on an
unseen principal is a FORCED candidate: bind it with a session artifact, exclude it
with evidence, or park it via disposition — before Report.

Directives are binding: `priority_tools` next in order; respect `skip_tools`,
`focus_pids`, `focus_paths`. When `reason.hypothesize` output names concrete
searches/artifacts in its text, convert them to tool calls and queue them even if
its `priority_tools` is empty. Triage max-pass cap: after 3 consecutive
`stay` responses with no open verification challenge, log
`misc.record_self_correction(trigger="dair_max_pass_cap")` and push Collect manually.
Report is refused server-side until findings exist AND Collect + Analyze (+ Scan when
host pivots exist) appear in the trace's phase history.

## Reason checkpoints (mandatory)

- `reason.hypothesize` — on the case question at Triage start; on every suspicious
  artifact in Analyze; whenever a new account/identity appears (frame it as a
  SEPARATE principal: `hypothesis_kind="distinct_principal"`,
  `contested_principals=[…]`); on any artifact that contradicts the working
  hypothesis (re-hypothesize, don't absorb).
- `reason.evaluate_finding` — BEFORE any CONFIRMED/LIKELY finding. Pass the SAME
  typed claim you will record (`claim_kind, category, act, entities, principal,
  channel`); `supporting_evidence` = tool output (command + field + value). It is a
  fact-check: SUPPORTED / CONTRADICTED (sticky CHALLENGED) / UNVERIFIABLE. Cite the
  EXTRACTOR run in `input_call_ids`, not just a `read.*` subset — the reviewer pulls
  rows only from what you cite. CHALLENGED/UNCERTAIN is sticky: new evidence tool
  call + a later SUPPORTED evaluate required before CONFIRMED/LIKELY.
- `reason.confidence_score(act=, channel=, input_call_ids=[…])` — deterministic tier
  preview before recording above SUSPECTED. The tier is arithmetic from the cited
  calls' artifact classes (`tier_contract` gate); if the preview is below what you
  intended, collect the named missing classes or record at the reachable tier.
- `reason.cite_check` — before recording findings with concrete claims (paths, IPs,
  hashes, technique IDs).
- Report phase: `reason.synthesize(findings=<narrative>)` → `reason.pre_report_check`
  → resolve ALL `blocking_issues` with evidence or typed dispositions (never
  wording) → `misc.export_execution_log("./reports/<case_id>_trace")` →
  `misc.write_final_report`.
- ATT&CK ids in findings are auto-validated; scout with `correlate.mitre_map` /
  `correlate.mitre_validate`.

## Recording findings (typed claims — the control plane reads these, not prose)

Every CONFIRMED/LIKELY/UNCONFIRMED finding via `misc.record_finding` needs:

| Field | Values / when |
|---|---|
| `linked_call_id` | the `_trudi_call_id` of the source tool call — always |
| `input_call_ids` | lineage cids that informed this step — always (all record_*/reason/dair calls) |
| `claim_kind` | `positive` \| `negative` — always |
| `category` | `exfil` `logon_auth` `identity` `persistence` `device_initial_access` `execution` `delivery` `destruction` `attribution` `privilege_escalation` `other` — always |
| `act` | `presence` `execution` `timeline` `account_creation` `persistence_install` `logon` `egress` `delivery` `possession` `c2` `lateral_movement` `credential_access` `privilege_escalation` `destruction` `attribution` `other` — always |
| `channel` + `transfer_call_ids` | `act="egress"`: channel enum + cids of a TRANSFER artifact (bytes moved — staging/tool presence is not egress) |
| `recipients` + `receipt_call_ids` | delivery/possession claims |
| `actor_kind` / `actor` | `human` `account` `process` `device` `system` `unknown`; human ⇒ name |
| `principal` + `session_binding_call_ids` | binding an account to a human needs a logon/session artifact (4624/4625 by type+source, TS channels, pcap identity) — an account name is not a person |
| `session_type`, `window`, `rule_outs`, `scope`, `entities`, `resolves`, `tested_hypothesis_id`, `answers_case_question` | situational — refusals name what's missing |

SUSPECTED needs no claim. Do not batch findings — one `record_finding` per finding
(or atomically via `record_agent_message(findings=[…])`). Narration/reasoning goes
in `misc.record_agent_message`; any paragraph stating a conclusion must be
accompanied by a structured finding. Add `_note="<narration>"` to ONE tool call per
parallel batch.

**Negatives are real work** (`confidence="UNCONFIRMED"`, `claim_kind="negative"`,
with `scope=[…]`) — but only over the COMPLETE source set for the category
(`negative_completeness` gate): a "no logon/RDP" claim needs the full
`winevt\Logs\` including TerminalServices channels, never a triage subset; a log
whose coverage starts after the incident window is silent, not negative.

## Dispositions — settling leads without a finding

`misc.record_disposition(target_kind, target_id, reason, evidence_call_ids, window)`
— prose ("ruled out", "controller unknown") is never read. Kinds → reasons:
`source`/`tool`/`challenge` → `absent_from_evidence|inapplicable|out_of_scope`;
`principal` → `excluded*|not_a_principal*|refuted*|same_as*|controller_unknown|
evidence_unavailable|out_of_scope`; `correspondent` → `noise|out_of_scope|excluded*`;
`device` → `ruled_out*` (window + device-record evidence required) |
`absent_from_evidence`; `hypothesis` → `refuted*|excluded*|evidence_unavailable`;
`host` → `out_of_scope|evidence_unavailable|excluded*`. (* = must cite successful
evidence calls.) Every contested principal reaches CONFIRMED/REFUTED/SAME-AS or a
typed park before Report — `pre_report_check` blocks otherwise.

## Investigation discipline (all server-checked)

- **Distinct principals:** the initial hypothesize must include at least one
  genuinely different actor/mechanism. A newly-seen account is a separate principal
  until an authentication/session artifact binds its controller. Never attribute an
  account's actions to a person by assumption.
- **BadUSB check:** when a covert account/persistence was created in an interactive
  session AND removable media is in evidence, run `misc.device_install_inventory`
  over `setupapi.dev.log` (enumerate, don't grep) before any "X did it
  interactively" finding (`interactive_injection_grounding` gate).
- **Knowns-driven hunting:** when case context has any roster/suspect list/asset
  inventory, run `misc.knowns_pattern_generate(reference_set, derivation_type=
  person_username|hostname|hash|domain|exact)` and hunt the returned patterns in
  the FIRST batch, before generic enumeration.
- **Normalize before declaring a non-match:** case-fold; treat `.`/`_`/`-`/absence
  as equivalent; generate username derivations (jdoe, jane.doe, doej…); extract
  email prefixes; canonicalize paths; match any of MD5/SHA1/SHA256.
- **Prefer structured extractors over keyword search:** `net.http_session_inventory`
  over repeated ngrep; `ez.evtxecmd`/`ez.recmd` over strings-and-grep;
  `misc.device_install_inventory` over grepping setupapi; `ez.mftecmd` over strings
  on $MFT. Keyword search is for ad-hoc lookups and confirmation passes.
- **Never stop at the first artifact:** all cookies/flows, all Run keys, all
  browser profiles, every SID's Recycle Bin/Desktop/Downloads, both `vol.malfind`
  AND `vol.hollowprocesses`, full event-log set (not the CyLR subset). Before any
  "identity unknown" conclusion: list every identity-bearing artifact type, confirm
  each was queried, cross-reference EVERY found identity against the roster.
- **Recipient exhaustion:** "who received the data" needs a full sender/recipient
  inventory of mail (`misc.readpst_extract`/`pff_export`) AND chat stores
  (`misc.chat_db_export`), read via `read.read_mail`/`read.read_output`,
  cross-referenced against the roster. Declare recipients typed; engaged or
  roster-matched correspondents left unreferenced block the report.
- **Exfil channels:** enumerate ALL candidates (removable, ftp, cloud, email, web,
  chat, c2), rank by evidence strength, never headline a weaker-evidenced channel
  over a stronger one. Egress needs a transfer artifact.
- **Attack lifecycle:** persistence, privilege escalation, lateral movement,
  execution evidence, exfiltration — establish or rule out each; an unexamined
  phase is a blind spot, not a clean bill (`pre_report_check` warns per phase).
- **Anti-forensics (`af.*`):** run the matching check when its input artifact
  exists — `timestomp_drift` after mftecmd, `event_log_clear` after evtxecmd,
  `usn_gaps` after usnparser, `prefetch_deletion` after pecmd/amcache.
- **Reformulation limit:** the same claim evaluated twice with no new tool calls
  refuses a third try — collect fresh evidence or park as UNCONFIRMED.
- **Failed tools need closure:** retry, replace with a named fallback, or
  disposition (`target_kind="tool"`) — otherwise `pre_report_check` blocks. Same
  for unrun DAIR verification challenges.

## Live monitoring

Velociraptor-backed live cases (`monitor.*`/`respond.*`) use per-investigation
traces and operator-gated containment — full detail in
`~/trudi/docs/live-monitoring.md`. Static forensic investigations never execute
response actions; Improve & Response are recommendations in the final report only.
