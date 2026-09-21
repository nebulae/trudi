# TRUDI Orchestrator (OpenCode)

Directs the coding agent running a TRUDI investigation under OpenCode. This is the
condensed orchestrator — every rule here is backed by a server-enforced gate; the
full rationale lives in `~/trudi/claude/CLAUDE.md` and `~/trudi/docs/gates.md`.

## Mode contract

Default mode is **autonomous agent** — the rules below apply as written.
When the **TRUDI Pilot profile** is active (the `trudi-pilot` agent), its
conversational rules OVERRIDE the autonomy directives here; every other
rule (evidence path, gates, typed claims, citability) applies unchanged.


**Bounded guidance and exploration.** Large control results provide `details`;
use `reason.readiness_status(section=..., state_version=...)` or
`reason.review_details(call_id=..., section=..., state_version=...)`. Follow
`next_offset`, concatenate `json_chunk`, then parse JSON. Do not rerun a model
or read internal caches just to retrieve its result. Synthesis checks deterministic
prerequisites before model work and shares finding-scoped evidence. A mistaken
reviewer premise can be independently corrected with existing source quotes;
do not retract supported observations merely to clear a gate.

Review responses carry `review_call_id`, verdict or access status, and a
versioned `details` route. Read the named blocker sections with
`reason.review_details` before retrying; never guess IDs or rerun an evaluation
to retrieve it. `access_failure` means required evidence was not reached: repair
the request/source, rather than treating it as a factual challenge or collecting
new evidence automatically. Fetch repairs use `replaces_request_id` and retain
successful reads. `uncited_sources` are optional leads from retained outputs,
including inline stdout: inspect them before citing, and obtain a new independent
review after changing citations. Empty/capped suggestions do not require new
collection. Narrowing the claim remains available.

`reason.hypothesize(mode="absence")` returns optional `exploratory_suggestions`;
do not merge them into mandatory `priority_tools` or extract binding work from
its prose. Choose a useful check within DAIR's allowance after the required batch,
or record that no useful candidate remains in the next normal summary. Link the
actual tool output when recording a curiosity probe. Budget is permission, not a
quota; probe metadata alone never supports a finding. Follow the actual question
and available evidence, including benign alternatives, rather than a fixed
platform or attack checklist.

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
- **Read produced output with `read.output` / `read.mail`** — never
  bash `cat`/`jq`/`python`. Bash reads are untraced and uncitable; `read.*` returns
  a `_trudi_call_id` you can cite. Recipient/dissemination claims MUST cite
  `read.mail` message BODIES (To/Cc + body), never subject lines alone.
- Timestamps always UTC. Check `success: true` after every run; on failure read
  stderr, correct, retry. A result with `truncated: true` is INCOMPLETE — re-run
  narrower before recording any negative.
- **Control-plane notices are instructions.** A tool result carrying a
  `dair_notice` or `finding_notice` field is the control plane telling you the
  next required call — act on it (call the named tool with the given shape)
  BEFORE any further forensic tool calls.
- **Background jobs** — long operations wait up to 15 seconds, then return a `job_id` if still running. Poll `misc.job_status` between useful work. Only validated partial outputs are citable; incomplete scope remains open. See the resumable review and jobs contract below.
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
   `ez.recmd_hive` (SOFTWARE/SYSTEM/SAM), `vol.symbol_check` on any memory
   image, `strings.stat_file` on evidence. PCAP-only cases: `net.tcpdump_read` +
   `net.tcpdump_extract_ips`/`list_connections` + `net.http_session_inventory`.
5. `reason.plan(case_description, evidence_available, case_question=…)`.
6. `dair.assess` — then follow the DAIR loop below for the whole investigation.

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
`focus_pids`, `focus_paths`. When presence-mode `reason.hypothesize` output names concrete
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
- Before Report, call `reason.readiness_status` to settle deterministic prerequisites.
  Call `reason.audit_findings` explicitly for new substantive narration; unchanged audits are cached.
- Report phase: `reason.synthesize(findings=<narrative>)` → `reason.pre_report_check`
  → resolve ALL `blocking_issues` with evidence or typed dispositions (never
  wording) → `misc.export_execution_log("./reports/<case_id>_trace")` →
  `misc.write_final_report`. Approval expires when relevant state changes. Repeated review
  rounds never waive factual blockers; resolve structured issue IDs with evidence or a
  reviewed correction. `supersedes` must target the current revision of the same claim;
  use `misc.retract_finding` to withdraw an unsupported claim explicitly.
- ATT&CK ids in findings are auto-validated; scout with `correlate.mitre_map` /
  `correlate.mitre_validate`.

## Recording findings (typed claims — the control plane reads these, not prose)

Prefer `misc.submit_finding` for a complete draft: pass description, confidence,
explicit evidence IDs, a stable idempotency key, and `claim={...}` containing the
same typed fields as record_finding. It preflights, reviews and commits one finding.
Reuse that exact key/request after timeout; a changed draft uses a new key.
`recorded` means committed; otherwise act on the returned issues. This operation
never silently lowers confidence. Legacy evaluate/record calls remain available,
with new review receipts bound to the exact description, typed claim and evidence.
The separate evaluate/confidence-score/cite-check steps above are handled inside
submission; do not repeat them before submitting. For a preview, use the separate
checks and finish with record_finding on the exact reviewed inputs.


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
  (`misc.chat_db_export`), read via `read.mail`/`read.output`,
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

## Report follow-up routing

Required forensic work discovered in Report uses a durable DAIR transition before
execution: new acquisition/extraction goes to Collect, new analysis to Analyze,
and discovery scans to Scan. A validated, already-authorized tool request continues
in the same call after that transition; do not repeat it just to change phase.
This does not authorize new work beyond the analyst's instructions in pilot mode.

Reads of traced, produced outputs and finding corrections remain in Report.
Synthesis may return `follow_up_required` with typed work and a `request_id`;
execute that work through normal MCP tools. Optional suggestions are not duties.
`repair_required` means an output-access/software problem, not a reason to collect
more evidence. Missing synthesis alone also stays in Report.

Pending/running/failed work appears in `reason.readiness_status().follow_up` and
blocks return to Report. A DAIR call or unrelated tool success does not settle it.
Completed duplicate requests reuse their result. For a deliberate repeat of a
completed/failed request, or after reconciling an unknown outcome, pass `_refresh=true`;
never refresh an operation merely because its response was delayed. Poll background
jobs with `misc.job_status`; do not restart them. A justified unavailable/inapplicable
request can be dispositioned with `target_kind="follow_up"`, its exact request ID,
a reasoned note and its result/trigger evidence call IDs. This settles the task,
not the underlying finding or independent review issue.

Return through DAIR after required work is settled, then rerun synthesis against
the updated evidence. Report publication still requires a current pre-report approval.

## Resumable review and accountable jobs

`reason.synthesize` returns `status: in_progress | complete | blocked` and a
`review_session_id`. For `in_progress`, call it again with `next_arguments` and
normal lineage; the server resumes unfinished requests and reuses current review
receipts. Stay in Report unless a typed follow-up routes actual evidence work.
A successful call or `issues: []` does not approve a report. Wait for `complete`
and `approved: true`, then run `reason.pre_report_check`. A budget blocker retains
the checkpoint; unchanged retries do not replenish its allowance.

Long tools wait up to 15 seconds for the complete operation, including fallback
parsing and validation. Otherwise they return a durable `job_id`. There are two
concurrent slots and no queue. `misc.job_list` supplies the current adapter
policies and active jobs. Poll `misc.job_status` between useful work; do not
restart a running operation. Jobs belong to a run, not merely a case/path.

Execution success, `result_status`, and `scope_complete` are separate. Cite only
validated outputs from a partial/cancelled job. Its original scope remains open,
and a partial search cannot prove absence. Traced reads preserve that incomplete
scope. Unsupported interrupted containers require subsequent validation.

To abandon work, call `misc.job_cancel(job_id, reason)` and collect the stopped
job. Then use `misc.record_disposition(target_kind="job", target_id=job_id,
reason="out_of_scope"|"inapplicable"|"evidence_unavailable", note=...,
evidence_call_ids=[<this job's collected call_id>])` when justified. This settles
only that job's obligation; a generic tool disposition cannot settle jobs.
Cancellation alone never settles scope. An orphan's explicit cancellation can
finalize retained partial output without re-running extraction. Both reset
entrypoints refuse while workers can write, including with `--force`.
