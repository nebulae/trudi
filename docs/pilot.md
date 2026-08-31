# TRUDI Pilot — the analyst at the controls

**Goal:** log onto a SIFT machine, install TRUDI and vera easily, open a
terminal, and run the investigation yourself — every command logged, every
output hashed and recorded — with TRUDI riding alongside: suggesting commands
and next steps, intellisensing the input, analyzing each output, and
highlighting findings. The full control plane — DAIR work orders, reason
checkpoints, typed-claim gates, the trace — verifies the human's findings
exactly as it verifies the agent's.

**The two modes are a duality:**

```
trudi --mode agent     # autopilot — an LLM drives (Claude Code or OpenCode)
trudi --mode pilot     # the analyst drives; TRUDI suggests, records, analyzes
```

The insight that makes this cheap: **nothing in the control plane knows the
driver is an LLM.** The MCP tools, reason backends, gates, and trace are
driver-agnostic. Pilot mode is a client, not a fork.

## Architecture

```
 analyst ──► trudi --mode pilot (prompt_toolkit REPL) ──► fastmcp Client ──► server.py (MCP)
                    │                                                            │
                    ▼                                                            ▼
              .vera case  ◄──────── trace→vera mirror ◄──────────────── TRUDI trace JSON
```

- **Terminal-first.** The driving surface is a REPL, not a menu and not a web
  page. Vera is the record and the browsable graph; the vera web work-order
  panel is optional polish, no longer core.
- **The command line is the interaction model:**
  - *Intellisense from the live server* — the completer is generated from the
    MCP tool schemas over the fastmcp `Client` (tool names, parameter names,
    enum values). It can never drift from the server. Familiar binary names
    are completion aliases: typing `fls` or `mftecmd` offers the MCP wrapper —
    muscle memory becomes a feature instead of a deny-loop.
  - *Suggestions pre-fill, never auto-run* — DAIR `priority_tools` and
    reason directives render as a selectable list; choosing one fills the
    editable command buffer. Accept it, edit it, or ignore it and type your
    own.
  - *Every run is a recorded MCP call* — trace `tool_call` with
    `_trudi_call_id`, full stdout in the `.tool_output` sidecar, sha256'd
    into vera by the mirror. **No shell escape hatch**: the MCP server is the
    only execution path — same guard posture as agent runs; that is what
    keeps the record court-defensible.
  - *Analysis is always async* — output renders instantly with TRUDI's
    server-side enrichment (`_metadata` caveats / field meanings); a reason
    pass then resolves an `[analyzing…]` marker in place with highlights,
    drafted findings, and next-step suggestions that feed back into the
    suggestion list. Async design makes both reason backends usable; the
    default sets the feel (see open questions).
- **The bridge lives in the TRUDI repo** (`pilot/`). Vera stays
  zero-dependency and untouched except deliberate upstream PRs (its `main` is
  PR-only). The bridge imports `vera` as an optional dependency
  (`pip install -e ~/vera` or a `[pilot]` extra).
- **One record pipeline for everything:** the *trace→vera mirror* converts
  TRUDI trace entries into vera rows (actions, findings, notes, evidence).
  Batch mode = the exporter (any past run → a browsable `.vera`); follow mode
  = live mirroring for pilot sessions AND agent runs alike. Build it once,
  both consumers get it.

## Target environment

The reference deployment is a **Windows forensic VM with WSL2 running SIFT**:
the pilot REPL, the MCP server, and all evidence processing live on the SIFT
side; the Windows side carries the GUI toolset (Zimmerman tools, Timeline
Explorer, Registry Explorer, EZViewer, HxD, Arsenal Image Mounter, FTK
Imager, Sysinternals, …) one alt-tab away. Consequences:

- **GUI handoff out:** when a TRUDI call produces a CSV/JSON the analyst will
  want to eyeball, the pilot prints the Windows-side path
  (`\\wsl$\...\analysis\mft.csv`) next to the Linux path — "open in Timeline
  Explorer" is a copy-paste, not a mount hunt.
- **GUI handoff back (`manual` command):** work done in a Windows GUI tool is
  recorded as a vera manual action + trace narration. If it produced an
  artifact file, the pilot immediately runs `hash.file` on it — so the
  manual record carries a real `_trudi_call_id` for the artifact's *identity*
  even though its *derivation* is untraced. Honest limit unchanged: findings
  resting only on manual steps cannot reach gate-tier CONFIRMED, and the
  pilot surfaces this rather than hiding it.
- **Dashboard and vera web** are reachable from the Windows browser via
  WSL2's localhost forwarding — no extra networking.
- Windows paths pasted into the REPL are translated (`wslpath`) before they
  reach a tool.

### Manual tools — "GUI to explore, MCP to prove"

Three distinct uses of the Windows toolset, with very different custody
weight:

**1. GUI as a lens on TRUDI output (most common, zero ceremony).** TRUDI
runs `ez.mftecmd` → CSV in `analysis/`; the analyst opens it in Timeline
Explorer via the printed `\\wsl$` path, sorts, filters, finds the row.
Nothing is recorded — viewing isn't evidence work; the citable artifact is
the extractor's CSV + cid. When the analyst returns with "this row
matters," the pilot prefills a **traced read** (`read.output` with a
matching `where=` query) so the finding cites the extractor run + the traced
read, exactly like an agent finding. The GUI is for human eyes; the citation
path never touches it.

**2. GUI discovery with an MCP twin (the upgrade path).** Most of the
Windows suite is the GUI half of a Zimmerman GUI/CLI pairing whose CLI half
is already an MCP tool:

| GUI on Windows | MCP twin |
|---|---|
| Registry Explorer | `ez.recmd_hive` |
| ShellBags Explorer | `ez.sbecmd` |
| JumpList Explorer | `ez.jlecmd` |
| MFTExplorer | `ez.mftecmd` |
| Event Log Explorer | `ez.evtxecmd` |
| HxD | `strings.hexdump` / `strings.xxd_dump` |
| PhotoRec GUI | `img.photorec_carve` |
| Browsing History View | `misc.hindsight_chrome` |

The analyst explores in the GUI, finds the lead, then **re-derives through
the twin**: the `manual` command, when the tool has a twin, prefills the MCP
command scoped to the discovery. The GUI session was the intuition; the MCP
run is the evidence — cid, sidecar, gate-eligible artifact class, full
CONFIRMED tier reachable. The narration can honestly say "surfaced via
ShellBags Explorer, verified via ez.sbecmd."

**3. GUI work with no MCP twin (the true manual record).** pestudio triage,
BEViewer, thumbcache_viewer, an Arsenal mount for visual browsing — no
re-derivation path exists. The `manual` command records it:

```
trudi> manual
  tool:      pestudio 9.55
  input:     analysis/carved/invoice.exe  (cid 0031 — carved by foremost)
  what:      examined imports/resources; UPX section, VT-flagged imphash
  artifact:  exports/manual/pestudio-invoice.xml   [optional]
```

→ vera manual action (analyst as `actor`), trace narration via
`record_agent_message`, and `hash.file` on any produced artifact — a
real cid for the artifact's *identity*, though its *derivation* stays
untraced. The composer states the ceiling up front ("manual derivation —
SUSPECTED/LIKELY ceiling; re-derive via `misc.pe_scanner` to go higher")
rather than letting the analyst discover it at report time.

**Guardrails:** Windows-side mounts (Arsenal, FTK Imager) must be read-only —
evidence integrity is a human duty there; the hooks only guard the agent.
GUI exports land in a dedicated `exports/manual/`, never mingled with tool
output in `analysis/` — the `agent_authored_source` gate treats
analyst-authored files exactly like agent-authored ones: never evidence,
only leads.

## Session walkthrough

`trudi --mode pilot`, inside a case dir. The dividing rule for everything
below: **bookkeeping auto-runs; anything interpretive is only ever
suggested.**

**Boot (automatic, seconds):**
1. Parse the case `CLAUDE.md` → case ID, evidence root, case question,
   roster. No case file → one-time guided setup (prompt for ID + question,
   scan `evidence/`), written back.
2. Spawn `server.py` over stdio (fastmcp Client), fetch tool schemas, build
   the completer.
3. Bookkeeping: `start_execution_log` (prints dashboard URL),
   `verify_evidence_hash` per evidence file (skipped if already recorded).
   Deterministic, custody-required, judgment-free — safe to auto-run.
4. Banner:

```
TRUDI PILOT ── M57-JEAN ─────────────────────────────────────────────
 Q: How did m57plan.xlsx get from Jean's workstation to the
    competitor's forum, and who within M57.biz was involved?
 evidence: jean.E01  ✓ sha256 verified (recorded 2026-06-02)
 trace: analysis/M57-JEAN_trace.json   dashboard: http://127.0.0.1:8765/…
 roster: 12 knowns loaded   phase: ─ (Triage not entered)
─────────────────────────────────────────────────────────────────────
```

**First-run ritual (suggested, never auto).** The contract's Triage entry —
`hypothesize(case_question)` → mount + pre-plan baseline reads →
`reason.plan` → `dair_assess` — *is* the initial suggestion queue, each entry
pre-filled and explained; the analyst runs, edits, or skips (skip = typed
disposition). The phase-boundary middleware built for local models does
double duty: forensic tools attempted before the ritual get the same
server-side coaching notice, rendered in the REPL — one enforcement path,
two drivers.

**The loop.** After `dair_assess` returns a work order:

```
 work order ── Collect (DAIR d3) ────────────────────────────────────
 ▸ 1  ez.mftecmd  file=…/$MFT --csv analysis/        [DAIR 1/4]
   2  misc.readpst_extract  file=…/jean.ost           [DAIR 2/4]
   3  net.ngrep_search  pattern="(jean|alison|…)"     [knowns hunt 3/4]
 trudi> ez.mftecmd file=…/$MFT --csv analysis/ vss=true█  ← #1 selected, edited
```

Enter runs a normal MCP call (cid, sidecar, mirror). Output pages
immediately with server-side enrichment; `[analyzing…]` resolves async:

```
 ✦ analysis (cid 0042)
   • m57plan.xlsx created 2008-07-19 (si+fn agree — no timestomp signal)
   • HIGHLIGHT: .xlsx in a second SID's profile → draft finding ready [f]
   • next: ez.evtxecmd Security (logon inventory)  ·  af.timestomp_drift
```

`[f]` opens the composer (typed claim pre-filled from the analyzed action;
gate refusals rendered as coaching); "next" items join the suggestion list.
Dismissing a work-order item prompts for a typed disposition. After N tools
since the last assess, a nag line appears — assess stays on-demand.

**Exit/resume.** Ctrl-D prints session state (findings by tier, open work
order, unresolved blockers). Relaunch detects the existing trace and, per
the resumption contract, opens with `dair_assess` on the last-known phase
stack — suggested, prefilled.

## Field mapping (verified against vera v0.24 schema 19)

| TRUDI | vera | note |
|---|---|---|
| `tool_call` (cmd, stdout, exit, cid) | Action `method="command"` | output ≤256KB, sha256'd by vera; full stdout stays in TRUDI's sidecar |
| finding + `linked_call_id` | Finding + `action_id` | 1:1 |
| typed claim (all fields) | `attrs` dict | verified: `_normalize_finding_attrs` never drops keys — the whole claim rides along |
| claim `category`/`act` | `ftype` | mapping table: exfil/c2→`netindicator`, persistence/execution→`hostindicator`, lateral_movement→`lateral`, account_creation→`account`, identity/attribution→`account`/`note`, timeline→`event`, else→`note` |
| `input_call_ids` (N:M) | primary edge = `parent_finding_id` chain; rest in `attrs.lineage` | vera lineage is single-parent |
| negatives (UNCONFIRMED, claim_kind=negative) | `note` + `attrs.claim_kind` (phase 1); upstream `negative` ftype (phase 5, vera PR) | vera has no negative concept yet |
| `hash.verify_evidence_hash` | Evidence row + hashes | |
| `record_disposition` host/principal | Host/Account registry disposition | near-1:1 |
| **DAIR `priority_tools`** | **Lead finding + `lead_items`** | suggestions taken=triaged+link, dismissed (+ TRUDI disposition) |
| narration / curiosity probes | `note` findings / follow-up items | |
| TRUDI runs / pilot sessions | `actor` + `origins` row per writer | attribution survives export |

## Phases

### Phase 0 — prerequisites + spike (~1–2 days)
- **Wire-name normalization.** ~150 tools across 15 namespaces have doubled
  wire names (`vol_info`, `tsk_fls`, `ez_mftecmd`). In an
  agent-driven system this was cosmetic; in a REPL a human types these names
  all day. Strip the redundant prefix at mount time in `server.py` (single
  choke point), update the ~10 consumer files/docs; the hint-resolution test
  pins the result. Do this before any pilot code depends on the old names.
  Cost: new traces won't be name-compatible with the 8 recorded case traces.
- **Spike:** fastmcp `Client` against `server.py` stdio (Client confirmed in
  fastmcp 3.2.4) + a prompt_toolkit REPL skeleton with schema-driven
  completion. Proves the core feel before anything else is built.

### Phase 1 — trace→vera mirror (~1 day) ✦ independently valuable
`pilot/mirror.py`: trace JSON → `.vera` via vera's `Case` API.
- Batch: `python -m pilot.mirror <trace.json> <case.vera>` — export any past
  run (the nitroba runs become walkable vera graphs; TRUDI runs export as
  FOR508 CSVs for free).
- Follow: tail the trace (mtime + entry count), append incrementally,
  idempotent via call_id↔action mapping stored in `attrs.trudi_call_id`.
- Tests: golden trace → expected vera rows; idempotence; the ftype mapping
  table; lineage fallback.

### Phase 2 — the `trudi` CLI + pilot REPL MVP (~3–4 days)
- **Umbrella entry point:** `trudi --mode pilot|agent [--case <dir>]`.
  - `--mode agent`: thin launcher over what the registrars already set up —
    picks the driving client (`--client claude|opencode`, or config default)
    and starts it in the case dir.
  - `--mode pilot`: the REPL. Session bootstrap owned by the pilot, same
    contract as agent runs: `start_execution_log`, `verify_evidence_hash`,
    beacon.
  - Room for the obvious siblings later: `trudi reset`, `trudi dashboard`,
    `trudi clear-case` (currently `python -m tools.…` invocations).
- **The loop:** suggestion list (DAIR work order + reason directives) →
  select-to-prefill / edit / type-your-own → run over the fastmcp Client →
  output pager (capped view; full output in the sidecar and vera action) →
  auto-drafted `tool_results_summary` the analyst can edit before the next
  `dair_assess`.
- Work orders mirrored as vera Leads; each run links the lead item to the
  resulting action. Dismissing a suggestion prompts for a typed disposition.
- Manual GUI steps: `manual` command → vera manual action + a trace narration
  (`record_agent_message`), with `hash.file` run on any produced
  artifact (see Target environment — the Windows GUI toolset is a first-class
  part of the workflow, not an edge case). *Honest limit: manual steps carry
  no derivation `_trudi_call_id`, so findings resting only on them cannot
  reach gate-tier CONFIRMED — the pilot surfaces this rather than hiding it.*
- **Install story:** `install.sh` grows a vera step + the `[pilot]` extra;
  the whole stack installs on a fresh SIFT machine in one pass.

### Phase 3 — the analysis layer (~2 days)
- **Async output analysis:** per-command reason pass → highlights rendered
  in place, candidate findings, and next-step suggestions feeding the list.
- **Composer:** guided prompts for the typed claim (ftype-appropriate fields
  pre-filled from the analyzed action), then: `evaluate_finding` →
  `confidence_score` preview → `record_finding` → on success, vera finding
  with tier + claim in attrs. **Gate refusals render as coaching** ("needs
  `session_binding_call_ids` — an account name is not a person") with the
  named remediation tools one keypress away.
- **Suggested findings:** `reason.audit_findings` over the recent batch →
  candidate list to accept/edit/reject.
- **Report:** `synthesize` → `pre_report_check` (blockers rendered as a
  worklist) → `write_final_report` + `export_execution_log`; vera export
  (md/csv/json) alongside; cross-link the two reports.

### Phase 4 — vera web work-order panel (optional polish; vera-side, PR flow)
- Bridge grows a small localhost HTTP surface (assess / run / compose); vera
  web UI gets a work-order panel on the Leads tab. Goes through vera's
  branch→PR workflow; vera remains fully functional without the bridge
  (panel hidden unless the bridge announces itself). **Terminal-first means
  this is no longer core — decide keep/drop after Phase 3 lands.**

### Phase 5 — closure (~1–2 days)
- Upstream vera `negative` finding type (PR) and migrate the phase-1 mapping.
- Custody: include the TRUDI trace + `.tool_output` sidecars in vera's signed
  chain-of-custody bundle (they are the machine half of the record).
- Docs + a worked example (nitroba end-to-end, human-piloted).

## Design decisions (settled)
- **Name and CLI shape:** pilot / agent duality via `trudi --mode pilot|agent`.
- **Terminal-first:** the REPL is the driving surface; vera web is optional.
- **No shell escape hatch:** MCP-only execution — the architectural guardrail
  and the court-defensibility story are the same thing.
- **Analysis is always async:** output never waits on the reason backend.
- **Gates before vera:** a finding enters vera only after `record_finding`
  accepts it. Vera holds accepted findings; refusals are transient coaching.
  (Drafts, if wanted later, are vera notes flagged `attrs.draft`.)
- **Vera purity is inviolable:** no TRUDI imports in vera; the bridge depends
  on vera, never the reverse.
- **Exam mode is absence, not a switch:** vera alone is the GCFA-legal
  workflow; pilot mode adds LLM assistance only when its commands are used.

## Open questions (owner: operator)
1. Reason backend default for pilot sessions: Claude (snappy — recommended)
   vs local Titus (1–5 min/call, fully local) — per-case `.env` choice
   either way; async design makes both usable.
2. Vera web work-order panel (Phase 4): keep or drop — decide after Phase 3.
3. Does the pilot auto-assess after every batch (agent parity) or only on
   demand (analyst autonomy)? MVP: on demand, with a nag line when >N tools
   have run since the last assess.
