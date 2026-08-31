# The Cockpit — human-driven TRUDI through vera

**Goal:** a human analyst runs the investigation with the full TRUDI control
plane — DAIR work orders, reason checkpoints, typed-claim gates, the trace —
while [vera](https://github.com/nebulae/vera) is the record and the UI. The
analyst manually invokes `hypothesize`/`plan`/`dair_assess`, chooses which
tools to run from the returned work order (or edits/substitutes their own),
sees the output, gets findings suggested along the way or submits their own,
and every finding is verified by the same gates that verify the agent's.

The insight that makes this cheap: **nothing in the control plane knows the
driver is an LLM.** The MCP tools, reason backends, gates, and trace are
driver-agnostic. The cockpit is a client, not a fork.

## Architecture

```
 analyst ──► cockpit CLI / vera web ──► fastmcp Client ──► server.py (MCP)
                    │                                          │
                    ▼                                          ▼
              .vera case  ◄──── trace→vera mirror ◄──── TRUDI trace JSON
```

- **The bridge lives in the TRUDI repo** (`cockpit/`). Vera stays
  zero-dependency and untouched except for deliberate upstream PRs (its
  `main` is PR-only). The bridge imports `vera` as an optional dependency
  (`pip install -e ~/vera` or a `[cockpit]` extra).
- **One record pipeline for everything:** the *trace→vera mirror* converts
  TRUDI trace entries into vera rows (actions, findings, notes, evidence).
  Batch mode = the exporter (any past run → a browsable `.vera`); follow mode
  = live mirroring for cockpit sessions AND autonomous runs alike. Build it
  once, both consumers get it.
- **The MCP server is the only execution path** — same guard posture, same
  trace, same `.tool_output` sidecars, same gates. The cockpit never shells
  out around it.

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
| **DAIR `priority_tools`** | **Lead finding + `lead_items`** | run=triaged+link, skip=dismissed (+ TRUDI disposition) |
| narration / curiosity probes | `note` findings / follow-up items | |
| TRUDI runs / cockpit sessions | `actor` + `origins` row per writer | attribution survives export |

## Phases

### Phase 0 — spikes (half a day)
- fastmcp `Client` against `server.py` stdio: call a tool, read `_trudi_call_id`. *(Client class confirmed present in fastmcp 3.2.4.)*
- Decide reason-backend pacing for human sessions: local Titus reason calls
  run 1–5 min — acceptable with async UX, or point `REASON_URL` at Claude for
  cockpit sessions (config note, not code).

### Phase 1 — trace→vera mirror (~1 day) ✦ independently valuable
`cockpit/mirror.py`: trace JSON → `.vera` via vera's `Case` API.
- Batch: `python -m cockpit.mirror <trace.json> <case.vera>` — export any past
  run (the nitroba runs become walkable vera graphs; TRUDI runs export as
  FOR508 CSVs for free).
- Follow: tail the trace (mtime + entry count), append incrementally,
  idempotent via call_id↔action mapping stored in `attrs.trudi_call_id`.
- Tests: golden trace → expected vera rows; idempotence; the ftype mapping
  table; lineage fallback.

### Phase 2 — cockpit CLI MVP (~2–3 days)
`python -m cockpit run --case <dir> --vera <case.vera> --investigator <name>`
- Session bootstrap: `start_execution_log`, `verify_evidence_hash`, beacon
  owned by the cockpit (same contract as agent runs).
- **The loop:** `assess` → render `priority_tools` as a numbered menu →
  per item: **[r]un / [e]dit args / [s]ubstitute / [d]ismiss** (dismiss
  prompts for a typed disposition) → output pager (capped view; full output
  in the sidecar and vera action) → back to assess with an auto-drafted
  `tool_results_summary` the analyst can edit.
- Work orders mirrored as vera Leads; each run links the lead item to the
  resulting action.
- Manual GUI steps: `manual` command → vera manual action + a trace narration
  (`record_agent_message`). *Honest limit: manual steps carry no
  `_trudi_call_id`, so findings resting only on them cannot reach gate-tier
  CONFIRMED — the cockpit surfaces this rather than hiding it.*

### Phase 3 — findings + verification (~2 days)
- **Composer:** guided prompts for the typed claim (ftype-appropriate fields
  pre-filled from the last action), then: `evaluate_finding` →
  `confidence_score` preview → `record_finding` → on success, vera finding
  with tier + claim in attrs. **Gate refusals render as coaching** ("needs
  `session_binding_call_ids` — an account name is not a person") with the
  named remediation tools one keypress away.
- **Suggested findings:** `reason.audit_findings` over the recent batch →
  candidate list to accept/edit/reject.
- **Report:** `synthesize` → `pre_report_check` (blockers rendered as a
  worklist) → `write_final_report` + `export_execution_log`; vera export
  (md/csv/json) alongside; cross-link the two reports.

### Phase 4 — vera web work-order panel (vera-side, PR flow) (~2–3 days)
- Bridge grows a small localhost HTTP surface (assess / run / compose).
- Vera web UI: work-order panel on the Leads tab, "Investigate →" wired to
  the bridge, finding composer with gate feedback inline.
- Goes through vera's branch→PR workflow; vera remains fully functional
  without the bridge present (panel hidden unless the bridge announces
  itself).

### Phase 5 — closure (~1–2 days)
- Upstream vera `negative` finding type (PR) and migrate the phase-1 mapping.
- Custody: include the TRUDI trace + `.tool_output` sidecars in vera's signed
  chain-of-custody bundle (they are the machine half of the record).
- Docs + a worked example (nitroba end-to-end, human-driven).

## Design decisions (settled)
- **Gates before vera:** a finding enters vera only after `record_finding`
  accepts it. Vera holds accepted findings; refusals are transient coaching.
  (Drafts, if wanted later, are vera notes flagged `attrs.draft`.)
- **Vera purity is inviolable:** no TRUDI imports in vera; the bridge depends
  on vera, never the reverse.
- **Exam mode is absence, not a switch:** vera alone is the GCFA-legal
  workflow; the cockpit adds LLM assistance only when its commands are used.

## Open questions (owner: operator)
1. CLI name/UX: `python -m cockpit` vs a `trudi` umbrella command vs
  `vera trudi …` shim (shim would need a vera-side hook — leans against).
2. Reason backend for human-paced sessions: local (slow, fully-local) vs
  Claude (snappy) — per-case `.env` choice; default?
3. Does the cockpit auto-assess after every batch (agent parity) or only on
  demand (analyst autonomy)? MVP: on demand, with a nag line when >N tools
  have run since the last assess.
