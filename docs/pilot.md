# TRUDI Pilot — the analyst at the controls

**Pilot mode is an agent-client session where the analyst drives.** The
LLM (Claude Code or OpenCode) is the copilot: it proposes and explains,
runs tools on the analyst's direction, digests every result, answers
questions about the evidence from traced reads, and drafts findings the
analyst confirms. The control plane — MCP-only evidence path, typed
claims, gates, trace citability — is identical to autonomous agent mode.

```
trudi --mode agent   # autonomous: the LLM runs the investigation to Report
trudi --mode pilot   # analyst-driven: the LLM is the copilot, you drive
```

The modes differ by operating PROFILE, not by program. This replaced an
earlier custom prompt_toolkit REPL (see "Retired components").

## Architecture

```
 analyst ──chat──► agent client (claude / opencode) ──MCP──► server.py
                        │  pilot profile active                  │ gates,
                        ▼                                        ▼ trace
                  .vera case  ◄── trace→vera mirror ◄── TRUDI trace JSON
```

**Profile delivery per client** (no global files mutated at launch;
concurrent agent+pilot sessions on different cases are safe):

- **Claude Code**: `claude --append-system-prompt-file <repo>/claude/PILOT.md`
  — the profile is appended to the system prompt for this session only.
- **OpenCode**: a custom primary agent, `opencode --agent trudi-pilot`.
  The agent definition (`opencode/agent/trudi-pilot.md`, YAML frontmatter
  `mode: primary`) is symlinked into `~/.config/opencode/agent/` by the
  registrar — repo-backed, no drift.

**Mode contract**: both global orchestrators (`claude/CLAUDE.md`,
`opencode/AGENTS.md`) carry a "Mode contract" section — default is
autonomous; an active pilot profile OVERRIDES the autonomy directives
("never ask questions", "run fully autonomously") while every other rule
(evidence path, gates, typed claims, citability) applies unchanged. The
profile opens with the mirror-image supersede statement, so whichever
document the model reads first, the contract is explicit.

## The profile

One canonical content, two renderings, heading parity + size budgets
pinned by `tests/pilot/test_profile.py`:

- `claude/PILOT.md` — full rendering (≤ ~4k tokens).
- `opencode/agent/trudi-pilot.md` — condensed (≤ ~3k tokens; OpenCode
  renders AGENTS.md + the agent prompt into every request, and local-model
  context is the constraint).

Sections: **Mode override** · **Conversational contract** (propose →
explain → wait; digest every result; answer evidence questions only from
traced `read.*`/forensic calls, citing `_trudi_call_id`s; GUI to explore,
MCP to prove) · **Opening playbook** (bookkeeping auto-runs: trace log +
evidence hashes; then a PROPOSED evidence-typed opening — pcap →
tcpdump read/connections/ips, E01 → ewf info/mount, raw → tsk.mmls, mem →
vol.symbol_check, roster → knowns_pattern_generate — then hypothesize →
plan → assess) · **DAIR, analyst-paced** · **Findings & dispositions**
(drafted fully typed, shown, confirmed before recording) · **Coaching**
(gate refusals translated; tier ceilings surfaced; `reason.advise` on
request) · **Unchanged control plane**.

## Launcher

```
cd ~/cases/<case> && trudi --mode pilot [--client claude|opencode] [--mirror]
```

`pilot/cli.py` prints a short case banner (id / question / evidence count,
parsed by `pilot/bootstrap.py`), optionally spawns the vera mirror, chdirs
to the case dir, and execs the client with the profile argv. Client
resolution: `--client` > `$TRUDI_AGENT_CLIENT` > first of claude/opencode
on PATH. Fallback if `--append-system-prompt-file` ever proves inert
interactively: pass the content inline via `--append-system-prompt`.

## Target environment

The reference deployment is a Windows forensic VM with WSL2 running SIFT:
the client session and all evidence processing live on the SIFT side; the
Windows GUI toolset (Zimmerman tools, Timeline Explorer, Registry
Explorer, Arsenal, FTK Imager, …) is one alt-tab away. The doctrine —
**GUI to explore, MCP to prove** — is part of the profile: analyst GUI
discoveries get re-derived through the MCP twin (Registry Explorer →
`ez.recmd_hive`, ShellBags Explorer → `ez.sbecmd`, MFTExplorer →
`ez.mftecmd`, Event Log Explorer → `ez.evtxecmd`, …) so findings can cite
a traced call. The dashboard and vera web are reachable from the Windows
browser via WSL localhost forwarding.

## The mirror (kept, standalone)

`pilot/mirror.py` converts a TRUDI trace into a browsable `.vera` case —
batch (`python -m pilot.mirror <trace.json> <case.vera>`) or `--follow`
(idempotent tail; `trudi --mode pilot --mirror` starts it automatically).
Field mapping is verified against vera v0.24 schema 19: tool_call →
Action (cid marker; full stdout stays in TRUDI's sidecar), finding →
Finding with the whole typed claim in attrs, `verify_evidence_hash` →
Evidence row, DAIR work order → Lead + items, narration → notes. The
`.vera` is a DERIVED artifact — always rebuildable from the trace, which
remains the authoritative record.

## Retired components

The prompt_toolkit REPL (`pilot/repl.py`), its work-order state machine
(`pilot/workorder.py`), and their tests were retired when pilot mode moved
onto the agent clients — the REPL was re-implementing agent capabilities
(arg filling, command drafting, output digests, briefing extraction) that
the clients do natively. Their UX lessons live on as profile instructions;
the code is in git history (branch `pilot`, pre-rebase). The server-side
assistance tools they motivated (`reason.draft_command`, `reason.advise`,
`reason.extract_case`) remain available to any client.

## Future work

- **Strict approval posture**: OpenCode's per-agent permission block could
  set forensic MCP namespaces to ask-level for the pilot agent (bookkeeping
  stays allowed). Claude Code's settings precedence (deny > allow > ask)
  means an ask-overlay cannot beat the case template's blanket
  `mcp__trudi-sift__*` allow without restructuring that allow — revisit if
  conversational control proves insufficient.
- Vera web work-order panel (bridge HTTP surface) — unchanged from the
  original plan, still optional polish.
- Custody: include the TRUDI trace + `.tool_output` sidecars in vera's
  signed chain-of-custody bundle.

## Verification walkthrough

1. Re-run the registrar (`./install.sh`, or
   `python3 opencode/register_opencode.py ~/.config/opencode ~/trudi
   ~/.venv/bin/python3`); `opencode agent list` shows `trudi-pilot`.
2. `cd ~/cases/nitroba && trudi --mode pilot --client claude` — the
   copilot does the bookkeeping, presents the case, proposes the pcap
   opening playbook, and WAITS. Ask it to run
   `net.tcpdump_list_connections`; confirm the trace grows with cited call
   ids. Ask "what did the cookie inventory show?" — it answers via a
   traced read. Ask it to draft a finding — it shows the typed claim and
   asks before `misc.record_finding`.
3. Repeat with `--client opencode` (the trudi-pilot agent is active).
4. `trudi --mode pilot --mirror` — the `.vera` file grows live.
5. `python -m pytest -q` — suite green.

Note: agent and pilot sessions on the SAME case contend for the TRUDI
session beacon (`~/.cache/trudi/session.json`) — one investigation per
case at a time, as always.
