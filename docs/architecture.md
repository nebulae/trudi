# TRUDI Architecture

This diagram is the submission architecture artifact for the Find Evil!
hackathon. It emphasizes the security boundary judges care about most:
TRUDI does not rely only on prompt instructions. Forensic execution is routed
through typed MCP tools, middleware gates, and executor-level evidence
protection before any external binary or live endpoint command can run.

```mermaid
flowchart LR
    User["DFIR practitioner"] --> Claude["Claude Code\nprimary analyst"]
    Orchestrator["Global orchestrator\nclaude/CLAUDE.md"] --> Claude
    CaseBrief["Case brief\ncases/CASE_ID/CLAUDE.md"] --> Claude

    subgraph MCP["Architectural guardrail: TRUDI MCP boundary"]
        Server["FastMCP server\nserver.py"]
        Middleware["Middleware\nDAIR window + narration"]
        Tools["Typed tool namespaces\nforensics, live, monitor, respond"]
        Gates["Finding gates\nconfidence, lineage, citation, MCP routing"]
    end

    subgraph Guidance["Parallel guidance tools"]
        DAIR["DAIR\nphase director"]
        Reason["reason.*\nadversarial reviewer"]
        DAIRBackend["DAIR backend"]
        ReasonBackend["Reason backend"]
    end

    subgraph Execute["Execution boundary"]
        Executor["Safe executor"]
        PathGuard["Read-only evidence guard"]
        SSH["Argv-only live SSH"]
        SIFT["SIFT forensic tools"]
    end

    subgraph Targets["Evidence and endpoints"]
        Evidence["Static evidence\nimages, memory, logs, PCAPs"]
        Endpoint["Registered live endpoint"]
        Velo["Velociraptor demo stack"]
    end

    subgraph Audit["Audit and output"]
        Trace["Execution trace\n_trudi_call_id"]
        Findings["Findings\nlinked_call_id required"]
        Reports["Reports"]
        Dashboard["Dashboard"]
        Accuracy["Accuracy / coverage"]
    end

    Claude -- "MCP tool calls only" --> Server
    Server --> Middleware --> Tools
    Middleware --> Gates

    Tools --> Executor --> PathGuard --> SIFT --> Evidence
    Tools --> SSH --> Endpoint
    Tools --> Velo

    Tools --> DAIR --> DAIRBackend
    Tools --> Reason --> ReasonBackend
    DAIR -- "phase + priority_tools" --> Claude
    Reason -- "plan + review" --> Claude

    Executor --> Trace
    SSH --> Trace
    Middleware --> Trace
    Gates -. blocks unsupported findings .-> Findings
    Tools -- "misc.record_finding" --> Findings
    Findings --> Trace
    Trace --> Reports
    Trace --> Dashboard
    Trace --> Accuracy

    PathGuard -. rejects evidence writes .-> Executor

    classDef guard fill:#fff4e5,stroke:#c77700,stroke-width:2px,color:#111;
    classDef evidence fill:#eef8f0,stroke:#2e7d32,stroke-width:2px,color:#111;
    classDef audit fill:#f7efff,stroke:#7b1fa2,stroke-width:2px,color:#111;
    classDef actor fill:#eef3ff,stroke:#4051b5,stroke-width:2px,color:#111;
    style MCP fill:#f5f7ff,stroke:#4051b5,stroke-width:2px,color:#111
    class Server,Middleware,Tools,Gates,Executor,PathGuard,SSH guard;
    class Evidence,Endpoint,Velo evidence;
    class Trace,Findings,Reports,Dashboard,Accuracy audit;
    class User,Claude,Orchestrator,CaseBrief actor;
```

## Guardrail Summary

| Boundary | Enforcement | Repository location |
| --- | --- | --- |
| Forensic tools must route through MCP | `core/middleware.py` detects direct forensic binary use and points the agent to typed wrappers | `core/middleware.py`, `tools/_gates/mcp_routing.py` |
| Evidence remains read-only | Output paths resolving under `/cases/`, `/mnt/`, `/media/`, or any `evidence/` segment are rejected before subprocess execution | `core/paths.py`, `core/executor.py` |
| Live endpoint commands avoid shell injection | Live tools use registered host aliases and fixed argv command construction over SSH | `core/ssh.py`, `tools/live.py` |
| Findings must be traceable | `misc.record_finding` requires `linked_call_id` to point to the producing `_trudi_call_id` | `tools/misc.py`, `tools/_gates/linked_call_id_must_exist.py` |
| Confirmed claims require review | Confidence, citation, DAIR, lineage, and adversarial-review gates block unsupported findings | `tools/_gates/*`, `tools/reasoning.py`, `tools/dair.py` |
| Audit trail is durable | Tool calls, reason calls, DAIR transitions, self-corrections, curiosity probes, and findings are written to JSON/Markdown trace logs | `core/execution_log.py`, `dashboard/*` |

## DAIR And Reason

DAIR and `reason.*` are separate MCP tool families. Claude invokes each through
the TRUDI MCP server and consumes their returned guidance; neither component
calls the other directly.

| Component | Purpose | Typical output | Trace entry |
| --- | --- | --- | --- |
| DAIR phase director | Maintains the investigation phase model: Triage, Scope, Analyze, Verify, and Report. It challenges whether the investigation is ready to move forward, identifies missing work, and returns `priority_tools` for the next batch. | Phase assessment, transition recommendation, verification challenges, investigation focus, priority tools | `dair_call` |
| `reason.*` adversarial reviewer | Provides analytical review around the evidence. It creates initial plans, generates hypotheses for ambiguous artifacts, evaluates whether findings are supported, performs citation/confidence checks, and synthesizes the final report posture. | Plan, hypothesis, finding evaluation, confidence score, citation check, synthesis, pre-report readiness | `reason_call` |

Tool selection is grounded by `tools/tool_capabilities.py`, a curated capability
manifest that maps phases and evidence types to allowed tool IDs and substitution
rules. DAIR and `reason.*` include the manifest in their prompts, and parsed
directives are annotated with `tool_manifest_version`, `priority_tool_capabilities`,
and `unknown_priority_tools`.

Beyond the prescribed work order, `dair_assess` returns a `curiosity_budget`: a
small allowance of read-only, self-directed looks the agent may take to chase a
hunch the work order did not name (a second SID's recycle bin, an untouched comms
store, a weaker exfil channel). Each look is logged as a `curiosity_probe` trace
entry via `misc.record_curiosity_probe` and is budget-enforced by
`tools/_gates/curiosity_budget.py`. A probe carries no evidentiary weight on its
own — to support a finding, its `call_id` must flow into `reason.*` or
`misc.record_finding` through `input_call_ids`, where the normal finding gates
apply. This widens coverage without loosening a gate. All three dashboard views
(`dashboard/trace_viewer.html`, `chain_view.html`, `graph_view.html`) render
curiosity probes and the lineage edges that connect them to the artifacts they
inspected and any finding they ultimately fed.

## Primary Data Flow

1. The practitioner opens a case in Claude Code with the TRUDI orchestrator and
   case-specific `CLAUDE.md`.
2. Claude selects forensic actions, but execution crosses the typed TRUDI MCP
   boundary rather than running SIFT binaries directly.
3. Middleware records call initiation, enforces recent DAIR guidance, and keeps
   narration in the trace.
4. Tool wrappers call the safe executor or live SSH runner. Output safety checks
   reject writes to evidence locations before the command runs.
5. Each successful or failed execution receives a `_trudi_call_id` in the trace.
6. Findings are submitted through `misc.record_finding` and must link back to
   the exact producing call ID.
7. DAIR and `reason.*` run as separate MCP tool families. Claude consumes both
   result streams; DAIR does not call reasoning, and reasoning does not call
   DAIR.
8. Accuracy, coverage, attribution, reports, and dashboards consume the same
   trace, so every final claim remains auditable.
