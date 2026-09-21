# Why curiosity probes are rarely recorded

Baseline read-only assessment, 2026-09-20. Subsequent runtime fixes and outstanding
work are tracked in [the workflow review](investigation-review.md#follow-up-delivery-status).
The full design is in [the general investigation plan](investigation-improvements-plan.md#4a-make-bounded-curiosity-usable-and-observable).

## What the traces establish

A targeted sample of five analysis traces contains 45 DAIR responses granting a positive curiosity budget and zero `curiosity_probe` entries:

| Trace | Positive budget grants | Recorded probes | Positive-grant intervals with at least 30 subsequent entries before the next DAIR/end |
|---|---:|---:|---:|
| `belkactf6-bogus-bill/analysis/BELKACTF6-BOGUS-BILL_trace.json` | 6 | 0 | 2 |
| `cfreds-deepseek/analysis/CFREDS-LEAK-DEEPSEEK_trace.json` | 11 | 0 | 4 |
| `nitroba/analysis/NITROBA-2008_trace.json` | 1 | 0 | 0 |
| `srl-2018-enterprise/analysis/SRL-2018-ENTERPRISE_trace.json` | 17 | 0 | 6 |
| `vanko-deepseek41/analysis/VANKO-2016-DEEPSEEK41_trace.json` | 10 | 0 | 3 |

Paths are relative to `/home/trin/cases/`. Counted only these analysis traces, not duplicate report exports. These are grants, not proof that each batch completed or offered a useful probe. The interval column measures exposure to the short-window defect, not observed rejected attempts. The same scan found one recorded probe in each of `clancy-trial/analysis/CLANCY-2026-PATRICK_trace.json` and `vanko-claude/analysis/VANKO-2016-CLAUDE_trace.json`, so the mechanism is reachable.

Absence-mode reasoning is also not equivalent to recorded curiosity. The newest DeepSeek trace has two hypothesis calls whose persisted prompts use the absence-mode `UNRESOLVED QUESTION` form, but no probe entries. Ordinary forensic calls may still explore those leads. Existing logs do not reliably separate prescribed work from unlogged exploration, so zero probe records does **not** establish zero investigative curiosity.

These observations span cases and roles, but are not a controlled model comparison. Current code explains plausible mechanisms; historical runs may have loaded different revisions or client profiles. Do not attribute every missing probe to the current defect without an actual failed invocation.

## Mechanisms in the baseline implementation

1. **Exploration is scheduled after potentially expanding mandatory work.** [Claude's loop](../claude/CLAUDE.md) allows probes only after the entire work order finishes. The same profile merges subsequent reasoning directives into that work order and requires concrete follow-ups extracted from prose. More mandatory work can keep moving the optional step away. [OpenCode's loop](../opencode/AGENTS.md) has the same after-work-order sequencing. This is a likely starvation mechanism, not proof of the agent's internal motivation.

2. **The instructions conflict.** [The DAIR prompt](../tools/dair.py) says the investigator executes only `priority_tools` and nothing else will run, then grants an allowance for investigator-chosen work outside that list. Claude's profile documents an exception, but the planner's own absolute instruction remains. A budget is permission; it supplies neither an executable candidate nor a reason to choose one now.

3. **A live allowance falls out of a 30-entry window.** [The recording tool](../tools/misc.py) calls `curiosity_budget.check(log.last_n_window(30), rationale)`. [The gate](../tools/_gates/curiosity_budget.py) searches only that window for the latest DAIR grant; no grant means zero budget. [The log method](../core/execution_log.py) returns the last 30 entries of every type, including narration/review bookkeeping. After 30 intervening entries, an unused positive grant becomes unavailable even without a new DAIR call. A small synthetic invocation of the actual gate returned success with 29 intervening entries and `No curiosity budget granted` with 30. This is a reproduced implementation defect. Calling DAIR just to recover that allowance adds avoidable model work and may replace the work order.

4. **Recording happens after the work and is easy to omit.** The tool contract tells the agent to run a normal forensic tool, then call `misc.record_curiosity_probe`. The gate governs the recording operation, not dispatch of the preceding forensic tool. There is no atomic link between intent, spend, execution and outcome; the current recorder accepts rationale and optional lineage without checking a completed read-only execution. It is therefore both extra interaction and an incomplete measure of actual exploration. Seed evidence and result evidence are not distinguished by the API.

5. **Generated probes can become ordinary binding work.** [Absence-mode reasoning](../tools/reasoning.py) calls its output curiosity candidates but places them in `priority_tools`. Agent profiles merge that field into binding work orders. A useful exploratory idea can thus be executed as prescribed work with no curiosity record, or add more work ahead of the optional exploration step. Required coverage and discretionary hunches need separate status even when they use the same scheduler.

6. **Discoverability varies by client.** [Slim tool descriptions](../core/slim_descriptions.py) preserve a curated hypothesis description that does not explain `mode="absence"`. The default first-paragraph summary for the curiosity recorder omits its later sequencing, budget and lineage instructions. OpenCode's main profile mentions probes but lacks Claude's fuller absence-mode explanation; the two Pilot profiles do not explicitly describe the curiosity workflow. Parameter schemas still expose mode and tool discovery remains possible, so this is reduced guidance rather than a disabled feature.

7. **Examples steer toward a narrow investigation pattern.** The absence prompt emphasizes identities, another principal, exfiltration and host artifacts. DAIR assumes a confirmed positive detection at investigation start. Those defaults fit some investigations but can be unhelpful for documentary questions, benign activity, non-host evidence or other unresolved mechanisms. Candidate generation should follow the actual question and available source capabilities, including evidence against the leading explanation.

## General design consequence

Treat exploration as an optional, budgeted task with a durable grant, a visible opportunity, a falsifiable question, an actual execution receipt and an outcome. Permit a reasoned decision that no useful probe remains. Do not require more probes merely to improve a utilization statistic, and do not turn discretionary suggestions into hidden report blockers.

Use one task/receipt model for required work and exploration, preserving their different transition effects. Keep probe metadata separate from citable source evidence; all resulting findings still require the normal review. Historical examples above diagnose behavior only. No runtime rule, candidate list or acceptance criterion should depend on these cases' names, artifacts or answers.
