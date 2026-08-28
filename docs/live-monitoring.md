# TRUDI live-monitoring & gated response — full reference

Applies only to Velociraptor-backed live-monitoring cases. Static forensic investigations never use this subsystem. CLAUDE.md carries a one-paragraph summary; this file is the detail.

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
   Exercise/demo cases may opt in to responding to confirmed planted TTPs via
   `monitoring/config.json` `demo_response.respond_to_synthetic=true`; those
   findings are treated as exercise-positive threats, not false positives.
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
Demo response is separately opt-in:
`{"demo_response":{"enabled":true,"respond_to_synthetic":true}}` means
CONFIRMED/LIKELY planted demo TTPs are response-eligible even when their
markers prove lab/exercise infrastructure. Keep the language precise:
"contained planted demo TTPs", not "remediated a real compromise".

`respond.*` cannot touch anything under `/cases/.../evidence/`,
`/mnt/`, or `/media/` — those refusals are unchanged.

**Not available:** MemProcFS, VSCMount (Windows-only), tshark, hayabusa, guymager.

**Volatility exit codes:** `1` = plugin ran but failed (may be normal — e.g. no data). `2` = argument error (TRUDI bug). `-1` (timeout) = symbols not cached — run `vol_symbol_check`.

---
