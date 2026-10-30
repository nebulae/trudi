---
description: "Drain TRUDI live-monitoring alerts and run a per-tick investigation over the bundle"
argument-hint: "[case_id]"
---

# /trudi-check-alerts

Polls the active TRUDI live-monitoring case for new alerts and runs
**one investigation per /loop tick** over the entire bundle of alerts
drained in that tick. Designed to be called on a fixed interval via
`/loop 15s /trudi-check-alerts` so anomalies are investigated within
~30s of firing on the victim host.

The argument, if supplied, names the case. Otherwise read it from
`~/cases/.common/active_case`.

## Response ordering — contain → eradicate → investigate-for-record

Both response actions are fast and up front; the forensic write-up trails and
never blocks them:

1. **Contain first (step 4).** The moment a high-confidence alert is in hand —
   *before* any `reason.*` / `dair_assess` call — snapshot the volatile evidence
   (read-only, ~seconds) and auto-execute the **reversible, low-risk**
   containment (e.g. block the egress channel). AUTO tier: no approval, no finding.
2. **Offer eradication right after (step 5).** For a confirmed-positive alert
   class, resolve the kill target with ONE fast pivot (or take the `pid`/
   `image_path` the bundle already carries) and immediately **queue the
   destructive action for operator approval** (a popup). This is seconds after
   containment — it waits only on *target resolution*, NOT on the finding/report
   ceremony. (The earlier design put eradication after the full investigation; a
   real run then contained in ~1s but never offered the kill, because the finding
   ceremony ran ~24 min and never finished. Don't repeat that.)
3. **Then the full investigation + report (step 6).** hypothesize → DAIR →
   findings → report, for the court-record, running *after* the response is
   already in flight. If it unexpectedly clears the alerts as benign, revert the
   step-4 containment and drop any still-queued eradication.

Containment is reversible so it runs on its own; eradication is irreversible so it
is operator-approved — but both fire within seconds, gated only on a
confirmed-positive alert plus a resolved target, never on the paperwork.

## ⛔ ABSOLUTE RULE — response precedes reasoning (live override, read twice)

On a tick with response-eligible alerts, the block `respond.execute_action` and
the eradication popup are your **first actions of the investigation**, and they
come **before the tick's first `reason.hypothesize` / `reason.plan` /
`dair_assess` call.**

This **OVERRIDES** the global TRUDI contract's *"run `reason.hypothesize` at the
very start of Triage, before `reason.plan`."* In a live-monitoring tick, **Triage
does not begin — and no `reason.*`/`dair_assess` call fires — until the reversible
block is executed AND the eradication action is queued for approval (or you've
confirmed there is nothing to eradicate).**

If you are about to call `reason.*` or `dair_assess` and the block has not executed
this tick, **STOP** and execute it first. A real run violated this: it had an
`executable` block in hand at 19:02:03 and spent **41 seconds running
`reason.hypothesize` before pulling the trigger** at 19:02:44 — containment lost
the race to a reasoning call that should not have run yet. Do not repeat it.

## Trace routing contract — read first

Live-monitoring cases use **per-investigation traces**. Each
`/trudi-check-alerts` tick that finds alerts opens (or resumes) ONE
investigation, identified by an `INV-NNN` id. Its trace lives at
`<case>/analysis/<case>_<INV-NNN>_trace.json` — flat under `analysis/`
so the dashboard scan picks it up. All alerts drained in that tick
share that single trace.

The case-wide trace at `<case>/analysis/<case>_trace.json` records
**orchestration only**: `monitor.list_watchers`,
`monitor.check_alerts`, `monitor.next_investigation_id`,
`monitor.open_investigation_state`,
`monitor.start_investigation` / `extend_investigation` /
`end_investigation` markers, `monitor.ack_alert`, and any operator
messages typed outside an open investigation.

The switch happens via `monitor.start_investigation` and
`monitor.end_investigation`. **Do not call
`misc.start_execution_log` during this workflow** — those helpers
manage the trace path.

Operator-typed messages follow the same routing automatically: the
`UserPromptSubmit` hook reads `~/.cache/trudi/session.json` (which
`log.configure()` updates whenever the trace flips) and appends the
typed prompt to whichever trace is currently active. That's how
`approve ACT-N` lands in the per-investigation trace and how the
`operator_text_required` gate finds it.

If response actions are pending operator approval at end of tick, the
investigation stays open across ticks — `_open_investigation.json`
holds the state, and the next tick rehydrates the same trace via
`start_investigation` (it's idempotent).

## Workflow

### 1. Resolve case + ensure case-wide trace

> **Tool schemas:** `monitor_*`/`respond_*`/`velo_*` are deferred tools. If this
> session has not already loaded them (e.g. `/trudi-watch-alerts` pre-warmed them —
> it does), batch-load the response set in ONE `ToolSearch("select:…")` call now,
> before draining alerts — searching per-tool mid-alert cost a real run ~30 s
> before it could contain. Once loaded they stay callable; never re-`ToolSearch`
> per tick.

1. Resolve `case_id` from `$ARGUMENTS` if non-empty, else
   `cat ~/cases/.common/active_case`. Refuse if neither is set.
2. Ensure the case-wide trace is active. If
   `core.execution_log.log._path` is unset (cold start), call
   `misc.start_execution_log(case_id,
   output_path="./analysis/<case>_trace.json")`. Otherwise skip — the
   case-wide trace is already configured from a prior iteration.
3. Call `monitor.list_watchers(case_id)`. If empty or none alive,
   surface a one-line warning and exit — there is nothing to consume.

### 2. Check for an open investigation + drain new alerts

```
state  = monitor.open_investigation_state(case_id)
alerts = monitor.check_alerts(case_id, since_seq=<read _last_check_seq>)
```

Branch:
- `alerts.empty AND not state.open` → print `"No anomalies."` and exit.
- `alerts.empty AND state.open` → continue at step 3 to handle pending
  approvals on the open investigation.
- `alerts.nonempty AND not state.open` → continue at step 3 to open a
  new investigation.
- `alerts.nonempty AND state.open` → continue at step 3 to extend the
  open investigation with the new alerts.

**Recurrence fast path.** `check_alerts` stamps each alert with its process
`signature` and, when a prior investigation fed that signature back via
`monitor.baseline_extend`, with `known_benign` (the investigation + finding
that established it). If `alerts.all_known_benign` is true, still open the
investigation (step 3) but SKIP steps 4–6 (no containment, no hypothesize /
DAIR cycle, no eradication): take one fresh `live.processes` (or
`Linux.Sys.Pslist`) capture, record an UNCONFIRMED `claim_kind="negative"`,
`category="execution"`, `act="execution"` finding stating the alerts are a
recurrence of the known-benign activity, citing the prior `finding_id` from
`known_benign` and the fresh capture, then go to step 8 (close). If only SOME
alerts are `known_benign`, investigate the bundle normally — the unknown ones
are the question.

### 3. Open / resume / extend the investigation trace

```
if state.open:
    investigation_id = state.investigation_id
    monitor.start_investigation(case_id, investigation_id,
                                alert_ids=state.alert_ids + [a.alert_id for a in alerts])
        # idempotent — rehydrates the existing trace
        # capture genesis_call_id (cid of the genesis agent_message
        #   that start_investigation just wrote in the per-investigation
        #   trace; root of every input_call_ids chain below)
        # capture rehydrated_entries — if > 0, we're resuming work
    if alerts.nonempty:
        monitor.extend_investigation(case_id, investigation_id,
                                     new_alert_ids=[a.alert_id for a in alerts])
else:
    inv = monitor.next_investigation_id(case_id).investigation_id
    monitor.start_investigation(case_id, inv,
                                alert_ids=[a.alert_id for a in alerts])
    investigation_id = inv
```

After this step, the active trace is the per-investigation file. The
`user_message` hook follows automatically via the session beacon.

**Opening the investigation is NOT entering Triage.** Do not call
`reason.hypothesize` / `reason.plan` / `dair_assess` here. Your very next actions
are step 4's response reflex (snapshot → block → eradication popup). Triage (step
6) begins only after that.

> If `rehydrated_entries > 0` AND `alerts.empty` — we're only here to handle a
> pending approval on a previously-opened investigation. Containment and the
> investigation already ran on an earlier tick; **skip to step 7** (operator
> approvals), then step 8.

### 4. Contain FIRST — reversible, off the alert, before any reasoning

**CEF trust gate.** For `DecoyTouch`, require `response_eligible: true` before
using the confirmed-positive fast path. Unsigned, replayed, or unbound CEF is
investigation input only: investigate and corroborate it, and surface any
response for operator approval. Never infer trust from the detector name or
copy an authentication flag into an action. Pass the alert's complete evidence
(including `alert_id`) into `respond.suggest_containment`; the server verifies
the saved signature and source/decoy bindings before permitting AUTO execution.

This runs only when there are **new alerts this tick** and they are
response-eligible. It is the **first thing you do after opening the investigation**
and it precedes every `reason.*` / `dair_assess` call (see the ABSOLUTE RULE
above) — the point is to stop an active intrusion at machine speed, not to wait on
the finding ceremony. If a reasoning call is tempting here, you are early: the
block must execute first.

> **The CEF ingest sidecar usually beat you to it.** For a confirmed-positive
> class (`DecoyTouch`), `trudi-cef-ingest.py` auto-executes the reversible/low
> containment **server-side the instant the alert lands** — so when you wake, the
> block is very likely ALREADY done. Call `monitor.get_response_state` and/or
> `respond.list_actions` FIRST: if the block action already shows an execution
> (`auto_executed` lists it / the `block_egress_to_endpoint` ACT has run), **do NOT
> re-run it** (a second `iptables -I` just stacks a duplicate rule). Acknowledge
> "containment already auto-applied by the sidecar", print its rollback, and go
> **straight to step 5** (eradication). Only run 4a–4c yourself if the sidecar did
> NOT contain (e.g. a detector class it doesn't auto-handle, or auto-contain was
> disabled).

**4a. Check posture.** Call `monitor.get_response_state(case_id)`.
- If `paused == true`, a prior tick already queued a destructive action awaiting
  the operator. Do NOT classify or execute anything new — re-surface each pending
  `approve ACT-N` prompt (with its would-be rollback) and **skip to step 7** (the
  investigation stays open).
- `get_response_state` also returns `demo_response`. In normal cases,
  synthetic/demo markers are false-positive evidence and must NOT trigger
  endpoint mutation — skip containment and investigate normally. Only in an
  explicitly opted-in exercise case (`demo_response.enabled == true` AND
  `demo_response.respond_to_synthetic == true`) are CONFIRMED/LIKELY planted demo
  TTPs treated as **exercise-positive threats** — response-eligible even on
  lab-only infrastructure (TEST-NET addresses, `TRUDI_DEMO_*` markers). Word the
  report as "contained planted demo TTPs", not "remediated a real compromise".

**4b. Snapshot the volatile evidence (read-only, mandatory before the block).**
Containment tears down the very artifacts a finding cites — `iptables REJECT`
drops the ESTABLISHED flow; a freeze/kill changes the process table. For each
response-eligible alert call

```
respond.snapshot_evidence(case_id, detector=<alert detector>,
                          evidence=<alert evidence>, client_id=<the alert's client_id>)
```

It runs the detector-appropriate READ-ONLY live captures **on the host the alert
came from** (resolved from `client_id` — pass it so a multi-host case snapshots
the right host; omitting it falls back to the single configured host and, on a
lateral A→B case, captures the wrong host) and returns `snapshot_call_ids`. This
is seconds of read-only SSH, so it does not cost containment latency. **Carry
`snapshot_call_ids` into the step-5 eradication evidence and the step-6 findings'
`input_call_ids`** so the intrusion stays provable after the channel is cut.

**4c. Auto-execute the reversible/low-risk containment.** For each
response-eligible alert:

```
respond.suggest_containment(case_id,
    detector="Custom.TRUDI.<DecoyTouch|NewLogon|NewNetwork|NewProcess|PrivilegeEscalation|NewPersistence|YaraProcess>",
    evidence=<the alert's evidence dict>, client_id=<the alert's client_id>)
    # finding_id OMITTED — live fast path; the finding is recorded in step 6.
    # client_id routes every action to the alerting host.
```

The instant `suggest_containment` returns an action that is **`executable: true`
AND `reversible: true` AND `risk: low`**, your **VERY NEXT tool call** is its
`respond.execute_action(case_id, action_id="ACT-N", mode="auto")` — nothing goes
between the suggestion and the block: no `reason.*`, no `dair_assess`, no extra
pivots, no narration-only turn. (The server permits the AUTO tier under
auto-protect and runs it over the gated write-SSH path.) Act by what the action
IS, not by classifying it yourself. On success, tell the operator what ran and
**print the `rollback_command` verbatim**:
> 🛡️ Contained **ACT-1** (reversible/low): `iptables -I OUTPUT -d 10.73.0.60 -p tcp --dport 3389 … -j REJECT` → OK
> Undo: `iptables -D OUTPUT …`

**Do NOT execute, auto-run, OR queue-for-approval the destructive actions here.**
An action that is irreversible (`reversible: false`), `risk >= medium`, or still
carries `unresolved_placeholders` (a `kill -9 <pid>` whose `pid` the alert
doesn't carry) is **eradication** — it belongs to **step 5**, offered within
seconds after a fast target-resolving pivot (NOT after the full investigation).
Note them as "deferred to eradication" and move on to step 5. Also skip any action with `executable: false` whose
`blocked_reason` is a validator rejection (a quarantine/kill aimed at a SYSTEM
binary like `/usr/bin/sleep`, a protected account) — surface it as an
informational note only; a shared system binary is never a containment target.

Containment latency is now ≈ one read-only snapshot + one SSH write, with zero
model/reasoning calls in front of it.

### 5. Resolve the target and offer eradication — fast, right after containment

Eradication is destructive, so it needs a high-confidence basis AND a resolved
target — but it must NOT wait on the full finding/report ceremony (that is step 6,
and it can run for many minutes). Offer it immediately after step 4, decoupled
from the forensic write-up. (This is the lesson from a run where containment fired
in ~1s but the kill, sitting ready behind a 24-minute finding ceremony that never
finished, was never even offered.)

**5a. High-confidence enough to eradicate now?** Eradicate-on-sight is justified
when the alert class is a confirmed positive with no false-positive branch — a
`DecoyTouch` (a honey credential has no legitimate use), an exercise-positive
planted TTP (`demo_response`), or a detector hit the operator pre-classed as
auto-eradicable. If the alert is ambiguous (a `NewProcess`/`NewNetwork` that could
be routine), do NOT offer a destructive kill yet — defer to step 6 and eradicate
from there only if it confirms.

**5b. Resolve the kill target — fast, NOT the DAIR loop.** The destructive actions
(`kill_owning_pid` / `kill_by_image`) need a `pid` / `image_path`. Get it the
quickest way available — this is one or two calls, seconds, no
`reason.hypothesize`/`dair_assess` in front of it:
- If the bundle already carries it — a `NewProcess` alert's `pid`/`image_path`, or
  the owning pid in the step-4 snapshot's `network_connections` capture — use that
  directly.
- Otherwise ONE targeted pivot: `velo.collect_artifact(Linux.Network.Netstat)` →
  the flow's owning pid → `Linux.Sys.Pslist` for its `image_path`.

**5c. Enrich + queue the kill for approval.** Re-call `respond.suggest_containment`
with the enriched evidence; the kill `ACT-N` returns `executable: true` and
**supersedes** the placeholder draft. Attempt
`respond.execute_action(case_id, action_id="ACT-N", mode="auto")` → the server
refuses with `gate: "approval_required"` (destructive). Do NOT retry — queue it
(`monitor.set_awaiting_approval(case_id, action_ids=["ACT-N"])`) and ask with a
**popup** (`AskUserQuestion`, NOT a "type this" instruction), the approve option's
label carrying the literal `ACT-N` (what the `operator_text_required` gate matches
after the PostToolUse hook records the selected label as a `user_message`):
- question: `"Eradicate the beachhead's RDP client process? ACT-N: kill -9 783 (irreversible)"`
- options: `"Approve ACT-N"` (→ authorises) · `"Skip ACT-N"` (→ stays queued)

Once the popup is up, this tick's **response** is done — containment is live and
eradication is one approval away, within seconds of the alert. Step 6 has not run
yet and must not hold any of this up. On **Approve**, authorise + execute (step 7);
on **Skip**, leave it queued. Once a destructive action is pending, take no new
autonomous actions this tick.

**Prefer `kill_by_image` for a respawning implant** (a cron/service relaunches
fresh PIDs; a single-pid kill leaves siblings and `verify_clean` stays dirty) —
but **skip any action `executable: false` for a validator reason** (`blocked_reason`
= "not under an allowed prefix" / a SYSTEM binary / a protected account): a shared
system-path binary is never a kill target. If a path-blocked `kill_by_image` is the
only image action, offer the single-pid `kill_owning_pid` instead.

**Nothing to eradicate is a clean outcome, not a failure.** A login-only touch has
no persistent payload, and cutting the egress in step 4 already drops the held
session — so the owning process may already be gone (the step-4 snapshot still
holds it for the record). Note it and move on; the recover decision is "keep the
block" plus a credential-rotation rec in the report, not a kill.

### 6. Full forensic investigation + report (for the record — never blocks response)

Containment is live and any eradication is already queued for approval; NOW run the
investigation that produces the court-record. It must not gate any step-4/5 action.
**This is where the tick's first `reason.hypothesize` / `dair_assess` call belongs
— and not one call earlier.** (If you have not executed the block and queued/skipped
eradication yet, you are in the wrong step — go back to 4 and 5.)

```
reason.hypothesize(
    observation="Live alert burst: <N> alerts via Velociraptor",
    evidence=<json of the bundle: per-alert summary, detector counts, hosts>,
    context="case=<case_id>; investigation=<INV>; alert_ids=...",
    input_call_ids=[genesis_call_id, <step-4 snapshot_call_ids>])

dair.assess(
    tool_results_summary="Investigation opened on bundle of <N> alerts; reversible containment applied, eradication queued for approval",
    phase_stack="[]",
    case_context="CASE_QUESTION: ...; investigation_id=<INV>",
    input_call_ids=[genesis_call_id, hypothesize_cid])
```

The phase stack starts empty — gate windows are scoped to this
per-investigation trace.

Then execute the DAIR `priority_tools` batch (velo.* substrate per the
existing guidance, see Substrate section below). Per finding:
- `reason.confidence_score` + `reason.cite_check` (so the
  `confidence_and_citation` gate passes for tier ≥ LIKELY)
- `misc.record_finding(...)` with
  - `linked_call_id = <source tool cid>`
  - `input_call_ids = [genesis_call_id, hypothesize_cid, <step-4 snapshot_call_ids>, <step-5 pivot cids>, <tool cids>]`
  - `tested_hypothesis_id = <hypothesis_id>`
  - description including detector T-numbers where applicable so
    `mitre_technique_validation` passes.

Cite the step-4 `snapshot_call_ids` and the step-5 pivot call_ids in each finding's
`input_call_ids` so the intrusion stays provable after contain/eradicate.

**Recover / benign reversal.** If — against the step-5a assumption — the
investigation concludes the alerts were legitimate activity, undo the response:
`respond.revert_action` each reversible step-4 action, and for any eradication
still only *queued* (not yet approved), drop it
(`monitor.clear_awaiting_approval(case_id, "ACT-N")`) without asking the operator.
Then feed the verdict back per step 7b. (A confirmed-positive class like
`DecoyTouch` won't reach this branch — it exists for the ambiguous detectors
deferred from step 5a. A contained/eradicated threat is NOT an allowlist entry —
only this benign branch calls `baseline_extend`.)

### 7. Operator approvals (resume path)

When the operator approves — either by selecting the `Approve ACT-N` option in
the step-6 popup (the `PostToolUse` hook records that selected label as a
`user_message`), or by typing `approve ACT-N` directly (the `UserPromptSubmit`
hook; still supported) — authorise + execute it:
```
respond.approve_action(case_id, "ACT-N", operator_text="ACT-N")
respond.execute_action(case_id, "ACT-N", mode="operator")
monitor.clear_awaiting_approval(case_id, "ACT-N")
```
`approve_action` succeeds because a recent `user_message` (popup or typed)
contains the `ACT-N` id — the agent still cannot self-approve, since only the
hooks write those entries from genuine human input. Print the
`rollback_command` for the executed action. To undo a prior action on request,
call `respond.revert_action(case_id, "ACT-N")`.

### 7b. Feed a benign verdict back (mandatory when the verdict is benign)

When the investigation's verdict is that the alerts were **legitimate
scheduled or routine activity** (a cron chain, a package timer, a monitoring
agent's own child) — not an intrusion — do not leave detection to re-learn it
tomorrow. Call:

```
monitor.baseline_extend(case_id, client_id=<alert client_id>,
                        benign_alert_ids=[<every alert id in the bundle that is benign>],
                        image_paths=[<image paths the verdict cleared, if any>],
                        root_image_paths=[<root-owned ones>],
                        reason="<one sentence: what it is and which finding proved it>",
                        finding_id="<the LIKELY/CONFIRMED benign finding's id>",
                        evidence_call_ids=[<the finding's cited cids>])
```

It records the alerts' process signatures as `benign_signatures`, extends the
allowlists, logs the change in the baseline's `extensions` ledger with your
reason, and re-pushes the detectors. Say in the closing narration what was
added. Never call it for an intrusion that was contained — a contained
threat is not an allowlist entry.

### 8. Close the investigation (unless paused)

Call `monitor.end_investigation(case_id, investigation_id,
outcome_note="<detector mix / verdict / actions taken>")`. If actions are
still awaiting approval it returns `closed: false, paused: true` and keeps
the investigation open for a later tick — that's expected; just continue.
When it does close, it writes a human-readable **findings report** to
`reports/<case>_<inv>.{json,md}` (verdict + findings by confidence tier +
ATT&CK chain), rendered from the recorded findings — distinct from the full
execution trace, which it writes alongside to
`reports/<case>_<inv>_trace.{json,md}`. The report also carries two appended
sections: **Recommended Containment Commands (run manually)** and
**Autonomous Response Actions** (what TRUDI executed, with rollback/undo
commands). Do **not** also call `misc.export_execution_log` into `reports/` —
that duplicates the trace. Then ack the bundle:
```
for alert_id in bundle.alert_ids:
    monitor.ack_alert(case_id, alert_id)
```

### 9. Write last-seen seq

Update `~/cases/<case>/monitoring/_last_check_seq.txt` to the highest
seq we **drained** in step 2 (whether or not the investigation closed
this tick). The drained alerts are accounted for in the open
investigation's tracker — they don't need to be re-drained next tick.

## Substrate choice — `velo.*` first, `live.*` only if registered

The alerts came from Velociraptor; the same Velociraptor client is the
canonical investigation surface for this case. Default plan:

- For any artifact-based pivot, use
  `velo.collect_artifact(client_id=<from alert>, artifact=<name>)`
  → `velo.wait_for_flow` → `velo.get_collection_results`.
- For ad-hoc one-shot VQL, use `velo.query(...)`.
- Only fall back to `live.*` SSH tools if BOTH:
  - `~/cases/.common/live_hosts.json` registers a host alias for this
    victim (check it; refuse to call `live.*` otherwise), AND
  - the pivot has no equivalent Velociraptor artifact.

> `respond.snapshot_evidence` and `respond.execute_action` use the live-SSH
> path by design (they act on the endpoint, read-only and write respectively) —
> the velo-first rule above governs the *investigation* pivots in step 5, not the
> response tools.

Common detector → recommended `velo.collect_artifact`:

| Detector | Primary artifact |
|---|---|
| `Custom.TRUDI.NewProcess` | `Linux.Sys.Pslist`, then `Linux.Sys.ProcessOpenFiles` |
| `Custom.TRUDI.NewPersistence` | `Linux.Sys.SystemdUnits` (for `.service` paths), `Linux.Sys.Crontab` (for cron paths), or `velo.query("SELECT FullPath, Size, Mtime, IsLink, LinkTarget FROM stat(filename=<path>)")` for symlink/inode inspection |
| `Custom.TRUDI.NewNetwork` | `Linux.Network.Netstat`, then `Linux.Sys.Pslist` keyed by PID |
| `Custom.TRUDI.YaraProcess` | `Linux.Sys.Pslist`, then `velo.query(...)` for memory regions |

DAIR's `priority_tools` directive is binding when it lists specific
MCP tool names — but if those names are `live_*` AND `live_hosts.json`
doesn't register the victim, translate to the equivalent
`velo.collect_artifact` call and record the substitution via
`misc.record_self_correction`.

Pass `_note` on one tool per parallel batch.

## Notes

- **Ordering recap:** contain (step 4, reversible/auto, off the alert) → offer
  eradication (step 5, destructive/approved, after ONE fast target-resolving
  pivot) → full forensic investigation + report (step 6, for the record). Both
  response actions fire within seconds, gated only on a confirmed-positive alert
  plus a resolved target; the finding/report ceremony trails and never blocks the
  kill. The reversible block runs before the first reasoning call; the destructive
  kill is queued for approval right after the pivot, not after the investigation.
- The investigation chain runs **once per bundle**, not once per
  alert. The bundle's evidence is the union of every alert's evidence,
  and a single `dair_assess` decides what to investigate for the whole
  set. DAIR's Scan→Triage push will surface per-host pivots inside
  that one investigation if cross-host evidence appears.
- `start_investigation` is idempotent — calling it again with the same
  `investigation_id` rehydrates the existing trace and returns
  `rehydrated_entries > 0`. The slash command can crash, the operator
  can interrupt, the /loop can fire again; nothing is lost.
- If `dair_assess` returns `next_phase: "Report"` inside an
  investigation, that's fine — call `reason.synthesize` +
  `reason.pre_report_check` and let `end_investigation`'s auto-export
  produce the report. The case-wide trace stays minimal.
- The command should be quiet when there's nothing to do — the
  `/loop 15s ...` invocation pattern fires constantly.
