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
   Deployment uses a `TRUDI-client-C.…` label per client. Shared artifact
   definitions have neutral defaults; each label's parameter specs carry that
   client's baseline. Starting, refreshing, or stopping one watcher preserves
   global monitoring, operator labels, and every other client's configuration.
   The active OS, detector selection, and parameters are saved in
   `monitoring/watchers/<client_id>.json`; baseline extensions reuse that selection.
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
5. Response follows the real-IR sequence **contain → eradicate →
   investigate-for-record**, with both response actions up front and the forensic
   write-up trailing (never blocking them):
   - **Contain first**, off the alert, before any `reason.*`/`dair_assess` call:
     `respond.snapshot_evidence` (read-only, preserves the flow a block tears
     down) then `respond.suggest_containment` → `respond.execute_action(mode="auto")`
     for the **reversible + low-risk** tier only (e.g. block the egress channel —
     its placeholders resolve from the alert). This auto-executes with no finding
     and no approval, with its rollback command surfaced.
   - **Offer eradication right after**, for a confirmed-positive alert class
     (DecoyTouch, exercise-positive TTP): resolve the `pid`/`image_path` with ONE
     fast pivot (or take it from the bundle), re-`suggest_containment` to enrich,
     and **queue the destructive action for approval** — seconds after
     containment, gated only on target resolution, NOT on the finding ceremony. It
     **pauses the loop** until the operator approves — a popup selection
     (`AskUserQuestion`, approve option labelled with the `ACT-N`) or
     `approve <action_id>` typed literally, captured into the per-investigation
     trace by the `UserPromptSubmit` hook and matched by `operator_text_required`
     before `respond.approve_action` → `respond.execute_action(mode="operator")`.
     A login-only touch may have no live process left (containment already severed
     it) — a clean outcome, not a failure.
   - **Then the full investigation + report** (hypothesize → DAIR → findings →
     report) runs for the court-record, after the response is already in flight;
     if it clears the alerts as benign it reverts containment and drops any
     still-queued eradication via `respond.revert_action` /
     `monitor.clear_awaiting_approval`.
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
irreversible action, or risk ≥ medium) requires an explicit operator
approval — either a **popup selection** (`AskUserQuestion` whose approve
option's label carries the `ACT-N`; the `PostToolUse` hook records the
selected label as a `user_message`) or a typed `approve ACT-N` (the
`UserPromptSubmit` hook). Both satisfy `operator_text_required` the same
way, and the agent cannot self-approve either way — only the hooks write
those trace entries, from genuine human input. Passing `mode="auto"` to
`execute_action` on a
destructive action does NOT bypass approval — permission is recomputed
from disk every call.

**Loop-pause.** When a destructive action is recommended, the watcher
queues it (`monitor.set_awaiting_approval`) and pauses autonomous response
for that investigation; it stays open across `/loop` ticks until the
operator approves. Every action — auto-executed, approved, or reverted —
is logged with its **rollback/undo command** to the console and the
report's *Autonomous Response Actions* section.

**Report scoping.** The response store (`monitoring/response/{suggestions,
executions}/ACT-N.json`) is per **case**, but each investigation report lists
only its own actions: `suggest_containment` and `execute_action` stamp every
record with the open `investigation_id`, and `end_investigation` filters both
report sections on it. Sidecar responses carry `alert_ids` before an
investigation exists; opening/extending the investigation adopts its alerts'
earlier actions, so immediate containment and its rollback appear in the report.
Timestamp fallback is reserved for legacy records without alert ownership.
Re-suggesting the same recipe action for the same
detector and host inside one investigation does not mint a new `ACT-N`: an
identical command reuses the existing record, and a rendering that fills
placeholders the earlier draft left open **supersedes** it (`supersedes` /
`superseded_by`; `execute_action` refuses a superseded draft). An investigation
with nothing suggested or executed gets an explicit "No containment actions"
note instead of silently omitted sections.
Suggestion/execution updates are serialized across the ingest and MCP processes.
Executing an already successful, unreverted action returns its existing result.

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

## Multi-host lateral-movement scenario + eradicate/verify

The `demo/live-monitoring` stack has a compose profile **`lateral`** that adds a
beachhead (`victim-a`) and a pivot target (`victim-b`), each its own
Velociraptor client, plus the `LATERAL-DEMO` case. `victim-a /attacks/run
lateral` moves A→B over SSH (stolen key, held session), escalates to root via a
sudo misconfiguration, and installs a root cron. Two detectors beyond the
original four carry this:

- **`Custom.TRUDI.NewLogon`** — a new inbound SSH (:22 ESTABLISHED) session from
  a source IP not in the baseline `logon_sources` allowlist (gateway `.1` and
  loopback excluded so the management plane doesn't self-alert). The
  lateral-movement signal; keyed on the socket, since key-based non-PTY sessions
  write no wtmp/utmp record.
- **`Custom.TRUDI.PrivilegeEscalation`** — a process running as **root**, whose
  image path is not in the baseline `root_image_paths` set, **and whose ancestry
  crosses a uid boundary**: some ancestor within six hops runs as a non-root
  user (the sudo/SUID/su pivot — the implant is root, its grandparent is the
  user's shell). An all-root chain such as the daily cron run is not an
  escalation and stays silent. The brokers themselves (`sudo`, `su`, `pkexec`,
  `doas`) are never the reported process; the root child they spawn is.

Both allowlists are captured by `monitor.baseline_capture` and substituted by
`monitoring/render.py`.

**Scheduled work, ancestry, and the benign-recurrence feedback loop.** A
single process snapshot at baseline time never contains the periodic children
cron launches later, so the stock Ubuntu `cron.daily` chain at 06:25 UTC
(`sh → run-parts → apt-compat → sleep`) opened a full investigation two
mornings in a row in DECOY-DEMO. Three mechanisms close that:

- Both process detectors resolve each process's **ancestry** (six Pid→Ppid
  hops over the same per-tick snapshot, no process tracker needed) and emit
  `parent_exe`, `parent_user` and `ancestry` on every row. `NewProcess` exempts
  **scheduled work**: cron-descended (`CronDaemonImages`, from the baseline's
  `cron_daemon_images`), image under a trusted-execution prefix
  (`ScheduledWorkBinRegex` — the system bin dirs plus `/usr/local` and `/opt`,
  where real hosts keep operator software), and no world-writable staging
  location (`/tmp`, `/var/tmp`, `/dev/shm`) in the command line
  (`DropPathRegex`). A cron job running `/usr/bin/python3 /tmp/payload` still
  alerts; one running `/usr/local/bin/backup` or `/usr/bin/bash
  /home/alice/sync.sh` does not. Both regexes are **detector parameters** (an
  operator overrides them per host) with their canonical defaults in
  `monitoring/render.py` — `tools.monitor.verify_clean` imports the same
  patterns, so the live detector and the post-eradication sweep cannot drift.
  `monitor.baseline_capture` also records the parsed cron schedule as
  `scheduled_jobs` (root-run dump of the system crontabs and periodic
  directories) for the investigator.

  The exemption additionally requires a complete persistence snapshot matching
  the baseline's `persistence_fingerprints` (`path|SHA256`) on that tick.
  `NewPersistence` detects changes to existing files as well as new files,
  including `/etc/crontab` and `/etc/anacrontab`. New, modified, missing, or
  unreadable schedule files disable the process exemption. Deployment enables
  it only when `NewPersistence` is selected and content fingerprints exist.
  Older path-only baselines retain conservative detection until a trusted
  baseline is captured again. `verify_clean` checks the same fingerprints.
- **`monitor.baseline_extend(case_id, client_id, image_paths=…,
  process_names=…, root_image_paths=…, benign_alert_ids=…, reason=…,
  finding_id=…, evidence_call_ids=…)`** feeds a benign verdict back: it extends
  the allowlists, records the alerts' process **signatures** (image path +
  digit-normalised command line + parent image) under `benign_signatures`,
  appends an auditable entry to the baseline's `extensions` ledger, and
  re-renders and re-pushes the detectors to the client event table (the
  sidecar needs no restart). `reason` is mandatory.
- **`monitor.check_alerts`** stamps every alert with its `signature` and marks
  one that matches a recorded benign signature as `known_benign` (naming the
  investigation and finding that established it); `all_known_benign` on the
  result lets `/trudi-check-alerts` take the **recurrence fast path** — open
  the investigation, record one recurrence finding citing the prior finding
  and the fresh process listing, close — instead of a full DAIR cycle.
- The watcher sidecar **merges** rows from different process detectors about
  the same `(client, pid, image, process start time)` arriving within 180 s into one alert
  (`detectors` list, `evidence_by_detector`, max severity), so four cron
  children are four alerts, not eight. An alert already inside an open
  investigation is never mutated; the later row becomes its own alert and
  extends the investigation.
  Distinct rows from the same detector, including additional YARA rules, stay
  separate. Rows without a process start time are not cross-detector merged.
  Windows logons deduplicate by event record identity and timestamp; a failed
  authentication never suppresses a later successful logon or another session.

`monitor.verify_clean` mirrors the same ancestry rules in Python, so a
post-eradication check neither reports the cron chain as a residual nor misses
a root implant with a user-shell ancestor. Their recipes add response actions (all built as
validated argv in `core/ssh_exec.py`):

| Action | Template | Tier |
|---|---|---|
| Block the lateral source IP (iptables INPUT REJECT) | `block_source_ip` (revert `unblock_source_ip`) | AUTO |
| Kill the live SSH session | `kill_session` | approval |
| Quarantine the escalated binary | `quarantine_image` (revert restore) | AUTO |
| Kill the escalated root process | `kill_pid` | approval |
| Kill the whole implant family by image | `kill_by_image` (`pkill -9 -f <image_path>`) | approval |
| Expire the abused account | `lock_account` (revert `unlock_account`), refuses protected accounts | approval |

**Snapshot before you contain.** Contain-first is fast, but quarantining a
binary / killing a process / deleting a cron file removes the artifacts a
finding must cite. `respond.snapshot_evidence(case_id, detector=, evidence=)`
runs the detector-appropriate READ-ONLY live captures (`/proc/<pid>` details,
persistence file content, inbound netstat, process table) and returns
`snapshot_call_ids` to cite in the finding's `input_call_ids` — so the
intrusion stays provable after eradication. Call it before any
kill/quarantine/removal. **Prefer `kill_by_image` over single-pid `kill_pid`
for a respawning implant**: a cron/service re-launches fresh PIDs, so a
single-pid kill leaves siblings that `verify_clean` then (correctly) reports.

After containment/eradication, **`monitor.verify_clean(client_id, case_id)`**
re-snapshots the host (Pslist / Netstat / PersistenceSnapshot) and recomputes
every detector's residual against the baseline allowlists; `clean=true` means no
process / root-process / persistence / logon / egress deviation remains. It is
read-only — it never remediates.

## External-detection ingest — Acalvio ShadowPlex (CEF) → autonomous response

A deception platform is a **detection source**, and the cleanest one TRUDI's
live loop can start from: a decoy has no legitimate reason to be touched, so a
decoy-touch alert is a confirmed positive with **no false-positive class**, and
it names the **credential** presented (a honey account) as well as the touching
host. The scenario: ShadowPlex reports a host touched an RDP decoy; TRUDI
investigates and contains **that host**, not the decoy (the decoy is the
platform's asset).

**Ingest path.** ShadowPlex emits CEF over syslog. `bin/trudi-cef-ingest.py`
(a sidecar managed by `monitor.start_cef_ingest` / `stop_cef_ingest`, registered
under `watchers/` as the `cef-ingest` pseudo-client) receives it and writes one
`Custom.TRUDI.DecoyTouch` alert per incident into the case's
`monitoring/alerts/` — the **same shape** `bin/trudi-velo-watcher.py` writes, so
`/trudi-check-alerts` / `/trudi-watch-alerts` consume it with no change. Two CEF
lines share one `incidentID` (the fused incident; the per-protocol service
interaction carrying the client fingerprint in `cs78`); the ingest merges them
into one alert. The field mapping and ATT&CK-name→id table live in
`monitoring/cef.py`. For a Splunk deployment, point a Splunk webhook alert
action (the saved search in Acalvio's sample) at the same ingest; for the demo
the decoy forwards syslog straight to it. This listener accepts UDP records,
not HTTP webhooks; a Splunk alert action must forward syslog or use a collector.

**Authenticated automatic response.** Raw UDP syslog is collection-only.
Automatic containment requires a `TRUDI-CEF-1` HMAC-SHA256 envelope from a
configured sender, a fresh timestamp (within 300 seconds), and a nonce not
previously accepted. Nonces persist across ingest restarts. Each sender has
an explicit source-IP-to-client mapping and allowed decoy endpoints; a claimed
vendor name, sender IP, or client hostname alone grants no authority.
Invalid signatures and unrelated event types are rejected. Valid unsigned
ShadowPlex incidents remain visible with `response_eligible: false` and require
corroboration/operator approval for response. Replay-mode alerts cannot
authorize automatic response.

`bring-up.sh` generates sender keys under `demo/live-monitoring/secrets/` in a
private, git-ignored directory. The decoy reads its Docker secret; Windows OEM
setup installs the other key beside the sensor with SYSTEM/Administrators ACLs.
The Windows relay forwards envelopes unchanged and holds no signing key.
Add this block to the case's existing `monitoring/config.json`, using the
actual beachhead address and Velociraptor client ID:

```json
{
  "cef_ingest": {
    "senders": {
      "decoy-emulator": {
        "key_file": "<repo>/demo/live-monitoring/secrets/decoy-cef.key",
        "source_clients": {"10.73.0.3": "C.REPLACE_WITH_BEACHHEAD_ID"},
        "decoy_endpoints": ["10.73.0.50:3389"]
      },
      "windows-decoy": {
        "key_file": "<repo>/demo/live-monitoring/secrets/windecoy-cef.key",
        "source_clients": {"10.73.0.3": "C.REPLACE_WITH_BEACHHEAD_ID"},
        "decoy_endpoints": ["10.73.0.60:3389"]
      }
    }
  }
}
```

Adjust the key paths for your checkout. Custom Compose key files may be set
with `TRUDI_DECOY_CEF_KEY_FILE` / `TRUDI_WINDECOY_CEF_KEY_FILE`. Keys must
contain at least 32 bytes after trimming whitespace. A trusted external
collector can wrap a vendor record with
`monitoring.cef_auth.sign(record, sender_id, key_bytes)` after authenticating
its own upstream; a relay must not sign arbitrary unauthenticated UDP input.
The envelope signs the UTF-8 string
`TRUDI-CEF-1\n<sender>\n<integer Unix timestamp>\n<32 lowercase hex nonce>\n<CEF record>`.
JSON fields are `trudi_cef: 1`, `sender`, `timestamp`, `nonce`, `cef`, and the
lowercase hex `signature`. The signature is checked again against the saved
alert and current sender configuration before an AUTO action runs.

**Client resolution + the self-correction beat.** The alert names the decoy
(`dstIP`/`decoy_name`) prominently, but the decoy has no Velociraptor client —
the pivot target is the **source host** (`srcIP`). The ingest resolves the
source host's client_id from the authenticated sender binding when available;
otherwise from `cef_ingest.source_map`, then `last_ip`, then hostname
(`cef.resolve_client`). An unresolved client is
written `null` with the reason, and the agent resolves it (`velo.list_clients`)
and records `misc.record_self_correction`. A second honest correction: the honey
credential (`linda`) is not a real principal — disposition it `not_a_principal`,
never attribute it to a person without a session artifact.

**Response.** `response/recipes/Custom.TRUDI.DecoyTouch.yaml` acts on the
touching host: `block_egress_to_endpoint` to the decoy (AUTO, reversible+low) and
`kill_owning_pid` / `kill_by_image` (approval). The alert carries no `pid`/
`image_path` (the decoy only sees the network side), so the kills are offered
**non-executable** until the Velociraptor pivot (netstat → pslist on the source
host) enriches the evidence; re-call `respond.suggest_containment` with the
enriched dict. `respond.snapshot_evidence` captures the inbound/outbound flow and
process table for `DecoyTouch` before any kill.

**Demo.** Compose profile `decoy` (built on `lateral`) adds the decoy emulator
(`demo/live-monitoring/decoy/` — ShadowPlex **CEF format emulation from the
published spec, not vendor software**). Case `~/cases/DECOY-DEMO/`:

```bash
cd ~/trudi/demo/live-monitoring
COMPOSE_PROFILES=lateral,decoy ./bring-up.sh
```
```
/trudi-start-watcher DECOY-DEMO        # baselines victim-a, starts the CEF ingest
/trudi-watch-alerts  DECOY-DEMO
```
```bash
sudo docker exec trudi-victim-a /attacks/run decoy-touch   # touch the decoy as 'linda'
```

With the sender configured, ingestion auto-blocks the egress to the decoy,
pivots victim-a over Velociraptor, records the findings, asks to approve the
kill, and `monitor.verify_clean` confirms the flow is gone. Reverse with
`/attacks/run decoy-touch --cleanup`.

### Upgrading an existing monitoring deployment

Stop existing watcher sidecars, remove legacy global `Custom.TRUDI.*` detector
entries from Velociraptor's **All** monitoring group, preserving
`Generic.Client.Stats` and operator-managed entries, then restart each watcher
with the new code. New deployments use client labels; the updater reports any
legacy global TRUDI entries it finds instead of deleting other clients' work.
Old baselines remain usable with the cron exemption disabled. Capture a new
baseline only from a host whose schedule is known to be trusted; refreshing
detectors does not automatically approve the current schedule.

Baseline and verification collections now retain complete results, including
collections exceeding the normal tool-output limits. Older baselines may have
been cut off by those limits; recapture them from a trusted host rather than
automatically approving its current state. Monitoring-table reads and update
verification also retain the full configuration, including large Windows
allowlists and the server's compiled queries.

On an existing Windows decoy, rebuilding the OEM payload does not update the
installed sensor. Stop the `ShadowPlexSensor` scheduled task, securely copy the
updated `sensor.ps1` and matching `cef.key` into `C:\ShadowPlexSensor`, restrict
that directory and its files to SYSTEM and Administrators as in the OEM
installer, then restart the task. Keep the ingest's configured key file in
sync. The unsigned sensor from an older VM remains collection-only until this
upgrade is applied.

---

**Not available:** MemProcFS, VSCMount (Windows-only), tshark, hayabusa, guymager.

**Volatility exit codes:** `1` = plugin ran but failed (may be normal — e.g. no data). `2` = argument error (TRUDI bug). `-1` (timeout) = symbols not cached — run `vol_symbol_check`.

---
