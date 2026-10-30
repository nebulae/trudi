# WINDECOY-DEMO — a constrained Windows intrusion

The source replays the local honeytoken credential linda into a real Windows
Server 2022 decoy, then attempts actions available to an ordinary user.
The deception sensor emits signed ShadowPlex-format CEF; TRUDI contains the
Linux source and investigates the Windows activity with Velociraptor.
This is format emulation, not Acalvio software.

## The security team's boundary

| Allowed inside the isolated decoy | Kept outside Linda's authority |
|---|---|
| Local RDP desktop as a standard user | Administrators and other privileged groups; domain access |
| Read synthetic files in C:\DecoyData\Finance | Real business data and usable production credentials |
| Write to her own profile, execute ordinary user tools | Changing services, HKLM, auditing, firewall, EDR or sensor configuration |
| Stage a ZIP and persist through her own HKCU Run key | Reading the protected canary or sensor signing key |
| Existing RDP interaction with the source | General outbound access; only EDR, relay and DHCP egress is allowed |

Ordinary-user persistence is intentional and does not imply admin rights.
The worker is a harmless 15-minute sleep. The example never exfiltrates the
documents and does not attempt privilege escalation.

## The machines

| Machine | Address | Role |
|---|---|---|
| Velociraptor server | 10.73.0.2 | Independent endpoint collection; GUI https://localhost:8889 |
| victim-a / trudi-victim-a | 10.73.0.3 | Linux beachhead; the response target |
| victim-win / trudi-victim-win | 10.73.0.60 | Windows decoy; console http://localhost:8006 |
| windecoy-relay | 10.73.0.55:5514 | Forwards signed sensor datagrams unchanged |

Resolve current client IDs before recording. Source bindings must use
victim-a's actual ID and address, not the decoy's hostname.

## Prepare before recording

    cd ~/trudi/demo/live-monitoring
    ./bring-up.sh --profiles lateral,winrdp,windecoy

Fresh installs run windecoy/provision.ps1 as defender preparation after account
creation. It removes Linda from privileged groups, creates read-only synthetic
bait and a protected canary, enables process/file/script-block auditing, and
sets the decoy's outbound allowlist. The original firewall policy is backed up
under the administrator-only C:\ProgramData\TRUDI-Decoy directory.

For an existing VM, securely transfer and run the updated provision.ps1 as an
administrator before capturing any trusted baseline. Updating the OEM volume
alone does not reprovision an already installed guest. Rebuild victim-a so it
has xdotool, win-decoy.sh, and the activity.ps1 directory. A controlled lab may
copy the changed files and install xdotool without recreating the client.

Confirm the honey account is local and belongs only to Users and Remote Desktop
Users, the sensor task is running, and Velociraptor still checks in.
C:\ProgramData\TRUDI-Decoy\policy.json records the defender-provisioned honey
SID and synthetic bait path. Keep the sensor and key restricted to SYSTEM and
Administrators.

Configure cef_ingest.senders.windows-decoy with the signing key file,
10.73.0.3 -> victim-a's current client ID, and decoy endpoint 10.73.0.60:3389.
See [authenticated ingest](../../docs/live-monitoring.md#external-detection-ingest--acalvio-shadowplex-cef--autonomous-response).
Keep auto_protect enabled for the default response mode.

### Codex investigator setup

MCP registration supplies tools. Claude's Markdown slash commands and its
approval-recording hooks are separate integrations. For Codex, install the
case-local live-monitoring skills and native operator-input hook:

    codex mcp add trudi-sift -- "$VENV/bin/python" ~/trudi/server.py
    "$VENV/bin/python" ~/trudi/codex/register_codex.py --case-dir ~/cases/WINDECOY-DEMO --python "$VENV/bin/python"
    codex --no-daemon -C ~/cases/WINDECOY-DEMO -c 'mcp_servers.trudi-sift.tool_timeout_sec=900'

(`$VENV` is the TRUDI virtualenv, e.g. `~/.venv`.)

In Codex, review and trust the case's two TRUDI hooks through `/hooks`: the
UserPromptSubmit trace hook and the PreToolUse evidence guard (matcher
`Bash|apply_patch`, refuses untraced reads of produced output, forensic binaries
outside MCP, and raw writes into `reports/`/`exports/`/`analysis/`). Codex
requires this review before local hooks execute. Check `/skills` for
`trudi-start-watcher` (`trudi-load-watcher` is an alias), `trudi-watch-alerts`,
`trudi-check-alerts`, and `trudi-stop-watcher`. Invoke them with `$`, for example
`$trudi-check-alerts WINDECOY-DEMO`. If a custom TRUDI_CACHE_DIR is configured
for the MCP server, pass the same directory to the registrar with --cache-dir.

The hook records actual operator prompts in the active case trace; it does
not approve actions or execute them. A destructive action still requires
respond.approve_action and the existing server gate. An approval submitted
before hook setup must be typed again afterward; never backfill or fabricate
user-message trace entries. Resume an existing investigation rather than
resetting it. The Codex skills cover the live-monitoring workflow; they do not
install all Claude commands or its narration/audit hooks.

Keep the investigator on hold during the full-activity exercise below. The
Codex watch skill keeps an active turn waiting in short intervals; it does
not claim that a detached waiter automatically wakes an idle Codex session.
After the full-activity attack finishes and protection is restored, invoke
`$trudi-watch-alerts WINDECOY-DEMO 1` for a one-second queue poll. This runs the
investigation when alerts arrive; it does not repeat the full investigation
every second or promise one-second end-to-end detection/response.

## Choose the response sequence explicitly

**Immediate containment:** Start the signed ingest and analyst loop, then run
the attack. A fast block may interrupt desktop loading or subsequent actions.
That is a valid prevented-activity take; report what the telemetry shows.

**Full-activity exercise:** Before starting, explicitly set the case's
monitoring/config.json auto_protect.enabled to false and keep the analyst loop
on hold. Start the signed ingest so the real honeytoken alert is retained.
Run the attack and wait for the Windows completion receipt. Restore
auto_protect.enabled to true before starting the analyst loop to investigate
and contain the queued signed alert. State the exercise response hold in the
recording and report. This does not demonstrate immediate containment latency.

Do not modify the sensor's polling or suppress the first honeytoken event to
make the story appear faster.

## Attack and investigate

    docker exec trudi-victim-a /attacks/run win-decoy

The launcher types a command into Linda's real RDP desktop. It uses the account's
own token, not a privileged investigator action. Only the exercise directory
is redirected; clipboard redirection is disabled.

The attempt performs:

1. whoami /all, hostname, and ipconfig /all.
2. Enumeration and reading of two synthetic finance documents.
3. Copies under AppData\Local\NorthstarCache\staging and finance-review.zip.
4. A denied read of the protected synthetic administrator canary.
5. HKCU Run value NorthstarWorkspace pointing to the profile's workspace.ps1.
6. A Linda-owned PowerShell worker that sleeps for 15 minutes.

An attacker-side receipt confirms the launcher received a completion claim.
Treat the receipt, local result.json, and transcript as attacker-controlled.

Upload monitoring/artifacts/Custom.TRUDI.Win.HoneyActivity.yaml, then collect
Custom.TRUDI.Win.HoneyActivity on the Windows client with a suitable SinceUTC.
Inspect every named source:

| Source | Investigative purpose |
|---|---|
| Policy | Resolve the honey account's local SID from defender-owned configuration |
| Security | 4624/4625 logons, 4688 processes, 4656/4663 file access attempts; retain record IDs |
| ScriptBlocks | SID-bound PowerShell 4104 content |
| LogonContext | Prior SID-bound type-10 logons, including sessions predating SinceUTC |
| Reconnects | Local account/domain-bound 4778/4779 records linking a reconnect to its retained LogonID |
| Persistence | The honey SID's loaded HKU Run value |
| Staging | Profile file paths, timestamps, ZIP size and SHA-256 |
| Processes | Current workspace.ps1 process, owner and ancestry |

Correlate the native SID and logon IDs to the source-bound 4624 type-10 session.
Check creator and target contexts on process events. For a reconnected desktop,
bind the retained LogonID through 4778 and the earlier SID-bound logon rather
than assuming processes use the latest 4624. Distinguish a denied read from a
successful file read, staging from exfiltration, and user persistence from
administrator compromise.

Live EVTX files may lag the event service briefly. Recollect after the records
flush before concluding an expected action has no native evidence.

Containment stays on victim-a. An RDP block does not remove the Windows worker
or Run key; preserve them as evidence and report them as residuals. Avoid using
Linux verify_clean as a Windows clearance test.

## Presenter narrative

“The credential is bait, but the Windows actions are real. The security team
gave this local account a normal desktop on an isolated decoy, synthetic files
to read, and its own user profile. It has no admin rights and no general
outbound access.

“The actor enumerates the machine, reads the bait documents, stages an archive,
and sets a current-user Run key. The attempt to read protected data is denied.
Those limits are part of the evidence, not a gap we fill by elevating the account.

“We bind the actions to the account SID and RDP logon, using native process,
file-access and PowerShell records. Linda is the honeytoken identity; the actor
is the source session using it.

“Blocking the source cuts the channel. It does not clean the Windows host.
The remaining worker and Run key show why containment and eradication are
different steps.”

For a full-activity take, disclose the exercise response hold before the attack.
For an immediate take, describe interrupted actions only when supported.

## Reset after preserving evidence

    docker exec trudi-victim-a /attacks/run win-decoy --cleanup

This closes the attacker's RDP client only; it intentionally leaves guest
artifacts. After stopping the analyst loop and ingest and explicitly clearing
the source containment through its recorded rollback, an operator can run:

    docker exec trudi-victim-a /attacks/win-decoy.sh --reset-activity
    docker exec trudi-victim-a /attacks/run win-decoy --cleanup

The reset opens a new real honey-account logon and runs activity.ps1 -Cleanup
under that account. It removes only NorthstarWorkspace, its sleeping worker,
and NorthstarCache. Do this off-camera; it creates additional audit records.
If RDP remains blocked, use the Windows console under Linda's token to run the
same cleanup script. Preserve case config, reports and logs; do not wipe the
monitoring directory or clear Windows logs to reset a take.
