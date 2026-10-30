---
name: trudi-check-alerts
description: Investigate queued TRUDI alerts or resume an open live investigation, with gated source containment, native evidence collection, and reporting.
---

Read the current case's CLAUDE.md, its monitoring/config.json, and the TRUDI
orchestrator instructions in the repository's claude/CLAUDE.md. The repository
is the parent of this skill's resolved codex/skills directory. Read the
canonical live workflow at [references/workflow.md](references/workflow.md).

Apply these Codex adaptations to that workflow:

- Resolve an explicit case argument first, then the current case directory;
  do not accidentally follow another case's shared active_case file.
- Call the MCP tools actually exposed by trudi-sift. ToolSearch is optional;
  discover schemas with this client's available tool discovery mechanism.
  Never substitute shell/Python imports for forensic MCP calls.
- Read open investigation state and resume the same ID and trace. Existing
  entries do not imply all investigative stages have finished. Continue the
  last unfinished stage; do not duplicate completed response actions.
- Respect a declared exercise response hold. When released, confirm
  auto_protect is enabled, preserve volatile evidence, and contain through the
  saved signed alert's normal server gate before reasoning. Check recorded
  response state first so an existing source block is not stacked again.
- For destructive actions, request an explicit operator answer naming the
  ACT-N. Submit it through respond.approve_action, then execute only if the
  gate accepts it. The trusted Codex UserPromptSubmit hook records genuine
  input. AskUserQuestion and Claude's popup hook are not available here.
- A declined answer is not approval, and a question mentioning an action is
  not consent. If the approval hook has not been reviewed/trusted in /hooks,
  leave the action pending and explain the setup problem. Never write an
  approval token or a user_message entry yourself. A fresh typed approval
  after hook setup is the reliable recovery path.
- Before executing a previously queued process action, revalidate that its
  PID still identifies the same owning process and start time. If containment
  already ended it, report that outcome instead of killing a stale/reused PID.
- Continue independent read-only investigation while an approval is pending.
  Do not acknowledge an alert or close its investigation just because a
  destructive action could not execute.
- Keep evidence and stage attribution separate. For WINDECOY-DEMO, use the
  recorded take's SinceUTC and every named HoneyActivity source. Bind the
  defender-owned SID, 4624/4778 logon context, source IP, process/file/script
  evidence, and residuals. Recollect after an EVTX flush delay if necessary.
  Attacker receipts, expected steps, and ground_truth.json are not proof.
- Record findings and write the report through the normal MCP workflow.
  Preserve history, carry snapshot call IDs, disclose the exercise hold, and
  acknowledge only alerts whose work is complete. Linux verify_clean does
  not establish Windows clearance.

An invocation checks one bundle and returns its status. Use
$trudi-watch-alerts for repeated waiting and investigation.
