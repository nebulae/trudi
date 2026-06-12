"""Containment for live-monitoring findings — recommend AND (gated) execute.

`suggest_containment` turns a CONFIRMED/LIKELY finding into operator-runnable
commands rendered from the detector's recipe. On top of that, the **auto-protect**
path lets TRUDI act as an autonomous blue-team agent for a *narrow,
server-classified* tier of safe containment:

  respond.suggest_containment(case_id, finding_id, detector=, evidence=)
      Writes one ACT-N.json per candidate action under
      ~/cases/<case>/monitoring/response/suggestions/, carrying the recipe's
      risk/reversible metadata + the structured action_template + raw_evidence
      needed to execute or revert.
  respond.list_actions(case_id)               — list suggested actions.
  respond.approve_action(case_id, action_id, operator_text)
      Operator approval for a destructive action (dual-key: action_id in the
      text AND a matching user_message trace entry). Issues a short-TTL token.
  respond.execute_action(case_id, action_id, mode="operator"|"auto")
      Runs the action over the gated write-SSH path (core.ssh_exec). Permission
      is decided by gates.check_execution_permitted: AUTO tier (reversible AND
      low-risk) runs without approval when auto_protect is enabled; everything
      else falls through to the approval-token gate. mode is advisory — the agent
      cannot self-execute a destructive action by passing mode="auto".
  respond.revert_action(case_id, action_id)   — run the recorded inverse.

Posture note: TRUDI's evidence stance stays strict read-only; execution exists
ONLY here, ONLY in live-monitoring scope, and ONLY through structured, validated
argv (no free-form command). The auto tier is classified from recipe metadata on
disk (the agent can't reclassify); destructive actions stay physically gated
behind operator-typed approval.
"""
from __future__ import annotations
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Optional

import yaml
from fastmcp import FastMCP

from core import output_safe, ssh_exec
from response import gates as response_gates
from response import policy

mcp = FastMCP("respond")

CASES_ROOT = Path(os.environ.get("TRUDI_CASES_ROOT") or os.path.expanduser("~/cases"))
RECIPES_DIR = Path(__file__).resolve().parent.parent / "response" / "recipes"

_PLACEHOLDER_RE = re.compile(r"<([A-Za-z0-9_]+)>")


def _response_dir(case_id: str) -> Path:
    return CASES_ROOT / case_id / "monitoring" / "response"


def _ensure_layout(case_id: str) -> None:
    (_response_dir(case_id) / "suggestions").mkdir(parents=True, exist_ok=True)
    (_response_dir(case_id) / "executions").mkdir(parents=True, exist_ok=True)


def _next_action_id(case_id: str) -> str:
    seq_file = _response_dir(case_id) / "_action_seq.txt"
    seq_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        cur = int(seq_file.read_text().strip() or "0")
    except (OSError, ValueError):
        cur = 0
    cur += 1
    seq_file.write_text(str(cur))
    return f"ACT-{cur}"


def _load_recipe(detector: str) -> Optional[dict]:
    path = RECIPES_DIR / f"{detector}.yaml"
    if not path.exists():
        return None
    return yaml.safe_load(path.read_text())


def _load_finding(finding_id: int) -> Optional[dict]:
    """Pull the finding entry by _trudi_call_id from the active trace."""
    try:
        from core.execution_log import log
        idx = log.index()
    except Exception:  # noqa: BLE001
        return None
    entry = idx.by_call_id.get(int(finding_id))
    if entry is None or entry.get("type") not in ("finding", "agent_message"):
        return None
    return entry


def _render(template: str, evidence_lc: dict) -> str:
    """Substitute <placeholder> tokens with lowercased-key evidence values.

    Detector alerts are inconsistent about case (`Pid` vs `pid`), so we match
    placeholders against lowercased evidence keys — `<pid>` resolves whether the
    alert field is `pid` or `Pid`."""
    s = template or ""
    for key, value in evidence_lc.items():
        if value is not None:
            s = s.replace(f"<{key}>", str(value))
    return s


# ── Tools ───────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def suggest_containment(
    case_id: str,
    finding_id: int,
    detector: Optional[str] = None,
    evidence: Optional[dict] = None,
) -> dict:
    """Recommend operator-runnable containment commands for a finding.

    Looks up the recipe matching the alert's detector and renders each candidate
    action's description + copyable `manual_command` with the finding's evidence
    substituted in, writing one ACT-N.json per option under
    `~/cases/<case>/monitoring/response/suggestions/`. NOTHING EXECUTES — the
    returned `manual_command` strings are for a human to run out-of-band.

    `finding_id` is the `_trudi_call_id` of the upstream `record_finding`.
    `detector` (e.g. 'Custom.TRUDI.NewNetwork') and `evidence` (the alert's
    evidence dict) should be passed explicitly from the alert payload.
    """
    refusal = response_gates.check_live_monitoring_scope(case_id)
    if refusal:
        return refusal
    _ensure_layout(case_id)

    finding = _load_finding(finding_id)
    if finding is None and (detector is None or evidence is None):
        return {
            "success": False,
            "error": f"finding_id {finding_id} not found in trace, and detector/evidence "
                     f"not supplied. Pass detector= and evidence= explicitly.",
        }

    if detector is None:
        desc = (finding or {}).get("description") or ""
        for known in ("NewProcess", "NewPersistence", "NewNetwork", "YaraProcess"):
            if known in desc:
                detector = f"Custom.TRUDI.{known}"
                break
    if detector is None:
        return {
            "success": False,
            "error": "could not infer detector from finding; pass detector= explicitly "
                     "(e.g. detector='Custom.TRUDI.NewNetwork')",
        }

    recipe = _load_recipe(detector)
    if recipe is None:
        return {"success": False, "error": f"no recipe for detector {detector!r}"}

    if evidence is None:
        evidence = (finding or {}).get("evidence") or {}
    evidence_lc = {str(k).lower(): v for k, v in (evidence or {}).items()}

    suggestions: list[dict] = []
    for action in recipe.get("actions", []):
        action_id = _next_action_id(case_id)
        description = _render(action.get("description", ""), evidence_lc)
        manual_command = _render(action.get("manual_command", ""), evidence_lc)
        # Any placeholder still present after substitution is unresolved evidence.
        unresolved = sorted(set(_PLACEHOLDER_RE.findall(manual_command + " " + description)))
        action_template = action.get("action_template")
        record = {
            "action_id": action_id,
            "case_id": case_id,
            "finding_id": finding_id,
            "detector": detector,
            "description": description,
            "manual_command": manual_command,
            "risk": action.get("risk", "medium"),
            "reversible": bool(action.get("reversible")),
            "unresolved_placeholders": unresolved,
            "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            # Self-contained execution metadata (additive — existing consumers
            # ignore these). action_template selects the validated argv builder;
            # raw_evidence carries the typed values execute/revert validate.
            "action_template": action_template,
            "revert_template": ssh_exec.revert_template_for(action_template),
            "raw_evidence": dict(evidence_lc),
        }
        path = _response_dir(case_id) / "suggestions" / f"{action_id}.json"
        path.write_text(json.dumps(record, indent=2))
        suggestions.append(record)

    return {
        "success": True,
        "case_id": case_id,
        "detector": detector,
        "finding_id": finding_id,
        "suggestions": suggestions,
    }


@mcp.tool()
@output_safe
def list_actions(case_id: str, status: str = "all") -> dict:
    """List the suggested containment actions for the case (with their
    manual_command). `status` is accepted for back-compat; all suggestions are
    recommendations only (nothing executes)."""
    refusal = response_gates.check_live_monitoring_scope(case_id)
    if refusal:
        return refusal
    _ensure_layout(case_id)
    actions: list[dict] = []
    for sug_path in sorted((_response_dir(case_id) / "suggestions").glob("ACT-*.json")):
        try:
            actions.append(json.loads(sug_path.read_text()))
        except (OSError, json.JSONDecodeError):
            continue
    return {"success": True, "case_id": case_id, "actions": actions}


# ── Execution path (gated) ────────────────────────────────────────────────────

def _executions_dir(case_id: str) -> Path:
    return _response_dir(case_id) / "executions"


def _load_suggestion(case_id: str, action_id: str) -> Optional[dict]:
    path = _response_dir(case_id) / "suggestions" / f"{action_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _load_execution(case_id: str, action_id: str) -> Optional[dict]:
    path = _executions_dir(case_id) / f"{action_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _resolve_host_for_case(case_id: str) -> Optional[str]:
    """The live-host alias to act on: explicit config.json 'host', else the sole
    entry in live_hosts.json (the common single-endpoint case)."""
    h = policy.configured_host(case_id)
    if h:
        return h
    try:
        from core.ssh import list_configured_hosts
        hosts = list_configured_hosts()
    except Exception:  # noqa: BLE001
        hosts = []
    return hosts[0] if len(hosts) == 1 else None


def _command_string(argv: list[str]) -> str:
    """Human-readable form of a remote argv. For sh -c wrappers show the inner
    command, which is the actual shell line that runs."""
    if len(argv) >= 3 and argv[0:2] == ["/bin/sh", "-c"]:
        return argv[2]
    return " ".join(argv)


def _rollback_command(revert_template: Optional[str], raw_evidence: dict) -> Optional[str]:
    """Build the verbatim undo command string, or None if irreversible/no-op."""
    if not revert_template:
        return None
    try:
        return _command_string(ssh_exec.build_argv(revert_template, raw_evidence or {}))
    except ssh_exec.ParamValidationError:
        return None


def _log_narration(content: str, input_call_ids: list[int]) -> Optional[int]:
    try:
        from core.execution_log import log
        cids = [c for c in input_call_ids if isinstance(c, int) and c > 0]
        return log.record_agent_message(content=content, input_call_ids=cids or None)
    except Exception:  # noqa: BLE001
        return None


@mcp.tool()
@output_safe
def approve_action(case_id: str, action_id: str, operator_text: str) -> dict:
    """Record operator approval for a (destructive) action.

    Dual-key: `operator_text` must contain `action_id` verbatim AND a matching
    operator-typed `user_message` must exist in the recent trace. The agent
    cannot self-approve. On success an approval token (short TTL) is written for
    execute_action to consume."""
    refusal = response_gates.check_live_monitoring_scope(case_id)
    if refusal:
        return refusal
    refusal = response_gates.check_operator_text(case_id, action_id, operator_text)
    if refusal:
        return refusal
    record = response_gates.issue_approval(case_id, action_id, operator_text)
    _log_narration(
        f"Operator approval recorded for {action_id} (token issued).",
        input_call_ids=[],
    )
    return {"success": True, "case_id": case_id, "action_id": action_id, "approval": record}


@mcp.tool()
@output_safe
def execute_action(case_id: str, action_id: str, mode: str = "operator") -> dict:
    """Execute a containment action over the gated write-SSH path.

    Permission is decided by gates.check_execution_permitted: the AUTO tier
    (reversible AND low-risk) runs without approval when auto-protect is enabled;
    every other action requires a valid operator approval token. `mode`
    ("auto"|"operator") is recorded for audit only — it cannot relax the gate."""
    refusal = response_gates.check_live_monitoring_scope(case_id)
    if refusal:
        return refusal

    suggestion = _load_suggestion(case_id, action_id)
    if suggestion is None:
        return {"success": False, "error": f"no suggestion record for action_id {action_id!r}"}
    if suggestion.get("unresolved_placeholders"):
        return {
            "success": False,
            "error": f"{action_id} has unresolved placeholders "
                     f"{suggestion['unresolved_placeholders']}; cannot execute a partial command.",
        }

    # The ONLY permission decision.
    refusal = response_gates.check_execution_permitted(case_id, action_id, suggestion, mode=mode)
    if refusal:
        return refusal

    action_template = suggestion.get("action_template")
    if not action_template:
        return {
            "success": False,
            "error": f"{action_id} has no action_template — re-run suggest_containment.",
        }

    host = _resolve_host_for_case(case_id)
    if host is None:
        return {
            "success": False,
            "error": "no live host configured — set 'host' in monitoring/config.json "
                     "or register exactly one host in ~/cases/.common/live_hosts.json.",
        }

    raw_evidence = suggestion.get("raw_evidence") or {}
    result = ssh_exec.ssh_run_write(case_id, host, action_template, raw_evidence)

    classification = policy.classify(suggestion)
    revert_template = suggestion.get("revert_template")
    rollback_command = _rollback_command(revert_template, raw_evidence)
    try:
        command_argv = ssh_exec.build_argv(action_template, raw_evidence)
    except ssh_exec.ParamValidationError:
        command_argv = []

    approval = response_gates.check_approval(case_id, action_id)[0]
    execution = {
        "action_id": action_id,
        "case_id": case_id,
        "detector": suggestion.get("detector"),
        "action_template": action_template,
        "classification": classification,
        "mode": mode,
        "host": host,
        "command_argv": command_argv,
        "command_str": _command_string(command_argv) if command_argv else result.get("cmd", ""),
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
        "exit_code": result.get("exit_code"),
        "success": bool(result.get("success")),
        "elapsed_seconds": result.get("elapsed_seconds"),
        "rollback_template": revert_template,
        "rollback_command": rollback_command,
        "raw_evidence": raw_evidence,
        "approval_token": (approval or {}).get("approval_token"),
        "executed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reverted": False,
    }
    _ensure_layout(case_id)
    (_executions_dir(case_id) / f"{action_id}.json").write_text(json.dumps(execution, indent=2))

    verb = "auto-executed" if classification == policy.AUTO and mode == "auto" else "executed"
    status = "OK" if execution["success"] else f"FAILED ({result.get('stderr','')[:120]})"
    rb = f"; rollback `{rollback_command}`" if rollback_command else " (irreversible — no rollback)"
    cid = _log_narration(
        f"{action_id} [{classification}] {verb} `{execution['command_str']}` on {host} → {status}{rb}.",
        input_call_ids=[result.get("_trudi_call_id"), suggestion.get("finding_id")],
    )
    execution["trace_call_id"] = cid

    return {
        "success": execution["success"],
        "case_id": case_id,
        "action_id": action_id,
        "classification": classification,
        "mode": mode,
        "execution": execution,
        "rollback_command": rollback_command,
    }


@mcp.tool()
@output_safe
def revert_action(case_id: str, action_id: str) -> dict:
    """Undo a previously-executed action by running its recorded inverse.

    Symmetric permission: a revert of an AUTO-classified action runs under
    auto-protect; otherwise it requires an operator approval token (same gate as
    execute)."""
    refusal = response_gates.check_live_monitoring_scope(case_id)
    if refusal:
        return refusal

    execution = _load_execution(case_id, action_id)
    if execution is None:
        return {"success": False, "error": f"no execution record for {action_id!r}; nothing to revert."}
    if execution.get("reverted"):
        return {"success": False, "error": f"{action_id} was already reverted."}
    if not execution.get("success"):
        return {"success": False, "error": f"{action_id} did not execute successfully; nothing to revert."}

    revert_template = execution.get("rollback_template")
    if not revert_template:
        return {"success": False, "error": f"{action_id} is irreversible — no rollback available."}

    suggestion = _load_suggestion(case_id, action_id) or {}
    refusal = response_gates.check_execution_permitted(case_id, action_id, suggestion, mode="operator")
    if refusal:
        return refusal

    host = execution.get("host") or _resolve_host_for_case(case_id)
    raw_evidence = execution.get("raw_evidence") or {}
    result = ssh_exec.ssh_run_write(case_id, host, revert_template, raw_evidence)

    execution["reverted"] = bool(result.get("success"))
    execution["reverted_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    execution["revert_stderr"] = result.get("stderr", "")
    (_executions_dir(case_id) / f"{action_id}.json").write_text(json.dumps(execution, indent=2))

    status = "OK" if result.get("success") else f"FAILED ({result.get('stderr','')[:120]})"
    revert_cmd = _rollback_command(revert_template, raw_evidence) or revert_template
    _log_narration(
        f"{action_id} reverted via `{revert_cmd}` on {host} → {status}.",
        input_call_ids=[result.get("_trudi_call_id")],
    )

    return {
        "success": bool(result.get("success")),
        "case_id": case_id,
        "action_id": action_id,
        "reverted": execution["reverted"],
        "result": {"exit_code": result.get("exit_code"), "stderr": result.get("stderr", "")},
    }
