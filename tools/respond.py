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
from functools import wraps
from pathlib import Path
from typing import Any, Optional

import yaml
from fastmcp import FastMCP

from core import output_safe, ssh_exec
from response import gates as response_gates
from response import policy
from monitoring import response_store

mcp = FastMCP("respond")

CASES_ROOT = Path(os.environ.get("TRUDI_CASES_ROOT") or os.path.expanduser("~/cases"))
RECIPES_DIR = Path(__file__).resolve().parent.parent / "response" / "recipes"

_PLACEHOLDER_RE = re.compile(r"<([A-Za-z0-9_]+)>")


def _serialized(fn):
    @wraps(fn)
    def wrapped(case_id, *args, **kwargs):
        with response_store.transaction(CASES_ROOT / case_id):
            return fn(case_id, *args, **kwargs)
    return wrapped


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


def _open_investigation_id(case_id: str) -> Optional[str]:
    """The INV id of the investigation currently open for the case (from
    `monitoring/_open_investigation.json`), or None. Suggestions and executions
    are stamped with it so a report lists only its own investigation's actions."""
    p = CASES_ROOT / case_id / "monitoring" / "_open_investigation.json"
    try:
        rec = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    inv = (rec or {}).get("investigation_id")
    return str(inv) if inv else None


def _find_supersedable(case_id: str, investigation_id: Optional[str], detector: str,
                       action_template: Optional[str], host: Optional[str],
                       manual_command: str, unresolved: list[str],
                       alert_ids: Optional[list[str]] = None) -> tuple[Optional[dict], str]:
    """Find an earlier suggestion in the SAME investigation that this one refines.

    Re-calling `suggest_containment` after the pivot enriches the evidence used
    to mint a fresh ACT-N per recipe action, so a report listed both the
    placeholder draft (`kill -9 <pid>`) and the filled command. Returns
    (record, how) where how is:
      "duplicate"  — same detector/template/host and identical rendered command:
                     reuse the existing record, mint nothing;
      "supersede"  — the existing record still has unresolved placeholders and
                     the new rendering resolves more of them: mark the old one
                     superseded_by the new id;
      ""           — nothing to relate (different target or unrelated alerts).
    A completed identical command is reused for the same alert. Only unexecuted
    drafts can be superseded; alert ownership also links pre-investigation actions.
    """
    if not (investigation_id or alert_ids) or not action_template:
        return None, ""
    sug_dir = _response_dir(case_id) / "suggestions"
    if not sug_dir.is_dir():
        return None, ""
    candidates: list[dict] = []
    for p in sorted(sug_dir.glob("ACT-*.json")):
        try:
            rec = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not ((investigation_id and rec.get("investigation_id") == investigation_id)
                or set(alert_ids or []) & set(rec.get("alert_ids") or [])):
            continue
        if alert_ids and rec.get("alert_ids") and not set(alert_ids) & set(rec["alert_ids"]):
            continue
        if rec.get("detector") != detector or rec.get("action_template") != action_template:
            continue
        if (rec.get("host") or None) != (host or None):
            continue
        if rec.get("superseded_by"):
            continue
        executed = _load_execution(case_id, rec.get("action_id", ""))
        if executed:
            if not executed.get("reverted") and rec.get("manual_command", "").strip() == manual_command.strip():
                return rec, "duplicate"
            continue
        candidates.append(rec)
    for rec in reversed(candidates):  # newest first
        if (rec.get("manual_command") or "").strip() == manual_command.strip():
            return rec, "duplicate"
        old_unresolved = set(rec.get("unresolved_placeholders") or [])
        if old_unresolved and set(unresolved) < old_unresolved:
            return rec, "supersede"
    return None, ""


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
    # narration entries are type 'investigation_narration' — 'agent_message'
    # never existed as an entry type.
    if entry is None or entry.get("type") not in ("finding", "investigation_narration"):
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
@_serialized
def suggest_containment(
    case_id: str,
    finding_id: int = 0,
    detector: Optional[str] = None,
    evidence: Optional[dict] = None,
    client_id: Optional[str] = None,
    investigation_id: Optional[str] = None,
    alert_id: Optional[str] = None,
) -> dict:
    """Recommend operator-runnable containment commands from an alert or finding.

    Looks up the recipe matching the detector and renders each candidate
    action's description + copyable `manual_command` with the evidence
    substituted in, writing one ACT-N.json per option under
    `~/cases/<case>/monitoring/response/suggestions/`. Nothing executes here —
    `execute_action` is the gated write path; the returned `manual_command`
    strings are the operator-runnable equivalents.

    Every suggestion is stamped with the open investigation's id (or
    `investigation_id=` when given) so the investigation report lists only its
    own actions. Re-suggesting the same recipe action for the same detector and
    host inside one investigation does not mint a new ACT: an identical command
    reuses the existing record, and a rendering that resolves placeholders the
    earlier draft left open supersedes it (`supersedes` / `superseded_by`).

    LIVE-MODE FAST PATH: `finding_id` is OPTIONAL. In live monitoring, call this
    straight off a high-confidence detector alert — pass `detector` + `evidence`
    from the alert payload and leave `finding_id=0`. Containment must NOT wait on
    the forensic finding ceremony (tier contracts, evidence-citation rounds);
    record the forensic finding in parallel/after for the report. When a recorded
    finding does exist, pass its `_trudi_call_id` as `finding_id` for linkage.
    """
    refusal = response_gates.check_live_monitoring_scope(case_id)
    if refusal:
        return refusal
    _ensure_layout(case_id)

    finding = _load_finding(finding_id) if finding_id else None
    if finding is None and (detector is None or evidence is None):
        return {
            "success": False,
            "error": "pass detector= and evidence= from the alert (live fast path), "
                     "or a valid finding_id whose trace entry carries them. "
                     f"finding_id={finding_id} resolved no finding and no detector/evidence given.",
        }

    if detector is None:
        desc = (finding or {}).get("description") or ""
        for known in ("NewProcess", "NewPersistence", "NewNetwork", "YaraProcess",
                      "NewLogon", "PrivilegeEscalation"):
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

    # Route this alert's containment to the host it came from (multi-host cases),
    # falling back to the single configured host. Stamped on every suggestion so
    # execute_action acts on the alerting host, not a hard-wired one.
    target_host = _host_for_alert(case_id, client_id or evidence_lc.get("client_id"))
    alert_id = alert_id or evidence_lc.get("alert_id")
    alert_ids = [str(alert_id)] if alert_id else []
    inv_id = investigation_id or (response_store.investigation_for_alerts(CASES_ROOT / case_id, alert_ids)
                                  if alert_ids else _open_investigation_id(case_id))

    suggestions: list[dict] = []
    reused: list[str] = []
    superseded: list[dict] = []
    for action in recipe.get("actions", []):
        description = _render(action.get("description", ""), evidence_lc)
        manual_command = _render(action.get("manual_command", ""), evidence_lc)
        # Any placeholder still present after substitution is unresolved evidence.
        unresolved = sorted(set(_PLACEHOLDER_RE.findall(manual_command + " " + description)))
        action_template = action.get("action_template")

        prior, how = _find_supersedable(case_id, inv_id, detector, action_template,
                                        target_host, manual_command, unresolved, alert_ids)
        if how == "duplicate":
            prior["alert_ids"] = sorted(set(prior.get("alert_ids") or []) | set(alert_ids))
            if inv_id and not prior.get("investigation_id"):
                prior["investigation_id"] = inv_id
            (_response_dir(case_id) / "suggestions" / f"{prior['action_id']}.json").write_text(json.dumps(prior, indent=2))
            # Same command already on offer in this investigation — hand it back
            # rather than minting a twin.
            suggestions.append(prior)
            reused.append(prior.get("action_id", ""))
            continue

        action_id = _next_action_id(case_id)
        # Pre-validate the structured argv now, so an action whose evidence the
        # validators reject (e.g. quarantine/kill_by_image targeting a SYSTEM
        # binary like /usr/bin/sleep, a protected account, a bad pid) is flagged
        # non-executable and never presented as an auto-runnable containment —
        # execute_action would refuse it anyway, but it must not be OFFERED
        # (least of all AUTO). unresolved placeholders already make it non-exec.
        executable, blocked_reason = True, ""
        if unresolved:
            executable = False
            blocked_reason = f"unresolved evidence placeholders: {unresolved}"
        elif action_template:
            try:
                ssh_exec.build_argv(action_template, dict(evidence_lc))
            except ssh_exec.ParamValidationError as e:
                executable = False
                blocked_reason = str(e)
        record = {
            "action_id": action_id,
            "case_id": case_id,
            "finding_id": finding_id,
            "detector": detector,
            "client_id": client_id or evidence_lc.get("client_id"),
            "host": target_host,
            "description": description,
            "manual_command": manual_command,
            "risk": action.get("risk", "medium"),
            "reversible": bool(action.get("reversible")),
            "executable": executable,
            "blocked_reason": blocked_reason,
            "unresolved_placeholders": unresolved,
            "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            # Self-contained execution metadata (additive — existing consumers
            # ignore these). action_template selects the validated argv builder;
            # raw_evidence carries the typed values execute/revert validate.
            "action_template": action_template,
            "revert_template": ssh_exec.revert_template_for(action_template),
            "raw_evidence": dict(evidence_lc),
            # Report scoping: which investigation this action belongs to.
            "investigation_id": inv_id,
            "alert_ids": alert_ids,
            "incident_id": evidence_lc.get("incident_id"),
            "supersedes": (prior or {}).get("action_id") if how == "supersede" else None,
            "superseded_by": None,
        }
        path = _response_dir(case_id) / "suggestions" / f"{action_id}.json"
        path.write_text(json.dumps(record, indent=2))
        suggestions.append(record)

        if how == "supersede" and prior is not None:
            prior["superseded_by"] = action_id
            prior["superseded_at_utc"] = record["created_at_utc"]
            old_path = _response_dir(case_id) / "suggestions" / f"{prior['action_id']}.json"
            old_path.write_text(json.dumps(prior, indent=2))
            superseded.append({"action_id": prior["action_id"], "superseded_by": action_id})

    return {
        "success": True,
        "case_id": case_id,
        "detector": detector,
        "finding_id": finding_id,
        "investigation_id": inv_id,
        "suggestions": suggestions,
        "reused_action_ids": reused,
        "superseded": superseded,
    }


@mcp.tool()
@output_safe
def list_actions(case_id: str, status: str = "all",
                 investigation_id: Optional[str] = None,
                 include_superseded: bool = False) -> dict:
    """List the suggested containment actions for the case (with their
    manual_command). `status` is accepted for back-compat. Pass
    `investigation_id` to see one investigation's actions only; superseded
    drafts are hidden unless `include_superseded=True`."""
    refusal = response_gates.check_live_monitoring_scope(case_id)
    if refusal:
        return refusal
    _ensure_layout(case_id)
    actions: list[dict] = []
    for sug_path in sorted((_response_dir(case_id) / "suggestions").glob("ACT-*.json")):
        try:
            rec = json.loads(sug_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if investigation_id and rec.get("investigation_id") != investigation_id:
            continue
        if rec.get("superseded_by") and not include_superseded:
            continue
        actions.append(rec)
    return {"success": True, "case_id": case_id, "actions": actions}


@mcp.tool()
@output_safe
def snapshot_evidence(
    case_id: str,
    detector: Optional[str] = None,
    evidence: Optional[dict] = None,
    host: Optional[str] = None,
    client_id: Optional[str] = None,
) -> dict:
    """Capture the alert's forensic grounding BEFORE containment destroys it.

    Contain-first is fast, but quarantining a binary / killing a process /
    deleting a cron file removes the very artifacts a finding must cite. Call
    this immediately after an alert fires and BEFORE respond.execute_action:
    it runs the detector-appropriate READ-ONLY live captures (process
    /proc details, persistence file content, inbound-session netstat) and
    returns their `_trudi_call_id`s. Cite those in the finding's
    `input_call_ids` so the intrusion stays provable after eradication.

    Read-only: uses the live.* read path, never mutates the endpoint.
    """
    refusal = response_gates.check_live_monitoring_scope(case_id)
    if refusal:
        return refusal
    if not detector or evidence is None:
        return {"success": False,
                "error": "pass detector= and evidence= from the alert payload."}
    ev = {str(k).lower(): v for k, v in (evidence or {}).items()}
    # Snapshot the host the ALERT came from (multi-host cases), else the single
    # configured host. An explicit `host=` still overrides. Capturing the wrong
    # host silently describes an unrelated process (observed in INV-001).
    h = host or _host_for_alert(case_id, client_id or ev.get("client_id"))
    if not h:
        return {"success": False,
                "error": "no live host configured — set 'host' in monitoring/config.json "
                         "or register one in live_hosts.json."}
    det = detector.rsplit(".", 1)[-1]
    pid, path = ev.get("pid"), ev.get("path")

    from tools import live as _live

    def _fn(tool):
        return getattr(tool, "fn", tool)

    captured: list[dict] = []

    def _cap(label: str, tool, *args):
        try:
            r = _fn(tool)(*args)
        except Exception as e:  # noqa: BLE001
            captured.append({"capture": label, "error": str(e)[:160]})
            return
        if isinstance(r, dict):
            captured.append({"capture": label, "call_id": r.get("_trudi_call_id"),
                             "success": r.get("success")})

    # Process-centric detectors: /proc/<pid> (uid, cmdline, exe, maps) is the
    # root/lineage proof that a kill erases.
    if det in ("NewProcess", "PrivilegeEscalation", "YaraProcess") and pid is not None:
        try:
            _cap("process_details", _live.live_process_details, h, int(pid))
        except (TypeError, ValueError):
            pass
    # Persistence: the file content a removal deletes.
    if det == "NewPersistence" and path:
        _cap("persistence_file", _live.live_read_file, h, path)
    # Session / egress detectors: the ESTABLISHED flow a block/kill tears down.
    # DecoyTouch is an external-detection egress touch — the beachhead→decoy
    # flow and (once the pivot enriches the evidence) its owning pid are what a
    # block/kill removes, so capture the same session surface.
    if det in ("NewLogon", "NewNetwork", "DecoyTouch"):
        _cap("network_connections", _live.live_network_connections, h)
        if pid is not None:
            try:
                _cap("session_proc", _live.live_process_details, h, int(pid))
            except (TypeError, ValueError):
                pass
    # Always anchor a full process table for lineage context.
    _cap("process_table", _live.live_processes, h)

    call_ids = [c["call_id"] for c in captured if c.get("call_id")]
    return {
        "success": bool(call_ids),
        "case_id": case_id, "host": h, "detector": detector,
        "snapshot_call_ids": call_ids,
        "captured": captured,
        "hint": "cite snapshot_call_ids in the finding's input_call_ids so the "
                "intrusion stays grounded after contain/eradicate.",
    }


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


def _host_for_alert(case_id: str, client_id: Optional[str]) -> Optional[str]:
    """Route this alert's response to the host it CAME FROM.

    A multi-host live case (e.g. a lateral A→B demo) emits alerts from several
    clients; snapshot/containment must act on the alerting client's host, not a
    single hard-wired one. Resolve by the alert's `client_id` via the case's
    client_map, falling back to the single-host resolution when the client is
    unmapped (single-endpoint cases) — never silently acting on the wrong host.
    """
    return policy.host_for_client(case_id, client_id) or _resolve_host_for_case(case_id)


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
@_serialized
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
    previous = _load_execution(case_id, action_id)
    if previous and previous.get("success") and not previous.get("reverted"):
        return {"success": True, "case_id": case_id, "action_id": action_id,
                "already_executed": True, "execution": previous,
                "rollback_command": previous.get("rollback_command")}
    # Superseded first: the refusal should point at the replacement, not at the
    # placeholder the replacement already filled.
    if suggestion.get("superseded_by"):
        return {
            "success": False,
            "error": f"{action_id} was superseded by {suggestion['superseded_by']} "
                     f"(re-suggested with enriched evidence); execute that one instead.",
        }
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

    # Act on the host the suggestion was routed to (the alerting client's host),
    # falling back to single-host resolution for suggestions recorded before
    # host-aware routing. This is what makes containment hit the right host in a
    # multi-host case rather than a single hard-wired one.
    host = suggestion.get("host") or _host_for_alert(case_id, suggestion.get("client_id"))
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
        # Report scoping: the investigation this execution belongs to.
        "investigation_id": suggestion.get("investigation_id") or (
            response_store.investigation_for_alerts(CASES_ROOT / case_id, suggestion.get("alert_ids") or [])
            if suggestion.get("alert_ids") else _open_investigation_id(case_id)),
        "alert_ids": suggestion.get("alert_ids") or [],
        "incident_id": suggestion.get("incident_id"),
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
@_serialized
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


# ── Autonomous containment (server-side; called by the ingest sidecar) ─────────

# Detector classes that are confirmed positives with NO false-positive branch,
# so the reversible containment can fire the instant the alert lands, with no
# agent in the loop: a decoy touch presents a honey credential that has no
# legitimate use — it is a positive by construction.
_AUTO_CONTAIN_DETECTORS = {"DecoyTouch"}


def _plain(tool):
    """The underlying function of an @mcp.tool()/@output_safe-wrapped callable."""
    return getattr(tool, "fn", tool)


def auto_contain(case_id: str, detector: str, evidence: Optional[dict] = None,
                 client_id: Optional[str] = None, alert_id: Optional[str] = None) -> dict:
    """Execute the reversible, low-risk containment for a confirmed-positive alert
    **immediately, without the agent** — the ingest sidecar calls this the instant
    it writes the alert, so containment latency is ~seconds (no agent wake, no
    tool-schema load, no `reason.*` call in front of it).

    Requires a saved, signed alert bound to the configured source client and
    decoy endpoint, as well as all three response-policy guards:
      1. the case opted into `auto_protect` (`monitoring/config.json`);
      2. the detector is a confirmed-positive class (`_AUTO_CONTAIN_DETECTORS`),
         i.e. an alert with no false-positive branch;
      3. only actions the server classifies **AUTO** (reversible AND risk:low)
         execute — through the SAME `execute_action` gate the agent is held to.
    Destructive actions are never executed here: they are left on disk as
    (possibly placeholder) suggestions for the agent to resolve + queue for
    operator approval. Reversible, so a mistaken block is one `revert_action`
    away. Never raises — returns a summary the caller logs.
    """
    out = {"case_id": case_id, "detector": detector, "ran": False,
           "contained": [], "deferred": [], "skipped": None}
    try:
        if response_gates.check_live_monitoring_scope(case_id, client_id):
            out["skipped"] = "not a live-monitoring case"
            return out
        leaf = (detector or "").rsplit(".", 1)[-1]
        if leaf not in _AUTO_CONTAIN_DETECTORS:
            out["skipped"] = f"{leaf} is not a confirmed-positive auto-contain class"
            return out
        cfg = policy.load_config(case_id, cases_root=CASES_ROOT)
        if not (cfg.get("auto_protect") or {}).get("enabled"):
            out["skipped"] = "auto_protect disabled"
            return out

        from monitoring.cef_auth import authorize_alert
        alert = response_store.find_alert(CASES_ROOT / case_id, alert_id or "")
        if not alert or not authorize_alert(CASES_ROOT / case_id, alert, evidence or {}, client_id):
            out["skipped"] = "no authenticated, source-bound alert authorizes containment"
            return out

        sug = _plain(suggest_containment)(case_id, detector=detector,
                                          evidence=evidence or {}, client_id=client_id,
                                          alert_id=alert_id)
        if not sug.get("success"):
            out["skipped"] = sug.get("error", "suggest_containment failed")
            return out
        out["ran"] = True
        for a in sug.get("suggestions", []):
            aid = a.get("action_id")
            # AUTO tier only — reversible AND low-risk AND executable off the alert.
            if a.get("executable") and a.get("reversible") and a.get("risk") == "low":
                res = _plain(execute_action)(case_id, action_id=aid, mode="auto")
                out["contained"].append({
                    "action_id": aid, "template": a.get("action_template"),
                    "success": bool(res.get("success")),
                    "command": (res.get("execution") or {}).get("command_str"),
                    "rollback": res.get("rollback_command"),
                    "error": None if res.get("success") else res.get("error") or (res.get("execution") or {}).get("stderr"),
                })
            else:
                # Destructive / placeholder → the agent resolves + queues for approval.
                out["deferred"].append({
                    "action_id": aid, "template": a.get("action_template"),
                    "reason": a.get("blocked_reason") or "destructive — operator approval required",
                })
    except Exception as e:  # noqa: BLE001 — auto-contain must never break the ingest
        out["skipped"] = f"auto_contain error: {e}"
    return out
