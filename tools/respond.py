"""Containment recommendations for live-monitoring findings.

TRUDI does NOT execute remediation. Velociraptor's `execve()` is absent from the
shipped client build, so automated artifact-based remediation is not available;
just as importantly, keeping execution out of the agent's hands is the safer
posture. Instead, `suggest_containment` turns a CONFIRMED/LIKELY finding into a
small set of **operator-runnable commands** (rendered from the detector's recipe
with the finding's evidence substituted in). The agent surfaces them and writes
them into the investigation report; a human runs them out-of-band.

  respond.suggest_containment(case_id, finding_id, detector=, evidence=)
      Looks up response/recipes/<detector>.yaml, renders each action's
      description + copyable `manual_command` with evidence values, and writes
      one ACT-N.json per option under
      ~/cases/<case>/monitoring/response/suggestions/. NOTHING EXECUTES.

  respond.list_actions(case_id)
      List the suggested actions for the case.

The only gate is `live_monitoring_scope` — these tools are meaningful only for an
active live-monitoring case.
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

from core import output_safe
from response import gates as response_gates

mcp = FastMCP("respond")

CASES_ROOT = Path(os.environ.get("TRUDI_CASES_ROOT") or os.path.expanduser("~/cases"))
RECIPES_DIR = Path(__file__).resolve().parent.parent / "response" / "recipes"

_PLACEHOLDER_RE = re.compile(r"<([A-Za-z0-9_]+)>")


def _response_dir(case_id: str) -> Path:
    return CASES_ROOT / case_id / "monitoring" / "response"


def _ensure_layout(case_id: str) -> None:
    (_response_dir(case_id) / "suggestions").mkdir(parents=True, exist_ok=True)


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
