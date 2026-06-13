"""Auto-protect policy: server-side action classifier + per-case config.

Two responsibilities, both deliberately read from disk (not from agent
arguments) so the agent cannot talk its way into a higher autonomy tier:

- `classify(suggestion)` — AUTO vs NEEDS_APPROVAL from the suggestion record's
  recipe-derived `risk`/`reversible` fields. AUTO iff reversible AND risk==low.
  Fail-closed: anything ambiguous is NEEDS_APPROVAL.
- `load_config(case_id)` — reads `~/cases/<case>/monitoring/config.json`.
  auto_protect.enabled defaults to True when the file is absent or unparseable
  ("enabled when unconfigured"), so the feature is on by default with no file.
  demo_response.respond_to_synthetic defaults to False: demo/synthetic findings
  are not response-eligible unless a lab case opts in explicitly.

This file is machine-read configuration (sibling to live_hosts.json), NOT
agent-parsed prose — keeping it out of any CLAUDE.md preserves the guardrail
that the agent cannot edit its own permission to act.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional

CASES_ROOT = Path(os.environ.get("TRUDI_CASES_ROOT") or os.path.expanduser("~/cases"))

AUTO = "AUTO"
NEEDS_APPROVAL = "NEEDS_APPROVAL"


def classify(suggestion: dict) -> str:
    """Server-side tier for a suggestion record.

    AUTO only when the action is explicitly reversible AND low risk. Every other
    case — irreversible, risk medium/high, or missing/garbled metadata — is
    NEEDS_APPROVAL (fail-closed)."""
    if not isinstance(suggestion, dict):
        return NEEDS_APPROVAL
    risk = str(suggestion.get("risk", "")).strip().lower()
    reversible = suggestion.get("reversible")
    if reversible is True and risk == "low":
        return AUTO
    return NEEDS_APPROVAL


def _config_path(case_id: str, cases_root: Optional[Path] = None) -> Path:
    root = cases_root or CASES_ROOT
    return root / case_id / "monitoring" / "config.json"


def load_config(case_id: str, cases_root: Optional[Path] = None) -> dict:
    """Return the normalized case config. Defaults auto_protect.enabled=True when
    the file is missing or unreadable. Demo-response is opt-in."""
    default = {
        "auto_protect": {"enabled": True},
        "demo_response": {"enabled": False, "respond_to_synthetic": False},
        "host": None,
    }
    path = _config_path(case_id, cases_root)
    if not path.exists():
        return default
    try:
        doc = json.loads(path.read_text()) or {}
    except (OSError, json.JSONDecodeError, ValueError):
        return default
    ap = doc.get("auto_protect")
    enabled = True
    if isinstance(ap, dict):
        enabled = bool(ap.get("enabled", True))
    dr = doc.get("demo_response")
    demo_enabled = False
    respond_to_synthetic = False
    if isinstance(dr, dict):
        demo_enabled = bool(dr.get("enabled", False))
        respond_to_synthetic = bool(dr.get("respond_to_synthetic", demo_enabled))
    return {
        "auto_protect": {"enabled": enabled},
        "demo_response": {
            "enabled": demo_enabled,
            "respond_to_synthetic": respond_to_synthetic,
        },
        "host": doc.get("host"),
    }


def auto_protect_enabled(case_id: str) -> bool:
    return bool(load_config(case_id)["auto_protect"]["enabled"])


def demo_response_enabled(case_id: str) -> bool:
    """Whether confirmed exercise/demo TTPs should receive containment.

    This is intentionally opt-in per live-monitoring case. A synthetic marker
    in a normal case remains evidence for false-positive handling, not a
    permission to mutate the endpoint.
    """
    dr = load_config(case_id).get("demo_response") or {}
    return bool(dr.get("enabled") and dr.get("respond_to_synthetic"))


def configured_host(case_id: str) -> Optional[str]:
    """Optional explicit live-host alias for this case (from config.json)."""
    return load_config(case_id).get("host")
