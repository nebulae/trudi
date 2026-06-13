"""Server-side gate checks for respond.* tools.

Three gates, all dual-key by design — the agent cannot self-approve
because every gate reaches back into the trace and demands evidence that
the operator put their literal text there.

- live_monitoring_scope     fires on every respond.* call
- approval_required         fires on execute_action / revert_action
- operator_text_required    fires on approve_action
"""
from __future__ import annotations
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Optional

CASES_ROOT = Path(os.environ.get("TRUDI_CASES_ROOT") or os.path.expanduser("~/cases"))

# How long an approval token stays valid. Short by design — operators are
# expected to type "approve ACT-N" right before the agent calls execute.
APPROVAL_TTL_SECONDS = 600

# How far back in the trace to look for the user_message that backs an
# approve_action call. Matches the standard "last 30 entries" window used
# by the record_finding gate stack so a multi-step investigation doesn't
# scroll the operator's approval out of range.
APPROVAL_LOOKBACK_ENTRIES = 30


def _approval_path(case_id: str, action_id: str) -> Path:
    return CASES_ROOT / case_id / "monitoring" / "response" / "approvals" / f"{action_id}.json"


def _suggestion_path(case_id: str, action_id: str) -> Path:
    return CASES_ROOT / case_id / "monitoring" / "response" / "suggestions" / f"{action_id}.json"


def _baseline_dir(case_id: str) -> Path:
    return CASES_ROOT / case_id / "monitoring" / "baselines"


def _refuse(gate: str, error: str, **extra) -> dict:
    out = {"success": False, "gate": gate, "error": error}
    out.update(extra)
    return out


# ─────────────────────────────────────────────────────────────────────────────

def check_live_monitoring_scope(case_id: str, client_id: Optional[str] = None) -> Optional[dict]:
    """Refuse if `case_id` isn't a live-monitoring case (no baselines)."""
    baselines = _baseline_dir(case_id)
    if not baselines.exists() or not any(baselines.iterdir()):
        return _refuse(
            "live_monitoring_scope",
            f"respond.* is restricted to active live-monitoring cases. "
            f"No baselines found under {baselines}. "
            f"Run monitor.baseline_capture against a client first.",
        )
    if client_id is not None:
        candidate = baselines / f"{client_id}.json"
        if not candidate.exists():
            return _refuse(
                "live_monitoring_scope",
                f"client_id {client_id!r} is not baselined for case {case_id!r}. "
                f"Expected baseline at {candidate}.",
            )
    return None


def check_operator_text(case_id: str, action_id: str, operator_text: str) -> Optional[dict]:
    """Refuse approve_action unless action_id is literally in operator_text
    AND a matching user_message exists in the recent trace.

    The recent-trace check is what makes this dual-key: the agent could
    *forge* operator_text in the function arg, but it cannot fabricate a
    `user_message` source entry — those come from the harness and carry
    the role/role-content fields the agent doesn't write."""
    if action_id not in operator_text:
        return _refuse(
            "operator_text_required",
            f"action_id {action_id!r} not literally present in operator_text. "
            f"Operator must type the action id verbatim (e.g. 'approve {action_id}').",
            operator_text_excerpt=operator_text[:240],
        )

    suggestion = _suggestion_path(case_id, action_id)
    if not suggestion.exists():
        return _refuse(
            "operator_text_required",
            f"no suggestion record found for action_id {action_id!r} at {suggestion}. "
            f"approve_action requires a prior respond.suggest_containment call.",
        )

    try:
        from core.execution_log import log
        entries = log.last_n_window(n=APPROVAL_LOOKBACK_ENTRIES)
    except Exception as e:  # noqa: BLE001
        return _refuse(
            "operator_text_required",
            f"trace not initialised — cannot verify operator message ({e})",
        )

    needle = operator_text.strip()
    matched = False
    for entry in entries:
        # The harness writes operator inputs as entries with type/source we
        # can recognise. We look for any recent entry where the content
        # equals operator_text and the source/type marks it as user-origin.
        content = (entry.get("content") or entry.get("user_message") or "").strip()
        if not content:
            continue
        source = entry.get("source", "")
        type_ = entry.get("type", "")
        role = (entry.get("role") or "")
        is_user_entry = (
            type_ == "user_message"
            or source == "claude_code_user_prompt"
            or "user_message" in source
            or "user_message" in type_
            or role == "user"
        )
        if needle == content and is_user_entry:
            matched = True
            break

    if not matched:
        return _refuse(
            "operator_text_required",
            f"could not find a recent user_message trace entry whose content matches operator_text. "
            f"The agent cannot self-approve — only operator-typed messages satisfy this gate. "
            f"Looked at the last {APPROVAL_LOOKBACK_ENTRIES} trace entries.",
        )
    return None


def issue_approval(case_id: str, action_id: str, operator_text: str) -> dict:
    """Persist an approval token for action_id; called by approve_action
    after the operator_text gate has passed."""
    path = _approval_path(case_id, action_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    record = {
        "action_id": action_id,
        "case_id": case_id,
        "operator_text": operator_text,
        "approval_token": token,
        "approved_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "expires_at_epoch": int(time.time()) + APPROVAL_TTL_SECONDS,
    }
    path.write_text(json.dumps(record, indent=2))
    return record


def check_approval(case_id: str, action_id: str) -> tuple[Optional[dict], Optional[dict]]:
    """Return (approval_record, refusal). Exactly one is non-None.

    refusal carries gate="approval_required" when no valid approval exists.
    """
    path = _approval_path(case_id, action_id)
    if not path.exists():
        return None, _refuse(
            "approval_required",
            f"no approval found for action_id {action_id!r}. "
            f"Operator must type 'approve {action_id}' and the agent must call "
            f"respond.approve_action before respond.execute_action.",
            expected_at=str(path),
        )
    try:
        record = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return None, _refuse("approval_required", f"approval record unreadable: {e}")

    if record.get("expires_at_epoch", 0) < int(time.time()):
        return None, _refuse(
            "approval_required",
            f"approval for {action_id!r} expired at "
            f"{record.get('approved_at_utc')!r}+{APPROVAL_TTL_SECONDS}s. "
            f"Operator must re-approve.",
        )
    return record, None


def check_execution_permitted(
    case_id: str, action_id: str, suggestion: dict, *, mode: str = "operator"
) -> Optional[dict]:
    """The single permission decision for respond.execute_action / revert_action.

    Composes the auto-protect policy with the existing approval gate:

      * If the action is server-classified AUTO (reversible AND low-risk) AND
        auto-protect is enabled for the case, permit with no approval token.
      * Otherwise (destructive, OR auto-protect disabled) fall through to
        check_approval — which requires a non-expired operator-issued token.

    `mode` is advisory (recorded for audit only). Permission is recomputed from
    disk every call, so passing mode='auto' on a destructive action does NOT
    bypass approval — classify() returns NEEDS_APPROVAL and the call falls into
    check_approval regardless. The agent therefore cannot self-execute a
    destructive action.
    """
    from response import policy
    tier = policy.classify(suggestion)
    if tier == policy.AUTO and policy.auto_protect_enabled(case_id):
        return None
    _, refusal = check_approval(case_id, action_id)
    return refusal
