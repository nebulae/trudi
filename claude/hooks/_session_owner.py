#!/usr/bin/env python3
"""Session-ownership resolution for TRUDI Claude Code hooks.

The trace beacon (~/.cache/trudi/session.json) is machine-global, and the hooks
are registered globally in ~/.claude/settings.json — so EVERY concurrent Claude
Code session used to write into the one active trace (a dev session's
narrations and bash calls polluting a live investigation's audit trail).

This helper scopes hook writes to the session that owns the beacon:

1. cwd containment — the hook payload's `cwd` must resolve inside the active
   case directory (the trace's parent.parent). A dev session in ~/trudi can
   never write into ~/cases/<case>/.
2. owner claim — the first writing hook to fire after the beacon changes claims
   ownership for its `session_id` (session_owner.json, written under the shared
   hook.lock flock so the claim is race-free). Later hooks carrying a different
   session_id no-op while the same beacon is active; a new investigation
   rewrites the beacon, which re-opens the claim.

Fail-open by design: payloads missing `session_id`/`cwd` (older harnesses)
behave as before — single-session use is never broken by this check.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

# Module-level so tests can monkeypatch them.
SESSION_FILE = Path.home() / ".cache/trudi/session.json"
OWNER_FILE = Path.home() / ".cache/trudi/session_owner.json"


def resolve_trace_path(session_file: "Path | None" = None) -> "str | None":
    """Beacon → absolute trace path (resolving legacy relative paths), or None."""
    session_file = Path(session_file or SESSION_FILE)
    try:
        session = json.loads(session_file.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    trace_path = session.get("path")
    if not trace_path:
        return None
    if not Path(trace_path).is_absolute():
        case_id = session.get("case_id") or ""
        candidate = Path.home() / "cases" / case_id / str(trace_path).lstrip("./")
        if candidate.exists():
            trace_path = str(candidate.resolve())
    if not Path(trace_path).exists():
        return None
    return trace_path


def resolve_owner(payload: dict, claim: bool = True,
                  session_file: "Path | None" = None,
                  owner_file: "Path | None" = None) -> "tuple[str | None, str]":
    """Return (trace_path, reason). trace_path=None ⇒ this hook must not write.

    claim=True (writing hooks) MUST be called while holding the shared
    hook.lock flock — the ownership claim is atomic only under it.
    claim=False (read-only checks, e.g. the PreToolUse guard) never writes.
    """
    session_file = Path(session_file or SESSION_FILE)
    owner_file = Path(owner_file or OWNER_FILE)

    trace_path = resolve_trace_path(session_file)
    if trace_path is None:
        return None, "no_active_case"

    # 1) cwd containment — a session outside the case dir never writes into it.
    cwd = payload.get("cwd")
    if cwd:
        case_dir = Path(trace_path).resolve().parent.parent
        try:
            Path(os.path.realpath(cwd)).relative_to(case_dir)
        except ValueError:
            return None, "cwd_outside_case"

    # 2) session ownership — first session to fire after a beacon change owns it.
    sid = payload.get("session_id")
    if not sid:
        return trace_path, "no_session_id"  # legacy payload — cwd check only
    try:
        beacon_sig = hashlib.sha256(session_file.read_bytes()).hexdigest()
    except OSError:
        return trace_path, "beacon_unreadable"
    try:
        owner = json.loads(owner_file.read_text())
    except (OSError, json.JSONDecodeError):
        owner = None
    now = datetime.now(timezone.utc)
    if owner and owner.get("beacon_sig") == beacon_sig:
        if owner.get("session_id") and owner["session_id"] != sid:
            # A claim is only as alive as its session: if the owner has not
            # fired a hook within OWNER_TTL_SEC, it is stale (closed session,
            # or the case-clear session that raced ahead of the real
            # investigation) and a same-case session may take over.
            if not _stale(owner, now):
                return None, "not_owner"
            if not claim:
                return trace_path, "stale_owner"
            _write_claim(owner_file, sid, beacon_sig, now)
            return trace_path, "claimed_stale_takeover"
        if claim:
            _write_claim(owner_file, sid, beacon_sig, now)  # refresh last_seen
        return trace_path, "owner"
    # Beacon changed (or never claimed) — claim it for this session.
    if claim:
        _write_claim(owner_file, sid, beacon_sig, now)
        return trace_path, "claimed"
    return trace_path, "unclaimed"


# Seconds without any hook from the owning session before its claim expires.
OWNER_TTL_SEC = int(os.environ.get("TRUDI_OWNER_TTL_SEC") or "600")


def _stale(owner: dict, now: datetime) -> bool:
    ts = owner.get("last_seen") or owner.get("claimed_ts") or ""
    try:
        seen = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
    except ValueError:
        return True  # unparseable → treat as stale rather than lock forever
    return (now - seen).total_seconds() > OWNER_TTL_SEC


def _write_claim(owner_file: Path, sid: str, beacon_sig: str, now: datetime) -> None:
    """Atomic claim/refresh. Caller holds the hook.lock flock. Fail-open."""
    stamp = now.isoformat(timespec="seconds")
    try:
        owner_file.parent.mkdir(parents=True, exist_ok=True)
        prior = {}
        try:
            prior = json.loads(owner_file.read_text())
        except (OSError, json.JSONDecodeError):
            pass
        claimed_ts = (prior.get("claimed_ts") if prior.get("session_id") == sid
                      and prior.get("beacon_sig") == beacon_sig else None) or stamp
        tmp = owner_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({
            "session_id": sid,
            "beacon_sig": beacon_sig,
            "claimed_ts": claimed_ts,
            "last_seen": stamp,
        }))
        os.replace(tmp, owner_file)
    except OSError:
        pass  # fail-open: the cwd check already passed
