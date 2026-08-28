#!/usr/bin/env python3
"""UserPromptSubmit hook: copy operator-typed prompts → TRUDI trace.

Sister to `log_narration.py` (PostToolUse). Whenever the operator
submits a prompt to Claude Code, this hook appends a `user_message`
entry to whichever trace file is currently active (looked up via
`~/.cache/trudi/session.json` — the same beacon `log.configure()`
writes from the MCP server side).

This is the load-bearing input to the `operator_text_required` gate in
`response/gates.py`: that gate refuses `respond.approve_action` unless
a recent `user_message` trace entry whose content matches
`operator_text` exists. Without this hook, the gate had nothing to
match and refused every approval.

Behaviour:
- No-op if `~/.cache/trudi/session.json` doesn't point at a real trace
  (no active TRUDI investigation).
- Acquires the shared `~/.cache/trudi/hook.lock` fcntl lock so we
  cannot race with `log_narration.py` or the MCP server's `_flush()`.
- Dedups on the harness-provided event UUID stored in the trace as
  `_source_uuid`, plus a state set under
  `~/.cache/trudi/hook_state.json` → `processed_user_message_uuids`.
- Uses the shared call_id counter (`_next_shared_id` from
  `log_narration.py`) so cids stay monotonic across hook + MCP writes.

Payload shape from Claude Code:
    {
      "session_id": "...",
      "transcript_path": "/path/to/transcript.jsonl",
      "cwd": "...",
      "hook_event_name": "UserPromptSubmit",
      "prompt": "...",        # the operator's verbatim text
      "uuid": "..."           # may or may not be present depending on version
    }

We tolerate missing fields (`uuid`, `prompt`) gracefully — the trace
just doesn't get an entry for that turn.
"""
import fcntl
import json
import os
import sys
import uuid as _uuid
from pathlib import Path
from datetime import datetime, timezone

_STATE_FILE = Path.home() / ".cache/trudi/hook_state.json"
_SESSION_FILE = Path.home() / ".cache/trudi/session.json"
_LOCK_FILE = Path.home() / ".cache/trudi/hook.lock"

_MAX_CONTENT = 2000


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _process(trace_path: str, payload: dict) -> None:
    prompt = payload.get("prompt") or payload.get("user_message")
    if not isinstance(prompt, str) or not prompt.strip():
        return

    source_uuid = payload.get("uuid") or _uuid.uuid4().hex

    # Load dedup state — same file `log_narration.py` writes to; scoped per
    # session so one session's churn can't evict another's dedup keys.
    try:
        state = json.loads(_STATE_FILE.read_text()) if _STATE_FILE.exists() else {}
    except (OSError, json.JSONDecodeError):
        state = {}
    sid = payload.get("session_id") or "_global"
    sessions = state.setdefault("sessions", {})
    mine = sessions.setdefault(sid, {})
    if state.get("processed_user_message_uuids"):  # legacy top-level key
        mine["processed_user_message_uuids"] = list(
            set(mine.get("processed_user_message_uuids", []))
            | set(state.pop("processed_user_message_uuids")))
    processed = set(mine.get("processed_user_message_uuids", []) or [])

    if source_uuid in processed:
        return

    # Belt-and-suspenders: scan the trace too in case our state file was lost.
    try:
        trace = json.loads(Path(trace_path).read_text())
    except (OSError, json.JSONDecodeError):
        return
    for e in trace.get("entries", []) or []:
        u = e.get("_source_uuid")
        if u:
            processed.add(u)
    if source_uuid in processed:
        return

    # Borrow `_next_shared_id` from the sister hook so the call_id counter
    # stays monotonic across hook + MCP writes.
    from log_narration import _next_shared_id

    cid = _next_shared_id(trace_path)
    entry = {
        "call_id": cid,
        "type": "user_message",
        "ts": _utcnow(),
        "content": prompt[:_MAX_CONTENT],
        "source": "claude_code_user_prompt",
        "role": "user",
        "_source_uuid": source_uuid,
    }
    if payload.get("session_id"):
        entry["_source_session_id"] = payload["session_id"]

    existing = trace.get("entries", []) or []
    existing.append(entry)
    trace["entries"] = existing
    trace["entry_count"] = len(existing)

    tmp_trace = Path(trace_path).with_suffix(".json.user.tmp")
    tmp_trace.write_text(json.dumps(trace, indent=2))
    os.replace(tmp_trace, trace_path)

    processed.add(source_uuid)
    mine["processed_user_message_uuids"] = list(processed)[-1000:]
    _STATE_FILE.write_text(json.dumps(state))


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return

    _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    lock = open(_LOCK_FILE, "w")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        # Make sibling modules importable (log_narration, _session_owner).
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        # Session-ownership gate — only the beacon-owning session writes
        # (claim atomic under the flock we hold). See _session_owner.py.
        from _session_owner import resolve_owner
        trace_path, _reason = resolve_owner(payload, claim=True)
        if trace_path is None:
            return
        _process(trace_path, payload)
    finally:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock.close()


if __name__ == "__main__":
    main()
