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

    # Load dedup state — same file `log_narration.py` writes to.
    try:
        state = json.loads(_STATE_FILE.read_text()) if _STATE_FILE.exists() else {}
    except (OSError, json.JSONDecodeError):
        state = {}
    processed = set(state.get("processed_user_message_uuids", []) or [])

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

    existing = trace.get("entries", []) or []
    existing.append(entry)
    trace["entries"] = existing
    trace["entry_count"] = len(existing)

    tmp_trace = Path(trace_path).with_suffix(".json.user.tmp")
    tmp_trace.write_text(json.dumps(trace, indent=2))
    os.replace(tmp_trace, trace_path)

    processed.add(source_uuid)
    state["processed_user_message_uuids"] = list(processed)[-1000:]
    _STATE_FILE.write_text(json.dumps(state))


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return

    if not _SESSION_FILE.exists():
        return  # No active TRUDI investigation.
    try:
        session = json.loads(_SESSION_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return
    trace_path = session.get("path")
    if not trace_path:
        return
    # Older session beacons stored a relative path (e.g.
    # `./analysis/<case>_trace.json`); resolve it against the case dir
    # so the hook works regardless of the harness CWD. New beacons store
    # absolute paths but we defensively handle both.
    if not Path(trace_path).is_absolute():
        case_id = session.get("case_id") or ""
        candidate = Path.home() / "cases" / case_id / trace_path.lstrip("./")
        if candidate.exists():
            trace_path = str(candidate.resolve())
    if not Path(trace_path).exists():
        return

    _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    lock = open(_LOCK_FILE, "w")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        # Make log_narration.py importable as a sibling module.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        _process(trace_path, payload)
    finally:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock.close()


if __name__ == "__main__":
    main()
