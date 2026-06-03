#!/usr/bin/env python3
"""PostToolUse hook: copy assistant narration + non-MCP tool calls → TRUDI trace.

Three responsibilities:

1. Append `investigation_narration` entries for any new assistant text blocks
   from the transcript that haven't been recorded yet.
2. Append a `tool_call` entry for non-MCP tool calls (Bash, Read, Edit, Write,
   Glob, Grep, etc.) so judges can trace findings back to ALL tool executions,
   not just MCP forensic tools. MCP tools (tool_name starts with `mcp__`) are
   skipped because they're already logged inside the MCP server.
3. Renumber call_ids chronologically and write atomically.

Serialized via an OS-level file lock so concurrent hook invocations (one per
tool in a parallel batch) can't race on the dedup state.

Belt-and-suspenders dedup: each appended entry carries `_source_uuid` (for
narrations) or `_source_tool_use_id` (for tool_calls) so we never double-append
even if the state file is lost.
"""
import fcntl
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

_STATE_FILE = Path.home() / ".cache/trudi/hook_state.json"
_SESSION_FILE = Path.home() / ".cache/trudi/session.json"
_LOCK_FILE = Path.home() / ".cache/trudi/hook.lock"

# Non-MCP Claude Code tools we want surfaced in the trace. Other tools
# (TodoWrite, ExitPlanMode, etc.) are control-plane noise and excluded.
_LOGGED_TOOLS = frozenset({
    "Bash", "Read", "Edit", "Write", "MultiEdit",
    "Glob", "Grep", "NotebookEdit",
})

# Maximum stdout/stderr capture per tool_call entry — keep traces readable.
_MAX_STDOUT = 1200
_MAX_STDERR = 600
_MAX_CMD    = 600


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _synthesize_cmd(tool_name: str, tool_input: dict) -> str:
    """Build a one-line `cmd`-style summary of a non-Bash Claude Code tool call
    so the dashboard's tool_call rendering treats it uniformly."""
    if tool_name == "Bash":
        return (tool_input.get("command") or "")[:_MAX_CMD]
    if tool_name == "Read":
        return f"read {tool_input.get('file_path', '')}"[:_MAX_CMD]
    if tool_name == "Write":
        return f"write {tool_input.get('file_path', '')}"[:_MAX_CMD]
    if tool_name in ("Edit", "MultiEdit"):
        return f"{tool_name.lower()} {tool_input.get('file_path', '')}"[:_MAX_CMD]
    if tool_name == "Glob":
        return f"glob {tool_input.get('pattern', '')}"[:_MAX_CMD]
    if tool_name == "Grep":
        path = tool_input.get('path', '.')
        return f"grep {tool_input.get('pattern', '')!r} in {path}"[:_MAX_CMD]
    if tool_name == "NotebookEdit":
        return f"notebookedit {tool_input.get('notebook_path', '')}"[:_MAX_CMD]
    # Fallback: tool_name + first input key
    return f"{tool_name} {next(iter(tool_input.values()), '')}"[:_MAX_CMD]


def _extract_tool_call_entry(payload: dict) -> dict | None:
    """Convert a PostToolUse payload into a TRUDI tool_call entry, or None
    if this tool should be skipped (MCP tool, unknown tool, etc.)."""
    tool_name = payload.get("tool_name", "")
    if not tool_name or tool_name.startswith("mcp__"):
        return None
    if tool_name not in _LOGGED_TOOLS:
        return None
    tool_use_id = payload.get("tool_use_id", "")
    tool_input = payload.get("tool_input", {}) or {}
    tool_response = payload.get("tool_response", {}) or {}

    cmd = _synthesize_cmd(tool_name, tool_input)
    if not cmd:
        return None

    # Determine success — different tools surface it differently.
    interrupted = bool(tool_response.get("interrupted"))
    is_error = bool(tool_response.get("is_error") or tool_response.get("isError"))
    explicit_success = tool_response.get("success")
    if explicit_success is False or interrupted or is_error:
        success = False
    else:
        success = True

    # Truncate stdout / stderr for trace readability.
    stdout = (tool_response.get("stdout") or tool_response.get("output") or "") or ""
    stderr = (tool_response.get("stderr") or "") or ""
    if isinstance(stdout, (list, dict)):
        try:
            stdout = json.dumps(stdout)[:_MAX_STDOUT]
        except (TypeError, ValueError):
            stdout = str(stdout)[:_MAX_STDOUT]
    if isinstance(stderr, (list, dict)):
        try:
            stderr = json.dumps(stderr)[:_MAX_STDERR]
        except (TypeError, ValueError):
            stderr = str(stderr)[:_MAX_STDERR]

    entry: dict = {
        "call_id": 0,  # renumbered chronologically
        "type": "tool_call",
        "ts": _utcnow(),
        "cmd": cmd,
        "success": success,
        "truncated": False,
        "retries": 0,
        "exit_code": 0 if success else 1,
        "elapsed_seconds": 0,
        "stderr": stderr[:_MAX_STDERR],
        "source": f"claude_code_{tool_name.lower()}",
    }
    if stdout:
        entry["stdout_excerpt"] = stdout[:_MAX_STDOUT]
    if interrupted:
        entry["timed_out"] = True
    if tool_use_id:
        entry["_source_tool_use_id"] = tool_use_id
    return entry


# Shared call_id counter — same file the MCP server reads/writes via
# core/execution_log.py:_next_shared_call_id. We're already inside the
# fcntl lock during _process, so we just bump and persist it inline.
_COUNTER_FILE = Path.home() / ".cache/trudi/call_id.counter"


def _next_shared_id(trace_path: str) -> int:
    """Read+increment the shared counter. Must be called while holding the
    process-wide flock on _LOCK_FILE (the caller already does)."""
    try:
        n = int(json.loads(_COUNTER_FILE.read_text()).get("next", 1))
    except (OSError, ValueError, json.JSONDecodeError, TypeError):
        # Bootstrap from the live trace so we don't reuse an existing id.
        n = 1
        try:
            existing = json.loads(Path(trace_path).read_text()).get("entries", []) or []
            if existing:
                n = max(int(e.get("call_id", 0)) for e in existing) + 1
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            pass
    tmp = _COUNTER_FILE.with_suffix(".counter.tmp")
    tmp.write_text(json.dumps({"next": n + 1}))
    os.replace(tmp, _COUNTER_FILE)
    return n


def _process(transcript_path: str, trace_path: str, payload: dict) -> None:
    # 1) Load dedup state.
    state = json.loads(_STATE_FILE.read_text()) if _STATE_FILE.exists() else {}
    processed_uuids   = set(state.get("processed_uuids", []))
    processed_tool_ids = set(state.get("processed_tool_use_ids", []))

    # 2) Belt-and-suspenders: collect prior dedup keys from the trace itself.
    trace = json.loads(Path(trace_path).read_text())
    for e in trace.get("entries", []):
        u = e.get("_source_uuid")
        if u:
            processed_uuids.add(u)
        t = e.get("_source_tool_use_id")
        if t:
            processed_tool_ids.add(t)

    new_entries: list[dict] = []

    # 3) New narrations from the transcript.
    new_uuids = []
    with open(transcript_path, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if entry.get("type") != "assistant":
                continue
            uuid = entry.get("uuid", "")
            if not uuid or uuid in processed_uuids:
                continue
            new_uuids.append(uuid)
            texts = [
                c["text"]
                for c in entry.get("message", {}).get("content", [])
                if c.get("type") == "text" and c.get("text", "").strip()
            ]
            if texts:
                new_entries.append({
                    "call_id": 0,
                    "type": "investigation_narration",
                    "ts": entry.get("timestamp", _utcnow()),
                    "content": "\n".join(texts)[:2000],
                    "source": "transcript",
                    "_source_uuid": uuid,
                })
            processed_uuids.add(uuid)

    # 4) This call's tool invocation (Bash etc.) — added per-invocation, not
    #    via transcript scan, because the transcript may not yet show it when
    #    the hook fires.
    tool_entry = _extract_tool_call_entry(payload)
    if tool_entry:
        tuid = tool_entry.get("_source_tool_use_id", "")
        if tuid and tuid not in processed_tool_ids:
            new_entries.append(tool_entry)
            processed_tool_ids.add(tuid)
        elif not tuid:
            # No use_id available — append unconditionally; the trace dedup is
            # already best-effort for this rare case.
            new_entries.append(tool_entry)

    if not new_entries:
        # Only persist dedup state if we saw new uuids; otherwise no-op.
        if new_uuids:
            state["processed_uuids"] = list(processed_uuids)[-1000:]
            state["processed_tool_use_ids"] = list(processed_tool_ids)[-1000:]
            _STATE_FILE.write_text(json.dumps(state))
        return

    # 5) Assign call_ids from the shared counter (single sequence across the
    #    MCP server and this hook), then merge under our existing flock so the
    #    server's _flush() can't trample us.
    def _ts_key(entry: dict) -> float:
        ts = entry.get("ts", "")
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except (ValueError, AttributeError):
            return 0.0

    try:
        trace_now = json.loads(Path(trace_path).read_text())
    except (OSError, json.JSONDecodeError):
        trace_now = trace
    existing_entries = trace_now.get("entries", []) or []

    for entry in new_entries:
        entry["call_id"] = _next_shared_id(trace_path)

    merged = existing_entries + new_entries
    merged.sort(key=_ts_key)
    trace_now["entries"] = merged
    trace_now["entry_count"] = len(merged)

    tmp_trace = Path(trace_path).with_suffix(".json.hook.tmp")
    tmp_trace.write_text(json.dumps(trace_now, indent=2))
    os.replace(tmp_trace, trace_path)

    # 6) Persist dedup state (cap dedup sets at 1000).
    state["processed_uuids"]         = list(processed_uuids)[-1000:]
    state["processed_tool_use_ids"]  = list(processed_tool_ids)[-1000:]
    state.pop("next_hook_call_id", None)  # legacy field — now handled by shared counter
    _STATE_FILE.write_text(json.dumps(state))


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return
    transcript_path = payload.get("transcript_path")
    if not transcript_path or not Path(transcript_path).exists():
        return

    if not _SESSION_FILE.exists():
        return  # no active TRUDI investigation
    try:
        session = json.loads(_SESSION_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return
    trace_path = session.get("path")
    if not trace_path or not Path(trace_path).exists():
        return

    _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    lock = open(_LOCK_FILE, "w")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        _process(transcript_path, trace_path, payload)
    finally:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock.close()


if __name__ == "__main__":
    main()
