#!/usr/bin/env python3
"""PostToolUse hook: copy assistant narration text from transcript → TRUDI trace."""
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

_STATE_FILE = Path.home() / ".cache/trudi/hook_state.json"
_SESSION_FILE = Path.home() / ".cache/trudi/session.json"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main() -> None:
    payload = json.load(sys.stdin)
    transcript_path = payload.get("transcript_path")
    if not transcript_path or not Path(transcript_path).exists():
        return

    if not _SESSION_FILE.exists():
        return  # no active TRUDI investigation
    session = json.loads(_SESSION_FILE.read_text())
    trace_path = session.get("path")
    if not trace_path or not Path(trace_path).exists():
        return

    # Load dedup state
    state = json.loads(_STATE_FILE.read_text()) if _STATE_FILE.exists() else {}
    processed = set(state.get("processed_uuids", []))

    # Scan transcript for new assistant entries with text blocks
    new_uuids = []
    new_messages = []
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
            if not uuid or uuid in processed:
                continue
            new_uuids.append(uuid)
            texts = [
                c["text"]
                for c in entry.get("message", {}).get("content", [])
                if c.get("type") == "text" and c.get("text", "").strip()
            ]
            if not texts:
                continue
            new_messages.append({
                "ts": entry.get("timestamp", _utcnow()),
                "text": "\n".join(texts),
            })

    if not new_messages:
        if new_uuids:
            state["processed_uuids"] = list(processed | set(new_uuids))[-1000:]
            _STATE_FILE.write_text(json.dumps(state))
        return

    def _ts_key(entry: dict) -> float:
        ts = entry.get("ts", "")
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except (ValueError, AttributeError):
            return 0.0

    # Append investigation_narration entries to trace
    trace = json.loads(Path(trace_path).read_text())
    for msg in new_messages:
        trace["entries"].append({
            "call_id": 0,                       # placeholder — renumbered below
            "type": "investigation_narration",
            "ts": msg["ts"],
            "content": msg["text"][:2000],
            "source": "transcript",
        })

    # Sort chronologically and renumber call_ids
    trace["entries"].sort(key=_ts_key)
    for i, entry in enumerate(trace["entries"], start=1):
        entry["call_id"] = i
    trace["entry_count"] = len(trace["entries"])
    Path(trace_path).write_text(json.dumps(trace, indent=2))

    # Persist dedup state (cap at 1000 UUIDs)
    state["processed_uuids"] = list(processed | set(new_uuids))[-1000:]
    _STATE_FILE.write_text(json.dumps(state))


if __name__ == "__main__":
    main()
