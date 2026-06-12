#!/usr/bin/env python3
"""Stop hook: append one timestamped line to the ACTIVE case's forensic audit log.

It writes to the case `analysis/` directory resolved as an ABSOLUTE path from the
TRUDI session beacon (`~/.cache/trudi/session.json`) — never the shell CWD.

Why this exists (a spoliation/bypass test found the bug it replaces):
  The previous Stop hook was an inline shell one-liner —
      mkdir -p ./analysis/ && echo "$(date -u): $CONVERSATION_SUMMARY" >> ./analysis/forensic_audit.log
  whose `./analysis/` is relative to wherever the agent's shell last `cd`'d. In
  practice it:
    * scattered audit lines into the wrong dirs — e.g. exports/analysis/ and even
      inside a parsed mailbox export (.../Sent Items/Message00016/analysis/);
    * FAILED (losing the audit entry) when the CWD drifted into a read-only
      evidence mount — `mkdir ./analysis/: Read-only file system`;
    * and, but for the read-only mount, would have written the audit log straight
      INTO the evidence tree — the audit mechanism becoming a spoliation vector.

This hook resolves the canonical location from the beacon, refuses any evidence /
mount path (defence in depth, mirroring core.paths.assert_output_safe), and
no-ops when there is no active investigation — it never falls back to CWD.
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Module-level so tests can monkeypatch it.
SESSION_FILE = Path.home() / ".cache" / "trudi" / "session.json"

# Path segments that must never appear in the resolved audit-log location. Segment
# based (not prefix based) so the case-local mount `~/cases/<case>/mnt/...` and any
# `.../evidence/...` tree are caught regardless of where the case dir lives.
_FORBIDDEN_SEGMENTS = {"mnt", "media", "evidence"}


def resolve_audit_log(session_file: Path = None) -> "Path | None":
    """Return the absolute forensic_audit.log path for the active case, or None.

    None means: no active TRUDI session, an unusable beacon, or a resolved
    location inside an evidence/mount tree — in every such case the hook must
    write nothing rather than fall back to the shell CWD.
    """
    session_file = session_file or SESSION_FILE
    try:
        session = json.loads(Path(session_file).read_text())
    except (OSError, json.JSONDecodeError):
        return None

    trace_path = session.get("path")
    if not trace_path:
        return None

    p = Path(trace_path)
    if not p.is_absolute():
        # Older beacons stored "./analysis/<case>_trace.json" — resolve against
        # the case dir, same as claude/hooks/log_user_message.py.
        case_id = session.get("case_id") or ""
        p = Path.home() / "cases" / case_id / str(trace_path).lstrip("./")

    analysis_dir = p.resolve().parent          # .../<case>/analysis
    target = analysis_dir / "forensic_audit.log"

    # Defence in depth: never resolve into an evidence/mount tree.
    if _FORBIDDEN_SEGMENTS.intersection(target.parts):
        return None
    try:
        from core.paths import is_evidence_path  # absolute /cases//mnt//media/ + evidence seg
        if is_evidence_path(str(target)):
            return None
    except Exception:
        pass  # guard import optional — the segment check above already covers us

    return target


def main() -> None:
    # Drain stdin (the Stop payload) so the harness never sees a broken pipe.
    try:
        payload = json.load(sys.stdin)
    except Exception:
        payload = {}

    target = resolve_audit_log()
    if target is None:
        return  # no active investigation / unsafe location → write nothing

    summary = os.environ.get("CONVERSATION_SUMMARY", "") or (
        payload.get("summary", "") if isinstance(payload, dict) else ""
    )
    ts = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a") as fh:
            fh.write(f"{ts}: {summary}\n")
    except OSError:
        return  # never block the agent's Stop on an audit-log write failure


if __name__ == "__main__":
    main()
