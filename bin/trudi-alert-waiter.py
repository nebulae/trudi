#!/usr/bin/env python3
"""Block until a new TRUDI alert appears, then exit — the event trigger for
the /trudi-watch-alerts second-granularity response loop.

The `/loop` skill re-fires on the scheduler, which clamps to a 60s floor, so
`/loop 15s /trudi-check-alerts` really polls ~once a minute. This waiter
converts that fixed poll into an *event*: it watches the case's alerts
directory at a fine interval (default 2s) and exits the moment a new alert
(seq > since-seq) lands. Run as a detached background Bash task, its completion
fires a harness task-notification that wakes the agent immediately — so
time-to-response is the poll interval, not a minute.

On reaching --timeout with nothing new it exits 0 with a HEARTBEAT line, so the
caller re-arms (and can re-check watcher health / pending approvals) instead of
hanging forever.

Output: exactly one JSON line on stdout, then exit 0:
  {"status": "ALERTS",    "since_seq": N, "new_seqs": [...], "count": K}
  {"status": "HEARTBEAT", "since_seq": N}

Pure stdlib — no MCP imports.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

_SEQ_RE = re.compile(r"^(\d+)_.+\.json$")


def _alerts_dir(cases_root: Path, case_id: str) -> Path:
    return cases_root / case_id / "monitoring" / "alerts"


def _last_check_seq(cases_root: Path, case_id: str) -> int:
    p = cases_root / case_id / "monitoring" / "_last_check_seq.txt"
    try:
        return int(p.read_text().strip() or "0")
    except (OSError, ValueError):
        return 0


def _new_seqs(alerts_dir: Path, since: int) -> list[int]:
    if not alerts_dir.is_dir():
        return []
    out: list[int] = []
    for entry in alerts_dir.iterdir():
        m = _SEQ_RE.match(entry.name)
        if not m:
            continue
        seq = int(m.group(1))
        if seq > since:
            out.append(seq)
    return sorted(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--cases-root", default=os.environ.get(
        "TRUDI_CASES_ROOT", os.path.expanduser("~/cases")))
    ap.add_argument("--since-seq", type=int, default=None,
                    help="watch for seq > this; defaults to _last_check_seq.txt")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="poll interval in seconds (default 2)")
    ap.add_argument("--timeout", type=float, default=900.0,
                    help="(one-shot only) heartbeat after this many idle seconds (default 900)")
    ap.add_argument("--follow", action="store_true",
                    help="run persistently, emitting one line per new-alert batch "
                         "forever (for the harness Monitor tool). No re-arm needed.")
    args = ap.parse_args(argv)

    cases_root = Path(args.cases_root)
    alerts_dir = _alerts_dir(cases_root, args.case_id)
    since = (args.since_seq if args.since_seq is not None
             else _last_check_seq(cases_root, args.case_id))
    interval = max(0.2, args.interval)

    if args.follow:
        # Persistent mode: emit an ALERTS line whenever new alerts appear,
        # advancing an internal cursor so each batch is reported exactly once.
        # Never returns — the Monitor tool owns the lifetime. Alerts that land
        # while the agent is mid-investigation still surface as later events,
        # so nothing is missed between turns (the one-shot re-arm gap).
        cursor = since
        while True:
            new = _new_seqs(alerts_dir, cursor)
            if new:
                print(json.dumps({"status": "ALERTS", "since_seq": cursor,
                                  "new_seqs": new, "count": len(new)}), flush=True)
                cursor = new[-1]
            time.sleep(interval)

    # One-shot mode: block until the first new alert (or heartbeat), then exit.
    deadline = time.monotonic() + max(interval, args.timeout)
    while True:
        new = _new_seqs(alerts_dir, since)
        if new:
            print(json.dumps({"status": "ALERTS", "since_seq": since,
                              "new_seqs": new, "count": len(new)}), flush=True)
            return 0
        if time.monotonic() >= deadline:
            print(json.dumps({"status": "HEARTBEAT", "since_seq": since}), flush=True)
            return 0
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
