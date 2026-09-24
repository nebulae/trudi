"""Replay the pre-report correspondent-exhaustion check over a finished trace.

Read-only with respect to the case: the trace is COPIED into a temp dir and
TRUDI_CACHE_DIR is pointed at a temp dir before any core/tools import, so the
live cache (~/.cache/trudi) and the case's trace are never touched.

    python -m tools.correspondent_replay --trace <case>/analysis/<CASE>_trace.json
    python -m tools.correspondent_replay --trace T --restamp \\
        --store-map /old/exports/mbox_gmail=/backup/exports/mbox_gmail

--keep-dispositions   keep the agent's correspondent dispositions (default:
                      strip them, to see what the check itself flags)
--restamp             re-parse every mail store the trace's read.mail calls
                      read (and the chat store) with the current feeders and
                      replace the legacy stamps — what a fresh run would stamp.
                      Store paths are read-only inputs; --store-map redirects a
                      path recorded in the trace to where the store lives now.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile


def _restamp(entries: list, store_map: dict) -> int:
    from core.mail_roster import roster_for_store
    from core.chat_db import parse_chat_db
    cache: dict = {}
    n = 0
    for e in entries:
        if e.get("type") != "tool_call" or not e.get("observed_correspondents"):
            continue
        cmd = str(e.get("cmd") or "")
        if e.get("chat_db_export"):
            db = cmd.split(" ", 1)[1] if " " in cmd else ""
            db = store_map.get(db, db)
            if db not in cache:
                cache[db] = parse_chat_db(db) if os.path.exists(db) else {}
            c = cache[db]
            if c.get("success"):
                e["observed_correspondents"] = c.get("participants", [])
                e["chat_engaged"] = c.get("engaged", [])
                e["chat_owners"] = c.get("owners", [])
                n += 1
            continue
        m = re.match(r"read\.mail -o (.+?) mode=", cmd)
        if not m:
            continue
        store = m.group(1).strip().strip("'")
        store = store_map.get(store, store)
        if store not in cache:
            cache[store] = roster_for_store(store) if os.path.exists(store) else None
        r = cache[store]
        if not r:
            continue
        e.update(observed_correspondents=r["observed"],
                 observed_correspondent_stats=r["stats"],
                 observed_correspondent_bulk=r["bulk"],
                 mailbox_owners=r["owners"],
                 correspondent_direction=True,
                 correspondents_partial=r["partial"])
        n += 1
    return n


def replay(trace: str, keep_dispositions: bool = False, restamp: bool = False,
           store_map: dict | None = None) -> dict:
    """Copy `trace`, optionally restamp, run assess_readiness; return a summary."""
    from core.execution_log import ExecutionLog
    from core.mail_roster import registry_record_engaged
    from tools._readiness import assess_readiness

    with open(trace) as fh:
        data = json.load(fh)
    if not keep_dispositions:
        data["entries"] = [e for e in data["entries"]
                           if not (e.get("type") == "disposition"
                                   and str(e.get("target_kind") or "").lower() == "correspondent")]
    restamped = _restamp(data["entries"], store_map or {}) if restamp else 0
    work = tempfile.mkdtemp(prefix="corr-replay-")
    path = os.path.join(work, "trace.json")
    with open(path, "w") as fh:
        json.dump(data, fh)
    lg = ExecutionLog()
    lg.configure(data.get("case_id") or "REPLAY", path, save_session=False)
    r = assess_readiness(lg)
    inv = r["registry_inventory"]["correspondents"]
    flagged = [c["address"] for c in inv if c["status"] in ("engaged (open)", "roster-match (open)")]
    issue = next((i for i in r["blocking_issues"] if "engaged correspondent" in i), "")
    m = re.match(r"(\d+)", issue)
    idx = lg.index()
    engaged_all = sorted(a for a, rec in idx.correspondents.items()
                         if registry_record_engaged(rec))
    return {
        "trace": trace, "restamped_stamps": restamped,
        "flagged_count": int(m.group(1)) if m else 0,
        "flagged": flagged,
        "engaged_any_reference_state": engaged_all,
        "registry_size": len(idx.correspondents),
        "inbound_only_inventory": len(r["correspondents_auto_noise"]),
        "owners": sorted(idx.correspondent_owners),
        "legacy_stores": sorted(idx.correspondent_legacy_stores),
        "alias_leads": r["registry_inventory"].get("alias_leads", []),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--trace", required=True, action="append")
    ap.add_argument("--keep-dispositions", action="store_true")
    ap.add_argument("--restamp", action="store_true")
    ap.add_argument("--store-map", action="append", default=[],
                    help="OLD_PATH=NEW_PATH (repeatable)")
    a = ap.parse_args(argv)
    smap = dict(s.split("=", 1) for s in a.store_map)
    for t in a.trace:
        print(json.dumps(replay(t, a.keep_dispositions, a.restamp, smap), indent=1))
    return 0


if __name__ == "__main__":
    # Never touch the live cache: isolate BEFORE core/tools import state.
    os.environ.setdefault("TRUDI_CACHE_DIR", tempfile.mkdtemp(prefix="corr-replay-cache-"))
    sys.exit(main())
