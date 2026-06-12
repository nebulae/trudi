"""Atomic reset of TRUDI cache + case trace state.

This is the only sanctioned way to "start over" a TRUDI investigation. Manual
editing of ~/.cache/trudi/call_id.counter or session.json can leave the counter
out of sync with the trace, which (after the F1 fix in core/execution_log.py)
is now self-healing but logs a noisy WARN — better to reset cleanly.

Usage:
    python -m tools.trudi_reset --case-dir ~/cases/example-case
    python -m tools.trudi_reset --case-dir ~/cases/example-case --keep-trace
    python -m tools.trudi_reset --case-dir ~/cases/example-case --purge-outputs

What it does (under the shared fcntl lock so no in-flight write races):
    1. Backs up the active trace JSON + dashboard.url to
       <case_dir>/.trace-backups/<timestamp>/  (unless --no-backup).
       With --purge-outputs, the full contents of analysis/, exports/, and
       reports/ are moved into the backup instead.
    2. Removes <case_dir>/analysis/<CASE>_trace.json (unless --keep-trace)
    3. Removes <case_dir>/analysis/dashboard.url
    4. Clears ~/.cache/trudi/session.json
    5. Clears ~/.cache/trudi/hook_state.json
    6. Resets ~/.cache/trudi/call_id.counter to {"next": 1}
    7. Preserves ~/.cache/trudi/hash_cache.json (evidence-hash memoisation,
       no investigative state)

Exit code is 0 on success, 1 on any error (so it's safe to chain in scripts).
"""
from __future__ import annotations
import argparse
import datetime
import fcntl
import json
import os
import shutil
import sys
from pathlib import Path

_CACHE_DIR = os.path.expanduser("~/.cache/trudi")
_LOCK_FILE = os.path.join(_CACHE_DIR, "hook.lock")
_COUNTER_FILE = os.path.join(_CACHE_DIR, "call_id.counter")
_SESSION_FILE = os.path.join(_CACHE_DIR, "session.json")
_HOOK_STATE_FILE = os.path.join(_CACHE_DIR, "hook_state.json")
_OUTPUT_DIRS = ("analysis", "exports", "reports")


def _detect_case_id(case_dir: str) -> str | None:
    """Best-effort case_id detection from <case_dir>/CLAUDE.md."""
    md = os.path.join(case_dir, "CLAUDE.md")
    if not os.path.exists(md):
        return None
    try:
        with open(md) as f:
            text = f.read(8192)
    except OSError:
        return None
    import re
    m = re.search(r"\*\*Case ID\*\*[:\s|]+([A-Za-z0-9_\-]+)", text)
    if m:
        return m.group(1)
    return None


def _find_trace_path(case_dir: str, case_id: str | None) -> str | None:
    analysis = os.path.join(case_dir, "analysis")
    if not os.path.isdir(analysis):
        return None
    if case_id:
        candidate = os.path.join(analysis, f"{case_id}_trace.json")
        if os.path.exists(candidate):
            return candidate
    # Fallback: any *_trace.json file directly under analysis/
    for name in sorted(os.listdir(analysis)):
        if name.endswith("_trace.json"):
            return os.path.join(analysis, name)
    return None


def _backup(case_dir: str, trace_path: str | None) -> str | None:
    """Move trace + dashboard.url into a timestamped backup directory.
    Returns the backup dir path, or None if there was nothing to back up."""
    if not trace_path or not os.path.exists(trace_path):
        # Still back up dashboard.url if it exists alone
        dash = os.path.join(case_dir, "analysis", "dashboard.url")
        if not os.path.exists(dash):
            return None
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = os.path.join(case_dir, ".trace-backups", ts)
    os.makedirs(backup_dir, exist_ok=True)
    moved = []
    if trace_path and os.path.exists(trace_path):
        dst = os.path.join(backup_dir, os.path.basename(trace_path))
        shutil.move(trace_path, dst)
        moved.append(os.path.basename(trace_path))
    dash = os.path.join(case_dir, "analysis", "dashboard.url")
    if os.path.exists(dash):
        shutil.move(dash, os.path.join(backup_dir, "dashboard.url"))
        moved.append("dashboard.url")
    if not moved:
        # Nothing was actually moved — clean up the empty dir
        try:
            os.rmdir(backup_dir)
        except OSError:
            pass
        return None
    return backup_dir


def _purge_outputs(case_dir: str, no_backup: bool) -> tuple[str | None, list[str]]:
    """Move (or delete) the contents of analysis/, exports/, reports/.

    Returns (backup_dir_path_or_None, actions). The case-level .trace-backups/
    directory lives outside these and is never touched."""
    actions: list[str] = []
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = os.path.join(case_dir, ".trace-backups", ts) if not no_backup else None
    any_moved = False

    for sub in _OUTPUT_DIRS:
        src_dir = os.path.join(case_dir, sub)
        if not os.path.isdir(src_dir):
            continue
        entries = os.listdir(src_dir)
        if not entries:
            continue
        if backup_dir:
            dest_sub = os.path.join(backup_dir, sub)
            os.makedirs(dest_sub, exist_ok=True)
            for name in entries:
                shutil.move(os.path.join(src_dir, name), os.path.join(dest_sub, name))
            any_moved = True
            actions.append(f"backed up + cleared {sub}/ ({len(entries)} entries)")
        else:
            for name in entries:
                p = os.path.join(src_dir, name)
                if os.path.isdir(p) and not os.path.islink(p):
                    shutil.rmtree(p)
                else:
                    os.remove(p)
            actions.append(f"deleted {len(entries)} entries from {sub}/")

    if backup_dir and not any_moved:
        try:
            os.rmdir(backup_dir)
        except OSError:
            pass
        backup_dir = None

    return backup_dir, actions


def reset(case_dir: str, keep_trace: bool = False, no_backup: bool = False,
          purge_outputs: bool = False) -> dict:
    """Perform the reset. Returns a result dict with what was done."""
    case_dir = os.path.abspath(os.path.expanduser(case_dir))
    if not os.path.isdir(case_dir):
        return {"success": False, "error": f"case_dir not a directory: {case_dir}"}

    case_id = _detect_case_id(case_dir)
    trace_path = _find_trace_path(case_dir, case_id)
    actions: list[str] = []
    result: dict[str, object] = {
        "success": True,
        "case_dir": case_dir,
        "case_id": case_id,
        "actions": actions,
    }

    os.makedirs(_CACHE_DIR, exist_ok=True)
    lock_fp = open(_LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)

        # 1. Backup + remove case outputs
        backup_dir = None
        if purge_outputs:
            if keep_trace:
                actions.append(
                    "WARN: --keep-trace ignored because --purge-outputs sweeps analysis/")
            backup_dir, purge_actions = _purge_outputs(case_dir, no_backup=no_backup)
            actions.extend(purge_actions)
            if backup_dir:
                result["backup_dir"] = backup_dir
        else:
            if not no_backup and not keep_trace:
                backup_dir = _backup(case_dir, trace_path)
                if backup_dir:
                    actions.append(f"backed up to {backup_dir}")
                    result["backup_dir"] = backup_dir

            # 2-3. Remove trace + dashboard.url (already moved by _backup if it ran)
            if not keep_trace:
                for p in (trace_path, os.path.join(case_dir, "analysis", "dashboard.url")):
                    if p and os.path.exists(p):
                        try:
                            os.remove(p)
                            actions.append(f"removed {os.path.basename(p)}")
                        except OSError as e:
                            actions.append(f"WARN: failed to remove {p}: {e}")

        # 4-5. Cache files cleared
        for p, label in [(_SESSION_FILE, "session.json"),
                         (_HOOK_STATE_FILE, "hook_state.json")]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                    actions.append(f"cleared {label}")
                except OSError as e:
                    actions.append(f"WARN: failed to clear {label}: {e}")

        # 6. Counter reset (atomic via temp file + rename)
        tmp = _COUNTER_FILE + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump({"next": 1}, f)
            os.replace(tmp, _COUNTER_FILE)
            actions.append("reset call_id.counter to {\"next\": 1}")
        except OSError as e:
            try:
                os.remove(tmp)
            except OSError:
                pass
            result["success"] = False
            result["error"] = f"counter reset failed: {e}"
            return result

        # 7. hash_cache.json preserved (intentional — it's just memoisation)
        actions.append("preserved hash_cache.json (evidence-hash memoisation only)")

    finally:
        try:
            fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock_fp.close()

    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Atomic reset of TRUDI cache + case trace.",
    )
    parser.add_argument("--case-dir", required=True,
                        help="Path to the case directory (e.g. ~/cases/example-case)")
    parser.add_argument("--keep-trace", action="store_true",
                        help="Don't delete the trace JSON. Cache files still get cleared.")
    parser.add_argument("--no-backup", action="store_true",
                        help="Don't back up the trace before deleting it.")
    parser.add_argument("--purge-outputs", action="store_true",
                        help="Also clear analysis/, exports/, and reports/. "
                             "Backed up into the same .trace-backups/<ts>/ tree "
                             "unless --no-backup is set.")
    args = parser.parse_args(argv)

    result = reset(args.case_dir, keep_trace=args.keep_trace,
                   no_backup=args.no_backup, purge_outputs=args.purge_outputs)
    if not result["success"]:
        print(f"ERROR: {result.get('error')}", file=sys.stderr)
        return 1
    print(f"Reset complete for {result['case_dir']} (case_id={result.get('case_id')})")
    for action in result["actions"]:
        print(f"  · {action}")
    if result.get("backup_dir"):
        print(f"\nBackup available at: {result['backup_dir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
