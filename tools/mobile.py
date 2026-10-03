"""mobile.* — iOS device artifact parsers (Amnesty MVT, mac_apt ios_apt).

Each wrapper runs the parser over an extracted iOS filesystem folder (or an
iTunes-style backup) and writes its native output — MVT: one JSON per module
plus timeline.csv; ios_apt: one CSV per artifact table plus ios_apt.db — into
an output_dir under analysis/ exports/ reports/. Success is judged on the exit
code AND on output presence, decided before the trace entry is written, so the
trace never records a run that produced nothing as a success. The produced
files are read with read.output (JSON arrays are read record-per-row).

Evidence stays read-only: no parser ever opens the input tree's SQLite stores.
Each run goes through a temporary WORKING TREE (see _stage): every SQLite store
and its -wal/-shm/-journal is a private copy (sqlite checkpoints a WAL into the
main file and deletes the sidecars on close), everything else a symlink to the
evidence. The traced cmd names the evidence path; the stage is removed
afterwards. When the extraction hides the iOS version file ios_apt needs (a
mode-000 system container), the stage's SystemVersion.plist is a symlink to
the device's own LastBuildInfo.plist.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile

from fastmcp import FastMCP

from core import run, output_safe
from tools import _parsed_outputs as _parsed
from tools._parsed_outputs import count_rows as _count_rows
from tools.tool_capabilities import tool_unavailable_result

mcp = FastMCP("mobile")

MVT_IOS = os.environ.get("TRUDI_MVT_IOS") or "/usr/local/bin/mvt-ios"
IOS_APT = os.environ.get("TRUDI_IOS_APT") or "/opt/mac-apt/bin/mac_apt_git/ios_apt.py"
IOS_APT_PYTHON = os.environ.get("TRUDI_MAC_APT_PYTHON") or "/opt/mac-apt/bin/python"

# Never phone home: no version check, no indicator download.
_MVT_OFFLINE = ["--disable-update-check", "--disable-indicator-update-check"]

# A full-size phone (100+ GB, 500k files) takes MVT's Filesystem module and
# ios_apt's SPOTLIGHT/FSEVENTS plugins well past half an hour; decrypting a
# large backup is I/O-bound on the whole backup.
MVT_FS_TIMEOUT = 7200
MVT_BACKUP_TIMEOUT = 3600
MVT_DECRYPT_TIMEOUT = 7200
IOS_APT_TIMEOUT = 7200

IOS_APT_PLUGINS = ("APPS", "BASICINFO", "DOCUMENTREVISIONS", "FSEVENTS", "INETACCOUNTS",
                   "NETUSAGE", "NETWORKING", "NOTES", "SAFARI", "SCREENTIME", "SPOTLIGHT",
                   "TERMSESSIONS", "WIFI")

_MAX_LISTED = 80                         # output files listed in the result

# Artifact families (tier-contract markers, data/fk/tiering.yaml) by produced
# file stem. MVT: <module>.json; ios_apt: <Table>.csv. Stamped only when the
# file holds at least one record — an empty parse carries no class.
_FAMILY_BY_STEM = (
    ("mobile_messaging", re.compile(
        r"^(sms|sms_attachments|whatsapp|calls|interaction_?c|contacts)(_detected)?$")),
    ("mobile_browser", re.compile(
        r"^(safari_history|safari_browser_state|safari_favicon|chrome_history|chrome_favicon"
        r"|firefox_history|firefox_favicon|webkit_\w+|safari)$")),
    ("mobile_location", re.compile(r"^(locationd_clients|wifi|network_\w+)$")),
    ("mobile_accounts", re.compile(
        r"^(applications|id_status_cache|internetaccounts|basic_info)$")),
)


def _which(path: str) -> str | None:
    return shutil.which(path)


def _input_dir_error(path: str, what: str) -> dict | None:
    if not path or not os.path.isdir(path):
        return {"success": False, "error": f"{what} is not a directory: {path!r}",
                "hint": "Pass the ROOT of the extracted iOS tree (the folder holding "
                        "private/ and Library/) or the backup folder (holding Manifest.db)."}
    return None


def _unreadable_dirs(root: str, seconds: float = 5.0) -> dict:
    """Directories under `root` this user cannot list (a tar extraction keeps
    iOS mode-000 system containers). Their content is invisible to every
    parser — the result says so instead of implying full coverage."""
    import time
    bad: list[str] = []
    deadline = time.monotonic() + seconds
    complete = True
    for _dp, _dn, _fn in os.walk(root, onerror=lambda e: bad.append(e.filename)):
        if time.monotonic() > deadline:
            complete = False
            break
    rel = [os.path.relpath(b, root) for b in bad]
    return {"count": len(rel), "sample": rel[:8], "walk_complete": complete}


# ── working tree ─────────────────────────────────────────────────────────────
#
# Opening a WAL-mode SQLite store checkpoints the -wal into the main file and
# deletes -wal/-shm on close: MVT run straight on an extraction rewrote ~60
# evidence databases (Bogus Bill, 2026-09-24). Every parser therefore runs on a
# staged tree: each SQLite store and its sidecars is a private writable COPY,
# every other file a symlink to the evidence, every evidence symlink recreated
# with its own target (so a relative link resolves inside the stage, never
# back into evidence). Unlistable (mode-000) directories are linked as-is —
# no parser can read them either way.

_SQLITE_MAGIC = b"SQLite format 3\x00"
_SQLITE_SIDECARS = ("-wal", "-shm", "-journal")


def _is_sqlite(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(16) == _SQLITE_MAGIC
    except OSError:
        return False


def _stage(src: str) -> tuple[str, dict]:
    """(stage_root, stats) — the parser's working tree for evidence `src`."""
    src = os.path.realpath(src)
    root = tempfile.mkdtemp(prefix="trudi-iosstage-")
    copied, nbytes, links = 0, 0, 0
    try:
        for dp, dn, fn in os.walk(src):
            rel = os.path.relpath(dp, src)
            dst_dir = root if rel == "." else os.path.join(root, rel)
            walk = []
            for d in dn:
                s, d_dst = os.path.join(dp, d), os.path.join(dst_dir, d)
                if os.path.islink(s):
                    os.symlink(os.readlink(s), d_dst)
                elif not os.access(s, os.R_OK | os.X_OK):
                    os.symlink(s, d_dst)
                else:
                    os.mkdir(d_dst)
                    walk.append(d)
                links += d not in walk
            dn[:] = walk
            for n in fn:
                s, f_dst = os.path.join(dp, n), os.path.join(dst_dir, n)
                if os.path.islink(s):
                    os.symlink(os.readlink(s), f_dst)
                    links += 1
                elif n.endswith(_SQLITE_SIDECARS) or _is_sqlite(s):
                    shutil.copy2(s, f_dst)
                    os.chmod(f_dst, 0o644)
                    copied += 1
                    nbytes += os.path.getsize(f_dst)
                else:
                    os.symlink(s, f_dst)
                    links += 1
    except OSError:
        _unstage(root)
        raise
    return root, {"sqlite_files_copied": copied, "sqlite_bytes_copied": nbytes,
                  "symlinks": links}


def _unstage(root: str) -> None:
    """Remove a stage: unlink links and the stage's own copies, rmdir its dirs.
    Never follows a link, so nothing under the evidence tree can be touched."""
    for dp, dn, fn in os.walk(root, topdown=False):
        for n in fn + dn:
            p = os.path.join(dp, n)
            if os.path.islink(p) or not os.path.isdir(p):
                os.unlink(p)
            else:
                os.rmdir(p)
    os.rmdir(root)


def _cmd_names_evidence(result: dict, stage: str, src: str) -> None:
    """The recorded cmd names the evidence tree, not the transient stage."""
    if isinstance(result.get("cmd"), str):
        result["cmd"] = result["cmd"].replace(stage, src)


def _inventory(out_dir: str, skip_dirs: tuple = ()) -> tuple[list[dict], int]:
    """(listed files with bytes/rows, total file count) under out_dir."""
    files: list[dict] = []
    total = 0
    for dp, dn, fn in os.walk(out_dir):
        rel_dp = os.path.relpath(dp, out_dir)
        if rel_dp.split(os.sep)[0] in skip_dirs:
            total += len(fn)
            continue
        for n in sorted(fn):
            total += 1
            p = os.path.join(dp, n)
            item = {"file": os.path.relpath(p, out_dir)}
            try:
                item["bytes"] = os.path.getsize(p)
            except OSError:
                pass
            rows = _count_rows(p)
            if rows is not None:
                item["rows"] = rows
            files.append(item)
    files.sort(key=lambda f: f["file"])
    return files, total


def _families(files: list[dict]) -> list[str]:
    fams = set()
    for f in files:
        if not f.get("rows"):
            continue
        stem = os.path.splitext(os.path.basename(f["file"]))[0].lower()
        for fam, rx in _FAMILY_BY_STEM:
            if rx.match(stem):
                fams.add(fam)
    return sorted(fams)


def _summary_text(title: str, files: list[dict], extra: list[str]) -> str:
    lines = [title]
    for f in files:
        if "rows" in f:
            lines.append(f"  {f['file']}: {f['rows']} records")
    lines.extend(extra)
    return "\n".join(lines) + "\n"


def _stamp(result: dict, summary: str) -> None:
    """Prepend the parse summary to the traced stdout (excerpt and sidecar)."""
    result["stdout"] = summary + (result.get("stdout") or "")
    if "_stdout_full" in result:
        result["_stdout_full"] = summary + (result.get("_stdout_full") or "")


def _annotate(result: dict, **fields) -> None:
    cid = result.get("_trudi_call_id")
    fields = {k: v for k, v in fields.items() if v}
    if not cid or not fields:
        return
    try:
        from core.execution_log import log
        log.annotate_tool_call(cid, **fields)
    except Exception:
        pass


def _finish(result: dict, extra: dict) -> dict:
    """Agent-facing result: keep it compact (the files are the evidence)."""
    out = {k: result.get(k) for k in ("success", "exit_code", "cmd", "elapsed_seconds",
                                      "timed_out", "_trudi_call_id") if k in result}
    out.update(extra)
    if result.get("error"):
        out["error"] = result["error"]
    if not result.get("success") and result.get("stderr"):
        out["stderr"] = result["stderr"][-1500:]
    return out


# ── MVT ──────────────────────────────────────────────────────────────────────

_MVT_RUNNING = re.compile(r" - INFO - Running module (\w+)")
_MVT_ERROR = re.compile(r"Error in running extraction from module (\w+): (.*)")


def _mvt_log_summary(out_dir: str) -> dict:
    ran, errors = [], {}
    try:
        with open(os.path.join(out_dir, "command.log"), "r", errors="replace") as fh:
            for ln in fh:
                m = _MVT_RUNNING.search(ln)
                if m and m.group(1) not in ran:
                    ran.append(m.group(1))
                m = _MVT_ERROR.search(ln)
                if m:
                    errors[m.group(1)] = m.group(2).strip()[:200]
    except OSError:
        pass
    return {"modules_run": ran, "module_errors": errors}


def _fresh(out_dir: str, rel: str, since: float) -> bool:
    try:
        return os.path.getmtime(os.path.join(out_dir, rel)) >= since - 1
    except OSError:
        return False


def _mvt_classify(out_dir: str, holder: dict, stage: str = "", src: str = ""):
    import time
    since = time.time()

    def classify(result: dict, _stdout: str, _stderr: str) -> None:
        if stage:
            _cmd_names_evidence(result, stage, src)
        files, total = _inventory(out_dir)
        log_sum = _mvt_log_summary(out_dir)
        data = [f for f in files if f["file"].endswith(".json") and f["file"] != "info.json"]
        fresh = [f for f in data if _fresh(out_dir, f["file"], since)]
        detected = [f["file"] for f in data if f["file"].endswith("_detected.json")]
        holder.update(files=files, total=total, detected=detected, **log_sum)
        result["output_path"] = out_dir
        if result.get("success") and not fresh:
            result["success"] = False
            result["error"] = (f"mvt-ios exited 0 but wrote no module JSON under {out_dir} — "
                               "wrong input path, or nothing it recognises (see stderr)")
        extra = [f"  modules run: {len(log_sum['modules_run'])}"]
        if log_sum["module_errors"]:
            extra.append("  module errors: " + "; ".join(
                f"{m}: {e}" for m, e in log_sum["module_errors"].items()))
        extra.append(f"  IOC detections: {', '.join(detected) or 'none'}")
        _stamp(result, _summary_text("MVT output summary (records per module file):",
                                     data, extra))
    return classify


def _mvt_result(r: dict, out_dir: str, holder: dict, input_path: str,
                unreadable: dict | None, staged: dict | None = None) -> dict:
    files = holder.get("files") or []
    fams = _families(files)
    _annotate(r, **{f: True for f in fams})
    records = {os.path.splitext(f["file"])[0]: f["rows"] for f in files
               if f["file"].endswith(".json") and "rows" in f}
    extra = {
        "output_dir": out_dir, "input_path": input_path,
        "records_by_module": records,
        "modules_with_records": sorted(k for k, v in records.items() if v),
        "modules_run": holder.get("modules_run", []),
        "module_errors": holder.get("module_errors", {}),
        "ioc_detections": holder.get("detected", []),
        "output_files": files[:_MAX_LISTED], "output_file_count": holder.get("total", 0),
        "artifact_families": fams,
        "hint": ("Read module JSON / timeline.csv with read.output (JSON arrays are "
                 "read one record per row). No IOC file was supplied, so no detections "
                 "are expected; module_errors lists modules that crashed on this iOS "
                 "version."),
    }
    if staged:
        extra["working_copy"] = staged
    if unreadable and unreadable.get("count"):
        extra["unreadable_dirs"] = unreadable
        extra["coverage_warning"] = (
            f"{unreadable['count']} directories in the input are not readable by this "
            "user (mode 000 in the extraction); their artifacts were NOT parsed.")
    return _finish(r, extra)


@mcp.tool()
@output_safe
def mvt_ios_check_fs(fs_path: str, output_dir: str, modules: str = "") -> dict:
    """MVT check-fs on an extracted iOS tree: JSON per module + timeline.csv.

    Modules: SMS, Safari, WhatsApp, Calls, Contacts, TCC, locationd, …
    modules: optional comma list of MVT module names (default: all).
    Offline (no update/IOC download). Read output with read.output.
    """
    err = _input_dir_error(fs_path, "fs_path")
    if err:
        return err
    missing = tool_unavailable_result("mobile.mvt_ios_check_fs", _which)
    if missing:
        return missing
    mods = [m.strip() for m in (modules or "").split(",") if m.strip()]
    bad = [m for m in mods if not re.fullmatch(r"[A-Za-z0-9_]+", m)]
    if bad:
        return {"success": False, "error": f"invalid MVT module name(s): {bad}"}
    os.makedirs(output_dir, exist_ok=True)
    unreadable = _unreadable_dirs(fs_path)
    runs = []
    stage, staged = _stage(fs_path)
    try:
        for mod in (mods or [""]):
            holder: dict = {}
            cmd = [MVT_IOS, *_MVT_OFFLINE, "check-fs", "-o", output_dir]
            if mod:
                cmd += ["-m", mod]
            cmd.append(stage)
            t0 = _parsed.now()
            r = run(cmd, timeout=MVT_FS_TIMEOUT, output_dir=output_dir,
                    classify=_mvt_classify(output_dir, holder, stage, fs_path))
            _parsed.stamp(r, output_dir, t0)
            runs.append(_mvt_result(r, output_dir, holder, fs_path, unreadable, staged))
    finally:
        _unstage(stage)
    if len(runs) == 1:
        return runs[0]
    last = dict(runs[-1])
    last["success"] = all(x.get("success") for x in runs)
    last["call_ids"] = [x.get("_trudi_call_id") for x in runs]
    return last


@mcp.tool()
@output_safe
def mvt_ios_check_backup(backup_path: str, output_dir: str) -> dict:
    """MVT check-backup on a decrypted iTunes backup: JSON per module.

    Offline. Read output with read.output.
    """
    err = _input_dir_error(backup_path, "backup_path")
    if err:
        return err
    missing = tool_unavailable_result("mobile.mvt_ios_check_backup", _which)
    if missing:
        return missing
    os.makedirs(output_dir, exist_ok=True)
    holder: dict = {}
    stage, staged = _stage(backup_path)
    try:
        cmd = [MVT_IOS, *_MVT_OFFLINE, "check-backup", "-o", output_dir, stage]
        t0 = _parsed.now()
        r = run(cmd, timeout=MVT_BACKUP_TIMEOUT, output_dir=output_dir,
                classify=_mvt_classify(output_dir, holder, stage, backup_path))
        _parsed.stamp(r, output_dir, t0)
    finally:
        _unstage(stage)
    return _mvt_result(r, output_dir, holder, backup_path, None, staged)


@mcp.tool()
@output_safe
def mvt_ios_decrypt_backup(backup_path: str, output_dir: str, password: str = "",
                           key_file: str = "") -> dict:
    """Decrypt an iTunes backup with MVT (password never traced).

    Pass password OR key_file; the password goes via environment. Then run
    mobile.mvt_ios_check_backup on output_dir.
    """
    err = _input_dir_error(backup_path, "backup_path")
    if err:
        return err
    if bool(password) == bool(key_file):
        return {"success": False, "error": "pass exactly one of password / key_file"}
    missing = tool_unavailable_result("mobile.mvt_ios_decrypt_backup", _which)
    if missing:
        return missing
    os.makedirs(output_dir, exist_ok=True)
    stage, staged = _stage(backup_path)
    cmd = [MVT_IOS, *_MVT_OFFLINE, "decrypt-backup", "-d", output_dir]
    env = None
    if key_file:
        cmd += ["-k", key_file]
    else:
        # MVT reads MVT_IOS_BACKUP_PASSWORD when -p is absent: the secret never
        # reaches argv (ps) or the traced cmd.
        env = {**os.environ, "MVT_IOS_BACKUP_PASSWORD": password}
    cmd.append(stage)

    def classify(result: dict, _stdout: str, _stderr: str) -> None:
        _cmd_names_evidence(result, stage, backup_path)
        result["output_path"] = output_dir
        has_manifest = os.path.isfile(os.path.join(output_dir, "Manifest.db"))
        if result.get("success") and not has_manifest:
            result["success"] = False
            result["error"] = ("mvt-ios decrypt-backup wrote no Manifest.db — wrong "
                               "password/key or not an encrypted backup (see stderr)")
        for k in ("stdout", "stderr", "_stdout_full"):
            if password and isinstance(result.get(k), str):
                result[k] = result[k].replace(password, "[REDACTED]")

    try:
        r = run(cmd, timeout=MVT_DECRYPT_TIMEOUT, output_dir=output_dir, env=env,
                classify=classify)
    finally:
        _unstage(stage)
    files, total = _inventory(output_dir)
    return _finish(r, {"output_dir": output_dir, "input_path": backup_path,
                       "working_copy": staged,
                       "output_file_count": total,
                       "manifest_db": os.path.isfile(os.path.join(output_dir, "Manifest.db")),
                       "password_source": "env" if password else "key_file",
                       "next": "mobile.mvt_ios_check_backup(backup_path=<output_dir>, ...)"})


# ── mac_apt ios_apt ──────────────────────────────────────────────────────────

_VERSION_FILES = (
    "System/Library/CoreServices/SystemVersion.plist",
    "private/var/containers/Shared/SystemGroup/systemgroup.com.apple.lsd.iconscache/"
    "Library/Caches/com.apple.IconsCache/__system_version_info__",
)
_LAST_BUILD_INFO = "private/var/installd/Library/MobileInstallation/LastBuildInfo.plist"


def _readable_file(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.R_OK)


def _version_link(stage: str, fs_path: str) -> str:
    """When the extraction hides the iOS version file ios_apt needs (a mode-000
    system container), point the stage's SystemVersion.plist at the device's own
    LastBuildInfo.plist. Returns a note ("" when no link was needed)."""
    if any(_readable_file(os.path.join(fs_path, v)) for v in _VERSION_FILES):
        return ""
    src = os.path.join(fs_path, _LAST_BUILD_INFO)
    if not _readable_file(src):
        return ("no readable iOS version file (SystemVersion.plist, IconsCache "
                "__system_version_info__, LastBuildInfo.plist)")
    target = "System/Library/CoreServices/SystemVersion.plist".split("/")
    cur = stage
    try:
        for depth, seg in enumerate(target):
            cur = os.path.join(cur, seg)
            last = depth == len(target) - 1
            if os.path.islink(cur):
                # a staged link (unreadable dir / evidence symlink): replace it with
                # a real dir whose listable children are mirrored as links
                real = os.path.realpath(cur)
                os.unlink(cur)
                if last:
                    break
                os.mkdir(cur)
                try:
                    names = os.listdir(real) if os.path.isdir(real) else []
                except OSError:
                    names = []
                for n in names:
                    os.symlink(os.path.join(real, n), os.path.join(cur, n))
            elif not last and not os.path.isdir(cur):
                os.mkdir(cur)
        os.symlink(os.path.realpath(src), cur)
    except OSError as e:
        return f"version link failed: {e}"
    return f"SystemVersion.plist -> {_LAST_BUILD_INFO} (symlink in working copy)"


_APT_RUNNING = re.compile(r"Running plugin (\w+)")
_APT_FAILED = re.compile(r"exception occurred while running plugin - (\w+)")


def _apt_log_summary(out_dir: str) -> dict:
    ran, failed = [], []
    try:
        logs = sorted(f for f in os.listdir(out_dir) if f.startswith("Log.") and f.endswith(".txt"))
    except OSError:
        logs = []
    if logs:
        with open(os.path.join(out_dir, logs[-1]), "r", errors="replace") as fh:
            for ln in fh:
                m = _APT_RUNNING.search(ln)
                if m and m.group(1) not in ran:
                    ran.append(m.group(1))
                m = _APT_FAILED.search(ln)
                if m and m.group(1) not in failed:
                    failed.append(m.group(1))
    return {"plugins_run": ran, "plugins_failed": failed}


@mcp.tool()
@output_safe
def ios_apt(fs_path: str, output_dir: str, plugins: str = "ALL") -> dict:
    """mac_apt ios_apt on an extracted iOS tree: artifact tables as CSV.

    Apps, accounts, Wi-Fi, networking, Safari, Notes, Screen Time, Spotlight …
    plugins: ALL or a comma list (e.g. WIFI,SAFARI,INETACCOUNTS). Read CSVs with read.output.
    """
    err = _input_dir_error(fs_path, "fs_path")
    if err:
        return err
    missing = tool_unavailable_result("mobile.ios_apt", _which)
    if missing:
        return missing
    wanted = [p.strip().upper() for p in re.split(r"[\s,]+", plugins or "ALL") if p.strip()]
    if not wanted or "ALL" in wanted:
        wanted = ["ALL"]
    bad = [p for p in wanted if p != "ALL" and p not in IOS_APT_PLUGINS]
    if bad:
        return {"success": False, "error": f"unknown ios_apt plugin(s): {bad}",
                "valid": list(IOS_APT_PLUGINS) + ["ALL"]}
    os.makedirs(output_dir, exist_ok=True)
    unreadable = _unreadable_dirs(fs_path)
    stage, staged = _stage(fs_path)
    overlay_note = _version_link(stage, fs_path)
    overlay = overlay_note.startswith("SystemVersion.plist")
    cmd = [IOS_APT_PYTHON, IOS_APT, "-i", stage, "-o", output_dir, "-c", *wanted]
    holder: dict = {}

    def classify(result: dict, stdout: str, stderr: str) -> None:
        _cmd_names_evidence(result, stage, fs_path)
        result["output_path"] = output_dir
        files, total = _inventory(output_dir, skip_dirs=("Export",))
        log_sum = _apt_log_summary(output_dir)
        csvs = [f for f in files if f["file"].endswith(".csv")]
        holder.update(files=files, total=total, **log_sum)
        no_ios = "Could not find an iOS installation" in (stdout + stderr)
        if result.get("success") and (no_ios or not csvs):
            result["success"] = False
            result["error"] = ("ios_apt found no iOS installation at the input root"
                               if no_ios else f"ios_apt exited 0 but wrote no CSV under {output_dir}")
        extra = [f"  plugins run: {', '.join(log_sum['plugins_run']) or 'none'}"]
        if log_sum["plugins_failed"]:
            extra.append(f"  plugins failed: {', '.join(log_sum['plugins_failed'])}")
        if overlay_note:
            extra.append(f"  iOS version source: {overlay_note}")
        _stamp(result, _summary_text("ios_apt output summary (rows per CSV):", csvs, extra))

    try:
        t0 = _parsed.now()
        r = run(cmd, timeout=IOS_APT_TIMEOUT, output_dir=output_dir, classify=classify)
        _parsed.stamp(r, output_dir, t0, skip_dirs=("Export",))
    finally:
        _unstage(stage)
    files = holder.get("files") or []
    fams = _families(files)
    _annotate(r, version_overlay=overlay_note if overlay else "",
              **{f: True for f in fams})
    rows = {f["file"]: f["rows"] for f in files if f["file"].endswith(".csv") and "rows" in f}
    extra = {
        "output_dir": output_dir, "input_path": fs_path, "working_copy": staged,
        "rows_by_csv": rows,
        "plugins_run": holder.get("plugins_run", []),
        "plugins_failed": holder.get("plugins_failed", []),
        "output_files": files[:_MAX_LISTED], "output_file_count": holder.get("total", 0),
        "artifact_families": fams,
        "hint": ("Read the CSVs with read.output (query/columns/where). Export/ holds raw "
                 "artifact copies ios_apt pulled; ios_apt.db is the same data as sqlite."),
    }
    if overlay_note:
        extra["version_source"] = overlay_note
    if unreadable.get("count"):
        extra["unreadable_dirs"] = unreadable
        extra["coverage_warning"] = (
            f"{unreadable['count']} directories in the input are not readable by this "
            "user (mode 000 in the extraction); their artifacts were NOT parsed.")
    return _finish(r, extra)
