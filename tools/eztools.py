"""EZ Tools (Eric Zimmerman) — Windows artifact parsers via .NET runtime."""
import os
from typing import Optional
from fastmcp import FastMCP
from core import run_dotnet, run, output_safe, DEFAULT_TIMEOUT, VOL_TIMEOUT, PLASO_TIMEOUT
from core.paths import assert_output_safe

mcp = FastMCP("eztools")

EZ = "/opt/zimmermantools"

# When an EZ Tool .dll is absent from a deployment, dotnet fails with a cryptic
# "The application '<dll>' does not exist" / exit 145. Surface that as a clear
# `tool_unavailable` result and, where the same artifact can be reached another
# way, name the fallback so the agent redirects instead of dropping the step.
_EZ_FALLBACKS = {
    "PECmd.dll": (
        "Prefetch parser unavailable — recover EXECUTION evidence from other "
        "artifacts instead: UserAssist (ez.recmd_hive on the user's NTUSER.DAT), "
        "Amcache (ez.amcacheparser), and AppCompatCache/ShimCache "
        "(ez.appcompatcacheparser). Prefetch existence/last-run can also be read "
        "from $MFT (ez.mftecmd on C:\\Windows\\Prefetch)."
    ),
    "AmcacheParser.dll": (
        "Amcache parser unavailable — use UserAssist (ez.recmd_hive) and "
        "AppCompatCache (ez.appcompatcacheparser) for execution/presence evidence."
    ),
    "AppCompatCacheParser.dll": (
        "ShimCache parser unavailable — use Amcache (ez.amcacheparser) and "
        "UserAssist (ez.recmd_hive) for presence/execution evidence."
    ),
}


def _ez(dll: str, args: list[str], output_dir: Optional[str] = None, timeout: int = 300) -> dict:
    if output_dir:
        assert_output_safe(output_dir)
    result = run_dotnet(dll, args, timeout=timeout, output_dir=output_dir)
    # Missing-binary detection: the .dll not being on disk is the unambiguous
    # signal (dotnet's exit 145 also fires for genuine runtime faults). Augment
    # the recorded result — the failed tool_call still lands in the trace, but
    # now with an actionable fallback instead of a raw dotnet stack.
    if not result.get("success") and not os.path.exists(dll):
        name = os.path.basename(dll)
        result["tool_unavailable"] = True
        result["error"] = f"{name} is not installed in this deployment ({dll} not found)"
        fb = _EZ_FALLBACKS.get(name)
        if fb:
            result["fallback"] = fb
    return result


def _attach_evtx_coverage(result: dict, output_dir: str, output_file: str) -> None:
    """Stamp the parsed log's event time-range (min/max TimeCreated) onto the
    tool_call entry as `coverage_window`, so the negative_completeness gate can
    tell whether the log actually covers a claim's window — a log that is silent
    about the window cannot ground a negative. Best-effort; never raises."""
    try:
        cid = result.get("_trudi_call_id")
        if not cid:
            return
        import csv as _csv
        import os as _os
        path = _os.path.join(output_dir, output_file)
        if not _os.path.exists(path):
            return
        start = end = None
        session_ids: set = set()
        from tools._gates._session import SESSION_EVENT_IDS
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            rdr = _csv.DictReader(fh)
            fields = rdr.fieldnames or []
            col = next((c for c in fields
                        if c.lstrip("﻿").strip().lower() == "timecreated"), None)
            eid_col = next((c for c in fields
                            if c.lstrip("﻿").strip().lower() == "eventid"), None)
            if not col and not eid_col:
                return
            for row in rdr:
                ts = (row.get(col) or "").strip() if col else ""
                if ts:
                    if start is None or ts < start:
                        start = ts
                    if end is None or ts > end:
                        end = ts
                if eid_col:
                    try:
                        eid = int((row.get(eid_col) or "").strip())
                    except ValueError:
                        continue
                    if eid in SESSION_EVENT_IDS:
                        session_ids.add(eid)
        from core.execution_log import log
        fields_out = {}
        if start and end:
            fields_out["coverage_window"] = {"start": start, "end": end}
        if session_ids:
            # Server-stamped marker: this parse holds logon/session events —
            # what the attribution gates require for a principal binding.
            fields_out["session_artifact"] = True
            fields_out["session_event_ids"] = sorted(session_ids)
        if fields_out:
            log.annotate_tool_call(cid, **fields_out)
    except Exception:
        pass


# ── MFT ──────────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_mftecmd(
    mft_path: str,
    output_dir: str,
    output_file: str = "mft.csv",
    include_slack: bool = False,
) -> dict:
    """
    Parse the Master File Table ($MFT) from a mounted or extracted NTFS volume.
    mft_path: path to $MFT file (e.g. /mnt/windows_mount/$MFT or extracted copy).
    Produces CSV with all file metadata, timestamps, and attributes.
    """
    args = ["-f", mft_path, "--csv", output_dir, "--csvf", output_file]
    if include_slack:
        args.append("--ds")
    return _ez(f"{EZ}/MFTECmd.dll", args, output_dir=output_dir)


@mcp.tool()
@output_safe
def ez_mftecmd_dir(
    volume_dir: str,
    output_dir: str,
    output_file: str = "mft_dir.csv",
) -> dict:
    """Parse $MFT from a directory scan of a mounted volume (searches for $MFT automatically)."""
    args = ["-d", volume_dir, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/MFTECmd.dll", args, output_dir=output_dir)


# ── Event Logs ────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_evtxecmd(
    evtx_path: str,
    output_dir: str,
    output_file: str = "evtx.csv",
    maps_dir: str = f"{EZ}/EvtxeCmd/Maps",
    event_ids: Optional[str] = None,
) -> dict:
    """
    Parse Windows Event Log (.evtx) files with enriched field mapping.
    evtx_path: path to a single .evtx file or a directory of .evtx files.
    event_ids: comma-separated event IDs to filter (e.g. '4624,4625,4688').
    Maps decode raw XML fields into human-readable columns.
    """
    flag = "-f" if evtx_path.endswith(".evtx") else "-d"
    args = [flag, evtx_path, "--csv", output_dir, "--csvf", output_file, "--maps", maps_dir]
    if event_ids:
        args += ["--inc", event_ids]
    result = _ez(f"{EZ}/EvtxeCmd/EvtxECmd.dll", args, output_dir=output_dir, timeout=VOL_TIMEOUT)
    _attach_evtx_coverage(result, output_dir, output_file)
    return result


# ── Registry ──────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_recmd_hive(
    hive_path: str,
    output_dir: str,
    output_file: str = "registry.csv",
    batch_file: str = f"{EZ}/RECmd/BatchExamples/DFIRBatch.reb",
) -> dict:
    """
    Parse a single registry hive using a RECmd batch file.
    hive_path: path to SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, etc.
    batch_file: path to .reb batch file (defaults to DFIRBatch.reb)
    """
    args = ["-f", hive_path, "--bn", batch_file, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/RECmd/RECmd.dll", args, output_dir=output_dir, timeout=DEFAULT_TIMEOUT)


@mcp.tool()
@output_safe
def ez_recmd_dir(
    hives_dir: str,
    output_dir: str,
    output_file: str = "registry_all.csv",
    batch_file: str = f"{EZ}/RECmd/BatchExamples/DFIRBatch.reb",
) -> dict:
    """Parse all registry hives in a directory recursively using a RECmd batch file."""
    args = ["-d", hives_dir, "--bn", batch_file, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/RECmd/RECmd.dll", args, output_dir=output_dir, timeout=VOL_TIMEOUT)


_HIVE_NAMES = ("ntuser.dat", "usrclass.dat", "sam", "system", "software", "security",
               "amcache.hve", "default")


def _find_hives(hives_dir: str, names=_HIVE_NAMES, max_hives: int = 64) -> list[str]:
    """Registry hive files under `hives_dir` (case-insensitive, transaction
    logs excluded), sorted, capped."""
    out: list[str] = []
    want = {n.lower() for n in names}
    for dirpath, dirnames, filenames in os.walk(hives_dir, followlinks=False):
        dirnames.sort()
        for fn in sorted(filenames):
            low = fn.lower()
            if low in want and not low.endswith((".log", ".log1", ".log2", ".regtrans-ms", ".blf")):
                out.append(os.path.join(dirpath, fn))
                if len(out) >= max_hives:
                    return out
    return out


@mcp.tool()
@output_safe
def ez_recmd_batch(
    hives_dir: str,
    batch_file: str,
    output_dir: str,
    per_hive: bool = True,
    max_hives: int = 64,
) -> dict:
    """Run a RECmd batch config (targeted key extraction) over the hives under
    `hives_dir`.

    per_hive=True (default): enumerate the hive FILES (NTUSER.DAT, UsrClass.dat,
    SAM, SYSTEM, SOFTWARE, SECURITY, Amcache.hve) under the tree and run RECmd
    `-f <hive> --bn <batch>` per hive, each with the normal timeout, output under
    `<output_dir>/<profile-or-parent>/`. One traced, citable call per hive;
    failures are isolated. `-d <whole tree>` is what ran to the 1800 s timeout
    twice on a full Users tree — kept behind per_hive=False for small dirs.
    """
    if not per_hive:
        args = ["-d", hives_dir, "--bn", batch_file, "--csv", output_dir]
        return _ez(f"{EZ}/RECmd/RECmd.dll", args, output_dir=output_dir, timeout=VOL_TIMEOUT)
    assert_output_safe(output_dir)
    hives = _find_hives(hives_dir, max_hives=max(1, int(max_hives)))
    if not hives:
        return {"success": False, "error": f"no registry hives found under {hives_dir}",
                "looked_for": list(_HIVE_NAMES)}
    runs: list[dict] = []
    for hive in hives:
        parent = os.path.basename(os.path.dirname(hive)) or "root"
        sub = os.path.join(output_dir, f"{parent}_{os.path.basename(hive)}".replace(" ", "_"))
        args = ["-f", hive, "--bn", batch_file, "--csv", sub]
        r = _ez(f"{EZ}/RECmd/RECmd.dll", args, output_dir=sub, timeout=DEFAULT_TIMEOUT)
        runs.append({"hive": hive, "success": bool(r.get("success")), "output_dir": sub,
                     "elapsed_seconds": r.get("elapsed_seconds"),
                     "_trudi_call_id": r.get("_trudi_call_id"),
                     "error": (r.get("error") or (r.get("stderr") or "")[:200]) if not r.get("success") else ""})
        if r.get("tool_unavailable"):
            return {"success": False, "tool_unavailable": True, "error": r.get("error"),
                    "fallback": r.get("fallback"), "hives": runs}
    ok = [x for x in runs if x["success"]]
    return {
        "success": bool(ok),
        "hives_found": len(hives),
        "hives_ok": len(ok),
        "hives_failed": len(runs) - len(ok),
        "capped": len(hives) >= max(1, int(max_hives)),
        "hives": runs,
        "output_dir": output_dir,
    }


# ── Amcache & AppCompat ───────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_amcacheparser(
    amcache_path: str,
    output_dir: str,
    output_file: str = "amcache.csv",
) -> dict:
    """
    Parse Amcache.hve — program execution evidence with SHA1 hashes.
    amcache_path: path to Amcache.hve (usually Windows/AppCompat/Programs/Amcache.hve).
    """
    args = ["-f", amcache_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/AmcacheParser.dll", args, output_dir=output_dir)


@mcp.tool()
@output_safe
def ez_appcompatcacheparser(
    system_hive: str,
    output_dir: str,
    output_file: str = "shimcache.csv",
) -> dict:
    """
    Parse AppCompatCache (ShimCache) from SYSTEM hive — execution evidence with timestamps.
    system_hive: path to SYSTEM registry hive.
    """
    args = ["-f", system_hive, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/AppCompatCacheParser.dll", args, output_dir=output_dir)


# ── Prefetch ──────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_pecmd(
    prefetch_path: str,
    output_dir: str,
    output_file: str = "prefetch.csv",
) -> dict:
    """
    Parse Windows Prefetch files — execution timestamps (up to 8 last run times), file references.
    prefetch_path: path to a single .pf file or the Prefetch directory.
    """
    flag = "-f" if prefetch_path.endswith(".pf") else "-d"
    args = [flag, prefetch_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/PECmd.dll", args, output_dir=output_dir)


# ── Jump Lists & LNK ──────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_jlecmd(
    jump_list_path: str,
    output_dir: str,
    output_file: str = "jumplists.csv",
) -> dict:
    """
    Parse Jump Lists (AutomaticDestinations / CustomDestinations).
    jump_list_path: path to a single .automaticDestinations-ms file or directory.
    """
    flag = "-f" if "automaticDestinations" in jump_list_path or "customDestinations" in jump_list_path else "-d"
    args = [flag, jump_list_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/JLECmd.dll", args, output_dir=output_dir)


@mcp.tool()
@output_safe
def ez_lecmd(
    lnk_path: str,
    output_dir: str,
    output_file: str = "lnk.csv",
) -> dict:
    """
    Parse Windows shortcut (.lnk) files — reveal accessed paths, timestamps, machine info.
    lnk_path: path to a single .lnk file or a directory to scan recursively.
    """
    flag = "-f" if lnk_path.endswith(".lnk") else "-d"
    args = [flag, lnk_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/LECmd.dll", args, output_dir=output_dir)


# ── Shellbags ─────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_sbecmd(
    usrclass_path: str,
    output_dir: str,
    output_file: str = "shellbags.csv",
) -> dict:
    """
    Parse Shellbags (UsrClass.dat) — folder access history including network and removable media.
    usrclass_path: path to UsrClass.dat hive.
    """
    args = ["-f", usrclass_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/SBECmd.dll", args, output_dir=output_dir)


# ── Recycle Bin ───────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_rbcmd(
    recycle_bin_path: str,
    output_dir: str,
    output_file: str = "recyclebin.csv",
) -> dict:
    """
    Parse Recycle Bin $I files — deleted file metadata (original path, deletion time, file size).
    recycle_bin_path: path to $Recycle.Bin directory or a single $I file.
    """
    flag = "-f" if recycle_bin_path.startswith("$I") or "/$I" in recycle_bin_path else "-d"
    args = [flag, recycle_bin_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/RBCmd.dll", args, output_dir=output_dir)


# ── Windows Timeline ──────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_wxtcmd(
    timeline_db: str,
    output_dir: str,
    output_file: str = "win_timeline.csv",
) -> dict:
    """
    Parse Windows 10 Timeline database (ActivitiesCache.db) — user activity history.
    timeline_db: path to ActivitiesCache.db.
    """
    args = ["-f", timeline_db, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/WxTCmd.dll", args, output_dir=output_dir)


# ── SQLite ────────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_sqlecmd(
    db_path: str,
    output_dir: str,
    output_file: str = "sqlite.csv",
    maps_dir: str = f"{EZ}/SQLECmd/Maps",
) -> dict:
    """
    Parse SQLite databases with known schema maps (browser history, Windows Timeline, etc.).
    db_path: path to a single .db file or directory to scan.
    """
    flag = "-f" if db_path.endswith(".db") else "-d"
    args = [flag, db_path, "--csv", output_dir, "--csvf", output_file, "--maps", maps_dir]
    return _ez(f"{EZ}/SQLECmd/SQLECmd.dll", args, output_dir=output_dir, timeout=DEFAULT_TIMEOUT)


# ── bstrings ──────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_bstrings(
    target_path: str,
    output_dir: str,
    output_file: str = "bstrings.csv",
    min_length: int = 5,
    pattern: Optional[str] = None,
) -> dict:
    """
    Extract strings from binary files with better filtering than GNU strings.
    target_path: file or directory to scan.
    min_length: minimum string length.
    pattern: optional regex pattern to filter results.
    """
    flag = "-f" if "." in target_path.split("/")[-1] else "-d"
    args = [flag, target_path, "--csv", output_dir, "--csvf", output_file, "-m", str(min_length)]
    if pattern:
        args += ["--lr", pattern]
    return _ez(f"{EZ}/bstrings.dll", args, output_dir=output_dir, timeout=DEFAULT_TIMEOUT)


# ── RLA (Registry Log Analysis) ──────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_rla(
    hive_dir: str,
    output_dir: str,
    output_file: str = "rla.csv",
) -> dict:
    """
    Replay registry transaction logs against hives for complete, up-to-date data.
    hive_dir: directory containing hive files and their .LOG1/.LOG2 files.
    """
    args = ["-d", hive_dir, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/rla.dll", args, output_dir=output_dir)


# ── RecentFileCacheParser ─────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def ez_recentfilecache(
    rfc_path: str,
    output_dir: str,
    output_file: str = "recentfilecache.csv",
) -> dict:
    """
    Parse RecentFileCache.bcf — Windows XP/Vista execution artifact.
    rfc_path: path to RecentFileCache.bcf.
    """
    args = ["-f", rfc_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/RecentFileCacheParser.dll", args, output_dir=output_dir)
