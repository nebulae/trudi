"""EZ Tools (Eric Zimmerman) — Windows artifact parsers via .NET runtime."""
from typing import Optional
from fastmcp import FastMCP
from core import run_dotnet, run, DEFAULT_TIMEOUT, VOL_TIMEOUT, PLASO_TIMEOUT
from core.paths import assert_output_safe

mcp = FastMCP("eztools")

EZ = "/opt/zimmermantools"


def _ez(dll: str, args: list[str], output_dir: Optional[str] = None, timeout: int = 300) -> dict:
    if output_dir:
        assert_output_safe(output_dir)
    return run_dotnet(dll, args, timeout=timeout, output_dir=output_dir)


# ── MFT ──────────────────────────────────────────────────────────────────────

@mcp.tool()
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
    assert_output_safe(output_dir)
    args = ["-f", mft_path, "--csv", output_dir, "--csvf", output_file]
    if include_slack:
        args.append("--ds")
    return _ez(f"{EZ}/MFTECmd.dll", args, output_dir=output_dir)


@mcp.tool()
def ez_mftecmd_dir(
    volume_dir: str,
    output_dir: str,
    output_file: str = "mft_dir.csv",
) -> dict:
    """Parse $MFT from a directory scan of a mounted volume (searches for $MFT automatically)."""
    assert_output_safe(output_dir)
    args = ["-d", volume_dir, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/MFTECmd.dll", args, output_dir=output_dir)


# ── Event Logs ────────────────────────────────────────────────────────────────

@mcp.tool()
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
    assert_output_safe(output_dir)
    flag = "-f" if evtx_path.endswith(".evtx") else "-d"
    args = [flag, evtx_path, "--csv", output_dir, "--csvf", output_file, "--maps", maps_dir]
    if event_ids:
        args += ["--inc", event_ids]
    return _ez(f"{EZ}/EvtxeCmd/EvtxECmd.dll", args, output_dir=output_dir, timeout=VOL_TIMEOUT)


# ── Registry ──────────────────────────────────────────────────────────────────

@mcp.tool()
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
    assert_output_safe(output_dir)
    args = ["-f", hive_path, "--bn", batch_file, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/RECmd/RECmd.dll", args, output_dir=output_dir, timeout=DEFAULT_TIMEOUT)


@mcp.tool()
def ez_recmd_dir(
    hives_dir: str,
    output_dir: str,
    output_file: str = "registry_all.csv",
    batch_file: str = f"{EZ}/RECmd/BatchExamples/DFIRBatch.reb",
) -> dict:
    """Parse all registry hives in a directory recursively using a RECmd batch file."""
    assert_output_safe(output_dir)
    args = ["-d", hives_dir, "--bn", batch_file, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/RECmd/RECmd.dll", args, output_dir=output_dir, timeout=VOL_TIMEOUT)


@mcp.tool()
def ez_recmd_batch(
    hives_dir: str,
    batch_file: str,
    output_dir: str,
) -> dict:
    """Run a RECmd batch config against a directory of hives (targeted key extraction)."""
    assert_output_safe(output_dir)
    args = ["-d", hives_dir, "--bn", batch_file, "--csv", output_dir]
    return _ez(f"{EZ}/RECmd/RECmd.dll", args, output_dir=output_dir, timeout=DEFAULT_TIMEOUT)


# ── Amcache & AppCompat ───────────────────────────────────────────────────────

@mcp.tool()
def ez_amcacheparser(
    amcache_path: str,
    output_dir: str,
    output_file: str = "amcache.csv",
) -> dict:
    """
    Parse Amcache.hve — program execution evidence with SHA1 hashes.
    amcache_path: path to Amcache.hve (usually Windows/AppCompat/Programs/Amcache.hve).
    """
    assert_output_safe(output_dir)
    args = ["-f", amcache_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/AmcacheParser.dll", args, output_dir=output_dir)


@mcp.tool()
def ez_appcompatcacheparser(
    system_hive: str,
    output_dir: str,
    output_file: str = "shimcache.csv",
) -> dict:
    """
    Parse AppCompatCache (ShimCache) from SYSTEM hive — execution evidence with timestamps.
    system_hive: path to SYSTEM registry hive.
    """
    assert_output_safe(output_dir)
    args = ["-f", system_hive, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/AppCompatCacheParser.dll", args, output_dir=output_dir)


# ── Prefetch ──────────────────────────────────────────────────────────────────

@mcp.tool()
def ez_pecmd(
    prefetch_path: str,
    output_dir: str,
    output_file: str = "prefetch.csv",
) -> dict:
    """
    Parse Windows Prefetch files — execution timestamps (up to 8 last run times), file references.
    prefetch_path: path to a single .pf file or the Prefetch directory.
    """
    assert_output_safe(output_dir)
    flag = "-f" if prefetch_path.endswith(".pf") else "-d"
    args = [flag, prefetch_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/PECmd.dll", args, output_dir=output_dir)


# ── Jump Lists & LNK ──────────────────────────────────────────────────────────

@mcp.tool()
def ez_jlecmd(
    jump_list_path: str,
    output_dir: str,
    output_file: str = "jumplists.csv",
) -> dict:
    """
    Parse Jump Lists (AutomaticDestinations / CustomDestinations).
    jump_list_path: path to a single .automaticDestinations-ms file or directory.
    """
    assert_output_safe(output_dir)
    flag = "-f" if "automaticDestinations" in jump_list_path or "customDestinations" in jump_list_path else "-d"
    args = [flag, jump_list_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/JLECmd.dll", args, output_dir=output_dir)


@mcp.tool()
def ez_lecmd(
    lnk_path: str,
    output_dir: str,
    output_file: str = "lnk.csv",
) -> dict:
    """
    Parse Windows shortcut (.lnk) files — reveal accessed paths, timestamps, machine info.
    lnk_path: path to a single .lnk file or a directory to scan recursively.
    """
    assert_output_safe(output_dir)
    flag = "-f" if lnk_path.endswith(".lnk") else "-d"
    args = [flag, lnk_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/LECmd.dll", args, output_dir=output_dir)


# ── Shellbags ─────────────────────────────────────────────────────────────────

@mcp.tool()
def ez_sbecmd(
    usrclass_path: str,
    output_dir: str,
    output_file: str = "shellbags.csv",
) -> dict:
    """
    Parse Shellbags (UsrClass.dat) — folder access history including network and removable media.
    usrclass_path: path to UsrClass.dat hive.
    """
    assert_output_safe(output_dir)
    args = ["-f", usrclass_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/SBECmd.dll", args, output_dir=output_dir)


# ── Recycle Bin ───────────────────────────────────────────────────────────────

@mcp.tool()
def ez_rbcmd(
    recycle_bin_path: str,
    output_dir: str,
    output_file: str = "recyclebin.csv",
) -> dict:
    """
    Parse Recycle Bin $I files — deleted file metadata (original path, deletion time, file size).
    recycle_bin_path: path to $Recycle.Bin directory or a single $I file.
    """
    assert_output_safe(output_dir)
    flag = "-f" if recycle_bin_path.startswith("$I") or "/$I" in recycle_bin_path else "-d"
    args = [flag, recycle_bin_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/RBCmd.dll", args, output_dir=output_dir)


# ── Windows Timeline ──────────────────────────────────────────────────────────

@mcp.tool()
def ez_wxtcmd(
    timeline_db: str,
    output_dir: str,
    output_file: str = "win_timeline.csv",
) -> dict:
    """
    Parse Windows 10 Timeline database (ActivitiesCache.db) — user activity history.
    timeline_db: path to ActivitiesCache.db.
    """
    assert_output_safe(output_dir)
    args = ["-f", timeline_db, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/WxTCmd.dll", args, output_dir=output_dir)


# ── SQLite ────────────────────────────────────────────────────────────────────

@mcp.tool()
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
    assert_output_safe(output_dir)
    flag = "-f" if db_path.endswith(".db") else "-d"
    args = [flag, db_path, "--csv", output_dir, "--csvf", output_file, "--maps", maps_dir]
    return _ez(f"{EZ}/SQLECmd/SQLECmd.dll", args, output_dir=output_dir, timeout=DEFAULT_TIMEOUT)


# ── bstrings ──────────────────────────────────────────────────────────────────

@mcp.tool()
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
    assert_output_safe(output_dir)
    flag = "-f" if "." in target_path.split("/")[-1] else "-d"
    args = [flag, target_path, "--csv", output_dir, "--csvf", output_file, "-m", str(min_length)]
    if pattern:
        args += ["--lr", pattern]
    return _ez(f"{EZ}/bstrings.dll", args, output_dir=output_dir, timeout=DEFAULT_TIMEOUT)


# ── RLA (Registry Log Analysis) ──────────────────────────────────────────────

@mcp.tool()
def ez_rla(
    hive_dir: str,
    output_dir: str,
    output_file: str = "rla.csv",
) -> dict:
    """
    Replay registry transaction logs against hives for complete, up-to-date data.
    hive_dir: directory containing hive files and their .LOG1/.LOG2 files.
    """
    assert_output_safe(output_dir)
    args = ["-d", hive_dir, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/rla.dll", args, output_dir=output_dir)


# ── RecentFileCacheParser ─────────────────────────────────────────────────────

@mcp.tool()
def ez_recentfilecache(
    rfc_path: str,
    output_dir: str,
    output_file: str = "recentfilecache.csv",
) -> dict:
    """
    Parse RecentFileCache.bcf — Windows XP/Vista execution artifact.
    rfc_path: path to RecentFileCache.bcf.
    """
    assert_output_safe(output_dir)
    args = ["-f", rfc_path, "--csv", output_dir, "--csvf", output_file]
    return _ez(f"{EZ}/RecentFileCacheParser.dll", args, output_dir=output_dir)
