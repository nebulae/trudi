"""Plaso (log2timeline) — super-timeline generation and filtering."""
import os
from typing import Optional
from fastmcp import FastMCP
from core import run
from core.paths import assert_output_safe

mcp = FastMCP("plaso")


@mcp.tool()
def plaso_create_timeline(
    evidence_path: str,
    storage_file: str,
    parsers: Optional[str] = None,
    timezone: str = "UTC",
) -> dict:
    """
    Create a Plaso storage file from an evidence source (disk image, directory, or file).
    evidence_path: E01 image, mounted directory, memory image, or log file.
    storage_file: output .plaso file path (must be in analysis/ or exports/).
    parsers: comma-separated parser names to limit scope (omit for all parsers).
    Note: Full disk images take 1-6 hours depending on size. Use filters to scope.
    """
    assert_output_safe(storage_file)
    cmd = ["log2timeline.py", "--storage-file", storage_file, f"--timezone={timezone}"]
    if parsers:
        cmd += ["--parsers", parsers]
    cmd.append(evidence_path)
    return run(cmd, timeout=21600)  # 6 hour timeout for full images


@mcp.tool()
def plaso_create_targeted(
    evidence_path: str,
    storage_file: str,
    artifact_filters: str,
    timezone: str = "UTC",
) -> dict:
    """
    Create a targeted Plaso timeline using artifact filters (much faster than full parse).
    artifact_filters: comma-separated artifact names e.g.
        'WindowsEventLogs,WindowsPrefetch,WindowsRegistryCurrentUser,WindowsMFT'
    Common artifacts: WindowsEventLogs, WindowsPrefetch, WindowsRegistryCurrentUser,
        WindowsRegistryCurrentControlSet, WindowsMFT, WindowsRecycleBin,
        WindowsScheduledTasks, WindowsUserShellFolders
    """
    assert_output_safe(storage_file)
    cmd = [
        "log2timeline.py",
        "--storage-file", storage_file,
        f"--timezone={timezone}",
        "--artifact-filters", artifact_filters,
        evidence_path,
    ]
    return run(cmd, timeout=7200)


@mcp.tool()
def plaso_export_csv(
    storage_file: str,
    output_csv: str,
    time_filter: Optional[str] = None,
    query_filter: Optional[str] = None,
) -> dict:
    """
    Export a Plaso storage file to l2tCSV format.
    time_filter: e.g. "date > '2023-01-20' AND date < '2023-01-30'"
    query_filter: additional psort query filter expression.
    """
    assert_output_safe(output_csv)
    cmd = ["psort.py", "-o", "l2tcsv", "-w", output_csv, storage_file]
    if time_filter:
        cmd.append(time_filter)
    elif query_filter:
        cmd.append(query_filter)
    return run(cmd, timeout=3600)


@mcp.tool()
def plaso_export_json(
    storage_file: str,
    output_json: str,
    time_filter: Optional[str] = None,
) -> dict:
    """Export a Plaso storage file to JSON Lines format."""
    assert_output_safe(output_json)
    cmd = ["psort.py", "-o", "json_line", "-w", output_json, storage_file]
    if time_filter:
        cmd.append(time_filter)
    return run(cmd, timeout=3600)


@mcp.tool()
def plaso_info(storage_file: str) -> dict:
    """Display metadata and statistics about a Plaso storage file (event counts, parsers used)."""
    return run(["pinfo.py", storage_file], timeout=120)


@mcp.tool()
def plaso_filter_incident_window(
    storage_file: str,
    output_csv: str,
    start_utc: str,
    end_utc: str,
) -> dict:
    """
    Export events within an incident time window to CSV.
    start_utc / end_utc: ISO format e.g. '2023-01-24 00:00:00'
    """
    assert_output_safe(output_csv)
    time_filter = f"date > '{start_utc}' AND date < '{end_utc}'"
    cmd = ["psort.py", "-o", "l2tcsv", "-w", output_csv, storage_file, time_filter]
    return run(cmd, timeout=3600)


@mcp.tool()
def plaso_list_parsers() -> dict:
    """List all available Plaso parsers and plugins."""
    return run(["log2timeline.py", "--parsers", "list"], timeout=30)
