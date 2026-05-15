"""Miscellaneous SIFT tools — evtx parsing, registry, USN journal, AV, browser forensics."""
from typing import Optional
from fastmcp import FastMCP
from core import run
from core.paths import assert_output_safe

mcp = FastMCP("misc")


# ── Event log parsing (python-evtx) ──────────────────────────────────────────

@mcp.tool()
def evtx_dump(evtx_file: str, output_path: Optional[str] = None) -> dict:
    """
    Dump an EVTX file to XML using python-evtx.
    Useful for inspection without EZ Tools or for piping to grep.
    """
    if output_path:
        assert_output_safe(output_path)
    cmd = ["/usr/local/bin/evtx_dump.py", evtx_file]
    if output_path:
        import subprocess
        try:
            with open(output_path, "w") as f:
                proc = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=300)
            return {
                "success": proc.returncode == 0,
                "stdout": f"Dumped to {output_path}",
                "stderr": proc.stderr.decode("utf-8", errors="replace")[:4096],
                "exit_code": proc.returncode,
                "truncated": False,
                "cmd": " ".join(cmd),
            }
        except Exception as e:
            return {"success": False, "stderr": str(e), "stdout": "", "exit_code": -1, "truncated": False, "cmd": ""}
    return run(cmd, timeout=300)


@mcp.tool()
def evtx_filter(evtx_file: str, event_ids: str) -> dict:
    """
    Extract specific event IDs from an EVTX file using evtx_filter_records.
    event_ids: comma-separated event IDs e.g. '4624,4625,4688,4698'.
    """
    from core import run as _run
    import subprocess
    import json

    ids = [int(x.strip()) for x in event_ids.split(",") if x.strip().isdigit()]
    cmd = ["/usr/local/bin/evtx_dump.py", evtx_file]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=300)
        output = proc.stdout.decode("utf-8", errors="replace")
        # Filter XML blocks containing the event IDs
        import re
        results = []
        for eid in ids:
            pattern = rf'<EventID[^>]*>{eid}</EventID>'
            # Find entire Event elements containing this ID
            for match in re.finditer(r'<Event\b[^>]*>.*?</Event>', output, re.DOTALL):
                if re.search(pattern, match.group()):
                    results.append(match.group()[:2000])  # cap per event

        return {
            "success": True,
            "event_ids_requested": ids,
            "matches_found": len(results),
            "events": results[:200],  # cap total results
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Registry (regripper) ──────────────────────────────────────────────────────

@mcp.tool()
def regripper_hive(
    hive_path: str,
    plugin: Optional[str] = None,
    all_plugins: bool = True,
) -> dict:
    """
    Parse a registry hive with regripper (rip.pl).
    plugin: run a specific plugin e.g. 'userassist', 'services', 'autoruns'.
    all_plugins: run all applicable plugins (ignored if plugin is specified).
    """
    cmd = ["/usr/local/bin/rip.pl", "-r", hive_path]
    if plugin:
        cmd += ["-p", plugin]
    elif all_plugins:
        cmd.append("-a")
    return run(cmd, timeout=120)


@mcp.tool()
def regripper_list_plugins() -> dict:
    """List all available regripper plugins."""
    return run(["/usr/local/bin/rip.pl", "-l"], timeout=30)


# ── USN Journal ───────────────────────────────────────────────────────────────

@mcp.tool()
def usnparser_parse(usn_journal: str, output_path: Optional[str] = None) -> dict:
    """
    Parse the NTFS USN Change Journal ($UsnJrnl:$J).
    usn_journal: path to extracted $J stream (from tsk_icat on inode 11-128-4).
    output_path: optional CSV output path.
    """
    if output_path:
        assert_output_safe(output_path)
    cmd = ["/usr/local/bin/usnparser", "-f", usn_journal]
    if output_path:
        cmd += ["-o", output_path]
    return run(cmd, timeout=300)


# ── MFT analysis ─────────────────────────────────────────────────────────────

@mcp.tool()
def analyzemft_parse(mft_path: str, output_csv: str) -> dict:
    """
    Parse $MFT file using analyzeMFT (Python-based alternative to MFTECmd).
    mft_path: path to extracted $MFT.
    output_csv: destination CSV file.
    """
    assert_output_safe(output_csv)
    return run(
        ["/usr/local/bin/analyzemft", "-f", mft_path, "-o", output_csv],
        timeout=600,
        output_dir=output_csv,
    )


# ── Browser forensics ─────────────────────────────────────────────────────────

@mcp.tool()
def hindsight_chrome(
    profile_path: str,
    output_dir: str,
    output_format: str = "json",
) -> dict:
    """
    Parse Chrome/Chromium browser history, cookies, cache, and extensions using Hindsight.
    profile_path: path to Chrome 'Default' profile directory.
    output_format: 'json', 'sqlite', 'csv'.
    """
    assert_output_safe(output_dir)
    import os
    output_file = os.path.join(output_dir, "hindsight_chrome")
    cmd = [
        "/usr/local/bin/hindsight.py",
        "-i", profile_path,
        "-o", output_file,
        "-f", output_format,
    ]
    return run(cmd, timeout=300, output_dir=output_dir)


# ── AV scanning ──────────────────────────────────────────────────────────────

@mcp.tool()
def clamscan_file(file_path: str) -> dict:
    """Scan a file for malware using ClamAV."""
    return run(["clamscan", "--no-summary", file_path], timeout=120)


@mcp.tool()
def clamscan_directory(directory: str, recursive: bool = True) -> dict:
    """Scan a directory for malware using ClamAV."""
    cmd = ["clamscan", "--no-summary"]
    if recursive:
        cmd.append("-r")
    cmd.append(directory)
    return run(cmd, timeout=1800)


# ── USB device forensics ──────────────────────────────────────────────────────

@mcp.tool()
def usbdeviceforensics(registry_path: str, output_path: Optional[str] = None) -> dict:
    """
    Extract USB device connection history from registry hives.
    registry_path: path to SYSTEM hive or a directory containing SYSTEM.
    """
    if output_path:
        assert_output_safe(output_path)
    cmd = ["/usr/local/bin/usbdeviceforensics", registry_path]
    return run(cmd, timeout=60)


# ── Scheduled tasks (disk) ────────────────────────────────────────────────────

@mcp.tool()
def parse_scheduled_tasks(tasks_dir: str) -> dict:
    """
    List and read Windows Scheduled Task XML files from disk.
    tasks_dir: path to Windows/System32/Tasks/ on a mounted volume.
    """
    import os
    results = []
    errors = []
    try:
        for root, dirs, files in os.walk(tasks_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read(8192)
                    results.append({"task": fpath.replace(tasks_dir, ""), "content": content})
                except Exception as e:
                    errors.append({"task": fpath, "error": str(e)})
        return {"success": True, "task_count": len(results), "tasks": results, "errors": errors}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── PDF analysis ──────────────────────────────────────────────────────────────

@mcp.tool()
def pdfid_scan(pdf_path: str) -> dict:
    """
    Quick triage of a PDF file using pdfid.
    Reports counts of key PDF keywords: /JS, /JavaScript, /AA, /OpenAction, /Launch, etc.
    High counts of these suggest malicious or suspicious content.
    """
    return run(["/usr/local/bin/pdfid.py", pdf_path], timeout=30)


@mcp.tool()
def pdf_parser_analyze(pdf_path: str, object_id: Optional[int] = None) -> dict:
    """
    Deep analysis of a PDF file using pdf-parser.
    object_id: analyze a specific PDF object by ID (from pdfid output).
    """
    cmd = ["/usr/local/bin/pdf-parser.py", pdf_path]
    if object_id is not None:
        cmd += ["-o", str(object_id)]
    return run(cmd, timeout=60)


# ── PE analysis ───────────────────────────────────────────────────────────────

@mcp.tool()
def pe_scanner(file_path: str) -> dict:
    """Scan a PE executable for suspicious characteristics using pe-scanner."""
    return run(["/usr/local/bin/pe-scanner", file_path], timeout=30)


@mcp.tool()
def pe_carver(file_path: str, output_dir: str) -> dict:
    """Carve PE files from a binary blob (memory dump, disk image segment) using pe-carver."""
    assert_output_safe(output_dir)
    return run(["/usr/local/bin/pe-carver", "-f", file_path, "-o", output_dir], timeout=120, output_dir=output_dir)


@mcp.tool()
def packerid(file_path: str) -> dict:
    """Identify PE packer or protector using packerid."""
    return run(["/usr/local/bin/packerid.py", file_path], timeout=30)


# ── Execution trace log ───────────────────────────────────────────────────────

@mcp.tool()
def start_execution_log(case_id: str, output_path: str) -> dict:
    """
    Initialize the execution trace log for a case. Call this at the very start
    of every investigation, before any tool runs.

    case_id: unique case identifier e.g. 'SRL-2018-WKSTN01'.
    output_path: path for incremental JSON log — must be in analysis/, exports/, or reports/.
    """
    assert_output_safe(output_path)
    from core.execution_log import log
    log.configure(case_id, output_path)
    return {"success": True, "case_id": case_id, "log_path": output_path}


@mcp.tool()
def record_finding(description: str, confidence: str, source: str = "") -> dict:
    """
    Record a confirmed finding to the execution trace.
    confidence: 'high', 'medium', 'low', or 'uncertain'.
    source: tool or artifact that produced the finding e.g. 'vol.psscan', 'Amcache'.
    """
    from core.execution_log import log
    log.record_finding(description, confidence, source)
    return {"success": True, "description": description, "confidence": confidence}


@mcp.tool()
def export_execution_log(output_path: str) -> dict:
    """
    Export the execution trace to <output_path>.json and <output_path>.md.
    Call after reason.synthesize completes and before writing the final report.
    output_path must be in analysis/, exports/, or reports/.
    """
    assert_output_safe(output_path)
    from core.execution_log import log
    result = log.export(output_path)
    return {
        "success": True,
        "entry_count": result.get("entry_count", 0),
        "json_path": output_path + ".json",
        "md_path": output_path + ".md",
    }
