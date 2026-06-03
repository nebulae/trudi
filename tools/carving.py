"""File carving tools — bulk_extractor, foremost, scalpel."""
from typing import Optional
from fastmcp import FastMCP
from core import run, output_safe, DEFAULT_TIMEOUT, VOL_TIMEOUT, PLASO_TIMEOUT
from core.paths import assert_output_safe

mcp = FastMCP("carving")


@mcp.tool()
@output_safe
def bulk_extractor_scan(
    image_path: str,
    output_dir: str,
    threads: int = 4,
    scanners: Optional[str] = None,
) -> dict:
    """
    Carve features from a disk image or raw file using bulk_extractor.
    Extracts: email addresses, URLs, domains, credit cards, Bitcoin addresses,
              phone numbers, GPS coordinates, Base64 strings, and more.
    output_dir: directory to write feature files (one per feature type).
    threads: parallel scanner threads (default 4).
    scanners: comma-separated scanner names to limit scope
              e.g. 'email,url,domain,ip' — omit for all scanners.
    """
    cmd = ["bulk_extractor", "-j", str(threads), "-o", output_dir]
    if scanners:
        for s in scanners.split(","):
            cmd += ["-e", s.strip()]
    cmd.append(image_path)
    return run(cmd, needs_sudo=True, timeout=VOL_TIMEOUT*12, output_dir=output_dir)


@mcp.tool()
@output_safe
def bulk_extractor_unallocated(
    unallocated_raw: str,
    output_dir: str,
    threads: int = 4,
) -> dict:
    """
    Run bulk_extractor on a raw unallocated blocks file (from tsk_blkls).
    Faster than scanning a full image when you only care about deleted/unallocated data.
    """
    cmd = ["bulk_extractor", "-j", str(threads), "-o", output_dir, unallocated_raw]
    return run(cmd, needs_sudo=True, timeout=VOL_TIMEOUT*6, output_dir=output_dir)


@mcp.tool()
@output_safe
def foremost_carve(
    image_path: str,
    output_dir: str,
    file_types: Optional[str] = None,
    config_file: Optional[str] = None,
) -> dict:
    """
    Carve files by header/footer signatures using foremost.
    file_types: comma-separated types e.g. 'jpg,pdf,doc,zip,exe' — omit for all.
    output_file: uses foremost default config if not specified.
    """
    cmd = ["foremost", "-o", output_dir]
    if file_types:
        cmd += ["-t", file_types]
    if config_file:
        cmd += ["-c", config_file]
    cmd.append(image_path)
    return run(cmd, needs_sudo=True, timeout=VOL_TIMEOUT*12, output_dir=output_dir)


@mcp.tool()
@output_safe
def scalpel_carve(
    image_path: str,
    output_dir: str,
    config_file: str = "/etc/scalpel/scalpel.conf",
) -> dict:
    """
    Carve files by signature using scalpel (faster than foremost for large images).
    config_file: scalpel.conf with file type definitions (edit to enable desired types).
    """
    cmd = ["scalpel", "-c", config_file, "-o", output_dir, image_path]
    return run(cmd, needs_sudo=True, timeout=VOL_TIMEOUT*12, output_dir=output_dir)


@mcp.tool()
@output_safe
def bulk_extractor_report(output_dir: str) -> dict:
    """
    Read and summarize bulk_extractor output feature files from a completed scan.
    Returns line counts per feature file and first 100 entries from each.
    """
    import os
    summary = {}
    try:
        for fname in os.listdir(output_dir):
            if fname.endswith(".txt") and not fname.endswith("_histogram.txt") and not fname.startswith("report"):
                fpath = os.path.join(output_dir, fname)
                try:
                    with open(fpath, "r", errors="replace") as f:
                        lines = [l.strip() for l in f if not l.startswith("#") and l.strip()]
                    summary[fname] = {
                        "count": len(lines),
                        "sample": lines[:100],
                    }
                except Exception as e:
                    summary[fname] = {"error": str(e)}
        return {"success": True, "output_dir": output_dir, "features": summary}
    except Exception as e:
        return {"success": False, "error": str(e)}
