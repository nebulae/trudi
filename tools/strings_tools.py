"""String extraction, file identification, and metadata tools."""
import os
import shutil
from typing import Optional
from fastmcp import FastMCP
from core import run, output_safe
from core.paths import assert_output_safe

mcp = FastMCP("strings")


@mcp.tool()
@output_safe
def strings_extract(
    file_path: str,
    min_length: int = 8,
    unicode: bool = True,
    output_path: Optional[str] = None,
) -> dict:
    """
    Extract printable ASCII and Unicode strings from a binary file.
    min_length: minimum string length (default 8 reduces noise).
    unicode: also extract Unicode (UTF-16LE) strings.
    """
    from core.paths import assert_output_safe, resolve_path_ci

    resolved, corrected = resolve_path_ci(file_path)
    if not os.path.exists(resolved):
        return {
            "success": False,
            "error": f"file not found on mounted filesystem: {file_path}",
            "hint": "File may have been deleted post-execution. Use vol_vol_dumpfiles --pid <PID> to extract from memory.",
            "ascii_lines": 0,
            "unicode_lines": 0,
            "ascii_stdout": "",
            "unicode_stdout": "",
            "output_path": output_path,
        }
    file_path = resolved

    results = {}

    # ASCII strings
    ascii_cmd = ["strings", "-a", "-n", str(min_length), file_path]
    results["ascii"] = run(ascii_cmd)

    # Unicode strings
    if unicode:
        uni_cmd = ["strings", "-a", "-el", "-n", str(min_length), file_path]
        results["unicode"] = run(uni_cmd)

    combined = results["ascii"].get("stdout", "") + "\n" + results.get("unicode", {}).get("stdout", "")

    if output_path:
        assert_output_safe(output_path)
        with open(output_path, "w") as f:
            f.write(combined)

    return {
        "success": results["ascii"]["success"],
        "ascii_lines": len(results["ascii"].get("stdout", "").splitlines()),
        "unicode_lines": len(results.get("unicode", {}).get("stdout", "").splitlines()),
        "ascii_stdout": results["ascii"].get("stdout", ""),
        "unicode_stdout": results.get("unicode", {}).get("stdout", ""),
        "output_path": output_path,
        "stderr": results["ascii"].get("stderr", ""),
        "path_resolved": file_path if corrected else None,
    }


@mcp.tool()
@output_safe
def strings_grep(file_path: str, pattern: str, min_length: int = 4, case_insensitive: bool = True) -> dict:
    """
    Extract strings from a file and filter by regex pattern.
    Useful for targeted IOC hunting: URLs, IPs, domain names, commands.
    """
    import re
    from core.paths import resolve_path_ci

    resolved, _ = resolve_path_ci(file_path)
    if not os.path.exists(resolved):
        return {
            "success": False,
            "error": f"file not found: {file_path}",
            "hint": "Use vol_vol_dumpfiles to extract from memory.",
            "matches": [],
        }
    file_path = resolved

    # Run strings
    cmd = ["strings", "-a", "-n", str(min_length), file_path]
    result = run(cmd)
    if not result["success"] and not result["stdout"]:
        return result

    flags = re.IGNORECASE if case_insensitive else 0
    try:
        matches = [line for line in result["stdout"].splitlines() if re.search(pattern, line, flags)]
        return {
            "success": True,
            "file": file_path,
            "pattern": pattern,
            "match_count": len(matches),
            "matches": matches,
        }
    except re.error as e:
        return {"success": False, "error": f"Invalid regex: {e}"}


@mcp.tool()
@output_safe
def file_identify(file_path: str) -> dict:
    """Identify file type using magic bytes (libmagic). More reliable than extension."""
    return run(["file", file_path])


@mcp.tool()
@output_safe
def file_identify_directory(directory: str) -> dict:
    """Identify file types for all files in a directory."""
    return run(["file", "-r", directory], timeout=120)


@mcp.tool()
@output_safe
def hexdump(file_path: str, length: int = 256, offset: int = 0) -> dict:
    """
    Display file content as hex dump.
    length: number of bytes to dump (default 256).
    offset: byte offset to start from.
    """
    cmd = ["hexdump", "-C", "-n", str(length), "-s", str(offset), file_path]
    return run(cmd)


@mcp.tool()
@output_safe
def xxd_dump(file_path: str, length: int = 256, offset: int = 0) -> dict:
    """
    Display file content as xxd hex dump (more readable than hexdump for some cases).
    length: number of bytes to dump.
    offset: byte offset to start from.
    """
    cmd = ["xxd", "-l", str(length), "-s", str(offset), file_path]
    return run(cmd)


@mcp.tool()
@output_safe
def exiftool_metadata(file_path: str) -> dict:
    """Extract EXIF and metadata from files (images, Office docs, PDFs, executables)."""
    return run(["exiftool", file_path])


@mcp.tool()
@output_safe
def exiftool_batch(directory: str, recursive: bool = True) -> dict:
    """Extract EXIF metadata from all files in a directory."""
    cmd = ["exiftool"]
    if recursive:
        cmd.append("-r")
    cmd.append(directory)
    return run(cmd, timeout=300)


@mcp.tool()
@output_safe
def stat_file(file_path: str) -> dict:
    """Display filesystem metadata for a file: timestamps, permissions, inode, size."""
    return run(["stat", file_path])


@mcp.tool()
@output_safe
def floss_extract(
    file_path: str,
    min_length: int = 6,
    output_path: Optional[str] = None,
) -> dict:
    """
    Extract obfuscated, stacked, and decoded strings from a malware sample
    using FLARE's floss. Catches C2 URLs, decoded keys, and stack-built strings
    that plain `strings` misses.

    file_path: PE/ELF binary or shellcode buffer.
    min_length: minimum reported string length.
    output_path: optional JSON report destination (under analysis/exports/reports).
    """
    if output_path:
        assert_output_safe(output_path)
    binary = shutil.which("floss")
    if not binary:
        return {"success": False, "error":
                "floss not installed — pip install flare-floss"}
    cmd = [binary, "-n", str(min_length)]
    if output_path:
        cmd += ["-j", output_path]
    cmd.append(file_path)
    return run(cmd, timeout=600)
