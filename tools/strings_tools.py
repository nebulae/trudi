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
            "hint": "File may have been deleted post-execution. Use vol_dumpfiles --pid <PID> to extract from memory.",
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
def strings_grep(file_path: str, pattern: str, min_length: int = 4, case_insensitive: bool = True,
                 max_matches: int = 500, timeout: int = 0) -> dict:
    """
    Extract strings from a file and filter by regex pattern, STREAMING.
    Useful for targeted IOC hunting: URLs, IPs, domain names, commands.

    The whole `strings` stream is filtered line by line, so the result is a
    true answer over the ENTIRE file. Contract:
      match_count   total matching lines in the file (counted past the cap)
      matches       the first `max_matches` of them
      complete      True when the whole file was scanned
      truncated     True when `matches` was capped OR the scan did not
                    complete — a negative is only trustworthy when
                    match_count == 0 and complete is True and truncated is
                    False (the negative_from_truncated gate reads this).

    Why streaming: buffering the whole `strings` output through the executor's
    stdout cap (~50 KB) before the regex would silently drop any match beyond
    the cap and report match_count 0 with success:true — a false negative with
    no truncation signal, which reads as "the string is absent" when it is
    present past the cap.
    """
    import re
    import subprocess
    import threading
    import time
    from core.paths import resolve_path_ci
    from core.executor import _log_tool, OUTPUT_CAP, DEFAULT_TIMEOUT

    resolved, _ = resolve_path_ci(file_path)
    if not os.path.exists(resolved):
        return {
            "success": False,
            "error": f"file not found: {file_path}",
            "hint": "Use vol_dumpfiles to extract from memory.",
            "matches": [],
        }
    file_path = resolved

    flags = re.IGNORECASE if case_insensitive else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        return {"success": False, "error": f"Invalid regex: {e}", "matches": []}

    max_matches = max(1, int(max_matches))
    timeout = int(timeout) if timeout and int(timeout) > 0 else DEFAULT_TIMEOUT
    cmd = ["strings", "-a", "-n", str(min_length), file_path]
    start = time.perf_counter()

    def _trace(success: bool, matches: list[str], stderr: str, exit_code: int,
               truncated: bool) -> None:
        _log_tool({
            "success": success,
            "stdout": "\n".join(matches)[:OUTPUT_CAP],
            "stderr": stderr,
            "exit_code": exit_code,
            "truncated": truncated,
            "cmd": " ".join(cmd),
            "retries": 0,
            "elapsed_seconds": round(time.perf_counter() - start, 1),
        })

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace", bufsize=1,
        )
    except OSError as e:
        _trace(False, [], str(e), -1, False)
        return {"success": False, "error": f"failed to spawn strings: {e}", "matches": []}

    stderr_buf: list[str] = []

    def _drain_err():
        try:
            for line in proc.stderr:
                if len(stderr_buf) < 200:
                    stderr_buf.append(line.rstrip())
        except Exception:
            pass

    threading.Thread(target=_drain_err, daemon=True).start()

    matches: list[str] = []
    total_matches = 0
    lines_scanned = 0
    timed_out = False
    deadline = start + timeout
    try:
        for line in proc.stdout:
            lines_scanned += 1
            if rx.search(line):
                total_matches += 1
                if len(matches) < max_matches:
                    matches.append(line.rstrip("\n"))
            if (lines_scanned & 0x3FFF) == 0 and time.perf_counter() > deadline:
                timed_out = True
                break
    finally:
        if timed_out:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=30)
        except Exception:
            pass

    exit_code = proc.returncode if proc.returncode is not None else -1
    complete = (not timed_out) and exit_code == 0
    cap_hit = total_matches > len(matches)
    truncated = cap_hit or not complete
    stderr = "\n".join(stderr_buf)
    if timed_out:
        stderr = (f"strings_grep scan aborted after {timeout}s "
                  f"({lines_scanned} lines scanned); " + stderr).strip("; ")

    _trace(complete, matches, stderr, exit_code, truncated)

    result = {
        "success": complete,
        "file": file_path,
        "pattern": pattern,
        "match_count": total_matches,
        "matches": matches,
        "returned": len(matches),
        "max_matches": max_matches,
        "lines_scanned": lines_scanned,
        "complete": complete,
        "truncated": truncated,
        "elapsed_seconds": round(time.perf_counter() - start, 1),
    }
    if cap_hit:
        result["note"] = (f"{total_matches} matches; only the first {max_matches} returned — "
                          f"raise max_matches or narrow the pattern")
    if not complete:
        result["error"] = ("scan incomplete (timed out)" if timed_out
                           else f"strings exited {exit_code}: {stderr[:200]}")
        result["hint"] = ("Do NOT record a negative from this result — the file was not "
                          "fully scanned. Raise `timeout` or target a smaller file.")
    if stderr and complete:
        result["stderr"] = stderr[:500]
    return result


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
    # -q: suppress status ("N image files read"). --ExifToolVersion: drop the
    # leading "ExifTool Version Number" pseudo-tag so the real metadata (Creator,
    # Last Modified By, …) leads the output instead of a tool banner — the
    # stdout excerpt stored in the trace then carries evidence, not preamble.
    return run(["exiftool", "-q", "--ExifToolVersion", file_path])


@mcp.tool()
@output_safe
def exiftool_batch(directory: str, recursive: bool = True) -> dict:
    """Extract EXIF metadata from all files in a directory."""
    cmd = ["exiftool", "-q", "--ExifToolVersion"]  # drop status + version banner (see exiftool_metadata)
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
