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


_ENC_FLAGS = {"ascii": [], "utf16le": ["-el"]}
_GREP_ENCODINGS = {
    "ascii": ["ascii"], "s": ["ascii"], "utf8": ["ascii"],
    "utf16le": ["utf16le"], "utf16": ["utf16le"], "l": ["utf16le"],
    "unicode": ["utf16le"], "wide": ["utf16le"],
    "both": ["ascii", "utf16le"], "all": ["ascii", "utf16le"],
}


@mcp.tool()
@output_safe
def strings_grep(file_path: str, pattern: str, min_length: int = 4, case_insensitive: bool = True,
                 max_matches: int = 500, timeout: int = 0, encoding: str = "ascii") -> dict:
    """
    Extract strings from a file and filter by regex pattern, STREAMING.
    Useful for targeted IOC hunting: URLs, IPs, domain names, commands.
    encoding: "ascii" (default), "utf16le" (Windows wide strings), or "both".

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

    enc = _GREP_ENCODINGS.get(str(encoding or "ascii").strip().lower().replace("-", "").replace("_", ""))
    if enc is None:
        return {"success": False, "matches": [],
                "error": f"invalid encoding {encoding!r}: use 'ascii', 'utf16le' or 'both'"}

    max_matches = max(1, int(max_matches))
    timeout = int(timeout) if timeout and int(timeout) > 0 else DEFAULT_TIMEOUT
    cmds = [["strings", "-a", *_ENC_FLAGS[e], "-n", str(min_length), file_path] for e in enc]
    start = time.perf_counter()

    def _trace(success: bool, matches: list[str], stderr: str, exit_code: int,
               truncated: bool) -> int:
        tc = {
            "success": success,
            "stdout": "\n".join(matches)[:OUTPUT_CAP],
            "stderr": stderr,
            "exit_code": exit_code,
            "truncated": truncated,
            "cmd": " ; ".join(" ".join(c) for c in cmds),
            "retries": 0,
            "elapsed_seconds": round(time.perf_counter() - start, 1),
        }
        _log_tool(tc)
        # Echo the id inline so the result is citable without a trace lookup.
        return tc.get("_trudi_call_id", 0)

    matches: list[str] = []
    total_matches = 0
    lines_scanned = 0
    timed_out = False
    exit_code = 0
    stderr_all: list[str] = []
    per_encoding: dict = {}
    deadline = start + timeout
    for e, cmd in zip(enc, cmds):
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, errors="replace", bufsize=1,
            )
        except OSError as err:
            cid = _trace(False, matches, str(err), -1, False)
            return {"success": False, "error": f"failed to spawn strings: {err}",
                    "matches": [], "_trudi_call_id": cid}

        stderr_buf: list[str] = []

        def _drain_err(p=proc, buf=stderr_buf):
            try:
                for line in p.stderr:
                    if len(buf) < 200:
                        buf.append(line.rstrip())
            except Exception:
                pass

        threading.Thread(target=_drain_err, daemon=True).start()

        hits = 0
        try:
            for line in proc.stdout:
                lines_scanned += 1
                if rx.search(line):
                    hits += 1
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
        total_matches += hits
        per_encoding[e] = hits
        rc = proc.returncode if proc.returncode is not None else -1
        if rc != 0 and exit_code == 0:
            exit_code = rc
        stderr_all.extend(stderr_buf)
        if timed_out:
            break

    complete = (not timed_out) and exit_code == 0
    cap_hit = total_matches > len(matches)
    truncated = cap_hit or not complete
    stderr = "\n".join(stderr_all)
    if timed_out:
        stderr = (f"strings_grep scan aborted after {timeout}s "
                  f"({lines_scanned} lines scanned); " + stderr).strip("; ")

    cid = _trace(complete, matches, stderr, exit_code, truncated)

    result = {
        "_trudi_call_id": cid,
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
        "encoding": "both" if len(enc) > 1 else enc[0],
    }
    if len(enc) > 1:
        result["match_count_by_encoding"] = per_encoding
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
def png_acropalypse(path: str, output_dir: str = "", max_seconds: int = 900) -> dict:
    """Detect Acropalypse-cropped PNG screenshots and rebuild the uncropped original.

    CVE-2023-21036 / CVE-2023-28303: data after the cropped PNG's IEND. path:
    file or directory.

    Recovered PNGs + acropalypse.csv go to output_dir (default
    ./exports/acropalypse/). JPEGs: trailing data after EOI, detection only.
    Detection is reported even when recovery fails. Read-only on the input.
    """
    import csv
    from core.acropalypse import scan
    from core.executor import _log_tool
    from core.paths import assert_case_output_path

    out_dir = output_dir or os.path.join(".", "exports", "acropalypse")
    assert_case_output_path(out_dir)
    res = scan(path, out_dir, max_seconds=max_seconds)
    ok = bool(res.get("success"))
    results = res.get("results", [])
    csv_path = None
    if ok:
        try:
            os.makedirs(out_dir, exist_ok=True)
            csv_path = os.path.join(out_dir, "acropalypse.csv")
            fields = ["path", "format", "size", "trailing_bytes", "detected", "recovered",
                      "cropped_width", "cropped_height", "recovered_width",
                      "recovered_height", "output_path", "note"]
            with open(csv_path, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=fields)
                w.writeheader()
                w.writerows(results)
        except OSError as e:
            res["warning"] = f"CSV write failed: {e}"
            csv_path = None
        hits = [r for r in results if r["detected"] or r["trailing_bytes"]]
        lines = [f"{res['detected']} Acropalypse-suspect file(s), {res['recovered']} recovered, "
                 f"of {res['files_scanned']}/{res['files_total']} image(s) scanned"
                 + (" (PARTIAL: file/time cap)" if res.get("truncated") else "")]
        lines += [f"{'DETECTED' if r['detected'] else 'trailing'} {r['path']}: "
                  f"{r['trailing_bytes']} bytes after end-of-image, cropped "
                  f"{r['cropped_width']}x{r['cropped_height']}"
                  + (f", RECOVERED {r['recovered_width']}x{r['recovered_height']} -> "
                     f"{r['output_path']}" if r["recovered"] else "")
                  + (f" ({r['note']})" if r["note"] else "") for r in hits]
        summary = "\n".join(lines)
    else:
        summary = res.get("error", "png_acropalypse failed")
    tc = {"success": ok, "stdout": summary[:4000], "_stdout_full": summary,
          "stderr": "" if ok else res.get("error", ""), "exit_code": 0 if ok else 1,
          "truncated": bool(res.get("truncated")), "retries": 0,
          "elapsed_seconds": float(res.get("elapsed_seconds") or 0.0),
          "cmd": f"strings.png_acropalypse {path}", "output_path": csv_path}
    _log_tool(tc)
    return {
        "success": ok, "error": res.get("error"), "warning": res.get("warning"),
        "_trudi_call_id": tc.get("_trudi_call_id"),
        "files_total": res.get("files_total", 0), "files_scanned": res.get("files_scanned", 0),
        "truncated": bool(res.get("truncated")), "detected": res.get("detected", 0),
        "recovered": res.get("recovered", 0),
        "findings": [r for r in results if r["detected"] or r["trailing_bytes"]][:100],
        "output_csv": csv_path, "elapsed_seconds": res.get("elapsed_seconds"),
        "summary": summary[:4000],
    }


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
    from tools.tool_capabilities import optional_binary, tool_unavailable_result
    missing = tool_unavailable_result("strings.floss_extract", shutil.which)
    if missing:
        return missing
    binary = optional_binary("strings.floss_extract", shutil.which)
    cmd = [binary, "-n", str(min_length)]
    if output_path:
        cmd += ["-j", output_path]
    cmd.append(file_path)
    return run(cmd, timeout=600)
