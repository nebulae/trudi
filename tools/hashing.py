"""File hashing and fuzzy hash tools."""
import os
import json
import hashlib
import glob
import threading
from typing import Optional
from fastmcp import FastMCP
from core import (run, DEFAULT_TIMEOUT, VOL_TIMEOUT, PLASO_TIMEOUT, HASH_TIMEOUT,
                  output_safe, with_tool_timeout)

mcp = FastMCP("hashing")


# ── Hash cache (keyed by absolute path + size + mtime) ──────────────────────

_HASH_CACHE_PATH = os.path.expanduser(
    os.environ.get("TRUDI_HASH_CACHE", "~/.cache/trudi/hash_cache.json")
)
_HASH_CACHE_LOCK = threading.Lock()
_HASH_CACHE: Optional[dict] = None


def _load_hash_cache() -> dict:
    global _HASH_CACHE
    if _HASH_CACHE is not None:
        return _HASH_CACHE
    try:
        with open(_HASH_CACHE_PATH) as f:
            data = json.load(f)
        if isinstance(data, dict):
            _HASH_CACHE = data
            return _HASH_CACHE
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    _HASH_CACHE = {}
    return _HASH_CACHE


def _save_hash_cache(cache: dict) -> None:
    os.makedirs(os.path.dirname(_HASH_CACHE_PATH), exist_ok=True)
    try:
        with open(_HASH_CACHE_PATH, "w") as f:
            json.dump(cache, f)
    except OSError:
        pass  # cache is opportunistic; tolerate filesystem errors


def _cache_key(stat_result, abs_path: str) -> str:
    return f"{abs_path}|{stat_result.st_size}|{int(stat_result.st_mtime)}"


@mcp.tool()
@output_safe
@with_tool_timeout(HASH_TIMEOUT, label="hash_file")
def hash_file(file_path: str) -> dict:
    """Compute MD5, SHA1, and SHA256 hashes of a file in one pass.

    Results are cached at TRUDI_HASH_CACHE (default ~/.cache/trudi/hash_cache.json)
    keyed by absolute path + size + mtime. Cache hits are returned instantly
    with `cache_hit: True` for the audit trail.
    """
    try:
        abs_path = os.path.abspath(file_path)
        stat = os.stat(abs_path)
    except OSError as e:
        return {"success": False, "error": str(e), "file": file_path}

    key = _cache_key(stat, abs_path)
    with _HASH_CACHE_LOCK:
        cache = _load_hash_cache()
        hit = cache.get(key)
        if hit:
            return {**hit, "cache_hit": True, "file": file_path}

    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        size = 0
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                size += len(chunk)
        result = {
            "success": True,
            "file": file_path,
            "size_bytes": size,
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except Exception as e:
        return {"success": False, "error": str(e), "file": file_path}

    with _HASH_CACHE_LOCK:
        cache = _load_hash_cache()
        cache[key] = {
            "success": True,
            "size_bytes": result["size_bytes"],
            "md5": result["md5"],
            "sha1": result["sha1"],
            "sha256": result["sha256"],
        }
        _save_hash_cache(cache)

    result["cache_hit"] = False
    return result


_CACHED_ALGOS = ("md5", "sha1", "sha256")


def _iter_files(directory: str, recursive: bool, start_after: str = ""):
    """Deterministic (sorted) walk so a capped run can be resumed from
    `next_start_path`. Yields absolute file paths; symlinks are not followed."""
    root = os.path.abspath(directory)
    # Hidden entries are skipped, as the previous glob("**/*") walk did.
    if not recursive:
        try:
            names = sorted(n for n in os.listdir(root) if not n.startswith("."))
        except OSError:
            return
        for n in names:
            p = os.path.join(root, n)
            if os.path.isfile(p) and not os.path.islink(p) and p > start_after:
                yield p
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for n in sorted(f for f in filenames if not f.startswith(".")):
            p = os.path.join(dirpath, n)
            if p <= start_after:
                continue
            if os.path.isfile(p) and not os.path.islink(p):
                yield p


@mcp.tool()
@output_safe
def hash_directory(
    directory: str,
    recursive: bool = True,
    algorithm: str = "sha256",
    output_manifest: Optional[str] = None,
    max_files: int = 5000,
    max_bytes: int = 2 * 1024 * 1024 * 1024,
    max_seconds: Optional[int] = None,
    skip_larger_than_mb: int = 512,
    start_after: str = "",
) -> dict:
    """
    Hash the files in a directory — BOUNDED and resumable.
    algorithm: md5, sha1, sha256, sha512 (md5/sha1/sha256 go through the
        per-file hash cache shared with hash_file).
    max_files / max_bytes / max_seconds: stop when any cap is reached and
        return the PARTIAL manifest with `truncated=True`, `truncation_reason`
        and `next_start_path` — call again with `start_after=<that path>` to
        continue. max_seconds defaults to HASH_TIMEOUT-5.
    skip_larger_than_mb: files above this size are listed in `skipped`, not read.
    output_manifest: optional CSV under analysis/exports (partial runs append).

    Why bounded: a recursive hash of a whole user profile (AppData, browser
    caches…) previously ran for 12+ minutes in-process with nothing in the
    trace, past the client's patience, and the work was orphaned.
    """
    import time
    from core.paths import assert_output_safe
    if output_manifest:
        assert_output_safe(output_manifest)

    algo_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    if algorithm not in algo_map:
        return {"success": False, "error": f"Unknown algorithm: {algorithm}"}
    if not os.path.isdir(directory):
        return {"success": False, "error": f"not a directory: {directory}"}

    budget_s = int(max_seconds) if max_seconds else max(5, int(HASH_TIMEOUT) - 5)
    max_files = max(1, int(max_files))
    max_bytes = max(1, int(max_bytes))
    skip_bytes = max(0, int(skip_larger_than_mb)) * 1024 * 1024
    deadline = time.monotonic() + budget_s
    start = time.monotonic()

    # Start marker: the trace shows what is running while the walk is in
    # progress (a long in-process tool used to be invisible until it returned).
    try:
        from core.execution_log import log as _elog
        _elog.record_call_initiated("hash_directory", "in-process", {
            "directory": directory, "algorithm": algorithm, "max_files": max_files,
            "max_bytes": max_bytes, "max_seconds": budget_s})
    except Exception:
        pass

    results, errors, skipped = [], [], []
    bytes_hashed = 0
    truncation_reason = ""
    last_done = ""                  # last path fully handled → resume point
    cache_hits = 0
    cache_dirty = False
    cache = _load_hash_cache() if algorithm in _CACHED_ALGOS else None

    for fpath in _iter_files(directory, recursive, start_after):
        # Caps are checked BEFORE a file is touched; `next_start_path` is the
        # last path completed, so `start_after=next_start_path` resumes
        # exactly where this run stopped (nothing skipped, nothing repeated).
        if len(results) + len(errors) + len(skipped) >= max_files:
            truncation_reason = "max_files"
            break
        if time.monotonic() > deadline:
            truncation_reason = "max_seconds"
            break
        if bytes_hashed >= max_bytes:
            truncation_reason = "max_bytes"
            break
        last_done = fpath
        try:
            st = os.stat(fpath)
        except OSError as e:
            errors.append({"file": fpath, "error": str(e)})
            continue
        if skip_bytes and st.st_size > skip_bytes:
            skipped.append({"file": fpath, "size_bytes": st.st_size, "reason": "larger_than_cap"})
            continue
        key = _cache_key(st, fpath)
        if cache is not None:
            hit = cache.get(key)
            if hit and hit.get(algorithm):
                results.append({"file": fpath, algorithm: hit[algorithm], "cache_hit": True})
                cache_hits += 1
                continue
        try:
            if cache is not None:
                md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
                with open(fpath, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
                        bytes_hashed += len(chunk)
                digests = {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
                           "sha256": sha256.hexdigest()}
                cache[key] = {"success": True, "size_bytes": st.st_size, **digests}
                cache_dirty = True
                results.append({"file": fpath, algorithm: digests[algorithm]})
            else:
                h = algo_map[algorithm]()
                with open(fpath, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                        bytes_hashed += len(chunk)
                results.append({"file": fpath, algorithm: h.hexdigest()})
        except Exception as e:
            errors.append({"file": fpath, "error": str(e)})

    if cache is not None and cache_dirty:
        with _HASH_CACHE_LOCK:
            _save_hash_cache(cache)

    if output_manifest:
        import csv
        mode = "a" if (start_after and os.path.exists(output_manifest)) else "w"
        with open(output_manifest, mode, newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["file", algorithm], extrasaction="ignore")
            if mode == "w":
                writer.writeheader()
            writer.writerows(results)

    out = {
        "success": True,
        "directory": directory,
        "algorithm": algorithm,
        "file_count": len(results),
        "hashes": results,
        "errors": errors,
        "skipped": skipped,
        "bytes_hashed": bytes_hashed,
        "cache_hits": cache_hits,
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "manifest": output_manifest,
        "truncated": bool(truncation_reason),
    }
    if truncation_reason:
        out["truncation_reason"] = truncation_reason
        out["next_start_path"] = last_done
        out["note"] = (f"Stopped at {truncation_reason} — partial manifest. Re-call with "
                       f"start_after={last_done!r} to continue, or narrow the directory.")
    return out


@mcp.tool()
@output_safe
def ssdeep_hash(file_path: str) -> dict:
    """Compute ssdeep fuzzy hash for similarity comparison."""
    return run(["ssdeep", file_path], line_cap=None)


@mcp.tool()
@output_safe
def ssdeep_compare(file1: str, file2: str) -> dict:
    """Compare two files using ssdeep fuzzy hashing — returns similarity score 0-100."""
    return run(["ssdeep", "-d", file1, file2], line_cap=None)


@mcp.tool()
@output_safe
def ssdeep_scan_directory(directory: str, threshold: int = 50) -> dict:
    """
    Find similar files in a directory using ssdeep.
    threshold: minimum similarity score (0-100) to report.
    """
    return run(["ssdeep", "-r", "-t", str(threshold), directory], timeout=DEFAULT_TIMEOUT, line_cap=None)


@mcp.tool()
@output_safe
def verify_evidence_hash(evidence_path: str, expected_md5: Optional[str] = None, expected_sha1: Optional[str] = None) -> dict:
    """
    Compute hashes of an evidence file and optionally compare to known values.
    Use to verify chain of custody integrity before analysis.

    On success, also records a `reason_call` entry tagged
    "hash_verify_evidence_hash" in the execution trace so downstream tools can
    look up whether a given evidence path has been verified in this session.
    """
    result = hash_file(evidence_path)
    if not result["success"]:
        return result

    result["md5_match"] = None
    result["sha1_match"] = None

    if expected_md5:
        result["md5_match"] = result["md5"].lower() == expected_md5.lower()
    if expected_sha1:
        result["sha1_match"] = result["sha1"].lower() == expected_sha1.lower()

    if expected_md5 or expected_sha1:
        result["integrity_verified"] = (
            (result["md5_match"] is None or result["md5_match"]) and
            (result["sha1_match"] is None or result["sha1_match"])
        )

    # Record hash-verification state in the execution log so downstream tools
    # (and the trace report) can confirm chain of custody.
    try:
        from core.execution_log import log
        sha256 = result.get("sha256", "")
        log.record_reason_call(
            tool="hash_verify_evidence_hash",
            success=True,
            conclusion=f"VERIFIED: {evidence_path} sha256={sha256}",
            directives={},
        )
    except Exception as _e:
        import sys
        print(f"[TRUDI WARN] verify_evidence_hash log failed: {_e}", file=sys.stderr)

    return result


@mcp.tool()
@output_safe
def hashdeep_compute(
    target: str,
    recursive: bool = True,
    algorithm: str = "md5,sha256",
    output_path: Optional[str] = None,
) -> dict:
    """
    Compute multiple hashes for files using hashdeep (supports md5, sha1, sha256, tiger, whirlpool).
    target: file or directory path.
    algorithm: comma-separated algorithms e.g. 'md5,sha1,sha256'.
    Produces a hash manifest that can be used with hashdeep_audit.
    """
    from core.paths import assert_output_safe
    if output_path:
        assert_output_safe(output_path)
    cmd = ["hashdeep", f"-c{algorithm}"]
    if recursive and os.path.isdir(target):
        cmd.append("-r")
    cmd.append(target)
    result = run(cmd, timeout=VOL_TIMEOUT, line_cap=None)
    if output_path and result["success"]:
        with open(output_path, "w") as f:
            f.write(result["stdout"])
        result["manifest_path"] = output_path
    return result


@mcp.tool()
@output_safe
def hashdeep_audit(
    manifest_file: str,
    target_directory: str,
    mode: str = "audit",
) -> dict:
    """
    Audit a directory against a hashdeep manifest to detect modified, missing, or unknown files.
    manifest_file: path to a hashdeep manifest file (from hashdeep_compute).
    mode: 'audit' (report all discrepancies), 'match' (only matching), 'negative' (only mismatches).
    """
    flag_map = {"audit": "-a", "match": "-m", "negative": "-X"}
    flag = flag_map.get(mode, "-a")
    cmd = ["hashdeep", flag, "-k", manifest_file, "-r", target_directory]
    return run(cmd, timeout=VOL_TIMEOUT, line_cap=None)


@mcp.tool()
@output_safe
def md5deep_scan(directory: str, recursive: bool = True, output_path: Optional[str] = None) -> dict:
    """
    Compute MD5 hashes for all files in a directory using md5deep.
    Faster than hashdeep for MD5-only workflows.
    """
    from core.paths import assert_output_safe
    if output_path:
        assert_output_safe(output_path)
    cmd = ["md5deep"]
    if recursive:
        cmd.append("-r")
    cmd.append(directory)
    result = run(cmd, timeout=VOL_TIMEOUT, line_cap=None)
    if output_path and result["success"]:
        with open(output_path, "w") as f:
            f.write(result["stdout"])
    return result
