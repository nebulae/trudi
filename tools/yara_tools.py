"""YARA scanning via yara-python (no binary required)."""
import os
import glob
from typing import Optional
from fastmcp import FastMCP
from core.paths import assert_output_safe

mcp = FastMCP("yara")


def _compile_rules(rules_path: str):
    import yara
    if os.path.isdir(rules_path):
        rule_files = {
            os.path.basename(f): f
            for f in glob.glob(os.path.join(rules_path, "**/*.yar"), recursive=True)
            + glob.glob(os.path.join(rules_path, "**/*.yara"), recursive=True)
        }
        if not rule_files:
            raise ValueError(f"No .yar/.yara files found in {rules_path}")
        return yara.compile(filepaths=rule_files)
    else:
        return yara.compile(filepath=rules_path)


def _match_to_dict(match) -> dict:
    return {
        "rule": match.rule,
        "namespace": match.namespace,
        "tags": list(match.tags),
        "meta": dict(match.meta),
        "strings": [
            {"offset": s.instances[0].offset if s.instances else 0, "identifier": s.identifier}
            for s in match.strings
        ],
    }


@mcp.tool()
def yara_scan_file(file_path: str, rules_path: str, timeout: int = 60) -> dict:
    """
    Scan a single file with YARA rules.
    rules_path: path to a .yar file or a directory of .yar/.yara files.
    Returns all matching rules with offsets and string identifiers.
    """
    try:
        import yara
        rules = _compile_rules(rules_path)
        matches = rules.match(file_path, timeout=timeout)
        return {
            "success": True,
            "file": file_path,
            "match_count": len(matches),
            "matches": [_match_to_dict(m) for m in matches],
        }
    except Exception as e:
        return {"success": False, "error": str(e), "file": file_path, "matches": []}


@mcp.tool()
def yara_scan_directory(
    directory: str,
    rules_path: str,
    recursive: bool = True,
    timeout_per_file: int = 30,
    max_files: int = 10000,
) -> dict:
    """
    Scan all files in a directory with YARA rules.
    Returns files with matches only (non-matching files omitted).
    """
    try:
        import yara
        rules = _compile_rules(rules_path)
        results = []
        errors = []
        scanned = 0

        pattern = "**/*" if recursive else "*"
        files = glob.glob(os.path.join(directory, pattern), recursive=recursive)

        for fpath in files[:max_files]:
            if not os.path.isfile(fpath):
                continue
            try:
                matches = rules.match(fpath, timeout=timeout_per_file)
                scanned += 1
                if matches:
                    results.append({
                        "file": fpath,
                        "matches": [_match_to_dict(m) for m in matches],
                    })
            except yara.TimeoutError:
                errors.append({"file": fpath, "error": "timeout"})
            except Exception as e:
                errors.append({"file": fpath, "error": str(e)})

        return {
            "success": True,
            "directory": directory,
            "scanned": scanned,
            "hits": len(results),
            "results": results,
            "errors": errors[:50],
        }
    except Exception as e:
        return {"success": False, "error": str(e), "directory": directory}


@mcp.tool()
def yara_scan_process_memory(
    dump_file: str,
    rules_path: str,
    timeout: int = 120,
) -> dict:
    """
    Scan a process memory dump file with YARA rules.
    dump_file: path to a .dmp or .raw memory file (e.g. from vol_memmap with dump=True).
    """
    return yara_scan_file(dump_file, rules_path, timeout=timeout)


@mcp.tool()
def yara_compile_check(rules_path: str) -> dict:
    """
    Compile and validate a YARA rule file without scanning anything.
    Returns success/error — use before a scan to catch syntax errors early.
    """
    try:
        rules = _compile_rules(rules_path)
        return {"success": True, "rules_path": rules_path, "message": "Rules compiled successfully."}
    except Exception as e:
        return {"success": False, "error": str(e), "rules_path": rules_path}


@mcp.tool()
def yara_scan_memory_image(
    image_path: str,
    rules_path: str,
    timeout: int = 300,
) -> dict:
    """
    Scan a full memory image (e.g. base-wkstn-01-memory.img) with YARA rules.
    Suitable for raw memory captures — not just per-process dumps.
    rules_path: path to a .yar file or directory of .yar/.yara files.
    Use /home/trin/trudi/rules/ for the built-in TTP rule library.
    timeout: per-scan timeout in seconds (default 300 — full images are large).
    """
    try:
        import yara
        rules = _compile_rules(rules_path)
        matches = rules.match(image_path, timeout=timeout)
        return {
            "success": True,
            "image": image_path,
            "rules": rules_path,
            "match_count": len(matches),
            "matches": [_match_to_dict(m) for m in matches],
        }
    except Exception as e:
        return {"success": False, "error": str(e), "image": image_path, "matches": []}


@mcp.tool()
def yara_scan_strings(inline_rule: str, file_path: str) -> dict:
    """
    Scan a file using an inline YARA rule string.
    inline_rule: complete YARA rule text (e.g. 'rule test { strings: $a = "evil" condition: $a }').
    """
    try:
        import yara
        rules = yara.compile(source=inline_rule)
        matches = rules.match(file_path)
        return {
            "success": True,
            "file": file_path,
            "match_count": len(matches),
            "matches": [_match_to_dict(m) for m in matches],
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
