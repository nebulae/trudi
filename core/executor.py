"""Safe subprocess executor for SIFT forensic tools."""
import subprocess
import shlex
from typing import Any
from .paths import OUTPUT_CAP, MAX_TOOL_OUTPUT_LINES, assert_output_safe

_MAX_RETRIES = 3

_TRUNCATION_FOOTER = (
    "\n[TRUNCATED — {n} lines omitted. Use a targeted follow-up query "
    "with focus_paths or focus_pids to retrieve specific records.]\n"
)


def _apply_line_cap(text: str, max_lines: int) -> tuple[str, bool]:
    """Trim text to max_lines, appending a footer if trimmed."""
    lines = text.splitlines(keepends=True)
    if len(lines) <= max_lines:
        return text, False
    omitted = len(lines) - max_lines
    return "".join(lines[:max_lines]) + _TRUNCATION_FOOTER.format(n=omitted), True


def run(
    cmd: list[str] | str,
    *,
    timeout: int = 300,
    output_dir: str | None = None,
    needs_sudo: bool = False,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    line_cap: int | None = MAX_TOOL_OUTPUT_LINES,
) -> dict[str, Any]:
    """
    Execute a forensic tool command safely.

    Returns dict with keys: success, stdout, stderr, exit_code, truncated, cmd, retries.
    Never raises — all errors are captured in the return value.
    Retries up to 3 times on TimeoutExpired before giving up.

    line_cap: max lines to return (None = no line cap; use for hash/integrity tools).
    """
    if output_dir:
        assert_output_safe(output_dir)

    if isinstance(cmd, str):
        cmd = shlex.split(cmd)

    if needs_sudo and cmd[0] != "sudo":
        cmd = ["sudo"] + cmd

    result: dict[str, Any] = {
        "success": False,
        "stdout": "",
        "stderr": "",
        "exit_code": -1,
        "truncated": False,
        "cmd": " ".join(cmd),
        "retries": 0,
    }

    retries = 0
    while True:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                env=env,
                cwd=cwd,
            )
            result["exit_code"] = proc.returncode
            result["success"] = proc.returncode == 0

            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")

            if len(stdout) > OUTPUT_CAP:
                stdout = stdout[:OUTPUT_CAP]
                result["truncated"] = True

            if line_cap is not None:
                stdout, line_truncated = _apply_line_cap(stdout, line_cap)
                if line_truncated:
                    result["truncated"] = True

            result["stdout"] = stdout
            result["stderr"] = stderr[:4096]
            break

        except subprocess.TimeoutExpired:
            if retries < _MAX_RETRIES:
                retries += 1
                result["retries"] = retries
                continue
            result["stderr"] = (
                f"Command timed out after {timeout}s "
                f"(retried {retries} times): {' '.join(cmd)}"
            )
            break
        except FileNotFoundError as e:
            result["stderr"] = f"Tool not found: {e}"
            break
        except Exception as e:
            result["stderr"] = f"Executor error: {e}"
            break

    try:
        from core.execution_log import log
        log.record_tool_call(
            cmd=result["cmd"],
            success=result["success"],
            truncated=result["truncated"],
            retries=result["retries"],
            exit_code=result["exit_code"],
            stderr=result["stderr"],
        )
    except Exception:
        pass

    return result


def run_dotnet(
    dll_path: str,
    args: list[str],
    *,
    timeout: int = 300,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Run an EZ Tools .NET binary via dotnet runtime."""
    cmd = ["dotnet", dll_path] + args
    return run(cmd, timeout=timeout, output_dir=output_dir)
