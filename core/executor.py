"""Safe subprocess executor for SIFT forensic tools."""
import re
import subprocess
import shlex
import time
import asyncio
from typing import Any
from .paths import OUTPUT_CAP, MAX_TOOL_OUTPUT_LINES, assert_output_safe

_TRUNCATION_FOOTER = (
    "\n[TRUNCATED — {n} lines omitted. Use a targeted follow-up query "
    "with focus_paths or focus_pids to retrieve specific records.]\n"
)

# Matches Volatility 3 progress lines: "\rProgress:  33.01\t\tdescription\r"
_PROGRESS_RE = re.compile(r"^Progress:\s+[\d.]+\t", re.MULTILINE)


def _apply_line_cap(text: str, max_lines: int) -> tuple[str, bool]:
    """Trim text to max_lines, appending a footer if trimmed."""
    lines = text.splitlines(keepends=True)
    if len(lines) <= max_lines:
        return text, False
    omitted = len(lines) - max_lines
    return "".join(lines[:max_lines]) + _TRUNCATION_FOOTER.format(n=omitted), True


def _parse_stderr(raw: str) -> tuple[str, list[str]]:
    """Split raw stderr into (error_text, progress_lines).

    Progress lines (\rProgress: XX.XX\t...) are extracted into a list for
    the trace log and stripped from the stored stderr so error messages
    are not crowded out by the 4096-char cap.
    """
    progress: list[str] = []
    errors: list[str] = []
    for line in re.split(r"[\r\n]+", raw):
        line = line.strip()
        if not line:
            continue
        if re.match(r"Progress:\s+[\d.]+\t", line):
            progress.append(line)
        else:
            errors.append(line)
    return "\n".join(errors)[:4096], progress[-20:]


def _log_tool(result: dict) -> None:
    try:
        from core.execution_log import log
        log.record_tool_call(
            cmd=result["cmd"],
            success=result["success"],
            truncated=result["truncated"],
            retries=result["retries"],
            exit_code=result["exit_code"],
            stderr=result["stderr"],
            elapsed_seconds=result.get("elapsed_seconds", 0.0),
        )
    except Exception:
        pass


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

    Returns dict with keys: success, stdout, stderr, exit_code, truncated,
    cmd, retries, elapsed_seconds, progress_lines.
    Never raises — all errors are captured in the return value.
    Does NOT retry on TimeoutExpired — a timeout means the tool needs more
    time or missing symbols; retrying just wastes time.
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
        "elapsed_seconds": 0.0,
        "truncated": False,
        "cmd": " ".join(cmd),
        "retries": 0,
        "progress_lines": [],
    }

    start = time.perf_counter()

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
        stderr_raw = proc.stderr.decode("utf-8", errors="replace")

        if len(stdout) > OUTPUT_CAP:
            stdout = stdout[:OUTPUT_CAP]
            result["truncated"] = True

        if line_cap is not None:
            stdout, line_truncated = _apply_line_cap(stdout, line_cap)
            if line_truncated:
                result["truncated"] = True

        result["stdout"] = stdout
        result["stderr"], result["progress_lines"] = _parse_stderr(stderr_raw)

    except subprocess.TimeoutExpired:
        result["stderr"] = f"Command timed out after {timeout}s: {' '.join(cmd)}"

    except FileNotFoundError as e:
        result["stderr"] = f"Tool not found: {e}"

    except Exception as e:
        result["stderr"] = f"Executor error: {e}"

    result["elapsed_seconds"] = round(time.perf_counter() - start, 1)
    _log_tool(result)
    return result


async def run_with_progress(
    cmd: list[str],
    ctx: Any,  # fastmcp.Context — typed as Any to avoid importing fastmcp in core
    *,
    timeout: int = 600,
    output_dir: str | None = None,
    line_cap: int | None = MAX_TOOL_OUTPUT_LINES,
) -> dict[str, Any]:
    """
    Async variant of run() that streams stderr progress lines to ctx.report_progress().
    Use this for long-running tools (vol_psscan, vol_filescan, etc.) where real-time
    feedback matters. ctx must be a fastmcp.Context injected by FastMCP.
    """
    if output_dir:
        assert_output_safe(output_dir)

    result: dict[str, Any] = {
        "success": False,
        "stdout": "",
        "stderr": "",
        "exit_code": -1,
        "elapsed_seconds": 0.0,
        "truncated": False,
        "cmd": " ".join(cmd),
        "retries": 0,
        "progress_lines": [],
    }

    start = time.perf_counter()
    stderr_buf: list[str] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def _drain_stderr() -> None:
            async for raw in proc.stderr:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                stderr_buf.append(line)
                if ctx is not None:
                    elapsed = time.perf_counter() - start
                    try:
                        await ctx.report_progress(elapsed, float(timeout), line[:120])
                    except Exception:
                        pass

        async def _drain_stdout() -> bytes:
            return await proc.stdout.read()

        try:
            stdout_bytes, _ = await asyncio.wait_for(
                asyncio.gather(_drain_stdout(), _drain_stderr()),
                timeout=float(timeout),
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.communicate()
            result["stderr"] = f"Command timed out after {timeout}s: {' '.join(cmd)}"
            result["elapsed_seconds"] = round(time.perf_counter() - start, 1)
            _, result["progress_lines"] = _parse_stderr("\n".join(stderr_buf))
            _log_tool(result)
            return result

        await proc.wait()

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        if len(stdout) > OUTPUT_CAP:
            stdout = stdout[:OUTPUT_CAP]
            result["truncated"] = True
        if line_cap is not None:
            stdout, line_truncated = _apply_line_cap(stdout, line_cap)
            if line_truncated:
                result["truncated"] = True

        result["stdout"] = stdout
        result["exit_code"] = proc.returncode
        result["success"] = proc.returncode == 0
        result["stderr"], result["progress_lines"] = _parse_stderr("\n".join(stderr_buf))

    except Exception as e:
        result["stderr"] = f"Executor error: {e}"

    result["elapsed_seconds"] = round(time.perf_counter() - start, 1)
    _log_tool(result)
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
