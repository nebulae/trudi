"""Read-only SSH runner for live endpoint analysis.

Used by `tools/live.py` to execute fixed-argv read-only commands on a remote
host. Mirrors `core.executor.run()`'s result schema so the trace pipeline
(_log_tool) treats the response identically to a local subprocess call.

Hard safety constraints:
  * `cmd_argv` MUST be `list[str]`. Strings are rejected — no shell parsing.
  * Each argv element is passed via SSH using its built-in `--` separator, so
    the remote shell cannot expand `$VAR`, `;`, `|`, etc., embedded in
    operands. Only the SSH-side command name is interpreted.
  * Identity files only — no password auth. Hosts are pre-registered in
    `~/cases/.common/live_hosts.json` with their key path + user.
  * No remote-side write tools exposed. The endpoint MCP wrapper layer
    (`tools/live.py`) only ever calls read-only utilities (ps, ss, lsof,
    journalctl, head, etc.).

Config schema (`~/cases/.common/live_hosts.json`):
    {
      "ubuntu-endpoint": {
        "user": "trudi",
        "host": "192.168.1.50",
        "identity": "~/.ssh/trudi_live",
        "port": 22
      }
    }

The host argument to ssh_run() is a config key, not a raw hostname — this
keeps connection details server-side and prevents the agent from being
prompted into SSHing to arbitrary hosts.
"""
from __future__ import annotations
import json
import os
import shlex
import subprocess
import time
from typing import Any, Optional

from .paths import DEFAULT_TIMEOUT, OUTPUT_CAP, MAX_TOOL_OUTPUT_LINES

# Config lives under the shared case-data prefix so it doesn't get
# overwritten by per-case operations.
DEFAULT_HOSTS_CONFIG = os.path.expanduser("~/cases/.common/live_hosts.json")
LIVE_HOSTS_CONFIG = os.environ.get("TRUDI_LIVE_HOSTS_CONFIG", DEFAULT_HOSTS_CONFIG)

# Pinned SSH options for every connection. accept-new lets the first-touch
# host fingerprint be cached without prompting; subsequent connections fail
# if the fingerprint changes.
_SSH_OPTS = [
    "-o", "BatchMode=yes",                       # never prompt for password
    "-o", "StrictHostKeyChecking=accept-new",    # accept-then-pin
    "-o", "ConnectTimeout=10",
    "-o", "ServerAliveInterval=15",
]


class SSHConfigError(ValueError):
    """Raised when the host is missing or misconfigured in live_hosts.json."""


def _load_hosts(path: Optional[str] = None) -> dict:
    # Resolve LIVE_HOSTS_CONFIG at call time (not def time) so monkeypatch in
    # tests + runtime env changes both take effect.
    if path is None:
        path = LIVE_HOSTS_CONFIG
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f) or {}
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _resolve_host(host: str) -> dict:
    hosts = _load_hosts()
    cfg = hosts.get(host)
    if not cfg:
        raise SSHConfigError(
            f"host {host!r} not found in {LIVE_HOSTS_CONFIG}. "
            f"Available: {sorted(hosts.keys()) or '(none configured)'}"
        )
    if not cfg.get("user") or not cfg.get("host"):
        raise SSHConfigError(
            f"host {host!r} config is missing required keys (user, host)"
        )
    identity = cfg.get("identity") or os.environ.get("TRUDI_LIVE_SSH_KEY")
    if not identity:
        raise SSHConfigError(
            f"host {host!r}: no identity file in config and TRUDI_LIVE_SSH_KEY env unset"
        )
    return {
        "user": cfg["user"],
        "host": cfg["host"],
        "port": int(cfg.get("port") or 22),
        "identity": os.path.expanduser(identity),
    }


def _build_ssh_argv(resolved: dict, cmd_argv: list[str]) -> list[str]:
    """Construct the full local argv: ssh + opts + user@host + -- + remote argv.

    The `--` separator tells SSH that everything after is the remote command
    as discrete argv tokens, not a single shell string. SSH still concatenates
    them, but each token is properly shell-quoted by ssh's own quoting layer,
    so an operand like `'; rm -rf /'` is passed as a literal filename, not
    parsed as a separator.
    """
    argv = ["ssh"] + _SSH_OPTS + [
        "-i", resolved["identity"],
        "-p", str(resolved["port"]),
        f"{resolved['user']}@{resolved['host']}",
        "--",
    ]
    # Quote each operand so the remote shell sees one token per item even
    # though SSH joins them into a single command-line string.
    quoted_remote = [shlex.quote(a) for a in cmd_argv]
    argv.extend(quoted_remote)
    return argv


def _log_ssh_tool(result: dict) -> None:
    """Mirror core.executor._log_tool — writes a tool_call trace entry."""
    try:
        from core.execution_log import log
        cid = log.record_tool_call(
            cmd=result["cmd"],
            success=result["success"],
            truncated=result["truncated"],
            retries=result["retries"],
            exit_code=result["exit_code"],
            stderr=result["stderr"],
            elapsed_seconds=result.get("elapsed_seconds", 0.0),
            stdout_excerpt=result.get("stdout", ""),
            timed_out=result.get("timed_out", False),
        )
        result["_trudi_call_id"] = cid
    except Exception as e:  # noqa: BLE001
        import sys
        print(f"[TRUDI WARN] _log_ssh_tool failed: {e}", file=sys.stderr)
        result.setdefault("_trudi_call_id", 0)


def ssh_run(
    host: str,
    cmd_argv: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    line_cap: int | None = MAX_TOOL_OUTPUT_LINES,
) -> dict[str, Any]:
    """Execute `cmd_argv` on the remote endpoint identified by `host`.

    host: config key in live_hosts.json (NOT a raw hostname).
    cmd_argv: list of argv tokens — first is the remote binary, rest are
              operands. Must be a list; strings are rejected.

    Returns the standard executor result dict with `source: "ssh_runner"` and
    `host` added.

    Never raises — all errors are captured in the return value.
    """
    result: dict[str, Any] = {
        "success": False,
        "stdout": "",
        "stderr": "",
        "exit_code": -1,
        "elapsed_seconds": 0.0,
        "truncated": False,
        "cmd": "",
        "retries": 0,
        "progress_lines": [],
        "host": host,
        "source": "ssh_runner",
    }

    if not isinstance(cmd_argv, list):
        result["stderr"] = (
            f"ssh_run cmd_argv must be list[str], got {type(cmd_argv).__name__}. "
            f"Strings would invite shell-injection on the remote side."
        )
        _log_ssh_tool(result)
        return result
    if not cmd_argv:
        result["stderr"] = "ssh_run cmd_argv is empty"
        _log_ssh_tool(result)
        return result

    try:
        resolved = _resolve_host(host)
    except SSHConfigError as e:
        result["stderr"] = str(e)
        result["cmd"] = f"ssh {host} -- {' '.join(cmd_argv)}"
        _log_ssh_tool(result)
        return result

    argv = _build_ssh_argv(resolved, cmd_argv)
    # The recorded cmd should not leak the identity path — clean it.
    result["cmd"] = (
        f"ssh {resolved['user']}@{resolved['host']}:{resolved['port']} -- "
        + " ".join(shlex.quote(a) for a in cmd_argv)
    )

    start = time.perf_counter()
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout)
        result["exit_code"] = proc.returncode
        result["success"] = proc.returncode == 0
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        if len(stdout) > OUTPUT_CAP:
            stdout = stdout[:OUTPUT_CAP]
            result["truncated"] = True
        if line_cap is not None:
            lines = stdout.splitlines(keepends=True)
            if len(lines) > line_cap:
                omitted = len(lines) - line_cap
                stdout = ("".join(lines[:line_cap])
                          + f"\n[TRUNCATED — {omitted} lines omitted]\n")
                result["truncated"] = True
        result["stdout"] = stdout
        result["stderr"] = stderr[:4096]
    except subprocess.TimeoutExpired:
        result["stderr"] = f"ssh timed out after {timeout}s on host {host!r}"
        result["timed_out"] = True
    except FileNotFoundError as e:
        result["stderr"] = f"ssh binary not found: {e}"
    except Exception as e:  # noqa: BLE001
        result["stderr"] = f"ssh_run error: {e}"

    result["elapsed_seconds"] = round(time.perf_counter() - start, 1)
    _log_ssh_tool(result)
    return result


def list_configured_hosts() -> list[str]:
    """Return the names of all hosts in live_hosts.json. Useful for tools
    that want to enumerate available endpoints without exposing their
    connection details."""
    return sorted(_load_hosts().keys())
