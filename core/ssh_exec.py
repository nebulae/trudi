"""Write-capable SSH execution for the gated respond.* containment path.

This is the ONLY place in TRUDI that runs state-changing commands on a live
endpoint. It is deliberately a separate module from `core/ssh.py` so the
read-only contract of `ssh_run` stays auditable and untouched.

Three structural guardrails make this safe to ship under "autonomous response":

1. **Live-monitoring scope, re-checked in the runner.** `ssh_run_write` calls
   `response.gates.check_live_monitoring_scope(case_id)` itself and refuses
   off-scope — so writable SSH is incapable of running outside a live-monitoring
   case even if a future caller forgets the gate.
2. **No tool surface.** This module exposes no `@mcp.tool()`. The agent has no
   MCP handle to it; the only callers are `respond.execute_action` /
   `respond.revert_action`, both independently gated.
3. **Structured, validated argv — never `sh -c <interpolated string>`.** Each
   action is built from a fixed argv table keyed by the recipe's
   `action_template`, mirroring the canonical `execve(argv=[...])` form of the
   `Custom.TRUDI.Respond.*` artifacts. Every evidence value is type-validated by
   an anchored regex (which rejects shell metacharacters by construction) BEFORE
   it is placed into the argv. The agent supplies only evidence values, never the
   command.
"""
from __future__ import annotations
import os
import re
import shlex
import subprocess
import time
from typing import Any, Callable

from core.paths import DEFAULT_TIMEOUT, OUTPUT_CAP, MAX_TOOL_OUTPUT_LINES
from core.ssh import (
    _SSH_OPTS,
    _build_ssh_argv,
    _log_ssh_tool,
    _resolve_host,
    SSHConfigError,
)


class ParamValidationError(ValueError):
    """Raised when an evidence value fails its type validator. The caller turns
    this into a refusal and NEVER executes."""


# ── Validators ────────────────────────────────────────────────────────────────
# Each returns the normalized string form, or raises ParamValidationError.
# Anchored patterns reject whitespace and shell metacharacters by construction.

_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_UNIT_RE = re.compile(r"^[A-Za-z0-9_@:.\-]+\.(service|timer|socket)$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Path: allowed chars only, no whitespace/metachars, no parent-dir traversal.
_PATH_CHARS_RE = re.compile(r"^[A-Za-z0-9_./@+\-]+$")
_QUARANTINE_PREFIXES = ("/tmp/", "/var/tmp/", "/home/", "/opt/", "/srv/", "/usr/local/")


def _v_pid(raw: Any) -> str:
    try:
        pid = int(str(raw).strip())
    except (TypeError, ValueError):
        raise ParamValidationError(f"pid {raw!r} is not an integer")
    if not (1 < pid < 4194304):
        raise ParamValidationError(f"pid {pid} out of range (1 < pid < 4194304)")
    return str(pid)


def _v_ipv4(raw: Any) -> str:
    s = str(raw).strip()
    m = _IPV4_RE.match(s)
    if not m or any(int(o) > 255 for o in m.groups()):
        raise ParamValidationError(f"{raw!r} is not a valid IPv4 address")
    return s


def _v_port(raw: Any) -> str:
    try:
        port = int(str(raw).strip())
    except (TypeError, ValueError):
        raise ParamValidationError(f"port {raw!r} is not an integer")
    if not (1 <= port <= 65535):
        raise ParamValidationError(f"port {port} out of range (1..65535)")
    return str(port)


def _v_unit(raw: Any) -> str:
    s = str(raw).strip()
    if not _UNIT_RE.match(s):
        raise ParamValidationError(f"{raw!r} is not a valid systemd unit name")
    return s


def _v_sha256(raw: Any) -> str:
    s = str(raw).strip().lower()
    if not _SHA256_RE.match(s):
        raise ParamValidationError(f"{raw!r} is not a sha256 hex digest")
    return s


def _v_safe_path(raw: Any) -> str:
    s = str(raw).strip()
    if not s.startswith("/") or not _PATH_CHARS_RE.match(s) or ".." in s:
        raise ParamValidationError(f"{raw!r} is not a safe absolute path")
    return s


def _v_path_quarantine(raw: Any) -> str:
    s = _v_safe_path(raw)
    if not s.startswith(_QUARANTINE_PREFIXES):
        raise ParamValidationError(
            f"{s!r} is not under an allowed prefix {_QUARANTINE_PREFIXES}"
        )
    return s


def _v_path_cron(raw: Any) -> str:
    s = _v_safe_path(raw)
    if not re.match(r"^/etc/cron(\.|/)", s):
        raise ParamValidationError(f"{s!r} is not an /etc/cron* path")
    return s


# ── Action argv builders ──────────────────────────────────────────────────────
# action_template -> {"params": {evidence_key: validator}, "argv": fn(validated) -> list[str]}
# The three shell-needing actions emit ["/bin/sh","-c", <cmd>] where <cmd> is
# assembled ONLY from regex-validated tokens (also shlex.quote'd, belt-and-braces).

def _quarantine_argv(p: dict) -> list[str]:
    path = p["image_path"]
    base = os.path.basename(path)
    cmd = (
        f"mkdir -p /var/quarantine && chmod 000 {shlex.quote(path)} && "
        f"mv {shlex.quote(path)} /var/quarantine/{shlex.quote(base)}"
    )
    return ["/bin/sh", "-c", cmd]


def _restore_image_argv(p: dict) -> list[str]:
    path = p["image_path"]
    base = os.path.basename(path)
    cmd = (
        f"mv /var/quarantine/{shlex.quote(base)} {shlex.quote(path)} && "
        f"chmod 755 {shlex.quote(path)}"
    )
    return ["/bin/sh", "-c", cmd]


def _remove_cron_argv(p: dict) -> list[str]:
    path = p["path"]
    base = os.path.basename(path)
    cmd = (
        f"mkdir -p /var/quarantine && "
        f"cp {shlex.quote(path)} /var/quarantine/cron_backup_{shlex.quote(base)} && "
        f"rm -f {shlex.quote(path)}"
    )
    return ["/bin/sh", "-c", cmd]


def _restore_cron_argv(p: dict) -> list[str]:
    path = p["path"]
    base = os.path.basename(path)
    cmd = f"cp /var/quarantine/cron_backup_{shlex.quote(base)} {shlex.quote(path)}"
    return ["/bin/sh", "-c", cmd]


ACTION_BUILDERS: dict[str, dict[str, Any]] = {
    # Forward actions
    "pause_pid": {"params": {"pid": _v_pid},
                  "argv": lambda p: ["/bin/kill", "-STOP", p["pid"]]},
    "kill_pid": {"params": {"pid": _v_pid},
                 "argv": lambda p: ["/bin/kill", "-9", p["pid"]]},
    "kill_owning_pid": {"params": {"pid": _v_pid},
                        "argv": lambda p: ["/bin/kill", "-9", p["pid"]]},
    "block_egress_to_endpoint": {
        "params": {"remote_ip": _v_ipv4, "remote_port": _v_port},
        "argv": lambda p: ["/sbin/iptables", "-I", "OUTPUT", "-d", p["remote_ip"],
                           "-p", "tcp", "--dport", p["remote_port"],
                           "-m", "comment", "--comment", "TRUDI_RESPOND", "-j", "REJECT"]},
    "disable_systemd_unit": {"params": {"path": _v_unit},
                             "argv": lambda p: ["/bin/systemctl", "disable", "--now", p["path"]]},
    "dump_process_memory": {"params": {"pid": _v_pid},
                            "argv": lambda p: ["/usr/bin/gcore", "-o",
                                               f"/var/quarantine/trudi-dump-{p['pid']}", p["pid"]]},
    "quarantine_image": {"params": {"image_path": _v_path_quarantine},
                         "argv": _quarantine_argv},
    "remove_cron_entry": {"params": {"path": _v_path_cron},
                          "argv": _remove_cron_argv},
    # Revert actions (inverse of the above)
    "resume_pid": {"params": {"pid": _v_pid},
                   "argv": lambda p: ["/bin/kill", "-CONT", p["pid"]]},
    "unblock_egress": {
        "params": {"remote_ip": _v_ipv4, "remote_port": _v_port},
        "argv": lambda p: ["/sbin/iptables", "-D", "OUTPUT", "-d", p["remote_ip"],
                           "-p", "tcp", "--dport", p["remote_port"],
                           "-m", "comment", "--comment", "TRUDI_RESPOND", "-j", "REJECT"]},
    "enable_systemd_unit": {"params": {"path": _v_unit},
                            "argv": lambda p: ["/bin/systemctl", "enable", "--now", p["path"]]},
    "restore_quarantined_image": {"params": {"image_path": _v_path_quarantine},
                                  "argv": _restore_image_argv},
    "restore_cron_entry": {"params": {"path": _v_path_cron},
                           "argv": _restore_cron_argv},
}

# Forward action_template -> its revert template (None = irreversible / no-op).
FORWARD_TO_REVERT_TEMPLATE: dict[str, str | None] = {
    "pause_pid": "resume_pid",
    "block_egress_to_endpoint": "unblock_egress",
    "disable_systemd_unit": "enable_systemd_unit",
    "quarantine_image": "restore_quarantined_image",
    "remove_cron_entry": "restore_cron_entry",
    "dump_process_memory": None,   # forensic capture; nothing to undo
    "kill_pid": None,              # irreversible
    "kill_owning_pid": None,       # irreversible
}


def build_argv(action_template: str, raw_params: dict) -> list[str]:
    """Validate every required evidence value, then build the structured remote
    argv. `raw_params` may carry extra keys (the whole evidence dict) — only the
    keys the template needs are read and validated.

    Raises ParamValidationError on an unknown template or any failed validation.
    """
    spec = ACTION_BUILDERS.get(action_template)
    if spec is None:
        raise ParamValidationError(f"unknown action_template {action_template!r}")
    validated: dict[str, str] = {}
    for key, validator in spec["params"].items():
        if key not in (raw_params or {}) or raw_params[key] is None:
            raise ParamValidationError(
                f"action {action_template!r} requires evidence key {key!r}")
        validated[key] = validator(raw_params[key])
    return spec["argv"](validated)


def revert_template_for(action_template: str) -> str | None:
    """The revert template for a forward action, or None if irreversible/no-op."""
    return FORWARD_TO_REVERT_TEMPLATE.get(action_template)


def _new_result(host: str, action_template: str) -> dict[str, Any]:
    return {
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
        "action_template": action_template,
        "source": "ssh_writer",
    }


def ssh_run_write(
    case_id: str,
    host: str,
    action_template: str,
    raw_params: dict,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    line_cap: int | None = MAX_TOOL_OUTPUT_LINES,
) -> dict[str, Any]:
    """Execute a containment action on `host` (a live_hosts.json alias).

    Gate order: live-monitoring scope (in-runner, defense-in-depth) → param
    validation → host resolution → run. Mirrors `core.ssh.ssh_run`'s result
    schema (source='ssh_writer') and logs via `_log_ssh_tool` so the trace
    pipeline treats it identically. Never raises — every failure mode returns
    success=False with a populated stderr.
    """
    result = _new_result(host, action_template)

    # 1. Scope — writable SSH is live-monitoring only, enforced here too.
    from response import gates  # local import avoids any import cycle
    refusal = gates.check_live_monitoring_scope(case_id)
    if refusal:
        result["stderr"] = refusal.get("error", "off live-monitoring scope")
        result["cmd"] = f"ssh_write {action_template} (scope-refused)"
        _log_ssh_tool(result)
        return result

    # 2. Validate + build the structured remote argv.
    try:
        remote_argv = build_argv(action_template, raw_params or {})
    except ParamValidationError as e:
        result["stderr"] = f"parameter validation failed: {e}"
        result["cmd"] = f"ssh_write {action_template} (validation-refused)"
        _log_ssh_tool(result)
        return result

    # 3. Resolve the host alias.
    try:
        resolved = _resolve_host(host)
    except SSHConfigError as e:
        result["stderr"] = str(e)
        result["cmd"] = f"ssh_write {host} -- {' '.join(remote_argv)}"
        _log_ssh_tool(result)
        return result

    argv = _build_ssh_argv(resolved, remote_argv)
    # Recorded cmd never leaks the identity path.
    result["cmd"] = (
        f"ssh {resolved['user']}@{resolved['host']}:{resolved['port']} -- "
        + " ".join(shlex.quote(a) for a in remote_argv)
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
        result["stderr"] = f"ssh write timed out after {timeout}s on host {host!r}"
        result["timed_out"] = True
    except FileNotFoundError as e:
        result["stderr"] = f"ssh binary not found: {e}"
    except Exception as e:  # noqa: BLE001
        result["stderr"] = f"ssh_run_write error: {e}"

    result["elapsed_seconds"] = round(time.perf_counter() - start, 1)
    _log_ssh_tool(result)
    return result
