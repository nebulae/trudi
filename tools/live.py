"""Live endpoint analysis tools — read-only over SSH.

Each tool wraps a fixed read-only command on a pre-registered remote host
(see `~/cases/.common/live_hosts.json`). All execution routes through
`core.ssh.ssh_run`, which uses fixed argv (no shell parsing on the remote
side) and writes a `tool_call` trace entry with `source: "ssh_runner"`.

The same trace + audit + gate machinery that covers static evidence applies
unchanged to live data: `linked_call_id` chains, `record_finding` gates,
attribution, coverage. Findings can cite `_trudi_call_id` values returned
here exactly as they would from `vol.*` or `ez.*` results.

Tools are intentionally narrow — one OS command per tool, no composition
on the remote side. Composition happens in TRUDI (correlate.*, attribution,
af.*) where the gate/index layer can audit it.
"""
from __future__ import annotations
from typing import Optional
from fastmcp import FastMCP

from core import output_safe
from core.ssh import ssh_run, list_configured_hosts

mcp = FastMCP("live")


# ── Process / runtime state ──────────────────────────────────────────────────

@mcp.tool()
@output_safe
def live_hosts() -> dict:
    """List configured live endpoints.

    Reads ~/cases/.common/live_hosts.json — returns just the host names so
    connection details (user, identity path) stay server-side.
    """
    hosts = list_configured_hosts()
    return {"success": True, "hosts": hosts, "count": len(hosts)}


@mcp.tool()
@output_safe
def live_processes(host: str) -> dict:
    """Snapshot the full process list on a live endpoint.

    Returns: ps -eo pid,ppid,user,etimes,start,cmd output. Use as the live
    equivalent of vol.pslist for memory images.
    """
    return ssh_run(host, ["ps", "-eo", "pid,ppid,user,etimes,start,cmd", "--no-headers"])


@mcp.tool()
@output_safe
def live_process_details(host: str, pid: int) -> dict:
    """Read /proc/<pid>/{status,cmdline,environ,maps} for a single process.

    Use after live_processes flags an interesting pid — equivalent to
    vol.cmdline + vol.envars + vol.vadinfo combined for a static image.
    """
    return ssh_run(
        host,
        ["sh", "-c",
         f"for f in status cmdline environ maps; do "
         f"echo ===/proc/{pid}/$f===; cat /proc/{pid}/$f 2>/dev/null | head -c 8192; echo; done"],
        timeout=30,
    )


@mcp.tool()
@output_safe
def live_open_files(host: str, pid: int) -> dict:
    """List open file handles for a single process via lsof.

    Captures sockets, regular files, and pipes — live equivalent of
    vol.handles + vol.filescan for a specific PID.
    """
    return ssh_run(host, ["lsof", "-p", str(pid), "-n", "-P"], timeout=30)


# ── Network state ────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def live_network_connections(host: str) -> dict:
    """All TCP connections + listening sockets with owning PID.

    Live equivalent of vol.netscan/netstat. Output format: ss -tnlpa.
    """
    return ssh_run(host, ["ss", "-tnlpa"], timeout=30)


# ── Accounts / login history ─────────────────────────────────────────────────

@mcp.tool()
@output_safe
def live_users(host: str) -> dict:
    """User accounts (getent passwd) + recent login history (last -F)."""
    return ssh_run(
        host,
        ["sh", "-c", "echo ===PASSWD===; getent passwd; echo ===LASTLOG===; last -F | head -50"],
        timeout=30,
    )


@mcp.tool()
@output_safe
def live_recent_logins(host: str, hours: int = 24) -> dict:
    """journalctl ssh logins within the last `hours` hours + lastlog snapshot."""
    if hours < 1 or hours > 720:
        return {"success": False, "error": "hours must be between 1 and 720"}
    return ssh_run(
        host,
        ["sh", "-c",
         f"echo ===SSHD===; journalctl _COMM=sshd --since '{hours} hours ago' --no-pager | tail -200; "
         f"echo ===LASTLOG===; lastlog"],
        timeout=60,
    )


# ── Persistence surface ──────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def live_services(host: str) -> dict:
    """systemctl list-units --type=service for all systemd-managed services."""
    return ssh_run(
        host,
        ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain"],
        timeout=30,
    )


@mcp.tool()
@output_safe
def live_scheduled_tasks(host: str) -> dict:
    """systemd timers + per-user crontabs + /etc/cron.* + /etc/anacrontab."""
    return ssh_run(
        host,
        ["sh", "-c",
         "echo ===TIMERS===; systemctl list-timers --all --no-pager --plain; "
         "echo ===CRON_D===; ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ "
         "/etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null; "
         "echo ===ANACRONTAB===; cat /etc/anacrontab 2>/dev/null; "
         "echo ===USER_CRONTABS===; "
         "for u in $(cut -d: -f1 /etc/passwd); do "
         "  c=$(sudo -n crontab -u $u -l 2>/dev/null); "
         "  if [ -n \"$c\" ]; then echo ---$u---; echo \"$c\"; fi; "
         "done"],
        timeout=60,
    )


@mcp.tool()
@output_safe
def live_persistence_audit(host: str) -> dict:
    """One-shot persistence sweep — services + timers + crontabs + autostart files.

    Composite Triage tool: covers systemd services, timers, crontabs,
    /etc/rc.local, /etc/profile.d/*, ~/.bashrc tails, and kernel modules
    loaded since boot. Use during Triage to surface high-yield persistence
    candidates before deciding what to drill into.
    """
    return ssh_run(
        host,
        ["sh", "-c",
         "echo ===SYSTEMD_ENABLED===; systemctl list-unit-files --type=service "
         "--state=enabled --no-pager --plain | tail -200; "
         "echo ===SYSTEMD_TIMERS===; systemctl list-timers --all --no-pager --plain; "
         "echo ===RC_LOCAL===; cat /etc/rc.local 2>/dev/null | tail -50; "
         "echo ===PROFILE_D===; ls -la /etc/profile.d/ 2>/dev/null; "
         "echo ===BASHRC_TAIL===; "
         "for h in /home/*/.bashrc /root/.bashrc; do "
         "  [ -r \"$h\" ] && echo ---$h---; [ -r \"$h\" ] && tail -10 \"$h\"; "
         "done; "
         "echo ===LSMOD===; lsmod | head -50"],
        timeout=90,
    )


# ── Files / logs ─────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def live_read_file(host: str, path: str, max_bytes: int = 65536) -> dict:
    """Read a remote file, capped at max_bytes.

    Use for small text artifacts (config files, logs, /etc/* checks).
    For binaries or large files, consider live_yara_scan or copy via separate
    tooling — this is a defensive cap to keep the trace bounded.
    """
    if max_bytes < 1 or max_bytes > 1_048_576:
        return {"success": False, "error": "max_bytes must be 1..1048576"}
    return ssh_run(host, ["head", "-c", str(max_bytes), path], timeout=30)


@mcp.tool()
@output_safe
def live_event_log_tail(host: str, unit: str, lines: int = 200) -> dict:
    """journalctl -u <unit> -n <lines> for a systemd-managed unit's log tail."""
    if lines < 1 or lines > 5000:
        return {"success": False, "error": "lines must be 1..5000"}
    return ssh_run(
        host,
        ["journalctl", "-u", unit, "-n", str(lines), "--no-pager"],
        timeout=60,
    )


# ── YARA on the live endpoint ────────────────────────────────────────────────

@mcp.tool()
@output_safe
def live_yara_scan(host: str, rules_path: str, target_dir: str) -> dict:
    """Run a YARA scan on a directory of the live endpoint.

    rules_path: path TO THE RULES ON THE ENDPOINT — they must already be
                present there (push via scp or initial deployment). Keeps
                this tool stateless and read-only on TRUDI side.
    target_dir: directory on the endpoint to scan.

    For one-off rules push, scp the rules during endpoint setup (see
    docs/live-endpoint-testing.md).
    """
    return ssh_run(
        host,
        ["yara", "-r", "-s", rules_path, target_dir],
        timeout=300,
    )
