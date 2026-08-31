"""The `trudi` umbrella command — one entry point, two operating modes.

    trudi --mode agent   # autonomous: the LLM runs the investigation to Report
    trudi --mode pilot   # analyst-driven: the LLM is the copilot, you drive

Both modes launch an agent client (Claude Code or OpenCode) in the case
dir; the difference is the operating PROFILE. Agent mode uses the global
orchestrator as installed. Pilot mode layers the analyst-driven copilot
profile on top:

- claude:   --append-system-prompt-file <repo>/claude/PILOT.md
- opencode: --agent trudi-pilot  (agent definition symlinked by the
            registrar from <repo>/opencode/agent/trudi-pilot.md)

The control plane (MCP-only evidence path, gates, trace citability) is
identical in both modes — see docs/pilot.md.

Installed on PATH by install.sh via bin/trudi (same pattern as
trudi-dashboard). The launcher carries the analyst's invocation directory
in TRUDI_INVOKE_DIR — the case dir defaults to wherever `trudi` was typed.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

AGENT_CLIENTS = ("claude", "opencode")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PILOT_PROFILE = os.path.join(REPO_ROOT, "claude", "PILOT.md")


def resolve_case_dir(arg: str | None) -> str:
    """--case wins; else where the analyst invoked `trudi` (TRUDI_INVOKE_DIR,
    set by bin/trudi before it cds to the repo); else the cwd."""
    return os.path.abspath(arg or os.environ.get("TRUDI_INVOKE_DIR") or os.getcwd())


def resolve_agent_client(arg: str | None) -> str:
    """Explicit flag > TRUDI_AGENT_CLIENT env > first client on PATH."""
    choice = arg or os.environ.get("TRUDI_AGENT_CLIENT")
    if choice:
        if choice not in AGENT_CLIENTS:
            raise SystemExit(
                f"unknown agent client {choice!r} (expected one of {', '.join(AGENT_CLIENTS)})")
        return choice
    for client in AGENT_CLIENTS:
        if shutil.which(client):
            return client
    raise SystemExit(
        "no agent client found on PATH (claude or opencode) — install one, "
        "or run install.sh which checks for the Claude Code CLI")


def check_case_dir(case_dir: str) -> None:
    if not os.path.isdir(case_dir):
        raise SystemExit(f"case directory not found: {case_dir}")
    if not os.path.exists(os.path.join(case_dir, "CLAUDE.md")):
        print(f"note: {case_dir} has no case CLAUDE.md — "
              "not a prepared case dir (see case-template/)", file=sys.stderr)


def client_argv(client: str, mode: str) -> list[str]:
    """The exec argv for a client+mode. Agent mode launches the client bare
    (the global orchestrator is the profile); pilot mode layers the
    analyst-driven copilot profile per client."""
    if mode == "agent":
        return [client]
    if client == "claude":
        return ["claude", "--append-system-prompt-file", PILOT_PROFILE]
    return ["opencode", "--agent", "trudi-pilot"]


def print_case_banner(case_dir: str, mode: str) -> None:
    """A few orienting lines before the client takes the terminal."""
    from pilot.bootstrap import discover_evidence, is_case_dir, parse_case_md
    if not is_case_dir(case_dir):
        return
    info = parse_case_md(case_dir)
    evidence = discover_evidence(info)
    print(f"TRUDI {mode.upper()} ── {info.case_id}")
    if info.question:
        print(f"  Q: {info.question[:120]}")
    print(f"  evidence: {len(evidence)} file(s)"
          + (f" · roster: {len(info.roster)} knowns" if info.roster else ""))


def spawn_mirror(case_dir: str) -> None:
    """Start the trace→vera mirror in follow mode, detached — the live
    record grows alongside the session (pilot/mirror.py is standalone and
    client-independent)."""
    from pilot.bootstrap import parse_case_md
    info = parse_case_md(case_dir)
    trace = os.path.join(case_dir, "analysis", f"{info.case_id}_trace.json")
    vera = os.path.join(case_dir, f"{info.case_id}.vera")
    proc = subprocess.Popen(
        [sys.executable, "-m", "pilot.mirror", trace, vera, "--follow"],
        cwd=REPO_ROOT, start_new_session=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"  vera mirror following → {vera} (pid {proc.pid})")


def launch(case_dir: str, client: str, mode: str, mirror: bool = False) -> int:
    binary = shutil.which(client)
    if not binary:
        raise SystemExit(f"{client} not found on PATH")
    if mode == "pilot" and client == "claude" and not os.path.exists(PILOT_PROFILE):
        raise SystemExit(f"pilot profile missing: {PILOT_PROFILE}")
    print_case_banner(case_dir, mode)
    if mirror:
        spawn_mirror(case_dir)
    os.chdir(case_dir)
    print(f"launching {client} ({mode} mode) in {case_dir}")
    sys.stdout.flush()  # execv replaces the process — unflushed output is lost
    os.execv(binary, client_argv(client, mode))  # replaces this process


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="trudi",
        description="TRUDI — agent mode (the LLM drives) or pilot mode (you drive)")
    ap.add_argument("--mode", choices=("agent", "pilot"), required=True,
                    help="agent: autonomous investigation; pilot: analyst-driven copilot")
    ap.add_argument("--case", help="case directory (default: where you ran trudi)")
    ap.add_argument("--client", choices=AGENT_CLIENTS,
                    help="which client hosts the session (default: "
                         "$TRUDI_AGENT_CLIENT, else first found on PATH)")
    ap.add_argument("--mirror", action="store_true",
                    help="also start the trace→vera mirror in follow mode")
    args = ap.parse_args(argv)

    case_dir = resolve_case_dir(args.case)
    check_case_dir(case_dir)
    return launch(case_dir, resolve_agent_client(args.client), args.mode,
                  mirror=args.mirror)


if __name__ == "__main__":
    sys.exit(main())
