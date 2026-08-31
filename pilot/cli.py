"""The `trudi` umbrella command — one entry point, two drivers.

    trudi --mode agent   # autopilot: launch the driving LLM client in the case dir
    trudi --mode pilot   # the analyst drives: the TRUDI pilot REPL

Installed on PATH by install.sh via bin/trudi (same pattern as
trudi-dashboard). The launcher runs this module from the repo root and
carries the analyst's invocation directory in TRUDI_INVOKE_DIR — the case
dir defaults to wherever the analyst typed `trudi`.

Agent mode is a thin launcher over what the registrars already configure:
it just starts the chosen client (claude / opencode) in the case dir; the
MCP server, hooks, and orchestrator are the registrars' job. Pilot mode
currently runs the Phase-0 spike REPL; the full session bootstrap and
work-order loop land on top of it (docs/pilot.md Phase 2).
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys

AGENT_CLIENTS = ("claude", "opencode")


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


def run_agent(case_dir: str, client: str) -> int:
    binary = shutil.which(client)
    if not binary:
        raise SystemExit(f"{client} not found on PATH")
    os.chdir(case_dir)
    print(f"launching {client} in {case_dir}")
    os.execv(binary, [client])  # replaces this process; no return


def run_pilot(case_dir: str, stdio: bool) -> int:
    os.environ["TRUDI_CASE_DIR"] = case_dir
    os.chdir(case_dir)
    import asyncio

    from pilot.repl import run
    asyncio.run(run(stdio=stdio))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="trudi",
        description="TRUDI — agent mode (an LLM drives) or pilot mode (you drive)")
    ap.add_argument("--mode", choices=("agent", "pilot"), required=True,
                    help="agent: launch the driving LLM client; pilot: the analyst REPL")
    ap.add_argument("--case", help="case directory (default: where you ran trudi)")
    ap.add_argument("--client", choices=AGENT_CLIENTS,
                    help="agent mode: which client drives (default: "
                         "$TRUDI_AGENT_CLIENT, else first found on PATH)")
    ap.add_argument("--stdio", action="store_true",
                    help="pilot mode: talk to server.py over stdio instead of in-process")
    args = ap.parse_args(argv)

    case_dir = resolve_case_dir(args.case)
    check_case_dir(case_dir)
    if args.mode == "agent":
        return run_agent(case_dir, resolve_agent_client(args.client))
    return run_pilot(case_dir, args.stdio)


if __name__ == "__main__":
    sys.exit(main())
