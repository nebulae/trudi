#!/usr/bin/env python3
"""Register TRUDI in an OpenCode install — side-by-side with Claude Code.

Stdlib only — called by install.sh and unit-tested directly. Idempotent and
self-healing (a stale command path or permission entry is rewritten in place),
mirroring claude/hooks/_register_hooks.py.

What it configures (all under ~/.config/opencode by default):

1. opencode.json — merges, preserving unrelated user keys:
   - mcp["trudi-sift"]: local server, command = [<venv python>, <repo>/server.py]
   - permission: "trudi-sift*": "allow" plus a bash deny map derived from the
     SAME ban list Claude Code uses (case-template/.claude/settings.json).
     One source of truth: the forensic-binary ban list is parsed, never copied.
2. command/ — symlinks each claude/commands/*.md (/trudi-* slash commands run
   from the repo path; no drift-prone deployed copies).
3. plugin/ — symlinks opencode/plugin/trudi.js (the hook adapter).
4. AGENTS.md — installs the TRUDI orchestrator (claude/CLAUDE.md), backing up
   any existing file with a UTC timestamp first (never overwritten silently).
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

_BASH_DENY_RE = re.compile(r"^Bash\((.+):\*\)$")


def _load_ban_list(case_template_settings: Path) -> list[str]:
    """Forensic-binary names from the Claude Code deny list (single source)."""
    data = json.loads(case_template_settings.read_text())
    out = []
    for entry in data.get("permissions", {}).get("deny", []):
        m = _BASH_DENY_RE.match(entry)
        if m:
            out.append(m.group(1))
    return out


def _bash_permission(ban: list[str]) -> dict:
    """OpenCode bash permission map. Order matters (last match wins), so the
    catch-all allow comes first and the denies after it. Two patterns per
    binary: bare invocation and with-arguments."""
    perm: dict[str, str] = {"*": "allow"}
    for b in ban:
        perm[b] = "deny"
        perm[f"{b} *"] = "deny"
    return perm


def register(config_path: Path, repo_root: Path, venv_python: str) -> list[str]:
    """Merge the TRUDI mcp + permission config into `config_path`."""
    config_path = Path(config_path)
    repo_root = Path(repo_root)
    msgs: list[str] = []

    if config_path.exists():
        config = json.loads(config_path.read_text() or "{}")
    else:
        config = {}
    before = json.dumps(config, sort_keys=True)

    # 1) MCP server
    server = str(repo_root / "server.py")
    mcp = config.setdefault("mcp", {})
    want = {"type": "local", "command": [venv_python, server], "enabled": True,
            # OpenCode renders every tool schema into every request — serve it
            # slim descriptions (typed parameter schemas are untouched).
            "environment": {"TRUDI_SLIM_TOOL_DESCRIPTIONS": "1"}}
    if mcp.get("trudi-sift") != want:
        stale = "trudi-sift" in mcp
        mcp["trudi-sift"] = want
        msgs.append(f"  {'re-pointed' if stale else 'Registered'} mcp.trudi-sift → {venv_python} {server}")

    # 2) Permissions: allow every trudi-sift tool; deny raw forensic binaries
    #    in bash (derived from the Claude Code ban list — one source of truth).
    ban = _load_ban_list(repo_root / "case-template" / ".claude" / "settings.json")
    perm = config.setdefault("permission", {})
    if perm.get("trudi-sift*") != "allow":
        perm["trudi-sift*"] = "allow"
        msgs.append("  permission: trudi-sift* → allow")
    bash = perm.get("bash")
    if not isinstance(bash, dict):
        bash = {"*": "allow"} if bash is None else {"*": bash}
    want_bash = _bash_permission(ban)
    missing = {k: v for k, v in want_bash.items() if k != "*" and bash.get(k) != v}
    if missing or "*" not in bash:
        bash.setdefault("*", "allow")
        bash.update(missing)
        perm["bash"] = bash
        if missing:
            msgs.append(f"  permission.bash: {len(missing)} forensic-binary deny rules merged")
    else:
        perm["bash"] = bash

    if json.dumps(config, sort_keys=True) != before:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config, indent=2) + "\n")
    if not msgs:
        msgs = ["  opencode.json already registered — nothing to do"]
    return msgs


def link_assets(opencode_dir: Path, repo_root: Path) -> list[str]:
    """Symlink slash commands and the plugin adapter from the repo (no drift)."""
    opencode_dir = Path(opencode_dir)
    repo_root = Path(repo_root)
    msgs: list[str] = []

    cmd_dest = opencode_dir / "command"
    cmd_dest.mkdir(parents=True, exist_ok=True)
    for src in sorted((repo_root / "claude" / "commands").glob("*.md")):
        if src.name.endswith(".bak"):
            continue
        dest = cmd_dest / src.name
        if dest.is_symlink() and dest.resolve() == src.resolve():
            continue
        if dest.exists() or dest.is_symlink():
            dest.unlink()
        dest.symlink_to(src.resolve())
        msgs.append(f"  command/{src.name} → repo")

    plug_src = (repo_root / "opencode" / "plugin" / "trudi.js").resolve()
    plug_dest = opencode_dir / "plugin" / "trudi.js"
    plug_dest.parent.mkdir(parents=True, exist_ok=True)
    if not (plug_dest.is_symlink() and plug_dest.resolve() == plug_src):
        if plug_dest.exists() or plug_dest.is_symlink():
            plug_dest.unlink()
        plug_dest.symlink_to(plug_src)
        msgs.append("  plugin/trudi.js → repo")

    if not msgs:
        msgs = ["  commands + plugin already linked — nothing to do"]
    return msgs


def install_agents_md(opencode_dir: Path, repo_root: Path) -> list[str]:
    """Install the orchestrator as AGENTS.md (backup any existing file)."""
    opencode_dir = Path(opencode_dir)
    src = Path(repo_root) / "claude" / "CLAUDE.md"
    dest = opencode_dir / "AGENTS.md"
    msgs: list[str] = []
    if dest.exists():
        if dest.read_text() == src.read_text():
            return ["  AGENTS.md already current — nothing to do"]
        bak = dest.with_name(f"AGENTS.md.{datetime.now(timezone.utc):%Y%m%dT%H%M%S}.bak")
        shutil.copy2(dest, bak)
        msgs.append(f"  backed up existing AGENTS.md → {bak.name}")
    opencode_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    msgs.append("  installed TRUDI orchestrator → AGENTS.md")
    return msgs


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: register_opencode.py <opencode_config_dir> <repo_root> <venv_python>",
              file=sys.stderr)
        return 2
    opencode_dir = Path(sys.argv[1])
    repo_root = Path(sys.argv[2])
    venv_python = sys.argv[3]
    for line in register(opencode_dir / "opencode.json", repo_root, venv_python):
        print(line)
    for line in link_assets(opencode_dir, repo_root):
        print(line)
    for line in install_agents_md(opencode_dir, repo_root):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
