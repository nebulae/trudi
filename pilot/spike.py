"""Phase-0 spike: prove the pilot REPL core feel.

Connects a fastmcp Client to the TRUDI server, builds an intellisense
completer from the live tool schemas (tool names, parameter names, familiar
binary-name aliases from the deny-hint table), and runs a minimal
prompt_toolkit loop: complete → edit → call → print. Everything the real
pilot needs to feel right, nothing else — no vera, no DAIR rendering, no
analysis pass.

    python -m pilot.spike            # in-process client (fast, default)
    python -m pilot.spike --stdio    # spawn server.py over stdio (deployment shape)

Commands: `ns.tool key=value …` (values parsed as JSON when they parse,
strings otherwise), `tools [substr]`, `schema ns.tool`, `exit`.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import sys

from fastmcp import Client
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.filters import completion_is_selected
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.styles import Style


# ── command-line parsing ─────────────────────────────────────────────────────

def dotted_to_wire(name: str) -> str:
    """`ez.mftecmd` → `ez_mftecmd`; already-wire names pass through."""
    return name.replace(".", "_", 1)


def wire_to_dotted(name: str) -> str:
    """`ez_mftecmd` → `ez.mftecmd` (first underscore is the namespace cut)."""
    return name.replace("_", ".", 1)


def parse_command(line: str) -> tuple[str, dict]:
    """`ns.tool k=v k2="a b" k3=[1,2]` → ("ns_tool", {k: v, …}).

    Values are JSON-parsed when they parse (numbers, booleans, lists,
    objects), kept as strings otherwise. Raises ValueError on malformed
    input.
    """
    parts = shlex.split(line)
    if not parts:
        raise ValueError("empty command")
    tool = dotted_to_wire(parts[0])
    args: dict = {}
    for tok in parts[1:]:
        if "=" not in tok:
            raise ValueError(f"expected key=value, got {tok!r}")
        k, v = tok.split("=", 1)
        try:
            args[k] = json.loads(v)
        except (json.JSONDecodeError, ValueError):
            args[k] = v
    return tool, args


# ── shell navigation ─────────────────────────────────────────────────────────
#
# The analyst needs to look around (ls, tree, cd) — that is navigation, not
# forensic execution, and refusing it just pushes them to a second terminal.
# The doctrine holds where it matters: shell commands pass the SAME
# forensic-binary deny the agent has (core/forensic_binaries — identical ban
# list, identical MCP-wrapper coaching), so evidence work still has exactly
# one path. `!cmd` runs anything else; bare ls/ll/tree/pwd/df need no prefix.

NAV_COMMANDS = {"ls", "ll", "tree", "df", "pwd"}
SHELL_OUTPUT_CAP = 16_384


def shell_guard(cmd: str) -> str | None:
    """The agent's deny message, for the human: MCP hint or None (allowed)."""
    from core.forensic_binaries import MCP_WRAPPER_HINTS, _identify_forensic_binary
    binary = _identify_forensic_binary(cmd)
    if binary:
        hint = MCP_WRAPPER_HINTS.get(binary, "the corresponding MCP wrapper")
        return (f"{binary} is a forensic binary — evidence work goes through "
                f"the traced MCP path so findings can cite it. Use: {hint}")
    return None


def run_shell(cmd: str) -> None:
    denied = shell_guard(cmd)
    if denied:
        print(_YELLOW + denied + _RESET)
        return
    import subprocess
    if cmd.split()[0] == "ll":
        cmd = "ls -la" + cmd[2:]
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    if len(out) > SHELL_OUTPUT_CAP:
        out = out[:SHELL_OUTPUT_CAP] + "\n… (truncated)"
    print(out.rstrip() or f"(exit {r.returncode})")


def complete_path(prefix: str) -> list[str]:
    """Filesystem completions for a partial path; dirs get a trailing /."""
    base = os.path.expanduser(prefix)
    dirname, part = os.path.split(base)
    try:
        entries = sorted(os.listdir(dirname or "."))
    except OSError:
        return []
    hits = []
    for name in entries:
        if name.startswith(part) and not (not part and name.startswith(".")):
            full = os.path.join(dirname, name) if dirname else name
            hits.append(full + "/" if os.path.isdir(full) else full)
    return hits


# ── completion ───────────────────────────────────────────────────────────────

def build_alias_map() -> dict[str, str]:
    """Familiar binary name → dotted wrapper, from the deny-hint table."""
    import re
    from core.forensic_binaries import MCP_WRAPPER_HINTS
    aliases: dict[str, str] = {}
    token = re.compile(r"\b[a-z]+\.[A-Za-z0-9_*]+")
    for binary, hint in MCP_WRAPPER_HINTS.items():
        for m in token.finditer(hint):
            if m.group(0) != "e.g":  # prose "e.g." in the vol hint
                aliases[binary.lower()] = m.group(0)
                break
    return aliases


class PilotCompleter(Completer):
    """Tool-name + parameter-name completion from live schemas.

    First word: dotted tool names, plus binary aliases (`fls` offers
    `tsk.fls`). Later words: `param=` names from the chosen tool's input
    schema, minus those already supplied. Subclassing prompt_toolkit's
    Completer is load-bearing: its async completion path calls the base
    class's get_completions_async wrapper.
    """

    def __init__(self, tools: list, aliases: dict[str, str]):
        self.dotted = sorted(wire_to_dotted(t.name) for t in tools)
        self.params = {
            wire_to_dotted(t.name): sorted(
                (t.inputSchema or {}).get("properties", {})
            )
            for t in tools
        }
        self.aliases = aliases

    def complete_first(self, prefix: str) -> list[str]:
        hits = [d for d in self.dotted if d.startswith(prefix)]
        hits += [
            f"{dotted}  (alias: {alias})"
            for alias, dotted in self.aliases.items()
            if alias.startswith(prefix.lower()) and dotted in self.params
        ]
        return hits

    def complete_param(self, tool_dotted: str, prefix: str,
                       used: set[str]) -> list[str]:
        return [
            f"{p}=" for p in self.params.get(tool_dotted, ())
            if p.startswith(prefix) and p not in used
        ]

    # prompt_toolkit adapter
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        words = text.split()
        shell_mode = text.lstrip().startswith("!") or (
            bool(words) and words[0] in NAV_COMMANDS)
        completing_first = not words or (len(words) == 1 and not text.endswith(" "))

        if shell_mode and not completing_first:
            # navigation: complete filesystem paths for every argument
            prefix = "" if text.endswith(" ") else words[-1]
            for hit in complete_path(prefix):
                yield Completion(hit, start_position=-len(prefix))
        elif completing_first:
            prefix = words[0] if words else ""
            for hit in self.complete_first(prefix):
                yield Completion(hit.split()[0], start_position=-len(prefix),
                                 display=hit)
        else:
            tool = words[0]
            used = {w.split("=", 1)[0] for w in words[1:] if "=" in w}
            current = "" if text.endswith(" ") else words[-1]
            if "=" in current:
                # param VALUE: complete as a filesystem path, keeping key=
                key, value = current.split("=", 1)
                for hit in complete_path(value):
                    yield Completion(hit, start_position=-len(value))
            else:
                for hit in self.complete_param(tool, current, used):
                    yield Completion(hit, start_position=-len(current))


# ── look & feel ──────────────────────────────────────────────────────────────

PILOT_STYLE = Style.from_dict({
    "prompt": "bold fg:ansicyan",
    "ns": "bold fg:ansiblue",
    "tool": "fg:ansicyan",
    "key": "fg:ansigreen",
    "shell": "fg:ansimagenta",
    "builtin": "bold",
})

_RED = "\x1b[31m"
_YELLOW = "\x1b[33m"
_GREEN = "\x1b[32m"
_RESET = "\x1b[0m"

_BUILTINS = {"tools", "schema", "exit", "quit"}


def make_key_bindings() -> KeyBindings:
    """Enter with a highlighted completion ACCEPTS it and keeps editing;
    Enter otherwise submits. This is the fix for the classic prompt_toolkit
    footgun where Enter mid-menu executes the half-finished command."""
    kb = KeyBindings()

    @kb.add("enter", filter=completion_is_selected)
    def _accept_completion(event):
        event.current_buffer.complete_state = None

    return kb


def classify_line(line: str) -> list[tuple[str, str]]:
    """Style fragments for one input line (the PilotLexer body)."""
    stripped = line.lstrip()
    first = stripped.split()[0] if stripped.split() else ""
    if stripped.startswith("!") or first in NAV_COMMANDS or first in ("cd", "pwd"):
        return [("class:shell", line)]
    if first in _BUILTINS:
        head = line[: line.index(first) + len(first)]
        return [("class:builtin", head), ("", line[len(head):])]

    frags: list[tuple[str, str]] = []
    pos = 0
    for m in re.finditer(r"\S+", line):
        if m.start() > pos:
            frags.append(("", line[pos:m.start()]))
        tok = m.group(0)
        if not frags or all(s == "" for s, _ in frags):  # first token
            if "." in tok:
                ns, rest = tok.split(".", 1)
                frags += [("class:ns", ns), ("", "."), ("class:tool", rest)]
            else:
                frags.append(("", tok))
        elif "=" in tok:
            key, val = tok.split("=", 1)
            frags += [("class:key", key), ("", "=" + val)]
        else:
            frags.append(("", tok))
        pos = m.end()
    if pos < len(line):
        frags.append(("", line[pos:]))
    return frags


class PilotLexer(Lexer):
    def lex_document(self, document):
        lines = document.lines

        def get_line(lineno):
            return classify_line(lines[lineno])
        return get_line


def print_result(payload) -> None:
    """Colored JSON when pygments is available; a ✓/✗ headline either way."""
    ok = isinstance(payload, dict) and payload.get("success", True)
    cid = isinstance(payload, dict) and payload.get("_trudi_call_id")
    head = f"{_GREEN}✓{_RESET}" if ok else f"{_RED}✗{_RESET}"
    print(f"{head} cid {cid}" if cid else head)
    text = json.dumps(payload, indent=2, default=str)[:4000]
    try:
        from pygments import highlight
        from pygments.formatters import TerminalFormatter
        from pygments.lexers import JsonLexer
        print(highlight(text, JsonLexer(), TerminalFormatter()), end="")
    except ImportError:
        print(text)


# ── the loop ─────────────────────────────────────────────────────────────────

async def run(stdio: bool = False) -> None:
    if stdio:
        client = Client("server.py")
    else:
        import server
        client = Client(server.mcp)

    async with client:
        tools = await client.list_tools()
        completer = PilotCompleter(tools, build_alias_map())

        # Session bootstrap (bookkeeping auto-runs; see pilot/bootstrap.py).
        # Only in a prepared case dir — a bare spike run stays a playground.
        from pilot.bootstrap import (bootstrap, is_case_dir, parse_case_md,
                                     render_banner)
        case_dir = os.environ.get("TRUDI_CASE_DIR") or os.getcwd()
        if is_case_dir(case_dir):
            info = parse_case_md(case_dir)
            state = await bootstrap(client, info)
            print(render_banner(info, state))
        else:
            print("(no case dir — playground session, nothing recorded)")
        print(f"TRUDI pilot (spike) — {len(tools)} tools, tab completes "
              f"(names, params, paths); 'tools <substr>' lists, 'schema ns.tool' "
              f"shows params, ls/cd/!cmd navigate, 'exit' quits")

        from prompt_toolkit import PromptSession
        from prompt_toolkit.shortcuts import CompleteStyle
        session = PromptSession(
            [("class:prompt", "trudi> ")],
            completer=completer,
            complete_while_typing=True,
            complete_style=CompleteStyle.MULTI_COLUMN,
            key_bindings=make_key_bindings(),
            style=PILOT_STYLE,
            lexer=PilotLexer(),
            reserve_space_for_menu=6,
        )

        while True:
            try:
                line = (await session.prompt_async()).strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            if line in ("exit", "quit"):
                break
            if line.startswith("tools"):
                sub = line.split(None, 1)[1] if " " in line else ""
                for d in completer.dotted:
                    if sub in d:
                        print(" ", d)
                continue
            if line.startswith("schema "):
                target = line.split(None, 1)[1]
                for t in tools:
                    if wire_to_dotted(t.name) == target:
                        print(json.dumps(t.inputSchema, indent=2))
                        break
                else:
                    print(f"no such tool: {target}")
                continue
            # navigation: cd/pwd builtins, ! prefix, bare ls/ll/tree/df.
            # Same forensic-binary deny as the agent (shell_guard).
            if line == "pwd":
                print(os.getcwd())
                continue
            if line == "cd" or line.startswith("cd "):
                target = os.path.expanduser(line[2:].strip() or "~")
                try:
                    os.chdir(target)
                    print(os.getcwd())
                except OSError as e:
                    print(f"cd: {e}")
                continue
            if line.startswith("!"):
                run_shell(line[1:].strip())
                continue
            first = line.split()[0]
            if first in NAV_COMMANDS:
                run_shell(line)
                continue
            if "." not in first:
                # not an MCP tool: a bare forensic binary gets the same
                # coaching the agent gets; anything else, a pointer.
                print(_YELLOW + (shell_guard(line) or
                      f"unknown command {first!r} — MCP tools are ns.tool "
                      f"(tab completes); prefix shell with !") + _RESET)
                continue
            try:
                tool, args = parse_command(line)
            except ValueError as e:
                print(f"{_YELLOW}parse error: {e}{_RESET}")
                continue
            try:
                result = await client.call_tool(tool, args)
                print_result(result.structured_content)
            except Exception as e:
                print(f"{_RED}error: {e}{_RESET}")


if __name__ == "__main__":
    asyncio.run(run(stdio="--stdio" in sys.argv))
