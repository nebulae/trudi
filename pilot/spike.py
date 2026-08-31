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
import shlex
import sys

from fastmcp import Client


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


class PilotCompleter:
    """Tool-name + parameter-name completion from live schemas.

    First word: dotted tool names, plus binary aliases (`fls` offers
    `tsk.fls`). Later words: `param=` names from the chosen tool's input
    schema, minus those already supplied.
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
        from prompt_toolkit.completion import Completion
        text = document.text_before_cursor
        words = text.split()
        completing_first = not words or (len(words) == 1 and not text.endswith(" "))
        if completing_first:
            prefix = words[0] if words else ""
            for hit in self.complete_first(prefix):
                yield Completion(hit.split()[0], start_position=-len(prefix),
                                 display=hit)
        else:
            tool = words[0]
            used = {w.split("=", 1)[0] for w in words[1:] if "=" in w}
            prefix = "" if text.endswith(" ") else words[-1]
            for hit in self.complete_param(tool, prefix, used):
                yield Completion(hit, start_position=-len(prefix))


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
        print(f"pilot spike — {len(tools)} tools, tab completes; "
              f"'tools <substr>' lists, 'schema ns.tool' shows params, 'exit' quits")

        from prompt_toolkit import PromptSession
        session = PromptSession("pilot> ", completer=completer)

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
            try:
                tool, args = parse_command(line)
            except ValueError as e:
                print(f"parse error: {e}")
                continue
            try:
                result = await client.call_tool(tool, args)
                payload = result.structured_content
                print(json.dumps(payload, indent=2, default=str)[:4000])
            except Exception as e:
                print(f"error: {e}")


if __name__ == "__main__":
    asyncio.run(run(stdio="--stdio" in sys.argv))
