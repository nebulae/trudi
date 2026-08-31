"""The pilot REPL — completion, navigation, and the work-order loop.

Connects a fastmcp Client to the TRUDI server, builds an intellisense
completer from the live tool schemas (tool names, parameter names, familiar
binary-name aliases from the deny-hint table), and runs a minimal
prompt_toolkit loop: complete → edit → call → print. Everything the real
pilot needs to feel right, nothing else — no vera, no DAIR rendering, no
analysis pass.

    python -m pilot.repl            # in-process client (fast, default)
    python -m pilot.repl --stdio    # spawn server.py over stdio (deployment shape)

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
            elif current and ("/" in current or current.startswith("~")):
                # a bare path in argument position completes as a path too
                for hit in complete_path(current):
                    yield Completion(hit, start_position=-len(current))
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
_CYAN = "\x1b[36m"
_BOLD = "\x1b[1m"
_RESET = "\x1b[0m"

_BUILTINS = {"tools", "schema", "exit", "quit", "task", "pick", "last",
             "assess", "wo", "dismiss", "advise"}


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


# keys the analyst never needs on screen (still in the trace; `last` shows all)
_NOISE_KEYS = {"inputs", "backend_meta", "evidence_audit", "_metadata",
               "result_block", "parse_path", "input_tokens", "output_tokens",
               "success"}
_STDOUT_HEAD = 30


def _print_json(obj) -> None:
    text = json.dumps(obj, indent=2, default=str)[:4000]
    try:
        from pygments import highlight
        from pygments.formatters import TerminalFormatter
        from pygments.lexers import JsonLexer
        print(highlight(text, JsonLexer(), TerminalFormatter()), end="")
    except ImportError:
        print(text)


def print_result(payload, verbose: bool = False) -> None:
    """A ✓/✗ headline, then a DIGEST of what matters — not the raw payload.
    `verbose` (the `last` command) prints everything."""
    ok = isinstance(payload, dict) and payload.get("success", True)
    cid = isinstance(payload, dict) and payload.get("_trudi_call_id")
    head = f"{_GREEN}✓{_RESET}" if ok else f"{_RED}✗{_RESET}"
    print(f"{head} cid {cid}" if cid else head)
    if not isinstance(payload, dict) or verbose:
        _print_json(payload)
        return

    body = {k: v for k, v in payload.items() if k not in _NOISE_KEYS}

    # reason.* digest: the hypothesis id + conclusion ARE the result
    if "conclusion" in body:
        hid = body.pop("hypothesis_id", None)
        if hid:
            print(f"  {_CYAN}{hid}{_RESET}")
        for ln in str(body.pop("conclusion", "")).splitlines():
            print(f"  {ln}")
        pts = (body.pop("directives", {}) or {}).get("priority_tools") or []
        if pts:
            print(f"  {_GREEN}→ {len(pts)} suggested tool(s) added to the "
                  f"work order{_RESET}")
        print("  (`last` shows the full payload)")
        return

    # long stdout: page the head, point at the traced sidecar for the rest
    stdout = body.get("stdout")
    if isinstance(stdout, str) and stdout.count("\n") > 8:
        body.pop("stdout")
        lines = stdout.splitlines()
        for ln in lines[:_STDOUT_HEAD]:
            print(f"  {ln}")
        if len(lines) > _STDOUT_HEAD:
            print(f"  {_YELLOW}… {len(lines) - _STDOUT_HEAD} more lines — "
                  f"full output in the traced sidecar (cid {cid}); query it "
                  f"with read.output, or `last` for the raw payload{_RESET}")
        if body:
            _print_json(body)
        return

    _print_json(body)


# ── task → command drafting ──────────────────────────────────────────────────

_BRIEF_LIMIT = 12


def build_tool_briefs(task: str, tools: list, limit: int = _BRIEF_LIMIT) -> str:
    """Lexical retrieval over the catalog: score tools by task-word overlap
    with name+description, return the top briefs (name, purpose, params) so
    the reason backend sees a dozen relevant schemas, not 278."""
    stop = {"the", "all", "and", "for", "from", "into", "with", "that",
            "this", "then", "them", "have", "what", "each", "another",
            "pull", "get", "show", "give"}
    words = {w for w in re.split(r"[^a-z0-9]+", task.lower())
             if len(w) > 2 and w not in stop}
    scored = []
    for t in tools:
        desc = (t.description or "").split("\n")[0]
        params = " ".join((t.inputSchema or {}).get("properties", {}))
        hay = f"{t.name} {desc} {params}".lower()
        score = sum(1 for w in words if w in hay)
        scored.append((score, t.name, desc, t.inputSchema or {}))
    scored.sort(key=lambda s: (-s[0], s[1]))
    briefs = []
    for score, name, desc, schema in scored[:limit]:
        props = schema.get("properties", {})
        required = set(schema.get("required", []))
        params = ", ".join(
            f"{p}*" if p in required else p for p in props)
        briefs.append(f"{wire_to_dotted(name)} — {desc[:140]}"
                      f"\n  params (*=required): {params}")
    return "\n".join(briefs)


def validate_candidates(candidates: list[dict], schema_map: dict) -> list[dict]:
    """Keep only candidates whose command parses and names a real tool —
    a drafted command that cannot run is worse than none."""
    good = []
    for c in candidates:
        try:
            tool, _args = parse_command(c.get("command", ""))
        except ValueError:
            continue
        if tool in schema_map:
            good.append(c)
    return good


# ── prefill & argument checking ──────────────────────────────────────────────

_PATHY = ("file", "path", "image", "evidence", "pcap", "hive", "mail",
          "db", "dump", "target", "dir")
_EXT_HINTS = (
    (("pcap",), (".pcap", ".pcapng")),
    (("image", "e01", "disk"), (".e01", ".ex01", ".dd", ".raw", ".img",
                                ".vmdk", ".vhd", ".vhdx")),
    (("mem", "dump"), (".mem", ".vmem", ".lime", ".dmp")),
    (("mail", "ost", "pst"), (".ost", ".pst")),
)


def guess_value(param: str, prop: dict, evidence: list[str]) -> str:
    """Best-effort default for a required param: schema default first, then
    an evidence path whose extension matches what the name suggests."""
    if "default" in prop and prop["default"] not in (None, ""):
        return str(prop["default"])
    low = param.lower()
    if any(p in low for p in _PATHY) and evidence:
        for names, exts in _EXT_HINTS:
            if any(n in low for n in names):
                for path in evidence:
                    if os.path.splitext(path)[1].lower() in exts:
                        return path
        return evidence[0]
    return ""


_PATTERNISH = ("pattern", "query", "regex", "search", "grep")


def prefill_command(suggestion: str, schema_map: dict, evidence: list[str]) -> str:
    """Turn a work-order suggestion into an editable command in OUR syntax.

    Already key=value (the ritual items): verbatim. Anything else — a bare
    tool name, or a DAIR/reason suggestion in CLI style with flags and
    placeholder paths ("net.ngrep_search -p 'Cookie:' /path/to/x.pcap") —
    is REBUILT from the schema: required params with values guessed from
    schema defaults and case evidence; a quoted string in the suggestion is
    adopted into the first pattern-ish param. Unguessable values stay
    `key=` to fill in. Unknown tools pass through untouched."""
    parts = suggestion.split()
    tool = parts[0] if parts else ""
    rest = parts[1:]
    if rest and all("=" in t for t in rest):
        return suggestion
    schema = schema_map.get(dotted_to_wire(tool))
    if not schema:
        return suggestion
    props = schema.get("properties", {})
    required = list(schema.get("required", []))
    quoted = next((a or b for a, b in
                   re.findall(r"'([^']+)'|\"([^\"]+)\"", suggestion)), "")
    args: dict[str, str] = {}
    for param in required:
        args[param] = guess_value(param, props.get(param, {}), evidence)
    if quoted:
        pat_param = next(
            (p for p in list(required) + sorted(props)
             if any(k in p.lower() for k in _PATTERNISH) and not args.get(p)),
            None)
        if pat_param:
            args[pat_param] = quoted
    frags = [tool]
    for param, value in args.items():
        if value and (" " in value or "|" in value):
            value = f'"{value}"'
        frags.append(f"{param}={value}")
    return " ".join(frags)


def filter_known(suggestions: list, schema_map: dict) -> list[str]:
    """Drop suggested tools that don't exist on the server (a model may
    suggest raw binaries like `sha256sum`) — an unrunnable work-order item
    is noise."""
    return [str(s) for s in suggestions
            if str(s).split() and
            dotted_to_wire(str(s).split()[0]) in schema_map]


def missing_required(tool_wire: str, args: dict, schema_map: dict) -> list[str]:
    """Required params absent or left empty — checked client-side so an
    unfilled prefill gets coaching, not a server error."""
    schema = schema_map.get(tool_wire) or {}
    props = schema.get("properties", {})
    out = []
    for param in schema.get("required", []):
        if args.get(param) in (None, ""):
            ptype = (props.get(param) or {}).get("type", "")
            out.append(f"{param}({ptype})" if ptype else param)
    return out


async def call_with_progress(client, tool: str, args: dict, label: str = "",
                             tick: float = 5.0):
    """call_tool with a heartbeat: silent awaits look like a frozen REPL
    (observed live: dair.assess on a local backend, minutes of nothing).
    Prints an elapsed counter every `tick` seconds; ctrl+c cancels the call
    and re-raises so the caller can abandon the step."""
    import time
    task = asyncio.ensure_future(client.call_tool(tool, args))
    start = time.monotonic()
    ticked = False
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=tick)
            if done:
                break
            elapsed = int(time.monotonic() - start)
            print(f"\r  … {label or tool} running {elapsed}s — a local "
                  f"reason/DAIR backend can take minutes; ctrl+c cancels ",
                  end="", flush=True)
            ticked = True
    except (KeyboardInterrupt, asyncio.CancelledError):
        task.cancel()
        print("\n  cancelled")
        raise KeyboardInterrupt
    if ticked:
        print()
    return task.result()


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
        # Only in a prepared case dir — a bare run stays a playground.
        from pilot import workorder as wo
        from pilot.bootstrap import (bootstrap, is_case_dir, parse_case_md,
                                     render_banner)
        state = wo.SessionState()
        schema_map = {t.name: (t.inputSchema or {}) for t in tools}
        evidence_paths: list[str] = []
        case_dir = os.environ.get("TRUDI_CASE_DIR") or os.getcwd()
        if is_case_dir(case_dir):
            info = parse_case_md(case_dir)
            boot = await bootstrap(client, info)
            evidence_paths = [p for p, _ in boot.evidence]
            print(render_banner(info, boot))
            state.case_context = (f"Case {info.case_id}. "
                                  f"Question: {info.question}")[:1500]
            state.resumed = boot.resumed
            state.items = wo.resume_items() if boot.resumed \
                else wo.ritual_items(info.question)
            print(wo.render(state, color=True))
        else:
            print("(no case dir — playground session, nothing recorded)")
        print(f"TRUDI pilot — {len(tools)} tools, tab completes "
              f"(names, params, paths); 'tools <substr>' lists, 'schema ns.tool' "
              f"shows params, ls/cd/!cmd navigate, '? <task>' drafts commands, 'advise' guidance, "
              f"'pick' checkboxes the work order, 'last' full payload, "
              f"'exit' quits")

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
        # Separate session for PROSE input (the summary). Passing a message
        # to prompt_async() PERSISTS it on the session (observed live: every
        # later prompt read "summary> "), and prose must not get tool-name
        # completion — so it gets its own session, not an override.
        prose_session = PromptSession(
            [("class:key", "summary> ")], style=PILOT_STYLE)

        def _prefill(suggestion: str) -> str:
            return prefill_command(suggestion, schema_map, evidence_paths)

        async def do_assess() -> None:
            """Call dair.assess with an editable auto-drafted summary, fold
            the returned work order + phase transition into the state."""
            if state.ran:
                print(f"  drafted summary of your last {len(state.ran)} "
                      f"call(s) — edit it, or press enter to send:")
                draft = wo.draft_summary(state)
                summary = (await prose_session.prompt_async(
                    default=draft)).strip() or draft
            else:
                summary = wo.opening_summary(state)
                print(f"  {_CYAN}summary:{_RESET} {summary}")
            print(f"  {_CYAN}calling dair.assess…{_RESET}", flush=True)
            try:
                result = await call_with_progress(client, "dair_assess", {
                    "tool_results_summary": summary,
                    "phase_stack": wo.phase_stack_json(state),
                    "case_context": state.case_context,
                    "input_call_ids": wo.ran_cids(state),
                }, label="dair.assess")
                payload = result.structured_content or {}
            except KeyboardInterrupt:
                return
            except Exception as e:
                print(f"{_RED}assess failed: {e}{_RESET}")
                return
            d = payload.get("directives")
            if isinstance(d, dict):
                d["priority_tools"] = filter_known(
                    d.get("priority_tools") or [], schema_map)
            wo.apply_assess(state, payload, prefill=_prefill)
            rationale = payload.get("transition_rationale") or ""
            if rationale:
                print(f" {_CYAN}dair:{_RESET} {rationale[:200]}")
            if not ((payload.get("directives") or {}).get("priority_tools")):
                print(f"{_YELLOW} dair returned no work order this round — "
                      f"proceed on your own judgment and assess again after "
                      f"running tools{_RESET}")
            print(wo.render(state, color=True))

        async def do_task(task_text: str) -> list[dict]:
            """Draft commands for a plain-English task via the reason
            backend; returns validated candidates."""
            nonlocal last_payload
            listing = ", ".join(sorted(os.listdir("analysis"))[:15]) \
                if os.path.isdir("analysis") else ""
            context = (f"case: {state.case_context}\n"
                       f"evidence files: {', '.join(evidence_paths) or '(none)'}\n"
                       f"produced output in analysis/: {listing or '(none)'}\n"
                       f"cwd: {os.getcwd()}")
            print(f"  {_CYAN}drafting commands…{_RESET}", flush=True)
            try:
                result = await call_with_progress(
                    client, "reason_draft_command",
                    {"task": task_text,
                     "tool_briefs": build_tool_briefs(task_text, tools),
                     "context": context,
                     "input_call_ids": wo.ran_cids(state)},
                    label="reason.draft_command")
                payload = result.structured_content or {}
                last_payload = payload
            except KeyboardInterrupt:
                return []
            except Exception as e:
                print(f"{_RED}draft failed: {e}{_RESET}")
                return []
            good = validate_candidates(payload.get("candidates") or [],
                                       schema_map)
            if not good:
                # sometimes the honest answer IS prose (a question, or a task
                # the tools can't do) — show it as an answer, not an error
                concl = (payload.get("conclusion") or "").strip()
                if concl:
                    print(f" {_CYAN}drafter:{_RESET}")
                    lines = concl.splitlines()
                    for ln in lines[:20]:
                        print(f"  {ln}")
                    if len(lines) > 20:
                        print(f"  {_YELLOW}… (`last` shows the rest){_RESET}")
                else:
                    print(f"{_YELLOW}no runnable command drafted{_RESET}")
            return good

        async def do_pick() -> list[str]:
            """Arrow/space checkbox over the open work order; checked items
            queue up to prefill one after another."""
            open_items = [i for i in state.items if i.status == "open"]
            if not open_items:
                print(f"{_YELLOW}no open work-order items to pick{_RESET}")
                return []
            from prompt_toolkit.shortcuts import checkboxlist_dialog
            picked = await checkboxlist_dialog(
                title="work order",
                text="↑/↓ move · space toggles · enter confirms · esc cancels",
                values=[(i.text, i.label[:70]) for i in open_items],
                default_values=[i.text for i in open_items],
            ).run_async()
            return list(picked) if picked else []

        async def do_advise(question: str) -> None:
            """Free-form guidance: package the session state, ask the reason
            backend, print the advice, merge suggested tools into the queue."""
            print(f"  {_CYAN}thinking…{_RESET}", flush=True)
            try:
                result = await call_with_progress(
                    client, "reason_advise",
                    {"question": question,
                     "situation": wo.build_situation(state),
                     "input_call_ids": wo.ran_cids(state)},
                    label="reason.advise")
                payload = result.structured_content or {}
            except KeyboardInterrupt:
                return
            except Exception as e:
                print(f"{_RED}advise failed: {e}{_RESET}")
                return
            advice = (payload.get("advice") or "").strip()
            if advice:
                print(f" {_CYAN}advice:{_RESET}")
                for ln in advice.splitlines():
                    print(f"  {ln}")
            else:
                print(f"{_YELLOW}no advice returned{_RESET}")
            pts = filter_known((payload.get("directives") or {})
                               .get("priority_tools") or [], schema_map)
            if pts and wo.merge_directives(state, pts, prefill=_prefill):
                print(wo.render(state, color=True))

        pending_default = ""
        pending_choices: list[dict] = []
        queued: list[str] = []
        last_payload = None
        while True:
            try:
                line = (await session.prompt_async(
                    default=pending_default)).strip()
                pending_default = ""
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            if line in ("exit", "quit"):
                break
            if line == "last":
                if last_payload is None:
                    print(f"{_YELLOW}no result yet{_RESET}")
                else:
                    print_result(last_payload, verbose=True)
                continue
            if line == "advise" or line.startswith("advise "):
                question = line.removeprefix("advise").strip() or \
                    "What should I do next?"
                await do_advise(question)
                continue
            # task drafting: plain English in, selectable commands out
            if line.startswith("?") or line.startswith("task "):
                task_text = line.lstrip("?").removeprefix("task").strip()
                if not task_text:
                    print(f"{_YELLOW}usage: ? <what you want done>{_RESET}")
                    continue
                cands = await do_task(task_text)
                if len(cands) == 1:
                    pending_default = cands[0]["command"]
                elif cands:
                    pending_choices = cands
                    for n, c in enumerate(cands, 1):
                        why = f"  — {c['why']}" if c.get("why") else ""
                        print(f" {_CYAN}▸{_RESET} {_BOLD}{n}{_RESET}  "
                              f"{c['command'][:74]}{why[:60]}")
                    print(f"   {_CYAN}type a number to prefill{_RESET}")
                continue
            # work-order interaction: number prefills, never auto-runs
            if line.isdigit():
                if pending_choices:
                    n = int(line)
                    if 1 <= n <= len(pending_choices):
                        pending_default = pending_choices[n - 1]["command"]
                    else:
                        print(f"{_YELLOW}no drafted command {line}{_RESET}")
                    pending_choices = []
                    continue
                text = wo.select(state, int(line))
                if text == "assess":
                    await do_assess()
                elif text:
                    pending_default = _prefill(text)
                else:
                    print(f"{_YELLOW}no open work-order item {line}{_RESET}")
                continue
            pending_choices = []
            if line == "pick":
                queued = await do_pick()
                if queued:
                    print(f"  {len(queued)} item(s) queued — each prefills "
                          f"after the previous run")
                    pending_default = queued.pop(0)
                continue
            if line in ("wo", "order"):
                print(wo.render(state, color=True))
                continue
            if line == "assess":
                await do_assess()
                continue
            if line.startswith("dismiss"):
                parts = line.split()
                if len(parts) != 3 or not parts[1].isdigit() or \
                        parts[2] not in wo.DISMISS_REASONS:
                    print(f"{_YELLOW}usage: dismiss N "
                          f"{{{'|'.join(wo.DISMISS_REASONS)}}}{_RESET}")
                    continue
                item = wo.dismiss(state, int(parts[1]), parts[2])
                if item is None:
                    print(f"{_YELLOW}no open work-order item {parts[1]}{_RESET}")
                    continue
                target = item.text.split()[0]
                try:
                    await client.call_tool("misc_record_disposition", {
                        "target_kind": "tool", "target_id": target,
                        "reason": parts[2],
                        "note": f"dismissed from pilot work order: {item.label}",
                    })
                    print(f"dismissed {target} ({parts[2]}) — recorded typed")
                except Exception as e:
                    print(f"{_RED}disposition failed: {e}{_RESET}")
                continue
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
            gaps = missing_required(tool, args, schema_map)
            if gaps:
                print(f"{_YELLOW}{line.split()[0]} needs: {', '.join(gaps)} "
                      f"— fill in the value and press enter{_RESET}")
                # re-prefill with guessed args where the line was bare, so the
                # buffer converges toward runnable instead of repeating
                pending_default = _prefill(line) if len(line.split()) == 1 else line
                continue
            try:
                result = await call_with_progress(client, tool, args,
                                                  label=line.split()[0])
                payload = result.structured_content
                last_payload = payload
                print_result(payload)
                ok = isinstance(payload, dict) and payload.get("success", True)
                cid = payload.get("_trudi_call_id") if isinstance(payload, dict) else None
                wo.record_ran(state, line, ok, cid)
                # Directive Binding: a reason.* result's priority_tools merge
                # into the queue (prefilled); DAIR's replace it at assess.
                if tool.startswith("reason_") and isinstance(payload, dict):
                    pts = filter_known((payload.get("directives") or {})
                                       .get("priority_tools") or [], schema_map)
                    if pts and wo.merge_directives(state, pts, prefill=_prefill):
                        print(wo.render(state, color=True))
                if wo.needs_nag(state):
                    print(f"{_YELLOW}{len(state.ran)} tools since the last "
                          f"assess — type `assess` to get the next work "
                          f"order{_RESET}")
                if queued:
                    pending_default = queued.pop(0)
                    print(f"  {_CYAN}next queued item prefilled "
                          f"({len(queued)} left){_RESET}")
            except KeyboardInterrupt:
                continue
            except Exception as e:
                print(f"{_RED}error: {e}{_RESET}")
                wo.record_ran(state, line, False)


if __name__ == "__main__":
    asyncio.run(run(stdio="--stdio" in sys.argv))
