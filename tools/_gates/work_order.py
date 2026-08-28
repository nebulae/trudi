"""Work-order completion — block-late at reason.pre_report_check.

The DAIR-batch gate refuses a forensic tool when no dair_assess is active. That
refusal is a signal, not a dead end: the agent is meant to call dair_assess and
re-run the tool. The recurring failure it guards against is the tool being
*dropped* after the single refusal (the investigation moves on and never runs it).

Because a blocked tool now leaves a `tool_blocked` audit entry
(core.middleware + ExecutionLog.record_tool_blocked), this check can flag a tool
that was blocked and then neither re-run nor dispositioned: at report time, every
`tool_blocked` whose binary signature never appears in a later successful
tool_call cmd — and which was not settled by a TYPED disposition
(misc.record_disposition(target_kind="tool", …)) — becomes a blocking issue.
Deterministic; block-late only. Prose ("inapplicable") is not read.
"""
from __future__ import annotations

from tools import _fk

from ._dispositions import SOURCE_WAIVER_REASONS_ALL, index_from_entries


# MCP tools whose wrapped binary is named differently from the 2nd segment of
# the tool name (the fallback derivation below). The signature is matched as a
# substring of a later successful tool_call cmd, so it must be a keyword that
# actually appears in the executed command line — without the alias, a tool
# that DID run reads as never-run and the work-order gate stalls the phase on
# it (misc.regripper_hive runs `rip.pl`; plaso tools run log2timeline/psort/
# pinfo). Keyed on the NORMALIZED (de-doubled) tool name.
_BINARY_ALIASES = {
    "misc_regripper_hive":          "rip.pl",
    "misc_regripper_list_plugins":  "rip.pl",
    "plaso_create_timeline":        "log2timeline",
    "plaso_create_targeted":        "log2timeline",
    "plaso_list_parsers":           "log2timeline",
    "plaso_export_csv":             "psort",
    "plaso_export_json":            "psort",
    "plaso_filter_incident_window": "psort",
    "plaso_info":                   "pinfo",
}


def _binary_sig(tool: str) -> str:
    """The binary keyword that shows up in a later successful tool_call cmd for a
    given MCP tool name — normally the FIRST segment after the namespace prefix
    (ez_sbecmd→'sbecmd', ez_recmd_hive→'recmd', vol_pslist→'pslist'). For tools
    whose wrapped binary is named differently, an explicit alias maps to the
    keyword the command actually contains (misc_regripper_hive→'rip.pl',
    plaso_create_timeline→'log2timeline'). Handles the namespace-doubled form the
    middleware passes ('ez_ez_sbecmd').

    A verbose model may append call arguments to the tool name
    (`tsk.fls(input_path=..., depth=2)`); the arguments are not part of the
    tool identity and corrupt the derived signature ('fls(input' matches no
    command), deadlocking the work-order gate on a tool that ran. Strip any
    trailing `(...)` or space-args first; since tool_waived also matches on
    _binary_sig, a plain `tsk.fls` disposition waives the arg-laden token too."""
    raw = (tool or "").strip().split("(", 1)[0]     # drop appended (args…)
    raw = (raw.split() or [""])[0]                   # drop any trailing space-args
    n = _fk.normalize_tool_name(raw.lower().replace(".", "_"))
    if n in _BINARY_ALIASES:
        return _BINARY_ALIASES[n]
    parts = [p for p in n.split("_") if p]
    if len(parts) >= 2:
        return parts[1]
    return parts[0] if parts else ""


def _display(tool: str) -> str:
    n = _fk.normalize_tool_name((tool or "").strip().lower().replace(".", "_"))
    return n.replace("_", ".", 1) if "_" in n else n


_CONTROL_PLANE_TOOLS = frozenset({
    "misc.start_execution_log", "misc.export_execution_log", "misc.write_final_report",
    "misc.serve_dashboard", "misc.clear_case_run",
})


def _control_plane_tool(tool: str) -> bool:
    """record_finding / record_disposition / export … are control-plane calls;
    a phase-gate block on one is not a dropped forensic work-order item (an
    agent must not clear this check by dispositioning a control-plane call as
    'inapplicable')."""
    d = _display(tool)
    base = d.split(".", 1)[-1]
    return (d in _CONTROL_PLANE_TOOLS or base.startswith("record_")
            or d.startswith(("reason.", "dair.", "monitor.", "accuracy.", "coverage.")))


def tool_waived(didx, tool: str) -> bool:
    """A typed disposition settles the tool: target_kind="tool", target_id any
    spelling of the MCP tool (ez.pecmd / ez_pecmd / ez_ez_pecmd), reason
    inapplicable | absent_from_evidence | out_of_scope."""
    sig = _binary_sig(tool)
    table = getattr(didx, "dispositions", None) or {}
    for (kind, _norm), rows in table.items():
        if kind != "tool":
            continue
        for d in rows:
            if str(d.get("reason") or "").lower() not in SOURCE_WAIVER_REASONS_ALL:
                continue
            if _binary_sig(str(d.get("target_id") or "")) == sig:
                return True
    return False


def _failed_tool_items(entries) -> list:
    """(index, pseudo-entry) per FAILED MCP forensic tool call — same closure
    duty as a gate-blocked tool: a capability gap must be retried,
    replaced, or typed-dispositioned, never silently dropped. Agent-side bash
    (source claude_code_*) and control-plane calls are out of scope."""
    out = []
    for i, e in enumerate(entries or []):
        if e.get("type") != "tool_call" or e.get("success") is not False:
            continue
        cmd = str(e.get("cmd") or "")
        if not cmd or cmd.startswith("<py>:"):
            continue
        if str(e.get("source") or "").startswith("claude_code_"):
            continue
        toks = cmd.split()
        dll = next((t for t in toks if t.lower().endswith(".dll")), "")
        if dll:
            tool = dll.rsplit("/", 1)[-1][:-4]           # PECmd.dll → PECmd
        else:
            tool = toks[0].rsplit("/", 1)[-1]
        if tool and tool.lower() not in ("dotnet", "python3", "python", "sudo"):
            out.append((i, {"tool": tool, "_failed": True}))
    return out


def unrun_from_list(entries, tools) -> list:
    """Which of `tools` (a single priority_tools work order) were never run
    successfully anywhere nor typed-dispositioned — display names. Control-plane /
    reason.* / coverage.* entries and sub-3-char signatures are excluded. Used by
    the per-transition work-order gate; unrun_priority_tools applies the same
    logic across the whole trace."""
    if not tools:
        return []
    succ_cmds = [(e.get("cmd") or "").lower() for e in entries
                 if e.get("type") == "tool_call" and e.get("success") is not False and e.get("cmd")]
    succ_tools = [str(e.get("tool") or "").lower().replace(".", "_") for e in entries
                  if e.get("type") in ("reason_call", "tool_call") and e.get("success") is not False]
    didx = index_from_entries(entries)
    out: list = []
    seen: set = set()
    for t in tools:
        t = str(t)
        if _control_plane_tool(t):
            continue
        sig = _binary_sig(t)
        if len(sig) < 3 or sig in seen:
            continue
        seen.add(sig)
        if any(sig in c for c in succ_cmds) or any(sig in tt for tt in succ_tools) \
                or tool_waived(didx, t):
            continue
        out.append(_display(t))
    return out


def unrun_priority_tools(entries) -> list:
    """Block-late: every FORENSIC tool DAIR prescribed in a priority_tools
    work order (directives.priority_tools on any dair_call) must have run
    successfully somewhere in the trace OR be typed-dispositioned. This catches
    a DAIR steamroll — pushing through Collect/Analyze/Scan/Report while
    discarding the prescribed work orders (phase-coverage counts phase *entry*,
    not phase *work*). Control-plane / reason.* / dair.* / coverage.* calls are excluded
    (they are not forensic collection). Symmetric: running OR dispositioning a
    prescribed tool clears it; it never favours a finding either way. Because it
    matches by binary signature anywhere in the trace, a legitimate front-load
    (the tool ran in an earlier phase) passes — only genuinely-skipped work is
    flagged."""
    prescribed: dict = {}          # binary sig -> display name (first seen)
    for e in entries or []:
        if e.get("type") != "dair_call":
            continue
        pt = ((e.get("directives") or {}).get("priority_tools")) or e.get("priority_tools") or []
        if not isinstance(pt, list):
            continue
        for t in pt:
            t = str(t)
            if _control_plane_tool(t):
                continue
            sig = _binary_sig(t)
            if len(sig) < 3:
                continue
            prescribed.setdefault(sig, _display(t))
    if not prescribed:
        return []
    succ_cmds = [(e.get("cmd") or "").lower() for e in entries
                 if e.get("type") == "tool_call" and e.get("success") is not False and e.get("cmd")]
    succ_tools = [str(e.get("tool") or "").lower().replace(".", "_") for e in entries
                  if e.get("type") in ("reason_call", "tool_call") and e.get("success") is not False]
    didx = index_from_entries(entries)
    missing = [disp for sig, disp in sorted(prescribed.items())
               if not (any(sig in c for c in succ_cmds) or any(sig in t for t in succ_tools)
                       or tool_waived(didx, disp))]
    if not missing:
        return []
    shown = ", ".join(missing[:12])
    return [
        f"{len(missing)} tool(s) DAIR prescribed in a priority_tools work order were "
        f"never run or dispositioned: {shown}{' …' if len(missing) > 12 else ''}. A phase "
        f"is entered to execute its work order, not to be passed through — run each, or "
        f"settle it with misc.record_disposition(target_kind=\"tool\", target_id=\"<tool>\", "
        f"reason=\"inapplicable\"|\"absent_from_evidence\"|\"out_of_scope\") before Report."
    ]


def unretried_blocks(entries) -> list:
    """Block-late issue strings: one per tool that was blocked OR FAILED and
    never re-run successfully nor dispositioned. `entries` is log._entries."""
    blocked = [(i, e) for i, e in enumerate(entries or [])
               if e.get("type") == "tool_blocked" and e.get("tool")]
    blocked += _failed_tool_items(entries)
    if not blocked:
        return []

    later_cmds = [(i, (e.get("cmd") or "").lower())
                  for i, e in enumerate(entries or [])
                  if e.get("type") == "tool_call" and e.get("success") is not False
                  and e.get("cmd")]
    didx = index_from_entries(entries)

    issues: list = []
    seen: set = set()
    for idx, e in blocked:
        tool = e.get("tool", "")
        if _control_plane_tool(tool):
            continue
        sig = _binary_sig(tool)
        if len(sig) < 3 or sig in seen:
            continue
        seen.add(sig)
        # Re-run: the binary signature appears in a successful tool_call after the
        # block (a later dair_assess + retry produces exactly such a cmd).
        retried = any(j > idx and sig in cmd for j, cmd in later_cmds)
        # Waived: a typed tool disposition settles it (prose is not read).
        waived = tool_waived(didx, tool)
        if not retried and not waived and e.get("_failed"):
            issues.append(
                f"Tool {_display(tool)} FAILED and was never re-run successfully, "
                f"replaced, or dispositioned — a failed capability is an audit "
                f"obligation, not a dead end. Retry it, run a named fallback and "
                f"record why, or misc.record_disposition(target_kind=\"tool\", "
                f"target_id=\"{_display(tool)}\", reason=\"inapplicable\"|"
                f"\"absent_from_evidence\") before Report."
            )
            continue
        if not retried and not waived:
            issues.append(
                f"Tool {_display(tool)} was blocked (no active DAIR batch) and never "
                f"re-run or dispositioned — a blocked tool is a deferred work-order "
                f"item, not a dead end. Call dair_assess and re-run it, or record "
                f'misc.record_disposition(target_kind="tool", target_id="{_display(tool)}", '
                f'reason="inapplicable"|"absent_from_evidence") before Report.'
            )
    return issues
