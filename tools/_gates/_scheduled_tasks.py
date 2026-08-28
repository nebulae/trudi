"""Scheduled-task / autorun enumeration — the persistence look a keystroke
injector's traces require.

A BadUSB injects keystrokes that create an account AND typically a scheduled
task / autorun; with task-auditing off there is NO 4698 event, so an
event-log-only investigation cannot see it. The task exists only as an
on-disk XML (\\Windows\\System32\\Tasks) or in the SOFTWARE TaskCache. This
module decides, from the trace, whether that enumeration actually happened —
so a creation/persistence/ownership verdict (in either direction) cannot skip
it. Symmetric: enumerating may equally exonerate (no malicious task).
"""
from __future__ import annotations

import re

# A tool call that ENUMERATES scheduled tasks (over cmd — what ran).
TASK_ENUM_RE = re.compile(
    r"parse_scheduled_tasks|scheduled_tasks|schtask|taskcache"
    r"|[\\/]System32[\\/]Tasks|[\\/]Tasks[\\/]|vol[^\n]*scheduled",
    re.IGNORECASE)

# Keystroke-injector PAYLOAD signatures in a task/autorun command.
# %duck%/%bunny% are the Hak5 Rubber Ducky / Bash Bunny payload env vars; a
# hidden PowerShell whose -file lives on an env-var/removable drive is the
# classic injected-recon shape. Presence flags a payload; absence supports the
# benign reading — a lead, never a verdict.
INJECTOR_PAYLOAD_RE = re.compile(
    r"%duck%|%bunny%|\bhak5\b|ducky|bashbunny|bash[\s_-]?bunny"
    r"|-w(?:indowstyle)?\s+hidden|-nop\b|-noprofile\b|-enc(?:odedcommand)?\b"
    r"|frombase64string",
    re.IGNORECASE)


def _tool_calls(entries):
    return [e for e in (entries or []) if isinstance(e, dict)
            and e.get("type") == "tool_call" and e.get("success")]


def tasks_examined(entries, idx=None) -> bool:
    """True when the trace shows a scheduled-task enumeration ran, OR a typed
    source disposition (scheduled_tasks) settles it as absent/inapplicable."""
    for e in _tool_calls(entries):
        if TASK_ENUM_RE.search(str(e.get("cmd") or "")):
            return True
    if idx is not None:
        try:
            from ._dispositions import find_disposition, SOURCE_WAIVER_REASONS_ALL
            if find_disposition(idx, "source", "scheduled_tasks",
                                reasons=SOURCE_WAIVER_REASONS_ALL) is not None:
                return True
        except Exception:
            pass
    return False


def flagged_injector_present(entries) -> bool:
    """A structured device-install inventory flagged a keystroke-injector."""
    for e in _tool_calls(entries):
        if e.get("device_install_inventory") and int(e.get("flagged_count") or 0) > 0:
            return True
    return False


def flagged_payload_tasks(entries) -> list:
    """Task names a scheduled-task enumeration flagged as carrying keystroke-
    injector payload signatures (the injector_payload_tasks marker stamped by
    misc.parse_scheduled_tasks). A flagged payload task is direct evidence that
    injection actually ran — stronger than a merely HID-capable device."""
    out: list = []
    for e in _tool_calls(entries):
        ipt = e.get("injector_payload_tasks")
        if isinstance(ipt, list):
            out.extend(str(t) for t in ipt if t)
    seen: set = set()
    return [t for t in out if not (t in seen or seen.add(t))]
