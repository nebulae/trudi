"""Work-order state for the pilot REPL — the suggestion queue.

Pure logic, no I/O: the REPL renders and calls, this module tracks. The
queue holds DAIR `priority_tools` (or the Triage ritual on a fresh
session); items are selected by number (prefill, never auto-run), marked
done when a matching call succeeds, or dismissed with a typed disposition.
The phase stack follows the DAIR contract (push/pop/stay, newest last).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

DISMISS_REASONS = ("absent_from_evidence", "inapplicable", "out_of_scope")


@dataclass
class WorkItem:
    text: str                  # what lands in the buffer on selection
    label: str = ""            # short display; defaults to text
    status: str = "open"       # open | done | dismissed
    cue: str = ""              # provenance: dair | ritual | reason

    def __post_init__(self):
        self.label = self.label or self.text


@dataclass
class SessionState:
    case_context: str = ""
    phase_stack: list[dict] = field(default_factory=list)
    items: list[WorkItem] = field(default_factory=list)
    ran: list[dict] = field(default_factory=list)   # calls since last assess
    nag_after: int = 6
    resumed: bool = False   # trace existed at boot (resumption contract)
    last_phase: str = ""    # DAIR's current_phase — display fallback only;
                            # the stack itself moves only on push/pop

    @property
    def phase(self) -> str:
        if self.phase_stack:
            return self.phase_stack[-1]["phase"]
        return self.last_phase or "—"


def ritual_items(question: str) -> list[WorkItem]:
    """The Triage entry ritual as the opening queue of a fresh session."""
    q = (question or "<state the case question>").replace('"', "'")
    return [
        WorkItem(f'reason.hypothesize observation="{q}" '
                 f'hypothesis_kind=case_question',
                 label="reason.hypothesize — the case question first", cue="ritual"),
        WorkItem(f'reason.plan case_description="{q}" '
                 f'evidence_available="<paste the baseline reads>"',
                 label="reason.plan — after the baseline reads", cue="ritual"),
        WorkItem("assess", label="assess — engage DAIR (unlocks forensic tools)",
                 cue="ritual"),
    ]


def resume_items() -> list[WorkItem]:
    return [WorkItem("assess",
                     label="assess — resume contract: dair.assess with the "
                           "last-known phase stack", cue="ritual")]


def apply_assess(state: SessionState, payload: dict, prefill=None) -> None:
    """Fold a dair_assess result into the state: phase stack per the
    contract, open items replaced by the new work order. `prefill` maps a
    suggestion to a runnable command (args filled from schema/evidence)."""
    action = payload.get("stack_action") or "stay"
    nxt = payload.get("next_phase") or ""
    state.last_phase = payload.get("current_phase") or state.last_phase
    if action == "push" and nxt:
        state.phase_stack.append({
            "phase": nxt,
            "entry_reason": payload.get("transition_rationale", "") or "",
            "depth": len(state.phase_stack),
        })
    elif action == "pop" and state.phase_stack:
        state.phase_stack.pop()

    tools = (payload.get("directives") or {}).get("priority_tools") or []
    kept = [i for i in state.items if i.status != "open" or i.cue == "reason"]
    state.items = kept + [WorkItem(prefill(str(t)) if prefill else str(t),
                                   cue="dair") for t in tools]
    state.ran = []


def merge_directives(state: SessionState, suggestions: list[str],
                     prefill=None, cue: str = "reason") -> int:
    """Append priority_tools from a reason.* result to the queue (Directive
    Binding: reason directives merge, DAIR replaces). Items whose tool is
    already open are not duplicated. Returns how many were added."""
    open_heads = {i.text.split()[0] for i in state.items if i.status == "open"}
    added = 0
    for s in suggestions:
        head = str(s).split()[0] if str(s).split() else ""
        if not head or head in open_heads:
            continue
        text = prefill(str(s)) if prefill else str(s)
        state.items.append(WorkItem(text, cue=cue))
        open_heads.add(head)
        added += 1
    return added


def mark_done(state: SessionState, cmd: str) -> None:
    """A successful call retires the first open item it matches (by the
    item's leading token — DAIR suggestions are tool names, sometimes with
    prose after them)."""
    head = cmd.split()[0] if cmd.split() else ""
    if not head:
        return
    for item in state.items:
        if item.status == "open" and item.text.split()[0] == head:
            item.status = "done"
            return


def record_ran(state: SessionState, cmd: str, ok: bool, cid=None,
               headline: str = "") -> None:
    state.ran.append({"cmd": cmd, "ok": ok, "cid": cid, "headline": headline})
    if ok:
        mark_done(state, cmd)


def draft_summary(state: SessionState) -> str:
    """Auto-drafted tool_results_summary — the analyst edits before send."""
    if not state.ran:
        return "No tools run since the last assess."
    parts = []
    for r in state.ran[-12:]:
        head = r["cmd"].split()[0]
        mark = "ok" if r["ok"] else "FAILED"
        extra = f" — {r['headline']}" if r.get("headline") else ""
        parts.append(f"{head} {mark}{extra}")
    return f"Ran {len(state.ran)} tools: " + "; ".join(parts)


def opening_summary(state: SessionState) -> str:
    """The tool_results_summary for an assess with no calls to summarize —
    the contract's wording, nothing for the analyst to edit."""
    if state.resumed:
        return "Resuming after interruption — re-establishing phase state."
    return "Investigation starting — no tools run yet"


def ran_cids(state: SessionState) -> list:
    return [r["cid"] for r in state.ran if r.get("cid") is not None]


def select(state: SessionState, n: int) -> str | None:
    """1-based selection → the text to prefill, or None."""
    open_items = [i for i in state.items if i.status == "open"]
    if 1 <= n <= len(open_items):
        return open_items[n - 1].text
    return None


def dismiss(state: SessionState, n: int, reason: str) -> WorkItem | None:
    """Mark open item #n dismissed; caller records the typed disposition."""
    if reason not in DISMISS_REASONS:
        return None
    open_items = [i for i in state.items if i.status == "open"]
    if not (1 <= n <= len(open_items)):
        return None
    item = open_items[n - 1]
    item.status = "dismissed"
    return item


def _fit(label: str, width: int = 74) -> str:
    """Middle-ellipsize: a truncated path must keep its FILENAME visible."""
    if len(label) <= width:
        return label
    return label[: width - 30] + "…" + label[-29:]


def render(state: SessionState, color: bool = False) -> str:
    b = "\x1b[1m" if color else ""       # bold
    c = "\x1b[36m" if color else ""      # cyan
    g = "\x1b[32m" if color else ""      # green
    r = "\x1b[0m" if color else ""
    lines = [f"{c}{b} work order ── {state.phase} "
             f"(depth {len(state.phase_stack)}) ────────────────────────{r}"]
    shown = 0
    for item in state.items:
        if item.status == "dismissed":
            continue
        if item.status == "done":
            lines.append(f"   {g}✓{r}  {_fit(item.label)}")
        else:
            shown += 1
            lines.append(f" {c}▸{r} {b}{shown}{r}  {_fit(item.label)}")
    if shown == 0:
        lines.append("   (no open items — investigate on your judgment; "
                     "assess again after running tools)")
    lines.append(f"   {c}type a number to prefill · assess · "
                 f"dismiss N <reason> · wo{r}")
    return "\n".join(lines)


def phase_stack_json(state: SessionState) -> str:
    return json.dumps(state.phase_stack)


def needs_nag(state: SessionState) -> bool:
    return len(state.ran) >= state.nag_after
