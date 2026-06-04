"""Execution trace log — records tool calls, reason calls, and findings per case."""
import fcntl
import json
import os
import sys
import tempfile
import threading
import datetime
from dataclasses import dataclass, field
from typing import Optional

# Shared lock file with the PostToolUse hook. Both writers acquire this
# exclusive lock around their read-merge-write cycles so they never lose
# each other's entries to a race.
_TRACE_LOCK_FILE = os.path.expanduser("~/.cache/trudi/hook.lock")
# Shared call_id counter — single monotonic sequence across MCP server + hook
# so call_ids are dense and reflect global write order.
_CALL_ID_COUNTER_FILE = os.path.expanduser("~/.cache/trudi/call_id.counter")


def _scan_trace_max_cid(trace_path: str) -> int:
    """Return max call_id present in the trace file, or 0 if missing/empty."""
    if not trace_path or not os.path.exists(trace_path):
        return 0
    try:
        with open(trace_path) as f:
            existing = json.load(f).get("entries", []) or []
        if not existing:
            return 0
        return max(int(e.get("call_id", 0) or 0) for e in existing)
    except (OSError, ValueError, json.JSONDecodeError, TypeError):
        return 0


def _next_shared_call_id(trace_path: Optional[str] = None, in_memory_seq: int = 0) -> int:
    """Atomically increment and return the next shared call_id.

    Both the MCP server (this module) and the PostToolUse hook
    (~/.claude/hooks/log_narration.py) call this so call_ids form a single
    dense monotonic sequence across both writers.

    Returns `max(counter_file, trace_max+1, in_memory_seq+1)` — so even if the
    counter file is stale (hand-edited, race-reset between writers, lost) the
    returned cid is provably greater than any cid present in the trace OR in
    the calling process's in-memory ExecutionLog state. Duplicates become
    impossible by construction; the counter file becomes a fast-path *cache*,
    not a source of truth.
    """
    os.makedirs(os.path.dirname(_TRACE_LOCK_FILE), exist_ok=True)
    lock_fp = open(_TRACE_LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        # Read counter file (the cheap fast path)
        try:
            with open(_CALL_ID_COUNTER_FILE) as f:
                counter_n = int(json.load(f).get("next", 1))
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            counter_n = 1
        # Validate counter against actual on-disk + in-memory state.
        # in_memory_seq is the calling ExecutionLog's last assigned cid; the
        # trace scan is the cross-process safety net (e.g. for the hook).
        trace_max = _scan_trace_max_cid(trace_path) if trace_path else 0
        n = max(counter_n, trace_max + 1, in_memory_seq + 1)
        if n != counter_n:
            # Stale counter detected — log once so corruption is visible.
            print(
                f"[TRUDI WARN] _next_shared_call_id: stale counter file "
                f"(was {counter_n}, returning {n}; trace_max={trace_max} "
                f"in_memory_seq={in_memory_seq})",
                file=sys.stderr,
            )
        tmp = _CALL_ID_COUNTER_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"next": n + 1}, f)
        os.replace(tmp, _CALL_ID_COUNTER_FILE)
        return n
    finally:
        try:
            fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock_fp.close()

# Written on every configure() so the singleton can auto-recover after a server restart.
_SESSION_FILE = os.path.expanduser("~/.cache/trudi/session.json")


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _warn(msg: str) -> None:
    print(f"[TRUDI WARN] {msg}", file=sys.stderr)


def _build_phase_index(entries: list[dict]) -> list[dict]:
    """Walk entries once; return phase blocks for TOC + transition headers.

    Each block: {phase, start_cid, end_cid, anchor}. A phase begins at the first
    dair_call announcing it and continues until the next dair_call shows a
    different current_phase (or the trace ends).
    """
    blocks: list[dict] = []
    current_phase = ""
    current_block: dict | None = None
    phase_count: dict[str, int] = {}
    for e in entries:
        if e.get("type") == "dair_call":
            phase = e.get("current_phase", "") or "unknown"
            cid = e.get("call_id", 0)
            if phase != current_phase:
                if current_block:
                    current_block["end_cid"] = cid - 1
                phase_count[phase] = phase_count.get(phase, 0) + 1
                anchor = f"phase-{phase.lower()}-{phase_count[phase]}"
                current_block = {
                    "phase": phase,
                    "start_cid": cid,
                    "end_cid": entries[-1].get("call_id", cid) if entries else cid,
                    "anchor": anchor,
                }
                blocks.append(current_block)
                current_phase = phase
    if current_block and entries:
        current_block["end_cid"] = entries[-1].get("call_id", current_block["start_cid"])
    return blocks


def _render_entries(case_id: str | None, entries: list[dict]) -> str:
    """Shared markdown renderer used by both to_markdown() and export()."""
    lines = [f"# Execution Trace — {case_id or 'unknown'}\n"]

    # Markdown navigability: Table of Contents listing phases encountered.
    phase_blocks = _build_phase_index(entries)
    if phase_blocks:
        lines.append("## Contents\n")
        for blk in phase_blocks:
            lines.append(
                f"- [{blk['phase']}](#{blk['anchor']}) — entries #{blk['start_cid']}–#{blk['end_cid']}"
            )
        lines.append("")

    # Markdown navigability: lookup table for evidence-chain rendering on
    # finding entries.
    by_call_id = {e.get("call_id"): e for e in entries if e.get("call_id")}
    phase_start_set = {(blk["start_cid"], blk["anchor"], blk["phase"]) for blk in phase_blocks}
    phase_start_by_cid = {start_cid: (anchor, phase) for start_cid, anchor, phase in phase_start_set}

    for e in entries:
        ts = e.get("ts", "")
        t = e.get("type", "")
        cid = e.get("call_id", "")
        prefix = f"[#{cid}] " if cid else ""
        # Markdown navigability: emit a phase anchor + header right before
        # its starting dair_call.
        if cid in phase_start_by_cid:
            anchor, phase = phase_start_by_cid[cid]
            lines.append(f"\n<a id=\"{anchor}\"></a>")
            lines.append(f"## Phase: {phase}\n")
        if t == "tool_call":
            if e.get("timed_out"):
                status = "TIMEOUT"
            elif e.get("success"):
                status = "OK"
            else:
                status = "FAIL"
            retries = f" ({e['retries']} retries)" if e.get("retries") else ""
            trunc = " [TRUNCATED]" if e.get("truncated") else ""
            elapsed = f" {e['elapsed_seconds']}s" if e.get("elapsed_seconds") else ""
            violation = f" ⚠ PROTOCOL_VIOLATION: {e['protocol_violation']}" if e.get("protocol_violation") else ""
            lines.append(f"- `{ts}` {prefix}**TOOL** `{e.get('cmd', '')}`  → {status}{retries}{trunc}{elapsed}{violation}")
            if not e.get("success") and e.get("stderr"):
                lines.append(f"  - stderr: {e['stderr'][:200]}")
            if e.get("stdout_excerpt"):
                lines.append(f"  - output: {e['stdout_excerpt'][:300]}")
        elif t == "reason_call":
            status = "OK" if e.get("success") else "FAIL"
            tok_in = e.get("input_tokens", 0)
            tok_out = e.get("output_tokens", 0)
            tok_str = f" tokens: in={tok_in} out={tok_out}" if tok_in or tok_out else ""
            lines.append(f"- `{ts}` {prefix}**REASON** `{e.get('tool', '')}`  → {status}{tok_str}")
            if e.get("conclusion"):
                lines.append(f"  - conclusion: {e['conclusion'][:400]}")
            if e.get("directives", {}).get("priority_tools"):
                lines.append(f"  - priority_tools: {e['directives']['priority_tools']}")
            for i, audit in enumerate(e.get("evidence_audit") or []):
                not_provided = sum(
                    1 for v in audit.values()
                    if isinstance(v, str) and v.upper() == "NOT PROVIDED"
                )
                flag = f" ⚠ {not_provided}×NOT_PROVIDED" if not_provided >= 2 else ""
                lines.append(
                    f"  - audit[{i}]: claim=\"{audit.get('claim', '')[:80]}\" "
                    f"tool={audit.get('tool', '?')}{flag}"
                )
        elif t == "call_initiated":
            backend = e.get("backend", "")
            inputs = e.get("inputs", {})
            input_str = " ".join(f"{k}={str(v)[:40]!r}" for k, v in inputs.items())
            lines.append(
                f"- `{ts}` {prefix}**→ CALL** `{e.get('tool', '')}` "
                f"via {backend} [{input_str}]"
            )
        elif t == "call_abandoned":
            lines.append(
                f"- `{ts}` {prefix}**✗ ABANDONED** `{e.get('tool', '')}` "
                f"reason: {e.get('reason', '')[:200]}"
            )
        elif t == "dair_call":
            phase = e.get("current_phase", "")
            next_p = e.get("next_phase", "")
            action = e.get("stack_action", "stay")
            transition = e.get("transition_recommended", False)
            rationale = e.get("transition_rationale") or e.get("phase_rationale", "")
            if e.get("verification_satisfied"):
                lines.append("\n---\n### ✓ Verification Satisfied")
                lines.append("*Core IOCs verified — residual uncertainty accepted. Transitioning to Scope.*\n---")
            if transition and next_p:
                if action == "push" and next_p == "Verification":
                    lines.append(f"\n---\n### ↳ Verification — Internal Challenge")
                    lines.append(f"*Reason: {rationale[:200]}*\n---")
                elif action == "pop":
                    lines.append(f"\n---\n### ↑ Returning to: {next_p}")
                    lines.append(f"*Verification complete — resuming {next_p}*\n---")
                else:
                    lines.append(f"\n---\n### Phase Transition: {phase} → {next_p}")
                    lines.append(f"*Reason: {rationale[:200]}*\n---")
            else:
                tok_in, tok_out = e.get("input_tokens", 0), e.get("output_tokens", 0)
                tok_str = f" tokens: in={tok_in} out={tok_out}" if tok_in or tok_out else ""
                lines.append(
                    f"- `{ts}` {prefix}**DAIR** phase={phase} action={action}{tok_str}"
                )
            if e.get("investigation_focus"):
                lines.append(f"  - focus: {e['investigation_focus'][:200]}")
            challenges = e.get("verification_challenges") or []
            if challenges:
                lines.append("  \n  #### Verification Challenges")
                lines.append("  | Claim | Method | Result | Confidence Impact |")
                lines.append("  |-------|--------|--------|-------------------|")
                for c in challenges:
                    claim = c.get("claim", "")[:60]
                    method = c.get("challenge_method", "")[:40]
                    verified = c.get("verified")
                    impact = c.get("confidence_impact", "—")
                    if verified is True:
                        result_str = "✓ CONFIRMED"
                    elif verified is False:
                        result_str = f"✗ REFUTED — {c.get('notes', '')[:40]}"
                    else:
                        result_str = "⏳ PENDING"
                    lines.append(f"  | {claim} | {method} | {result_str} | {impact} |")
            rec = e.get("recommended_actions") or []
            if rec:
                lines.append("  \n  **Recommended Actions (for IR team):**")
                for item in rec:
                    lines.append(f"  - {item}")
        elif t == "investigation_narration":
            refs = (
                f" [from #{', #'.join(str(i) for i in e['input_call_ids'])}]"
                if e.get("input_call_ids") else ""
            )
            lines.append(f"- `{ts}` {prefix}**AGENT**{refs} {e.get('content', '')[:300]}")
        elif t == "finding":
            conf = e.get("confidence", "").upper()
            linked = e.get("linked_call_id", 0)
            link_str = f" ← tool call #{linked}" if linked else ""
            lines.append(f"- `{ts}` {prefix}**FINDING** [{conf}] {e.get('description', '')}{link_str}")
            if e.get("source"):
                lines.append(f"  - source: {e['source']}")
            if e.get("tested_hypothesis_id"):
                lines.append(f"  - tests hypothesis: {e['tested_hypothesis_id']}")
            # Markdown navigability: Evidence Chain — render the linked
            # tool/reason entry inline.
            linked_entry = by_call_id.get(linked) if linked else None
            if linked_entry:
                ltype = linked_entry.get("type", "")
                if ltype == "tool_call":
                    cmd = (linked_entry.get("cmd") or "")[:80]
                    succ = "OK" if linked_entry.get("success") else "FAIL"
                    excerpt = (linked_entry.get("stdout_excerpt") or "")[:200]
                    lines.append(f"  - **Evidence Chain:** call #{linked} (`{cmd}`) — {succ}")
                    if excerpt:
                        lines.append(f"    - excerpt: {excerpt}")
                elif ltype == "reason_call":
                    rtool = linked_entry.get("tool", "")
                    lines.append(f"  - **Evidence Chain:** call #{linked} (reason `{rtool}`)")
        elif t == "self_correction":
            trigger = e.get("trigger", "")
            linked = e.get("linked_call_id", 0)
            link_str = f" (from #{linked})" if linked else ""
            lines.append(f"\n- `{ts}` {prefix}**🔄 SELF-CORRECTION** trigger: `{trigger}`{link_str}")
            if e.get("prior_belief"):
                lines.append(f"  - **prior:** {e['prior_belief'][:300]}")
            if e.get("new_belief"):
                lines.append(f"  - **revised:** {e['new_belief'][:300]}")
            if e.get("evidence"):
                lines.append(f"  - **evidence:** {e['evidence'][:300]}")
        else:
            lines.append(f"- `{ts}` {prefix}**[UNKNOWN TYPE: {t}]** {json.dumps(e)[:120]}")
    return "\n".join(lines) + "\n"


@dataclass
class LogIndex:
    """Pre-computed lookups over the entries list. Built lazily by
    ExecutionLog.index() and invalidated whenever an entry is appended
    (cheap version-counter check on access)."""
    by_call_id: dict[int, dict] = field(default_factory=dict)
    by_type: dict[str, list[dict]] = field(default_factory=dict)
    by_tool: dict[str, list[dict]] = field(default_factory=dict)
    findings_by_linked: dict[int, list[dict]] = field(default_factory=dict)
    hypotheses_by_id: dict[str, dict] = field(default_factory=dict)

    def recent(self, type_filter: str, window: list[dict]) -> list[dict]:
        """Return entries in `window` (a slice of recent entries) matching type_filter."""
        return [e for e in window if e.get("type") == type_filter]


def _extract_tool_from_entry(entry: dict) -> str:
    """Pick the canonical tool name for index lookup. Prefers explicit
    `tool` field (reason/dair calls); falls back to first token of `cmd`
    for tool_call entries — useful for `idx.by_tool['vol']`, etc."""
    tool = entry.get("tool")
    if tool:
        return tool
    cmd = entry.get("cmd") or ""
    if not cmd:
        return ""
    first = cmd.split()[0] if cmd else ""
    # Strip path prefix for binaries like /usr/local/bin/vol
    return os.path.basename(first)


class ExecutionLog:
    def __init__(self):
        self._entries: list[dict] = []
        self._path: Optional[str] = None
        self._case_id: Optional[str] = None
        self._seq: int = 0
        self._lock = threading.RLock()
        # DAIR phase state — the active phase + stack at write time. Each
        # record_* call stamps these onto its entry via _append_entry. State
        # is updated when record_dair_call processes a transition.
        self._current_phase: str = ""
        self._phase_stack: list[dict] = []   # [{phase, entry_reason, depth}, …]
        # call_id of the most recently completed dair_assess. Every tool call,
        # narration, and exception entry reads this and carries it as
        # input_call_ids so the trace forms a proper causal DAG:
        #   dair_call → [tool_calls, narrations, reason_calls] → findings
        # Reset to 0 on configure() so a new case starts without stale context.
        self._last_dair_cid: int = 0
        # Lazy index cache — bumped on every mutation; rebuild on next index() call.
        self._index_version: int = 0
        self._cached_index: Optional[tuple[int, LogIndex]] = None

    def _next_id(self) -> int:
        # Shared counter across MCP server + PostToolUse hook so call_ids form
        # a single dense monotonic sequence. _next_shared_call_id validates the
        # counter against the on-disk trace AND our in-memory seq, so a stale
        # counter file (e.g. hand-edited or race-reset) can never produce a
        # duplicate cid.
        cid = _next_shared_call_id(self._path, in_memory_seq=self._seq)
        self._seq = cid  # kept for introspection / tests
        return cid

    def _append_entry(self, entry: dict) -> None:
        """Append `entry` and flush. Must be called under self._lock.

        Stamps `dair_phase` + `dair_depth` when phase state is known.
        setdefault() so callers can override (e.g. dair_call post-transition).
        """
        if self._current_phase:
            entry.setdefault("dair_phase", self._current_phase)
            entry.setdefault("dair_depth", len(self._phase_stack))
        self._entries.append(entry)
        self._index_version += 1
        self._flush()

    def index(self) -> LogIndex:
        """Return memoized indices over self._entries.

        First call after any append rebuilds in O(n); subsequent calls in O(1)
        until the next mutation. Used by gate checks, correlate.*, attribution,
        coverage_report — anywhere the trace needs to be queried by call_id,
        type, tool, or hypothesis_id.
        """
        with self._lock:
            if self._cached_index is not None and self._cached_index[0] == self._index_version:
                return self._cached_index[1]
            idx = LogIndex()
            for e in self._entries:
                cid = e.get("call_id")
                if cid is not None:
                    idx.by_call_id[cid] = e
                t = e.get("type") or ""
                if t:
                    idx.by_type.setdefault(t, []).append(e)
                tool = _extract_tool_from_entry(e)
                if tool:
                    idx.by_tool.setdefault(tool, []).append(e)
                if t == "finding":
                    linked = e.get("linked_call_id") or 0
                    if linked:
                        idx.findings_by_linked.setdefault(linked, []).append(e)
                if t == "reason_call" and e.get("tool") == "reason_hypothesize":
                    hid = e.get("hypothesis_id")
                    if hid:
                        idx.hypotheses_by_id[hid] = e
            self._cached_index = (self._index_version, idx)
            return idx

    def last_n_window(self, n: int = 30) -> list[dict]:
        """Return the last n entries — used by gate checks for bounded look-back."""
        with self._lock:
            if len(self._entries) > n:
                return list(self._entries[-n:])
            return list(self._entries)

    def _apply_dair_transition(self, current_phase: str, stack_action: str,
                                next_phase: str, transition_rationale: str,
                                verification_satisfied: bool) -> None:
        """Update phase state based on a dair_call's declared transition.
        Must be called under self._lock, before the dair_call is appended.

        Returns nothing — mutates self._current_phase and self._phase_stack so
        the dair_call's own entry (and every subsequent entry) is stamped with
        the post-transition phase.
        """
        sa = (stack_action or "stay").lower()
        if sa == "push" and next_phase:
            self._phase_stack.append({
                "phase": next_phase,
                "entry_reason": transition_rationale or "",
                "depth": len(self._phase_stack),
            })
            self._current_phase = next_phase
        elif sa == "pop":
            # If the dair_call names a `next_phase`, pop until that phase is
            # at the top — this matches the agent's mental model ("I'm popping
            # back to Report") rather than blindly popping a single frame.
            if next_phase and self._phase_stack:
                while self._phase_stack and self._phase_stack[-1]["phase"] != next_phase:
                    self._phase_stack.pop()
                # If next_phase wasn't found anywhere, fall back to plain pop
                # on whatever was the top before this call.
                if not self._phase_stack:
                    self._phase_stack.append({
                        "phase": next_phase,
                        "entry_reason": "pop_fallback",
                        "depth": 0,
                    })
            elif self._phase_stack:
                self._phase_stack.pop()
            self._current_phase = (
                self._phase_stack[-1]["phase"] if self._phase_stack else ""
            )
        # stack_action == "stay" → no change to stack (but agent reconciliation below)

        # Triage-satisfied without explicit push: auto-advance to Collect so
        # subsequent entries are correctly attributed.
        if (verification_satisfied and sa == "stay"
                and (current_phase == "Triage" or self._current_phase == "Triage")):
            self._phase_stack.append({
                "phase": "Collect",
                "entry_reason": "verification_satisfied",
                "depth": len(self._phase_stack),
            })
            self._current_phase = "Collect"

        # First-ever dair_call (cold start, no transition): adopt the
        # declared current_phase AND push it onto the stack so depth is 1
        # at the root, 2 after a push, etc. — easier to read than depth=0
        # for the initial phase.
        if not self._current_phase and current_phase:
            self._current_phase = current_phase
            if not self._phase_stack:
                self._phase_stack.append({
                    "phase": current_phase,
                    "entry_reason": "initial_phase",
                    "depth": 0,
                })

        # Agent reconciliation (stay only): when the agent declares a stay but
        # their `current_phase` differs from ours, adopt what the agent
        # declared. push/pop already set _current_phase intentionally from
        # next_phase / stack-top, so we don't override those.
        if (sa == "stay" and current_phase
                and self._current_phase != current_phase
                and not (verification_satisfied
                         and self._current_phase == "Collect")):
            self._current_phase = current_phase
            if self._phase_stack:
                self._phase_stack[-1] = {
                    **self._phase_stack[-1],
                    "phase": current_phase,
                }
            else:
                self._phase_stack.append({
                    "phase": current_phase,
                    "entry_reason": "agent_reconcile",
                    "depth": 0,
                })

    def _rehydrate_phase_state(self) -> None:
        """Replay the dair_call history to reconstruct current phase state.
        Used after configure() rehydrates an existing trace."""
        self._current_phase = ""
        self._phase_stack = []
        for e in self._entries:
            if e.get("type") != "dair_call":
                continue
            self._apply_dair_transition(
                current_phase=e.get("current_phase", "") or "",
                stack_action=e.get("stack_action", "") or "",
                next_phase=e.get("next_phase", "") or "",
                transition_rationale=e.get("transition_rationale", "") or "",
                verification_satisfied=bool(e.get("verification_satisfied")),
            )
        # If no dair_call has happened yet on the rehydrated trace, default
        # to Triage so subsequent entries are phased.
        if not self._current_phase:
            self._current_phase = "Triage"
            self._phase_stack = [{
                "phase": "Triage",
                "entry_reason": "session_resume_default",
                "depth": 0,
            }]

    def has_evidence_been_verified(self, evidence_path: str) -> bool:
        """True if a successful hash_verify_evidence_hash exists in the trace
        for this evidence_path. Used by the hash-verification feature to
        avoid re-running the check on the same evidence in one session."""
        with self._lock:
            for e in self._entries:
                if e.get("type") != "reason_call":
                    continue
                if e.get("tool") != "hash_verify_evidence_hash":
                    continue
                if not e.get("success"):
                    continue
                conclusion = e.get("conclusion", "") or ""
                if conclusion.startswith("VERIFIED:") and evidence_path in conclusion:
                    return True
            return False

    def configure(self, case_id: str, path: str,
                  save_session: bool = True) -> int:
        """Open or resume the trace log for case_id at path.

        If a valid trace file already exists at path with a matching case_id,
        rehydrates in-memory state and resumes appending without overwriting.
        Otherwise starts fresh. Returns the number of entries recovered (0 for
        a new case).

        save_session: when True (default), persist (case_id, path) to
            ~/.cache/trudi/session.json so a future MCP server boot
            auto-recovers this trace. Test fixtures, ad-hoc smoke scripts,
            and any non-investigator caller MUST pass save_session=False —
            otherwise they hijack the active investigation's recovery
            beacon and silently redirect tool calls to the wrong trace.
            (Was the root cause of one silent-failure incident: smoke
            tests pointed at /tmp/smoke_trace.json hijacked an in-flight
            investigation when its MCP server next restarted.) When
            save_session=True is requested but the existing session
            points at a different case, a loud WARN is emitted before
            the overwrite happens.
        """
        with self._lock:
            try:
                with open(path) as f:
                    data = json.load(f)
                existing_id = data.get("case_id")
                if existing_id == case_id:
                    entries = data.get("entries", [])
                    self._entries = entries
                    self._seq = max((e.get("call_id", 0) for e in entries), default=0)
                    self._case_id = case_id
                    self._path = path
                    self._index_version += 1  # invalidate any cached LogIndex
                    self._cached_index = None
                    self._rehydrate_phase_state()
                    self._sync_shared_counter()
                    self._flush()
                    if save_session:
                        self._save_session()
                    return len(entries)
                elif existing_id:
                    _warn(
                        f"existing trace has case_id={existing_id!r}, "
                        f"overwriting with {case_id!r} at {path}"
                    )
            except OSError:
                pass  # file doesn't exist — normal for a new case
            except (json.JSONDecodeError, ValueError) as e:
                _warn(f"trace file corrupted at {path}, starting fresh: {e}")
            self._entries = []
            self._seq = 0
            self._last_dair_cid = 0
            self._case_id = case_id
            self._path = path
            # Default to Triage — the DAIR spec says every investigation starts
            # there ("with a confirmed positive detection already in hand"),
            # so every entry from session start should be stamped with a phase.
            # The first dair_assess will reconcile if the agent's declared
            # current_phase differs.
            self._current_phase = "Triage"
            self._phase_stack = [{
                "phase": "Triage",
                "entry_reason": "session_start_default",
                "depth": 0,
            }]
            self._index_version += 1
            self._cached_index = None
            self._sync_shared_counter()
            self._flush()
            if save_session:
                self._save_session()
            return 0

    def _sync_shared_counter(self) -> None:
        """Write the shared counter file to match self._seq + 1.

        Called from configure() after rehydrate / fresh-start so the next
        _next_shared_call_id() call returns the right id. Also covers the
        case where the counter file was deleted (e.g. by a reset) but the
        trace was not. When the existing counter is meaningfully behind
        the rehydrated self._seq, emit a WARN — it's a strong signal that
        the cache files were manually edited or the trace was restored from
        backup, and the next investigation might otherwise hit ID collisions.
        """
        os.makedirs(os.path.dirname(_CALL_ID_COUNTER_FILE), exist_ok=True)
        # Detect drift between counter and our rehydrated state — symptom of a
        # bad reset (cache cleared while trace preserved, or backup restore).
        # The F1 fix in _next_shared_call_id corrects it automatically; this
        # warn makes the corruption visible at session start.
        existing_counter = None
        try:
            with open(_CALL_ID_COUNTER_FILE) as f:
                existing_counter = int(json.load(f).get("next", 0))
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            pass
        expected = self._seq + 1
        if existing_counter is not None and existing_counter < expected - 1:
            _warn(
                f"counter file drift detected at configure(): "
                f"counter says next={existing_counter} but trace max_cid={self._seq} "
                f"(rehydrating to next={expected}). Likely cause: cache files "
                f"manually edited or trace restored from backup. Use "
                f"`python -m tools.trudi_reset` for clean resets in future."
            )
        tmp = _CALL_ID_COUNTER_FILE + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump({"next": expected}, f)
            os.replace(tmp, _CALL_ID_COUNTER_FILE)
        except OSError as e:
            _warn(f"could not sync shared counter file: {e}")

    def _save_session(self) -> None:
        # Must be called under self._lock.
        # Surface cross-case overwrites loudly — if a previously active
        # session for a different case is still on disk and its trace dir
        # exists, that investigation will silently follow this one's path
        # on the next MCP server restart. The historical incident: ad-hoc
        # `python -c 'log.configure("SMOKE", "/tmp/x")'` smoke scripts
        # hijacked an in-flight investigation's session beacon.
        try:
            with open(_SESSION_FILE) as f:
                prior = json.load(f)
            prior_case = prior.get("case_id")
            prior_path = prior.get("path")
            if (prior_case and prior_path
                    and prior_case != self._case_id
                    and os.path.isdir(os.path.dirname(os.path.abspath(prior_path)))):
                _warn(
                    f"session.json overwrite: was case_id={prior_case!r} "
                    f"path={prior_path!r}; now {self._case_id!r} at "
                    f"{self._path!r}. If you're running a test or smoke "
                    f"script, pass save_session=False to configure()."
                )
        except (OSError, json.JSONDecodeError, ValueError):
            pass
        try:
            os.makedirs(os.path.dirname(_SESSION_FILE), exist_ok=True)
            with open(_SESSION_FILE, "w") as f:
                json.dump({"case_id": self._case_id, "path": self._path}, f)
        except OSError as e:
            _warn(f"session save failed — auto-recovery on restart will not work: {e}")

    def _auto_recover(self) -> None:
        # Must be called under self._lock.
        if self._path is not None:
            return

        # 1) Session-file recovery (preserves cross-CWD MCP-server restart cases).
        try:
            with open(_SESSION_FILE) as f:
                s = json.load(f)
            case_id, path = s.get("case_id"), s.get("path")
            if case_id and path:
                # Reject stale sessions pointing to deleted directories
                # (e.g. pytest temp dirs).
                parent = os.path.dirname(os.path.abspath(path))
                if os.path.isdir(parent):
                    # save_session=False — we already read it from disk;
                    # rewriting under contention with another process can
                    # race on the file.
                    self.configure(case_id, path, save_session=False)
                    if self._path is not None:
                        return
        except (OSError, json.JSONDecodeError, ValueError):
            pass

        # 2) CWD-based recovery: if the MCP server is launched inside a real
        # case directory (CLAUDE.md present AND analysis/<X>_trace.json
        # present), resume from that trace. Both signals are required so the
        # repo root, pytest tmp dirs, etc. never trigger this fallback.
        # Lets the agent skip start_execution_log on resume without losing
        # writes — every record_* call into an unconfigured log will lazily
        # bind to the case's existing trace.
        try:
            cwd = os.getcwd()
            if not os.path.exists(os.path.join(cwd, "CLAUDE.md")):
                return
            analysis_dir = os.path.join(cwd, "analysis")
            if not os.path.isdir(analysis_dir):
                return
            import glob as _glob
            traces = sorted(_glob.glob(os.path.join(analysis_dir, "*_trace.json")))
            if not traces:
                return
            trace_path = traces[0]
            basename = os.path.basename(trace_path)
            suffix = "_trace.json"
            if not basename.endswith(suffix):
                return
            case_id = basename[: -len(suffix)]
            # save_session=False — cwd-based recovery is best-effort and
            # shouldn't claim the session beacon out from under an
            # explicit start_execution_log running elsewhere.
            self.configure(case_id, trace_path, save_session=False)
        except OSError:
            pass

    def _flush(self) -> None:
        """Must be called under self._lock. Atomic write via temp file + rename.

        Read-merge-write to preserve hook-written entries (marked with
        `_source_tool_use_id` or `_source_uuid`) that live in trace.json but
        not in self._entries. Without this merge, the MCP server would
        overwrite the disk file and clobber Bash/Read/etc. tool_call entries
        recorded by the PostToolUse hook between MCP server flushes.

        Both this method and the hook hold an exclusive fcntl flock on
        `~/.cache/trudi/hook.lock` so the read/merge/write cycle is atomic
        cross-process.
        """
        if not self._path:
            return

        # Acquire the shared lock with the hook. Best-effort: if we can't
        # open the lock file (cache dir missing, etc.) skip the lock and
        # accept the small race window rather than dropping the flush.
        lock_fp = None
        try:
            os.makedirs(os.path.dirname(_TRACE_LOCK_FILE), exist_ok=True)
            lock_fp = open(_TRACE_LOCK_FILE, "w")
            fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        except OSError:
            lock_fp = None

        try:
            # 1) Read what's currently on disk and pull out hook entries that
            # the MCP server doesn't own.
            disk_entries: list[dict] = []
            try:
                with open(self._path) as f:
                    disk_data = json.load(f)
                disk_entries = disk_data.get("entries", []) or []
            except (OSError, json.JSONDecodeError, ValueError):
                disk_entries = []

            our_ids = {e.get("call_id") for e in self._entries}
            hook_entries = [
                e for e in disk_entries
                if (e.get("_source_tool_use_id") or e.get("_source_uuid"))
                and e.get("call_id") not in our_ids
            ]

            # 2) Merge: our in-memory entries + hook entries on disk we don't
            # already have. Sort chronologically by ts so the dashboard view
            # is correct. call_ids stay intact (hook uses 1e9+ range, we use
            # monotonic 1, 2, 3, … so no collisions).
            if hook_entries:
                def _ts_sort(e: dict) -> float:
                    ts = e.get("ts", "") or ""
                    try:
                        return datetime.datetime.fromisoformat(
                            ts.replace("Z", "+00:00")
                        ).timestamp()
                    except (ValueError, AttributeError):
                        return 0.0
                merged = sorted(list(self._entries) + hook_entries, key=_ts_sort)
                data_dict = {
                    "schema_version": "2.0",
                    "case_id": self._case_id,
                    "entry_count": len(merged),
                    "entries": merged,
                }
            else:
                data_dict = self.to_json()

            data = json.dumps(data_dict, indent=2)

            # 3) Atomic write via temp + rename.
            dir_ = os.path.dirname(os.path.abspath(self._path))
            try:
                fd, tmp = tempfile.mkstemp(dir=dir_, suffix=".tmp")
                try:
                    with os.fdopen(fd, "w") as f:
                        f.write(data)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp, self._path)
                except Exception:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                    raise
            except OSError as e:
                _warn(f"trace flush failed ({self._path}): {e}")
                # Trace integrity is non-negotiable — bubble up so callers
                # (record_*, _log_tool, middleware) can surface a clear
                # ToolError instead of silently losing the entry.
                raise
        finally:
            if lock_fp is not None:
                try:
                    fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
                lock_fp.close()

    # ── Record methods ────────────────────────────────────────────────────────

    def _require_configured(self, kind: str) -> None:
        """Raise if no trace path is set. Replaces the old warn-and-drop
        behaviour so callers can't silently lose entries when
        start_execution_log was skipped."""
        if self._path is None:
            raise RuntimeError(
                f"trace log not configured — cannot record {kind}. Call "
                f"misc.start_execution_log(case_id, output_path) at the start "
                f"of the investigation before any forensic tools."
            )

    def record_system_error(
        self,
        category: str,
        detail: str,
        input_call_ids: list[int] | None = None,
    ) -> int:
        """Loud-but-non-blocking system error: gate bug, dashboard probe
        failure, narration log failure, etc. Best-effort write — falls back
        to stderr on its own failure so we never throw an exception from a
        path that's already handling a failure."""
        with self._lock:
            if self._path is None:
                _warn(f"system_error pre-configure [{category}]: {detail[:200]}")
                return 0
            try:
                cid = self._next_id()
                entry: dict = {
                    "call_id": cid,
                    "type": "system_error",
                    "ts": _utcnow(),
                    "category": category,
                    "detail": detail[:2048],
                }
                if input_call_ids:
                    entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
                self._append_entry(entry)
                return cid
            except Exception as e:
                _warn(f"system_error log failed [{category}]: {e} | "
                      f"original: {detail[:200]}")
                return 0

    def record_tool_call(
        self,
        cmd: str,
        success: bool,
        truncated: bool,
        retries: int,
        exit_code: int,
        stderr: str = "",
        elapsed_seconds: float = 0.0,
        stdout_excerpt: str = "",
        timed_out: bool = False,
        input_call_ids: list[int] | None = None,
    ) -> int:
        with self._lock:
            self._auto_recover()
            self._require_configured(f"tool_call: {cmd[:80]}")
            entry: dict = {
                "call_id": self._next_id(),
                "type": "tool_call",
                "ts": _utcnow(),
                "cmd": cmd,
                "success": success,
                "truncated": truncated,
                "retries": retries,
                "exit_code": exit_code,
                "elapsed_seconds": elapsed_seconds,
                "stderr": stderr[:512] if stderr else "",
            }
            if timed_out:
                entry["timed_out"] = True
            if stdout_excerpt:
                entry["stdout_excerpt"] = stdout_excerpt[:600]
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            # Protocol audit: a tool_call must be preceded by an active DAIR batch.
            # Scan the last 20 entries; if no dair_call is present (and the log is
            # not empty), flag the tool_call as a protocol violation. The flag is
            # surfaced in trace.json and trace.md so silent skips are auditable.
            if self._entries:
                window = self._entries[-20:]
                has_recent_dair = any(e.get("type") == "dair_call" for e in window)
                if not has_recent_dair:
                    entry["protocol_violation"] = "no_active_dair_batch"
            self._append_entry(entry)
            return entry["call_id"]

    def record_reason_call(
        self,
        tool: str,
        success: bool,
        conclusion: str,
        directives: dict,
        evidence_audit: list | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        hypothesis_id: str = "",
        inputs: dict | None = None,
        input_call_ids: list[int] | None = None,
    ) -> int:
        with self._lock:
            self._auto_recover()
            self._require_configured(f"reason_call: {tool}")
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
                "type": "reason_call",
                "ts": _utcnow(),
                "tool": tool,
                "success": success,
                "conclusion": conclusion or "",
                "directives": directives,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            }
            if evidence_audit:
                entry["evidence_audit"] = evidence_audit
            if hypothesis_id:
                entry["hypothesis_id"] = hypothesis_id
            if inputs:
                entry["inputs"] = inputs
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            self._append_entry(entry)
            return cid

    def record_self_correction(
        self,
        trigger: str,
        prior_belief: str,
        new_belief: str,
        evidence: str = "",
        linked_call_id: int = 0,
        input_call_ids: list[int] | None = None,
    ) -> int:
        """Record a first-class self-correction event in the trace.

        trigger: one of evaluate_challenged, dair_max_pass_cap, tool_failure_recovery,
                 hypothesis_refuted, verification_challenge_refuted, gate_refusal.
        """
        with self._lock:
            self._auto_recover()
            self._require_configured(f"self_correction: {trigger}")
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
                "type": "self_correction",
                "ts": _utcnow(),
                "trigger": trigger,
                "prior_belief": prior_belief,
                "new_belief": new_belief,
                "evidence": evidence,
                "linked_call_id": linked_call_id,
            }
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            self._append_entry(entry)
            return cid

    def record_call_initiated(
        self,
        tool: str,
        backend: str,
        inputs: dict,
        input_call_ids: list[int] | None = None,
    ) -> int:
        with self._lock:
            self._auto_recover()
            self._require_configured(f"call_initiated: {tool}")
            entry: dict = {
                "call_id": self._next_id(),
                "type": "call_initiated",
                "ts": _utcnow(),
                "tool": tool,
                "backend": backend,
                "inputs": inputs,
            }
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            self._append_entry(entry)
            return entry["call_id"]

    def record_call_abandoned(
        self,
        tool: str,
        reason: str,
        input_call_ids: list[int] | None = None,
    ) -> int:
        with self._lock:
            self._auto_recover()
            self._require_configured(f"call_abandoned: {tool}")
            entry: dict = {
                "call_id": self._next_id(),
                "type": "call_abandoned",
                "ts": _utcnow(),
                "tool": tool,
                "reason": reason,
            }
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            self._append_entry(entry)
            return entry["call_id"]

    def record_dair_call(
        self,
        current_phase: str,
        phase_rationale: str,
        transition_recommended: bool,
        next_phase: str,
        transition_rationale: str,
        stack_action: str,
        investigation_focus: str,
        verification_satisfied: bool = False,
        verification_challenges: list = None,
        recommended_actions: list = None,
        directives: dict = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        inputs: dict | None = None,
        input_call_ids: list[int] | None = None,
        pending_pivots: list[str] | None = None,
    ) -> int:
        with self._lock:
            self._auto_recover()
            self._require_configured(f"dair_call: phase={current_phase}")
            # Apply the transition BEFORE creating the entry so that
            # _append_entry stamps the dair_call entry itself with its
            # post-transition phase. Subsequent record_* calls inherit too.
            self._apply_dair_transition(
                current_phase=current_phase,
                stack_action=stack_action,
                next_phase=next_phase,
                transition_rationale=transition_rationale,
                verification_satisfied=verification_satisfied,
            )
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
                "type": "dair_call",
                "ts": _utcnow(),
                "current_phase": current_phase,
                "phase_rationale": phase_rationale,
                "transition_recommended": transition_recommended,
                "next_phase": next_phase,
                "transition_rationale": transition_rationale,
                "stack_action": stack_action,
                "investigation_focus": investigation_focus,
                "verification_satisfied": verification_satisfied,
                "verification_challenges": verification_challenges or [],
                "recommended_actions": recommended_actions or [],
                "directives": directives or {},
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            }
            if inputs:
                entry["inputs"] = inputs
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            if pending_pivots:
                entry["pending_pivots"] = [str(h) for h in pending_pivots if h]
            self._append_entry(entry)
            self._last_dair_cid = cid
            return cid

    def record_finding(
        self,
        description: str,
        confidence: str,
        source: str = "",
        linked_call_id: int = 0,
        tested_hypothesis_id: str = "",
        gate_metadata: dict | None = None,
        input_call_ids: list[int] | None = None,
    ) -> int:
        """Record a finding entry.

        gate_metadata: optional dict of explicit foreign keys stamped by the
        record_finding gates — gated_by_evaluate_call_id,
        gated_by_confidence_call_id, gated_by_cite_check_call_id,
        gated_by_hypothesize_call_id, validated_techniques. Stored on the
        entry so consumers (chain view, accuracy report, synthesize) can
        traverse the audit chain via real call_ids instead of inferring
        links from substring matches.
        input_call_ids: agent-declared upstream lineage — list of
        _trudi_call_id values that informed this finding (complements
        linked_call_id which is 1:1 evidence; this is N:M lineage).
        """
        with self._lock:
            self._auto_recover()
            self._require_configured(f"finding: {description[:60]}")
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
                "type": "finding",
                "ts": _utcnow(),
                "description": description,
                "confidence": confidence,
                "source": source,
                "linked_call_id": linked_call_id,
            }
            if tested_hypothesis_id:
                entry["tested_hypothesis_id"] = tested_hypothesis_id
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            if gate_metadata:
                for k, v in gate_metadata.items():
                    if v:  # skip empty / 0 — keeps entries small
                        entry[k] = v
            self._append_entry(entry)
            return cid

    def record_agent_message(
        self,
        content: str,
        input_call_ids: list[int] | None = None,
    ) -> int:
        with self._lock:
            self._auto_recover()
            self._require_configured(f"agent_message: {content[:60]}")
            entry: dict = {
                "call_id": self._next_id(),
                "type": "investigation_narration",
                "ts": _utcnow(),
                "content": content[:2000],
            }
            if input_call_ids:
                entry["input_call_ids"] = input_call_ids
            self._append_entry(entry)
            return entry["call_id"]

    # ── Read / export ─────────────────────────────────────────────────────────

    def to_json(self) -> dict:
        # Must be called under self._lock when used from _flush().
        return {
            "schema_version": "2.0",
            "case_id": self._case_id,
            "entry_count": len(self._entries),
            "entries": list(self._entries),  # snapshot
        }

    def to_markdown(self) -> str:
        with self._lock:
            return _render_entries(self._case_id, list(self._entries))

    def export(self, path: str) -> dict:
        """Write JSON and Markdown to <path>.json and <path>.md.

        Falls back to reading the flushed analysis JSON file when the in-memory
        log is empty — handles MCP server restarts mid-investigation where the
        singleton state is lost but the on-disk file survives.

        Returns {"entry_count": int, "json_wrote": bool, "md_wrote": bool}.
        """
        with self._lock:
            self._auto_recover()
            data = self.to_json()
            fallback_path = self._path

        if data["entry_count"] == 0 and fallback_path:
            try:
                with open(fallback_path) as f:
                    data = json.load(f)
            except OSError as e:
                _warn(f"export fallback read failed ({fallback_path}): {e}")
            except (json.JSONDecodeError, ValueError) as e:
                _warn(f"export fallback file corrupted ({fallback_path}): {e}")

        entry_count = data.get("entry_count", 0)
        json_ok = md_ok = False
        try:
            with open(path + ".json", "w") as f:
                json.dump(data, f, indent=2)
            json_ok = True
        except OSError as e:
            _warn(f"export JSON write failed ({path}.json): {e}")
        try:
            with open(path + ".md", "w") as f:
                f.write(_render_entries(data.get("case_id"), data.get("entries", [])))
            md_ok = True
        except OSError as e:
            _warn(f"export MD write failed ({path}.md): {e}")

        return {
            "entry_count": entry_count,
            "json_wrote": json_ok,
            "md_wrote": md_ok,
        }


log = ExecutionLog()  # module-level singleton
