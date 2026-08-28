"""Execution trace log — records tool calls, reason calls, and findings per case."""
import fcntl
import json
import os
import re
import sys
import tempfile
import threading
import datetime
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Optional

# Shared lock file with the PostToolUse hook. Both writers acquire this
# exclusive lock around their read-merge-write cycles so they never lose
# each other's entries to a race.
_TRACE_LOCK_FILE = os.path.expanduser("~/.cache/trudi/hook.lock")
# Durability knob: every flush fsyncs the trace (a crash must not lose an
# entry — the audit trail is the product). Tests patch this False: on WSL2 an
# fsync costs ~80 ms and the suite writes ~100k entries (the whole 11-minute
# runtime was fsync + lock waits, not test logic).
_TRACE_FSYNC = os.environ.get("TRUDI_TRACE_FSYNC", "1") != "0"
# Shared call_id counter — single monotonic sequence across MCP server + hook
# so call_ids are dense and reflect global write order.
_CALL_ID_COUNTER_FILE = os.path.expanduser("~/.cache/trudi/call_id.counter")


@contextmanager
def _hook_flock():
    """Exclusive flock on the shared hook.lock. EVERY writer of the shared
    call-id counter or trace must hold it — the MCP server here, the
    claude/hooks scripts on their side — so concurrent sessions can't rewind
    the counter or trample each other's writes."""
    os.makedirs(os.path.dirname(_TRACE_LOCK_FILE), exist_ok=True)
    fp = open(_TRACE_LOCK_FILE, "w")
    try:
        fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        fp.close()


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
    with _hook_flock():
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
        elif t == "finding_refused":
            gate = e.get("detail_gate") or e.get("gate") or ""
            lines.append(f"\n- `{ts}` {prefix}**⛔ FINDING REFUSED** [{e.get('tier', '')}] "
                         f"gate: `{gate}` — {(e.get('description') or '')[:200]}")
        elif t == "disposition":
            ev = e.get("evidence_call_ids") or []
            ev_s = f" ← evidence #{', #'.join(str(c) for c in ev)}" if ev else ""
            lines.append(f"- `{ts}` {prefix}**📌 DISPOSITION** {e.get('target_kind')}:"
                         f"`{e.get('target_id')}` → {e.get('reason')}{ev_s}"
                         + (f" — {e.get('note')[:200]}" if e.get("note") else ""))
        elif t == "reason_evidence_fetch":
            reqs = e.get("requests") or []
            summary = "; ".join(
                f"call {r.get('call_id')} '{str(r.get('query') or '')[:40]}' → "
                f"{r.get('rows_returned', 0)} rows"
                for r in reqs[:4])
            lines.append(f"- `{ts}` {prefix}**🔎 EVIDENCE FETCH** for reason call "
                         f"#{e.get('reason_call_id')}: {summary}")
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
    # Evidence registries — built from server-stamped annotate_tool_call
    # markers (observed_correspondents / observed_identities), which the agent
    # cannot fabricate in prose. Exhaustion checks do set arithmetic over these
    # instead of substring-matching descriptions. correspondents_complete goes
    # False when any feeder marked its scan partial (truncated roster ⇒ never
    # do blocking arithmetic on it).
    correspondents: dict[str, dict] = field(default_factory=dict)
    identities: dict[str, dict] = field(default_factory=dict)
    correspondents_complete: bool = True
    # Case roster: the terms misc.knowns_pattern_generate derived
    # from the operator's reference set, stamped server-side (knowns_roster).
    # The pre-report exhaustion checks treat a registry identity that matches
    # a roster term as mandatory; everything else is report inventory.
    roster: dict[str, dict] = field(default_factory=dict)
    # Typed dispositions keyed (target_kind, target_norm) → [entries, oldest first].
    dispositions: dict[tuple, list] = field(default_factory=dict)

    def recent(self, type_filter: str, window: list[dict]) -> list[dict]:
        """Return entries in `window` (a slice of recent entries) matching type_filter."""
        return [e for e in window if e.get("type") == type_filter]


# Address patterns that appear in every mailbox (bulk/bounce senders). They
# are FLAGGED at registry build (`bulk`) — present in every inventory, never a
# blocking leftover; dropping them would hide e.g. DSN/bounce evidence.
_IDENTITY_NOISE_RE = re.compile(
    r"mailer-daemon|postmaster|no-?reply|do-?not-?reply|undisclosed[- ]recipients"
    r"|notifications?@|newsletters?@|bounce|feedback@|automated@",
    re.IGNORECASE)


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
        # Beacon ownership + flush bookkeeping for the reset-under-a-live-server
        # hazard: only a log configured with save_session=True re-saves the
        # beacon when the trace file vanishes underneath it (never a test log).
        self._owns_beacon: bool = False
        self._flush_count: int = 0
        self._trace_missing_noted: bool = False

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
                if t == "disposition":
                    key = (str(e.get("target_kind") or "").lower(),
                           str(e.get("target_norm") or ""))
                    idx.dispositions.setdefault(key, []).append(e)
                if t == "tool_call":
                    # Evidence registries from annotate_tool_call markers.
                    oc = e.get("observed_correspondents")
                    if isinstance(oc, list) and oc:
                        src = ""
                        if e.get("cmd"):
                            src = str(e["cmd"]).split()[0]
                        stats = e.get("observed_correspondent_stats")
                        stats = stats if isinstance(stats, dict) else {}
                        # RFC bulk-header senders (List-Unsubscribe / List-Id /
                        # Precedence: bulk) — flagged bulk so inbound volume is
                        # never read as engagement.
                        bulk_set = e.get("observed_correspondent_bulk")
                        bulk_set = {str(a).strip().lower()
                                    for a in bulk_set} if isinstance(bulk_set, list) else set()
                        for v in oc:
                            v = str(v).strip().lower()
                            if not v:
                                continue
                            rec = idx.correspondents.setdefault(
                                v, {"first_cid": cid, "sources": []})
                            if _IDENTITY_NOISE_RE.search(v) or v in bulk_set:
                                # kept and FLAGGED, never dropped: a bulk-class
                                # address (bounce daemons included) can carry
                                # decisive evidence — it is inventoried, just
                                # never a mandatory disposition.
                                rec["bulk"] = True
                            if src and src not in rec["sources"]:
                                rec["sources"].append(src)
                            # Direction counts only when the feeder stamped
                            # them — a registry without stats stays conservative
                            # (every leftover blocks) in the pre-report check.
                            st = stats.get(v)
                            if isinstance(st, dict):
                                rec["from"] = rec.get("from", 0) + int(st.get("from") or 0)
                                rec["to"] = rec.get("to", 0) + int(st.get("to") or 0)
                        if e.get("correspondents_partial"):
                            idx.correspondents_complete = False
                    kr = e.get("knowns_roster")
                    if isinstance(kr, list):
                        for v in kr:
                            v = str(v).strip().lower()
                            if v:
                                idx.roster.setdefault(v, {"first_cid": cid})
                    oi = e.get("observed_identities")
                    if isinstance(oi, list):
                        for v in oi:
                            v = str(v).strip().lower()
                            if not v:
                                continue
                            irec = idx.identities.setdefault(v, {"first_cid": cid})
                            if _IDENTITY_NOISE_RE.search(v):
                                irec["bulk"] = True
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
            beacon and silently redirect tool calls to the wrong trace. When
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
                    self._owns_beacon = bool(save_session)
                    self._flush_count = 0
                    self._trace_missing_noted = False
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
            self._owns_beacon = bool(save_session)
            self._flush_count = 0
            self._trace_missing_noted = False
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
        # Under the shared flock: without it, a second session's configure()
        # could rewind the counter between another writer's read and write.
        with _hook_flock():
            os.makedirs(os.path.dirname(_CALL_ID_COUNTER_FILE), exist_ok=True)
            # Detect drift between counter and our rehydrated state — symptom of
            # a bad reset (cache cleared while trace preserved, or backup
            # restore). _next_shared_call_id corrects it automatically; this
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
            # Never move the shared counter BACKWARDS — a concurrent session
            # (hook or second server) may already have advanced it past our
            # trace max; rewinding would mint duplicate call_ids under it.
            target = max(expected, existing_counter or 1)
            tmp = _CALL_ID_COUNTER_FILE + ".tmp"
            try:
                with open(tmp, "w") as f:
                    json.dump({"next": target}, f)
                os.replace(tmp, _CALL_ID_COUNTER_FILE)
            except OSError as e:
                _warn(f"could not sync shared counter file: {e}")

    def _save_session(self) -> None:
        # Must be called under self._lock.
        # Surface cross-case overwrites loudly — if a previously active
        # session for a different case is still on disk and its trace dir
        # exists, that investigation will silently follow this one's path
        # on the next MCP server restart.
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
            # Persist the ABSOLUTE path so the UserPromptSubmit /
            # PostToolUse hooks can resolve it regardless of CWD. The
            # hooks read this beacon and write to `path` directly —
            # relative paths there silently no-op when the hook is
            # launched from a different working directory than the
            # one the MCP server happened to be in.
            abs_path = os.path.abspath(self._path) if self._path else self._path
            with open(_SESSION_FILE, "w") as f:
                json.dump({"case_id": self._case_id, "path": abs_path}, f)
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
            except FileNotFoundError:
                disk_entries = []
                if self._flush_count > 0 and not self._trace_missing_noted:
                    # The trace file vanished underneath a live server (a reset
                    # while running). We can only rewrite from memory — hook-
                    # authored entries lived on disk alone and are now in the
                    # backup only. Say so IN the trace, and re-arm the beacon so
                    # the hooks are not silenced for the rest of the run.
                    self._trace_missing_noted = True
                    backup = ""
                    try:
                        case_dir = os.path.dirname(os.path.dirname(os.path.abspath(self._path)))
                        bdir = os.path.join(case_dir, ".trace-backups")
                        latest = sorted(os.listdir(bdir))[-1:] if os.path.isdir(bdir) else []
                        backup = os.path.join(bdir, latest[0]) if latest else ""
                    except OSError:
                        pass
                    # NOT _next_id(): that takes hook.lock, which _flush already
                    # holds on another descriptor → self-deadlock. The in-memory
                    # sequence is enough; the shared counter re-syncs on the
                    # next allocation (max(counter, trace_max, seq)).
                    self._seq += 1
                    self._entries.append({
                        "call_id": self._seq,
                        "type": "system_error",
                        "ts": _utcnow(),
                        "category": "trace_file_missing_at_flush",
                        "detail": ("trace file vanished underneath a live server (reset while "
                                   "running?) — recreated from memory; hook-authored entries "
                                   "exist only in the backup" + (f": {backup}" if backup else "")),
                    })
                    _warn("trace file missing at flush — recreated from memory (see system_error entry)")
                    if self._owns_beacon:
                        self._save_session()
            except (OSError, json.JSONDecodeError, ValueError):
                disk_entries = []
            self._flush_count += 1

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
                        if _TRACE_FSYNC:
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

    def record_curiosity_probe(
        self,
        rationale: str,
        seeded_by: str = "",
        input_call_ids: list[int] | None = None,
    ) -> int:
        """Log an exploratory 'curiosity_probe' — a read-only look the agent
        chose ITSELF, outside directives.priority_tools.

        Budget-gated by the caller (tools/_gates/curiosity_budget.py); this
        method only writes the entry. A probe carries NO evidentiary weight on
        its own: to support a finding its call_id must flow into reason.* /
        record_finding via input_call_ids, where the finding gates apply. So a
        probe can widen what gets looked at without ever loosening a gate.

        rationale  — the hunch + what would confirm or kill it (the audit hook).
        seeded_by  — hypothesis_id of the reason.hypothesize(mode="absence")
                     that motivated the probe, if any.
        """
        with self._lock:
            self._auto_recover()
            self._require_configured("curiosity_probe")
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
                "type": "curiosity_probe",
                "ts": _utcnow(),
                "probe_rationale": rationale,
                "seeded_by": seeded_by,
            }
            # Never an orphan in the causal DAG: default lineage to the most
            # recent dair_assess (mirrors tool_call / narration behavior).
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            elif self._last_dair_cid:
                entry["input_call_ids"] = [self._last_dair_cid]
            self._append_entry(entry)
            return cid

    def record_reason_evidence_fetch(
        self,
        reason_call_id: int,
        requests: list[dict],
        input_call_ids: list[int] | None = None,
    ) -> int:
        """One entry per EVIDENCE_REQUEST round: what the reviewer asked for and
        what came back (call_id, query, columns, file, rows_returned,
        total_rows, status). This is the grounding record behind a verdict —
        "CHALLENGED after inspecting the 4720 rows" vs "on a 600-char excerpt".
        Fail-open: never breaks a reviewer call."""
        try:
            with self._lock:
                if self._path is None:
                    return 0
                cid = self._next_id()
                entry: dict = {
                    "call_id": cid,
                    "type": "reason_evidence_fetch",
                    "ts": _utcnow(),
                    "reason_call_id": int(reason_call_id or 0),
                    "requests": [
                        {k: r.get(k) for k in ("call_id", "query", "columns", "file",
                                               "rows_returned", "total_rows", "bytes",
                                               "status", "source_kind", "source_complete",
                                               "clipped_rows", "truncation_reason",
                                               "missing_columns", "columns_ignored",
                                               "scan_incomplete") if k in r}
                        for r in (requests or []) if isinstance(r, dict)
                    ],
                }
                if input_call_ids:
                    entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
                elif self._last_dair_cid:
                    entry["input_call_ids"] = [self._last_dair_cid]
                self._append_entry(entry)
                return cid
        except Exception as e:
            _warn(f"record_reason_evidence_fetch failed: {e}")
            return 0

    def record_disposition(
        self,
        target_kind: str,
        target_id: str,
        reason: str,
        evidence_call_ids: list[int] | None = None,
        note: str = "",
        window: dict | None = None,
        input_call_ids: list[int] | None = None,
    ) -> int:
        """A typed disposition entry (`disposition`): target_kind/target_id/
        reason are enumerated by tools/_gates/_dispositions.py; target_norm is
        the shared-normalizer key the gates look up. Validation happens in the
        MCP tool; this only persists."""
        from tools._gates._dispositions import normalize_target
        with self._lock:
            self._auto_recover()
            self._require_configured(f"disposition: {target_kind}:{target_id}")
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
                "type": "disposition",
                "ts": _utcnow(),
                "target_kind": (target_kind or "").strip().lower(),
                "target_id": str(target_id or "").strip()[:200],
                "target_norm": normalize_target(target_kind, target_id),
                "reason": (reason or "").strip().lower(),
            }
            if evidence_call_ids:
                entry["evidence_call_ids"] = sorted({int(c) for c in evidence_call_ids if c})
            if note:
                entry["note"] = str(note)[:500]
            if window:
                entry["window"] = dict(window)
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            elif self._last_dair_cid:
                entry["input_call_ids"] = [self._last_dair_cid]
            self._append_entry(entry)
            return cid

    def record_finding_refused(
        self,
        description: str,
        tier: str,
        gate: str,
        detail_gate: str = "",
        claim: dict | None = None,
        input_call_ids: list[int] | None = None,
        cited_call_ids: list[int] | None = None,
        extra: dict | None = None,
        tested_hypothesis_id: str = "",
        error: str = "",
    ) -> int:
        """Refusal ledger: every record_finding refusal becomes a trace entry
        (`finding_refused`) so a re-record of the same finding with the
        triggering words edited out is visible to the refusal_rewording gate —
        and to the auditor. Fail-open: never breaks the refusal path."""
        try:
            with self._lock:
                if self._path is None:
                    return 0
                cid = self._next_id()
                entry: dict = {
                    "call_id": cid,
                    "type": "finding_refused",
                    "ts": _utcnow(),
                    "description": (description or "")[:500],
                    "tier": (tier or "").upper(),
                    "gate": gate or "",
                    "detail_gate": detail_gate or "",
                }
                if claim:
                    entry["claim"] = claim
                if tested_hypothesis_id:
                    entry["tested_hypothesis_id"] = str(tested_hypothesis_id)
                if cited_call_ids:
                    entry["cited_call_ids"] = sorted({int(c) for c in cited_call_ids if c})
                if extra:
                    entry["extra"] = extra
                if error:
                    entry["error"] = str(error)[:800]     # what the agent was told
                if input_call_ids:
                    entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
                elif self._last_dair_cid:
                    entry["input_call_ids"] = [self._last_dair_cid]
                self._append_entry(entry)
                return cid
        except Exception as e:
            _warn(f"record_finding_refused failed: {e}")
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
        stdout_full: str | None = None,
        output_path: str | None = None,
        exit_meaning: str = "",
        gate: str = "",
    ) -> int:
        """Record a tool execution.

        stdout_full: the COMPLETE captured stdout (before the agent-facing
            caps). The entry keeps `stdout_excerpt[:600]` for readability; when
            the full text is longer than the excerpt it is persisted to a
            sidecar file (`<analysis>/.tool_output/<cid>.txt`, `stdout_path`)
            so the reviewer can fetch rows the excerpt cut off. `stdout_chars`
            always records the raw length, which is how a reader tells a
            COMPLETE excerpt from a PARTIAL one.
        output_path: the tool's own artifact file (run_with_output_file,
            wrappers that write a CSV) — fetchable evidence.
        exit_meaning: tool-specific meaning of the exit code (e.g. clamscan
            1 = infected) when the wrapper declared an exit policy.
        gate: for `<py>:` baseline entries — the gate id when the wrapper
            returned a refusal, so a refused export/report write is visible
            as a failure in the trace.
        """
        with self._lock:
            self._auto_recover()
            self._require_configured(f"tool_call: {cmd[:80]}")
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
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
            if stdout_full is None and stdout_excerpt:
                stdout_full = stdout_excerpt
            if stdout_full is not None:
                # Stamped even when EMPTY (0) so "ran and produced nothing"
                # is distinguishable from "output never persisted".
                entry["stdout_chars"] = len(stdout_full)
                entry["stdout_lines"] = (stdout_full.count("\n") + (
                    0 if stdout_full.endswith("\n") else 1)) if stdout_full else 0
                if len(stdout_full) > len(entry.get("stdout_excerpt") or ""):
                    self._write_stdout_sidecar(cid, stdout_full, entry)
            if output_path:
                entry["output_path"] = str(output_path)
            if exit_meaning:
                entry["exit_meaning"] = str(exit_meaning)[:200]
            if gate:
                entry["gate"] = str(gate)[:80]
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            # Protocol audit: flag a forensic tool_call that ran outside an active
            # DAIR phase (i.e. in Report, after DAIR decided the investigation is
            # converging). Read DAIR's own phase state, not a window count, so a
            # long collection batch is never flagged. Surfaced in the trace so a
            # protocol lapse stays auditable.
            phase = self._current_phase or ""
            if phase and phase not in ("Triage", "Collect", "Analyze", "Scan"):
                entry["protocol_violation"] = f"forensic_tool_in_{phase.lower()}_phase"
            self._append_entry(entry)
            return entry["call_id"]

    # ── full-stdout sidecar ────────────────────────────────────────────────
    def stdout_sidecar_dir(self) -> str | None:
        """`<dirname(trace)>/.tool_output` — inside analysis/, so it is a
        readable produced-output location and is wiped with the case run."""
        if not self._path:
            return None
        return os.path.join(os.path.dirname(os.path.abspath(self._path)), ".tool_output")

    def _write_stdout_sidecar(self, cid: int, text: str, entry: dict) -> None:
        """Persist the complete stdout for `cid`. Called from record_tool_call
        between _next_id() and _append_entry() — no lock is held across the
        write and the filename is unique per cid, so the _flush re-entrancy
        hazard does not apply. Never raises: a failed sidecar is recorded on
        the entry (`stdout_sidecar_error`) and the entry is still written."""
        try:
            from core.paths import STDOUT_SIDECAR_CAP
            d = self.stdout_sidecar_dir()
            if not d:
                return
            os.makedirs(d, exist_ok=True)
            partial = len(text) > STDOUT_SIDECAR_CAP
            body = text[:STDOUT_SIDECAR_CAP]
            import tempfile
            fd, tmp = tempfile.mkstemp(prefix=f".{cid}-", suffix=".tmp", dir=d)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as fh:
                    fh.write(body)
                final = os.path.join(d, f"{cid}.txt")
                os.replace(tmp, final)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            entry["stdout_path"] = final
            if partial:
                entry["stdout_partial"] = True
        except Exception as e:
            _warn(f"stdout sidecar for call {cid} failed: {e}")
            entry["stdout_sidecar_error"] = str(e)[:200]

    def record_reason_call(
        self,
        tool: str,
        success: bool,
        conclusion: str,
        directives: dict,
        evidence_audit: list | None = None,
        blockers: list | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        hypothesis_id: str = "",
        inputs: dict | None = None,
        input_call_ids: list[int] | None = None,
        error: str = "",
        backend_meta: dict | None = None,
        extra: dict | None = None,
    ) -> int:
        """`extra`: additional typed fields stamped on the entry (non-None values
        only) — e.g. parse_path / result_block (which parser produced the
        structured fields), ready_to_report / blocking_issues (pre_report), a
        declared claim. Readers key on these instead of scraping conclusion text."""
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
            if blockers is not None:
                # Store even [] — an empty list is the structured "ready" signal
                # that pre_report_check reads instead of scraping prose.
                entry["blockers"] = list(blockers)
            if hypothesis_id:
                entry["hypothesis_id"] = hypothesis_id
            if inputs:
                entry["inputs"] = inputs
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            # Persist the error and any backend diagnostics (finish_reason,
            # reasoning_tokens, retry count, reasoning excerpt) so a failed
            # reason call explains itself instead of a bare success:false.
            if error:
                entry["error"] = str(error)
            if backend_meta:
                entry["backend_meta"] = dict(backend_meta)
            if extra:
                for k, v in extra.items():
                    if v is not None and k not in entry:
                        entry[k] = v
            self._append_entry(entry)
            return cid

    def update_reason_call(self, call_id: int, **fields) -> bool:
        """Stamp additional fields onto an already-recorded reason_call entry
        (e.g. `sub_hypotheses` parsed from the conclusion, or post-processed
        directives). Returns True if the entry was found and updated. Used by
        reason_hypothesize to attach per-hypothesis records after the model
        round-trip. Bumps the index version so the next index() rebuild sees the
        new fields. Non-None values only — never clobbers a field with None."""
        if not call_id:
            return False
        with self._lock:
            for e in self._entries:
                if e.get("call_id") == call_id and e.get("type") == "reason_call":
                    for k, v in fields.items():
                        if v is not None:
                            e[k] = v
                    self._index_version += 1
                    self._flush()
                    return True
        return False

    def annotate_tool_call(self, call_id: int, **fields) -> bool:
        """Stamp additional fields onto an already-recorded tool_call entry
        (e.g. `coverage_window` = {start, end} of a parsed log, so the
        negative_completeness gate can tell whether a source actually covers a
        claim's time window). Mirrors update_reason_call: non-None values only,
        bumps the index version. Used by the log-parsing wrappers (ez.evtxecmd,
        misc.chainsaw_hunt) after they compute a log's event time-range."""
        if not call_id:
            return False
        with self._lock:
            for e in self._entries:
                if e.get("call_id") == call_id and e.get("type") == "tool_call":
                    for k, v in fields.items():
                        if v is not None:
                            e[k] = v
                    self._index_version += 1
                    self._flush()
                    return True
        return False

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

    def record_tool_blocked(self, tool: str, reason: str) -> int:
        """Record that a tool invocation was refused by a pre-execution gate (e.g.
        the DAIR-batch gate) and never ran. A block otherwise leaves NO trace, so a
        tool that was blocked and then silently dropped is invisible. This makes
        the block auditable, so the work-order retry check can flag a blocked tool
        that was abandoned rather than re-run or dispositioned."""
        with self._lock:
            self._auto_recover()
            self._require_configured(f"tool_blocked: {tool}")
            entry: dict = {
                "call_id": self._next_id(),
                "type": "tool_blocked",
                "ts": _utcnow(),
                "tool": tool,
                "reason": reason,
            }
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
        candidate_pivots: list[dict] | None = None,
        error: str = "",
        backend_meta: dict | None = None,
        parse_path: str = "",
        server_override: dict | None = None,
        observed_principals: list[dict] | None = None,
        observed_hosts: list[str] | None = None,
        case_question: str = "",
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
            if candidate_pivots:
                entry["candidate_pivots"] = [
                    p for p in candidate_pivots
                    if isinstance(p, dict) and p.get("value")
                ]
            if error:
                entry["error"] = str(error)
            if backend_meta:
                entry["backend_meta"] = dict(backend_meta)
            if parse_path:
                entry["parse_path"] = str(parse_path)
            if server_override:
                entry["server_override"] = dict(server_override)
            if observed_principals:
                entry["observed_principals"] = [dict(p) for p in observed_principals if isinstance(p, dict)]
            if observed_hosts:
                entry["observed_hosts"] = [str(h) for h in observed_hosts if str(h).strip()]
            if case_question:
                entry["case_question"] = str(case_question).strip()
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
        supersedes: int = 0,
        supporting_evidence: str = "",
        claim: dict | None = None,
    ) -> int:
        """Record a finding entry.

        gate_metadata: explicit foreign keys stamped by the record_finding gates
        (gated_by_*_call_id, validated_techniques) so consumers traverse the
        audit chain by call_id, not substring.
        input_call_ids: N:M upstream lineage (complements 1:1 linked_call_id).
        supersedes: call_id of an earlier finding this one replaces — the old
        entry is stamped superseded_by so the report/accuracy layer counts only
        the final tier. Used to re-tier a finding upward once new evidence earns
        a SUPPORTED evaluate.
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
            if supporting_evidence:
                # Persisted (capped) so report-time checks (affirmative_coverage
                # dispositions, pre_report recipient/channel checks) have a real
                # evidence surface — previously this text died with the call.
                entry["supporting_evidence"] = supporting_evidence[:2000]
            if claim and any(claim.values()):
                # Typed claim (kind/category/entities/channel/window) — the
                # declared structure downstream gates and report-time
                # exhaustion checks key on instead of description regexes.
                entry["claim"] = claim
            if tested_hypothesis_id:
                entry["tested_hypothesis_id"] = tested_hypothesis_id
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            if gate_metadata:
                for k, v in gate_metadata.items():
                    if v:  # skip empty / 0 — keeps entries small
                        entry[k] = v
            if supersedes:
                entry["supersedes"] = int(supersedes)
                for prior in self._entries:
                    if prior.get("call_id") == supersedes and prior.get("type") == "finding":
                        prior["superseded_by"] = cid
                        break
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
