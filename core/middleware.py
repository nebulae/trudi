"""FastMCP middleware: trace every MCP tool call and enforce DAIR oversight."""
import asyncio
import os
import sys
import time
import traceback

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp import types as mt


# ── DAIR gate configuration ───────────────────────────────────────────────────

_SKIP_TOOLS = frozenset({"misc_record_agent_message", "misc_start_execution_log"})

DAIR_GATE_ALLOWLIST = frozenset({
    # Trace lifecycle
    "misc_start_execution_log",
    "misc_export_execution_log",
    "misc_write_final_report",
    "misc_record_agent_message",
    "misc_record_self_correction",
    # Typed dispositions are bookkeeping, not evidence: legal in Report, where
    # pre_report_check surfaces the leads/sources/tools that need settling.
    "misc_record_disposition", "record_disposition",
    "misc_serve_dashboard",
    # Phase director itself
    "dair_assess",
    # Adversarial-review + scoring META tools (they reason ABOUT findings, they
    # don't execute forensics), exempt so they never require a fresh dair_assess.
    # record_finding still carries the dair_required gate, keeping the
    # investigation DAIR-directed. Wire names are single-namespace since the
    # mount-time dedup (core/normalize_names.py).
    "reason_plan",
    "reason_hypothesize",
    "reason_evaluate_finding",
    "reason_confidence_score",
    "reason_cite_check",
    "reason_audit_findings",
    # Task→command drafting and free-form advice are assistance, not
    # forensics — usable any time (whatever gets run passes every gate).
    "reason_draft_command",
    "reason_advise",
    "reason_extract_case",
    "reason_synthesize",
    "reason_pre_report_check",
    "accuracy_compare",
    "accuracy_export_report",
    "correlate_mitre_validate",
    # Produced-output readers — they read parsed output only (never evidence),
    # so they are phase-free: legal in Report to ground citations while writing.
    "read_output",
    "read_mail",
    # Pre-flight reads that run before the first dair_assess
    "hash_verify_evidence_hash",
    "vol_symbol_check",
    "ez_recmd_hive",
    "strings_stat_file",
})

# The gate reads DAIR's own phase state (the execution log maintains
# _current_phase via DAIR transitions), not a tool counter. Forensics are allowed
# pre-plan (before DAIR engages) and in any active evidence phase; blocked only in
# Report, where DAIR has decided the investigation is converging — new evidence
# then requires a DAIR-directed return to a collection phase.
_DAIR_ACTIVE_PHASES = frozenset({"Triage", "Collect", "Analyze", "Scan"})
DAIR_WINDOW = 20       # retained for backward-compat imports; no longer used by the gate

# ── DAIR engagement nudge (phase-boundary, counter-free) ────────────────────
# A local driving model (observed: Titus) investigates competently but never
# consults DAIR or records findings (108 and 177 forensic calls with DAIR never
# engaged in the two pathological runs). The dair_required gate teaches at
# record_finding time, but a model that also never records findings never meets
# it. This gate teaches at the PHASE BOUNDARIES of the investigation protocol
# instead — no call counters (a windowed counter is the retired DAIR_WINDOW
# friction: long legitimate batches age out mid-work-order):
#
#   Triage (DAIR not yet engaged, _current_phase == ""):
#     baseline collection        → allow + standing protocol notice (a session
#                                  that never STARTS the ritual would otherwise
#                                  stay in baseline freedom forever — observed
#                                  live within minutes of the first deploy:
#                                  48 calls, no hypothesize, tcpdump_read x38)
#     after reason_hypothesize   → notice: finish the ritual (reason.plan → dair)
#     after reason_plan          → BLOCK forensic tools: call dair_assess to
#                                  enter Collect. Measured 2026-08-28: 10/11
#                                  compliant historical runs make ZERO MCP
#                                  forensic calls between plan and first dair,
#                                  so this boundary never fires on a compliant
#                                  driver. dair/reason/record tools are
#                                  allowlisted — the way forward is always open.
#   Engaged (Triage/Collect/Analyze/Scan): allow — DAIR directs via its own
#     directives; Report blocking stays with the existing phase gate above.
#   Analyze/Scan with zero recorded findings: advisory finding_notice
#     (time-throttled) — analysis that is never recorded cannot reach the report.
DAIR_NUDGE_ENABLED = (os.environ.get("TRUDI_DAIR_NUDGE") or "1").strip().lower() not in (
    "0", "off", "false", "none")

# Live-monitoring uses per-investigation traces and its own flow; job polling
# must never be gated.
_NUDGE_SKIP_PREFIXES = ("monitor_", "respond_", "velo_", "live_")
_NUDGE_SKIP_SUFFIXES = ("job_status", "job_list")

_FINDING_NOTICE_INTERVAL_S = 60.0   # advisory throttle, wall-clock (not a counter)

_DAIR_CALL_SHAPE = (
    "dair.assess(tool_results_summary=\"<3-5 sentences: what this batch "
    "found>\", phase_stack='[]' (or the current stack), case_context=\"<case id "
    "+ confirmed IOCs>\", input_call_ids=[<recent cids>])"
)


class _RitualState:
    """Incremental view of the trace's Triage-ritual facts. Per-process; a
    trace reset (new case / shorter entry list) clears it."""
    def __init__(self) -> None:
        self.scanned_idx = 0
        self.has_hypothesize = False
        self.has_plan = False
        self.findings = 0
        self.last_finding_notice = 0.0


_ritual = _RitualState()


def _scan_ritual() -> None:
    from core.execution_log import log
    entries = log._entries
    if len(entries) < _ritual.scanned_idx:      # trace reset / new case
        _ritual.__init__()
    for e in entries[_ritual.scanned_idx:]:
        t = e.get("type")
        if t == "reason_call":
            tool = e.get("tool", "")
            if tool == "reason_hypothesize":
                _ritual.has_hypothesize = True
            elif tool == "reason_plan":
                _ritual.has_plan = True
        elif t == "finding":
            _ritual.findings += 1
    _ritual.scanned_idx = len(entries)


def _nudge_decision(tool_name: str) -> tuple[str, str]:
    """('allow'|'notice'|'block', message). Fail-open on any internal error."""
    if not DAIR_NUDGE_ENABLED:
        return "allow", ""
    if tool_name.startswith(_NUDGE_SKIP_PREFIXES) or tool_name.endswith(_NUDGE_SKIP_SUFFIXES):
        return "allow", ""
    try:
        from core.execution_log import log
        phase = getattr(log, "_current_phase", "") or ""
        if phase:
            return "allow", ""            # engaged: DAIR directs; Report handled above
        _scan_ritual()
        if _ritual.has_plan:
            return "block", (
                "DAIR PROTOCOL: Triage is complete (reason.plan recorded) but "
                "DAIR has not been engaged. Call " + _DAIR_CALL_SHAPE + " to "
                "receive the Collect work order before any further forensic "
                "tools. Findings cannot be recorded until DAIR is engaged "
                "(gate dair_required)."
            )
        if _ritual.has_hypothesize:
            return "notice", (
                "DAIR PROTOCOL: Triage ritual in progress — after the baseline "
                "batch, run reason.plan(case_description=..., "
                "evidence_available=..., case_question=...), then "
                + _DAIR_CALL_SHAPE + ". Findings cannot be recorded until DAIR "
                "is engaged."
            )
        # Ritual not yet started: standing notice on every forensic result —
        # persistent instruction pressure, no counter, no block.
        return "notice", (
            "DAIR PROTOCOL: the Triage ritual has not started. After the "
            "baseline batch: (1) reason.hypothesize(hypothesis_kind="
            "\"case_question\", observation=<the case question>), then "
            "(2) reason.plan(case_description=..., evidence_available=..., "
            "case_question=...), then (3) " + _DAIR_CALL_SHAPE + ". Findings "
            "cannot be recorded until DAIR is engaged (gate dair_required)."
        )
    except Exception:
        return "allow", ""


def _finding_nudge() -> str:
    """Advisory, phase-conditioned: in Analyze/Scan with zero recorded findings."""
    if not DAIR_NUDGE_ENABLED:
        return ""
    try:
        from core.execution_log import log
        phase = getattr(log, "_current_phase", "") or ""
        if phase not in ("Analyze", "Scan"):
            return ""
        _scan_ritual()
        if _ritual.findings:
            return ""
        now = time.monotonic()
        if now - _ritual.last_finding_notice < _FINDING_NOTICE_INTERVAL_S:
            return ""
        _ritual.last_finding_notice = now
        return (
            f"FINDINGS: the investigation is in {phase} with 0 recorded "
            f"findings. For each confirmed observation call "
            f"misc.record_finding(description=..., confidence=..., "
            f"linked_call_id=<this call's _trudi_call_id>, claim_kind=..., "
            f"category=..., act=..., input_call_ids=[...]). Analysis that is "
            f"never recorded cannot reach the report."
        )
    except Exception:
        return ""


# ── Repeat-call gate (identical call + identical result = redundant) ─────────
# Observed live: a compaction-driven closed loop re-ran the SAME two ngrep
# searches 147 and 146 times — each returned the same empty result, each
# compaction dropped the low-salience negative, and OpenCode's auto-continue
# prompt restarted the cycle. The context forgets what the trace knows; this
# gate lends the trace's memory back at the moment of action. A call triggers
# ONLY when both the arguments AND the previous result are identical — a
# re-read of a changed file resets it, so legitimate repetition never fires.
REPEAT_GATE_ENABLED = (os.environ.get("TRUDI_REPEAT_GATE") or "1").strip().lower() not in (
    "0", "off", "false", "none")
# Refuse the call once the same call has returned the same result this many
# times (0 = never refuse, notices only).
REPEAT_BLOCK_AFTER = int(os.environ.get("TRUDI_REPEAT_BLOCK_AFTER") or "4")

_REPEAT_MAX_KEYS = 512
# key -> {"result_hash": str, "identical": int}
_repeat_state: dict = {}

# Volatile result keys that differ on every run of an otherwise identical call.
# enrich()'s interpretive fields now live under the `_metadata` sub-object,
# which the hash drops via the `_`-prefix rule — so only genuinely volatile
# top-level result keys need listing here.
_REPEAT_VOLATILE = ("elapsed_seconds", "retries", "stdout_path")


def _repeat_key(tool_name: str, args: dict) -> str:
    import hashlib
    import json as _json
    payload = _json.dumps({k: v for k, v in (args or {}).items() if k != "_note"},
                          sort_keys=True, default=str)
    return hashlib.sha256(f"{tool_name}|{payload}".encode()).hexdigest()


def _result_hash(payload: dict) -> str:
    import hashlib
    import json as _json
    clean = {k: v for k, v in payload.items()
             if not k.startswith("_") and k not in _REPEAT_VOLATILE
             and not k.endswith("_notice")}
    return hashlib.sha256(_json.dumps(clean, sort_keys=True, default=str).encode()).hexdigest()


def _repeat_precheck(key: str, tool_name: str) -> str:
    """Return a refusal message when this exact call has already returned the
    same result REPEAT_BLOCK_AFTER times; else ''. Fail-open."""
    if not REPEAT_GATE_ENABLED or REPEAT_BLOCK_AFTER <= 0:
        return ""
    st = _repeat_state.get(key)
    if st and st["identical"] >= REPEAT_BLOCK_AFTER:
        n = st["identical"] + 1
        return (
            f"repeat_call_gate: this exact {tool_name} call has run {n - 1} "
            f"times with an IDENTICAL result. A repeated negative is evidence "
            f"of absence — record it once via misc.record_finding("
            f"description=\"No matches for <what was searched>\", "
            f"confidence=\"UNCONFIRMED\", claim_kind=\"negative\", "
            f"category=..., act=..., scope=[...], linked_call_id=<the prior "
            f"call's cid>, input_call_ids=[...]) and run a DIFFERENT query, or "
            f"call dair.assess for the next work order."
        )
    return ""


def _repeat_update(key: str, tool_name: str, payload: dict) -> str:
    """Record this call's result; return a repeat notice when the result is
    identical to the previous run of the same call. Fail-open."""
    if not REPEAT_GATE_ENABLED:
        return ""
    try:
        h = _result_hash(payload)
        st = _repeat_state.get(key)
        if st is None or st["result_hash"] != h:
            if len(_repeat_state) >= _REPEAT_MAX_KEYS and key not in _repeat_state:
                _repeat_state.pop(next(iter(_repeat_state)), None)
            _repeat_state[key] = {"result_hash": h, "identical": 0}
            return ""
        st["identical"] += 1
        n = st["identical"] + 1
        return (
            f"REPEAT CALL: this exact call has now run {n}x with an identical "
            f"result — re-running it cannot produce new evidence. If it is a "
            f"negative, record it once (misc.record_finding, "
            f"confidence=\"UNCONFIRMED\", claim_kind=\"negative\", with "
            f"scope) and move to a DIFFERENT query, or call dair.assess "
            f"for the next work order."
        )
    except Exception:
        return ""


# ── Consecutive-poll advisory (job_status busy-wait) ────────────────────────
# Async carve jobs exist so the agent keeps investigating while the carve runs
# — job_status is exempt from every gate so polling is always allowed. But a
# literal model treats a running job as a blocking wait and busy-polls
# (observed live: 86 consecutive job_status calls, nothing else). This advisory
# rides the job_status result after a few back-to-back polls and tells the
# model to do OTHER work between polls. Never blocks — the loop self-terminates
# when the carve finishes, and blocking a poll could strand the model.
POLL_ADVISORY_AFTER = int(os.environ.get("TRUDI_POLL_ADVISORY_AFTER") or "2")

# consecutive job_status calls with no intervening real tool call
_poll_run = {"count": 0}


def _note_poll_and_advise(payload: dict) -> str:
    """Called on a job_status result. Returns an advisory once the model has
    polled several times in a row without doing other work."""
    try:
        _poll_run["count"] += 1
        n = _poll_run["count"]
        if n <= POLL_ADVISORY_AFTER:
            return ""
        if not isinstance(payload, dict) or payload.get("status") != "running":
            return ""
        files = payload.get("output_files_so_far", "?")
        secs = payload.get("elapsed_seconds", "?")
        return (
            f"POLLING LOOP: you have called job_status {n}x in a row with no "
            f"other work — the carve is still running ({secs}s, {files} files) "
            f"and polling does not speed it up. Do OTHER analysis NOW (query "
            f"the http_session_inventory / ngrep patterns you have not tried, "
            f"read.output on produced files, record findings, or call "
            f"dair.assess); poll job_status again only AFTER a real step. "
            f"The finished result will be waiting."
        )
    except Exception:
        return ""


def _reset_poll_run() -> None:
    _poll_run["count"] = 0


def _apply_notices(payload: dict, notices: list) -> dict:
    for key, msg in notices:
        payload.setdefault(key, msg)
    return payload


# ── MCP routing gate configuration ───────────────────────────────────────────
# Definitions live in core/forensic_binaries.py (stdlib-only, so the PreToolUse
# guard hook can import them without fastmcp); re-exported here for existing
# importers (tools/_gates/mcp_routing.py, tests).
from core.forensic_binaries import (  # noqa: F401
    FORENSIC_BINARY_PATTERNS, MCP_WRAPPER_HINTS, _identify_forensic_binary,
)

# ── Gate helpers ──────────────────────────────────────────────────────────────

def _gate_decision() -> tuple[bool, str]:
    """Return (should_block, reason). Fail-open on gate errors, but log them."""
    try:
        from core.execution_log import log
        if not log._entries:
            return False, "cold start (empty trace)"
        phase = getattr(log, "_current_phase", "") or ""
        if not phase:
            return False, "cold start (DAIR not yet engaged)"
        if phase in _DAIR_ACTIVE_PHASES:
            return False, f"active DAIR phase ({phase})"
        # Report (or any non-active phase): the investigation is converging.
        return True, (f"investigation is in the {phase} phase — call dair_assess to "
                      f"return to a collection phase before running more forensic tools")
    except Exception:
        tb = traceback.format_exc()
        print(f"[TRUDI WARN] dair gate check failed (fail-open): {tb}", file=sys.stderr)
        try:
            from core.execution_log import log
            log.record_system_error("dair_gate", tb)
        except Exception as _e:
            print(f"[TRUDI WARN] dair_gate system_error log failed: {_e}", file=sys.stderr)
        return False, "gate check error (fail-open)"


# ── Trace-write helpers ───────────────────────────────────────────────────────
# Centralised so the three outcome paths in on_call_tool stay readable.

def _trace_narration_failure(e: Exception, note: str) -> None:
    print(f"[TRUDI WARN] narration logging failed: {e}", file=sys.stderr)
    try:
        from core.execution_log import log
        log.record_system_error(
            "narration",
            f"narration log failed: {e!r}\nnote={note[:200]}",
        )
    except Exception:
        pass


def _parent_cids() -> list[int] | None:
    """Return [log._last_dair_cid] if a dair_call has been recorded, else None.

    This is the prescribing DAIR entry for the current tool batch. Every
    tool_call, call_abandoned, and narration carries it as input_call_ids
    so the trace forms a proper causal DAG:
        dair_call → [tool_calls, narrations, call_abandoned, …] → findings
    """
    try:
        from core.execution_log import log
        cid = log._last_dair_cid
        return [cid] if cid else None
    except Exception:
        return None


def _trace_cancelled(tool_name: str, elapsed: float) -> None:
    try:
        from core.execution_log import log
        log.record_call_abandoned(
            tool_name,
            f"client cancellation after {elapsed}s — "
            f"check client tool-timeout or reduce work scope",
            input_call_ids=_parent_cids(),
        )
    except Exception as err:
        print(f"[TRUDI FATAL] {tool_name} cancelled + trace-write failure: "
              f"{err!r}", file=sys.stderr, flush=True)


def _arg_shapes(args: dict | None) -> str:
    """Argument NAMES and python types — never values — so a validation
    failure is diagnosable from the trace (which field, which type)."""
    try:
        return ", ".join(f"{k}:{type(v).__name__}" for k, v in (args or {}).items()
                         if not str(k).startswith("_"))[:400]
    except Exception:
        return ""


def _is_input_validation(exc: Exception) -> bool:
    return type(exc).__name__ in ("ValidationError", "ArgumentError") or \
        "validation error" in str(exc).lower()


def _trace_exception(tool_name: str, exc: Exception, elapsed: float,
                     args: dict | None = None) -> None:
    tb = traceback.format_exc()
    # The exception MESSAGE first (a traceback head tells the auditor nothing
    # about WHICH field failed), then arg names/types, then the traceback tail.
    msg = f"{type(exc).__name__}: {str(exc)[:700]}"
    shapes = _arg_shapes(args)
    head = (f"Unhandled {msg} in {tool_name}"
            + (f" | args: {shapes}" if shapes else "")
            + f"\n--- traceback tail ---\n{tb[-1500:]}")
    try:
        from core.execution_log import log
        log.record_tool_call(
            cmd=f"<py>:{tool_name}",
            success=False,
            truncated=False,
            retries=0,
            exit_code=-1,
            stderr=head[:4096],
            elapsed_seconds=elapsed,
            input_call_ids=_parent_cids(),
            gate="input_validation" if _is_input_validation(exc) else "",
        )
    except Exception as log_err:
        print(
            f"[TRUDI FATAL] tool exception + trace-write failure for "
            f"{tool_name}: original={exc!r}; trace_err={log_err!r}\n{tb}",
            file=sys.stderr, flush=True,
        )


def _result_payload(result) -> dict | None:
    """The dict a tool returned — directly, or unwrapped from a FastMCP
    ToolResult's structured_content. None when neither shape applies."""
    if isinstance(result, dict):
        return result
    sc = getattr(result, "structured_content", None)
    return sc if isinstance(sc, dict) else None


def _trace_success_baseline(tool_name: str, elapsed: float,
                             entries_before: int | None, result=None) -> None:
    """Write a baseline tool_call entry if the tool didn't self-log.

    Subprocess tools self-log via core.executor._log_tool. reason_*/dair_*
    self-log via record_reason_call/record_dair_call. Pure-Python tools
    (correlate_*, accuracy_*, etc.) don't — this baseline makes them visible.
    Self-logging is detected by whether log._entries grew during the call.

    The baseline honours the tool's OWN verdict: a wrapper that returned
    `{"success": False, "gate": ...}` (a refused export_execution_log /
    write_final_report) is logged as a failure carrying the gate id — a
    refusal must never read as a successful run in the audit trail.
    """
    if entries_before is None:
        return
    try:
        from core.execution_log import log
        if len(log._entries) == entries_before:
            payload = _result_payload(result) or {}
            ok = payload.get("success", True) is not False
            err = "" if ok else str(payload.get("error") or "")[:512]
            log.record_tool_call(
                cmd=f"<py>:{tool_name}",
                success=ok,
                truncated=False,
                retries=0,
                exit_code=0 if ok else 1,
                stderr=err,
                elapsed_seconds=elapsed,
                input_call_ids=_parent_cids(),
                gate=str(payload.get("gate") or "") if not ok else "",
            )
    except Exception as err:
        print(f"[TRUDI WARN] success-baseline log failed for {tool_name}: "
              f"{err!r}", file=sys.stderr)


# ── Middleware ────────────────────────────────────────────────────────────────

class NarrationMiddleware(Middleware):
    """Single middleware over every @mcp.tool() invocation.

    Responsibilities (in order):
      1. Narration  — extract _note= arg, write as agent_message, strip arg.
      2. DAIR gate  — block forensic tools when DAIR oversight has lapsed.
      3. Trace coverage — guarantee every call produces ≥1 trace entry:
           success   → baseline tool_call if the tool didn't self-log
           exception → tool_call(success=False, traceback) + re-raise ToolError
           cancel    → call_abandoned + re-raise CancelledError
           ToolError → pass through (already structured, no extra entry)
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next,
    ):
        args = dict(context.message.arguments or {})
        note = args.pop("_note", None)
        tool_name = context.message.name

        # 1. Narration
        if note and tool_name not in _SKIP_TOOLS:
            try:
                from core.execution_log import log
                log.record_agent_message(str(note),
                                         input_call_ids=_parent_cids())
            except Exception as e:
                _trace_narration_failure(e, str(note))

        # 2. DAIR gate
        if tool_name not in DAIR_GATE_ALLOWLIST:
            should_block, reason = _gate_decision()
            # A CORRECTION of an existing finding (supersedes=<cid>) is
            # report-phase work — re-tiering, dropping an unprovable field —
            # and must not be refused in Report; only NEW findings are.
            if (should_block and tool_name.endswith("record_finding")
                    and args.get("supersedes")):
                should_block, reason = False, "finding correction (supersedes) allowed in Report"
            if should_block:
                # Record the block so a blocked-then-dropped tool is auditable.
                try:
                    from core.execution_log import log
                    log.record_tool_blocked(tool_name, f"dair_phase_gate: {reason}")
                except Exception:
                    pass
                raise ToolError(f"Tool {tool_name} blocked: {reason}.")

        # 2b. DAIR engagement nudge (allow → notice → block; see constants above)
        notices: list = []
        repeat_key = None
        if tool_name not in DAIR_GATE_ALLOWLIST:
            if not (tool_name.startswith(_NUDGE_SKIP_PREFIXES)
                    or tool_name.endswith(_NUDGE_SKIP_SUFFIXES)):
                repeat_key = _repeat_key(tool_name, args)
                rmsg = _repeat_precheck(repeat_key, tool_name)
                if rmsg:
                    try:
                        from core.execution_log import log
                        log.record_tool_blocked(tool_name, rmsg[:300])
                    except Exception:
                        pass
                    raise ToolError(f"Tool {tool_name} blocked: {rmsg}")
            action, nmsg = _nudge_decision(tool_name)
            if action == "block":
                try:
                    from core.execution_log import log
                    log.record_tool_blocked(tool_name, f"dair_engagement_gate: {nmsg[:300]}")
                except Exception:
                    pass
                raise ToolError(f"Tool {tool_name} blocked: {nmsg}")
            if action == "notice":
                notices.append(("dair_notice", nmsg))
            fmsg = _finding_nudge()
            if fmsg:
                notices.append(("finding_notice", fmsg))

        if "_note" in (context.message.arguments or {}):
            new_message = context.message.model_copy(update={"arguments": args})
            context = context.copy(message=new_message)

        # 3. Trace coverage
        try:
            from core.execution_log import log as _log
            entries_before: int | None = len(_log._entries)
        except Exception:
            entries_before = None

        start = time.perf_counter()

        try:
            result = await call_next(context)
        except ToolError:
            raise
        except asyncio.CancelledError:
            _trace_cancelled(tool_name, round(time.perf_counter() - start, 2))
            raise
        except Exception as e:
            _trace_exception(tool_name, e, round(time.perf_counter() - start, 2), args)
            if _is_input_validation(e):
                # A typed refusal shape, like the gates: name the fields so the
                # agent fixes the kwarg instead of guessing from a 500.
                raise ToolError(
                    f"{tool_name} rejected its input (gate: input_validation): "
                    f"{str(e)[:600]} | args received: {_arg_shapes(args)}"
                ) from e
            raise ToolError(f"{tool_name} raised {type(e).__name__}: {e}") from e

        _trace_success_baseline(tool_name, round(time.perf_counter() - start, 2),
                                entries_before, result)

        # 4. Forensic-knowledge enrichment — adds interpretive context to the
        #    result (caveats, does_not_prove, field/exit-code meanings, generic
        #    provenance + discipline tier). Additive only; never touches
        #    success/data/_trudi_call_id. Fails open.
        #    FastMCP wraps dict-returning tools in a ToolResult (content +
        #    structured_content); enrich the structured dict and keep the text
        #    content block in sync so the client sees it either way.
        try:
            _is_poll = tool_name.endswith("job_status")
            if not _is_poll and tool_name not in DAIR_GATE_ALLOWLIST:
                _reset_poll_run()   # a real tool call breaks a poll run
            from tools._enrich import enrich
            if isinstance(result, dict):
                # Repeat-hash the RAW tool output, BEFORE enrich() decorates it
                # — enrich adds rotating interpretive fields (discipline_reminder)
                # that would make every identical call look different.
                if repeat_key:
                    rn = _repeat_update(repeat_key, tool_name, result)
                    if rn:
                        notices.append(("repeat_notice", rn))
                if _is_poll:
                    pn = _note_poll_and_advise(result)
                    if pn:
                        notices.append(("poll_advisory", pn))
                result = _apply_notices(enrich(tool_name, result), notices)
            else:
                sc = _result_payload(result)
                if isinstance(sc, dict):
                    if repeat_key:
                        rn = _repeat_update(repeat_key, tool_name, dict(sc))
                        if rn:
                            notices.append(("repeat_notice", rn))
                    if _is_poll:
                        pn = _note_poll_and_advise(dict(sc))
                        if pn:
                            notices.append(("poll_advisory", pn))
                    enriched = _apply_notices(enrich(tool_name, dict(sc)), notices)
                    update = {"structured_content": enriched}
                    blocks = getattr(result, "content", None)
                    if (isinstance(blocks, list) and len(blocks) == 1
                            and getattr(blocks[0], "type", None) == "text"):
                        import json as _json
                        from mcp.types import TextContent
                        update["content"] = [TextContent(type="text",
                                                         text=_json.dumps(enriched))]
                    result = result.model_copy(update=update)
        except Exception:
            pass

        return result
