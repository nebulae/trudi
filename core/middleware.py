"""FastMCP middleware: trace every MCP tool call and enforce DAIR oversight."""
import asyncio
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
    "dair_dair_assess",
    # Adversarial-review + scoring META tools (they reason ABOUT findings, they
    # don't execute forensics), exempt so they never require a fresh dair_assess.
    # record_finding still carries the dair_required gate, keeping the
    # investigation DAIR-directed. Bare and namespace-doubled forms both listed.
    "reason_plan", "reason_reason_plan",
    "reason_hypothesize", "reason_reason_hypothesize",
    "reason_evaluate_finding", "reason_reason_evaluate_finding",
    "reason_confidence_score", "reason_reason_confidence_score",
    "reason_cite_check", "reason_reason_cite_check",
    "reason_audit_findings", "reason_reason_audit_findings",
    "reason_synthesize", "reason_reason_synthesize",
    "reason_pre_report_check", "reason_reason_pre_report_check",
    "accuracy_compare", "accuracy_accuracy_compare",
    "accuracy_export_report", "accuracy_accuracy_export_report",
    "correlate_mitre_validate", "correlate_correlate_mitre_validate",
    # Produced-output readers — they read parsed output only (never evidence),
    # so they are phase-free: legal in Report to ground citations while writing.
    "read_output", "read_read_output",
    "read_mail", "read_read_mail",
    # Pre-flight reads that run before the first dair_assess
    "hash_verify_evidence_hash",
    "vol_symbol_check",
    "vol_vol_symbol_check",
    "ez_ez_recmd_hive",
    "strings_stat_file",
})

# The gate reads DAIR's own phase state (the execution log maintains
# _current_phase via DAIR transitions), not a tool counter. Forensics are allowed
# pre-plan (before DAIR engages) and in any active evidence phase; blocked only in
# Report, where DAIR has decided the investigation is converging — new evidence
# then requires a DAIR-directed return to a collection phase.
_DAIR_ACTIVE_PHASES = frozenset({"Triage", "Collect", "Analyze", "Scan"})
DAIR_WINDOW = 20       # retained for backward-compat imports; no longer used by the gate


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
            from tools._enrich import enrich
            if isinstance(result, dict):
                result = enrich(tool_name, result)
            else:
                sc = _result_payload(result)
                if isinstance(sc, dict):
                    enriched = enrich(tool_name, dict(sc))
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
