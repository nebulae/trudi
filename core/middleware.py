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
    "misc_record_agent_message",
    "misc_record_self_correction",
    "misc_serve_dashboard",
    # Phase director itself
    "dair_assess",
    "dair_dair_assess",
    # Pre-flight reads that run before the first dair_assess
    "reason_plan",
    "hash_verify_evidence_hash",
    "vol_symbol_check",
    "vol_vol_symbol_check",
    "ez_ez_recmd_hive",
    "strings_stat_file",
})

DAIR_WINDOW = 20


# ── MCP routing gate configuration ───────────────────────────────────────────

FORENSIC_BINARY_PATTERNS = (
    r"/usr/local/bin/vol\b",
    r"(?<![\w-])vol\.py\b",
    r"\bdotnet\s+\S*(?:MFTECmd|RECmd|EvtxECmd|PECmd|JLECmd|LECmd|SBECmd|"
    r"AmcacheParser|AppCompatCacheParser|WxTCmd|SQLECmd|RBCmd|RLA)\.dll",
    r"(?<![\w-])(?:fls|icat|istat|ils|blkls|mactime|tsk_recover|sigfind|"
    r"sorter|jls|jcat|mmls|fsstat|mmcat|mmstat|blkcalc|blkcat|blkstat|"
    r"ffind|hfind)\b",
    r"(?<![\w-])(?:hexdump|xxd|exiftool|ssdeep|hashdeep|md5deep)\b",
    r"(?<![\w-])(?:log2timeline\.py|psort\.py|pinfo\.py)\b",
    r"(?<![\w-])(?:yara|yarac|bulk_extractor|foremost|scalpel|photorec)\b",
    r"(?<![\w-])(?:ewfmount|ewfinfo|ewfverify|vshadowmount|bdemount|xmount)\b",
    r"(?<![\w-])tcpdump\b",
    r"(?<![\w-])clamscan\b",
    r"(?<![\w-])rip\.pl\b",
)

MCP_WRAPPER_HINTS = {
    "vol": "vol.vol_* (e.g. vol.vol_pslist, vol.vol_netscan)",
    "RECmd": "ez.ez_recmd_hive / ez.ez_recmd_batch",
    "MFTECmd": "ez.ez_mftecmd",
    "EvtxECmd": "ez.ez_evtxecmd",
    "PECmd": "ez.ez_pecmd",
    "JLECmd": "ez.ez_jlecmd",
    "LECmd": "ez.ez_lecmd",
    "SBECmd": "ez.ez_sbecmd",
    "AmcacheParser": "ez.ez_amcacheparser",
    "AppCompatCacheParser": "ez.ez_appcompatcacheparser",
    "WxTCmd": "ez.ez_wxtcmd",
    "SQLECmd": "ez.ez_sqlecmd",
    "RBCmd": "ez.ez_rbcmd",
    "RLA": "ez.ez_rla",
    "fls": "tsk.tsk_fls",
    "icat": "tsk.tsk_icat",
    "istat": "tsk.tsk_istat",
    "ils": "tsk.tsk_ils",
    "blkls": "tsk.tsk_blkls",
    "mactime": "tsk.tsk_mactime",
    "tsk_recover": "tsk.tsk_recover",
    "sigfind": "tsk.tsk_sigfind",
    "sorter": "tsk.tsk_sorter",
    "jls": "tsk.tsk_jls",
    "jcat": "tsk.tsk_jcat",
    "mmls": "tsk.tsk_mmls",
    "fsstat": "tsk.tsk_fsstat",
    "hexdump": "strings.strings_hexdump",
    "xxd": "strings.strings_xxd_dump",
    "exiftool": "strings.strings_exiftool_metadata / strings.strings_exiftool_batch",
    "ssdeep": "hash.hash_ssdeep_hash / hash.hash_ssdeep_compare",
    "hashdeep": "hash.hash_hashdeep_compute / hash.hash_hashdeep_audit",
    "md5deep": "hash.hash_md5deep_scan",
    "log2timeline.py": "plaso.plaso_create_timeline / plaso.plaso_create_targeted",
    "psort.py": "plaso.plaso_export_csv / plaso.plaso_export_json / plaso.plaso_filter_incident_window",
    "pinfo.py": "plaso.plaso_info / plaso.plaso_list_parsers",
    "yara": "yara.yara_scan_file / yara.yara_scan_directory / yara.yara_scan_memory_image",
    "bulk_extractor": "carve.carve_bulk_extractor_scan",
    "foremost": "carve.carve_foremost_carve",
    "scalpel": "carve.carve_scalpel_carve",
    "photorec": "img.img_photorec_carve",
    "ewfmount": "ewf.ewf_ewf_mount / ewf.ewf_mount_full_image",
    "ewfinfo": "ewf.ewf_ewf_info",
    "ewfverify": "ewf.ewf_ewf_verify",
    "vshadowmount": "img.img_vshadow_mount",
    "bdemount": "img.img_bde_mount",
    "xmount": "img.img_xmount_image",
    "tcpdump": "net.net_tcpdump_read / net.net_tcpdump_extract_http / net.net_tcpdump_extract_dns",
    "clamscan": "misc.misc_clamscan_file / misc.misc_clamscan_directory",
    "rip.pl": "misc.misc_regripper_hive",
}


def _identify_forensic_binary(cmd: str) -> str | None:
    import re
    if not cmd:
        return None
    for pat in FORENSIC_BINARY_PATTERNS:
        if not re.search(pat, cmd):
            continue
        for key in MCP_WRAPPER_HINTS:
            if key in cmd:
                return key
        return ""
    return None


# ── Gate helpers ──────────────────────────────────────────────────────────────

def _gate_decision() -> tuple[bool, str]:
    """Return (should_block, reason). Fail-open on gate errors, but log them."""
    try:
        from core.execution_log import log
        entries = log._entries
        if not entries:
            return False, "cold start (empty trace)"
        ever_dair = any(e.get("type") == "dair_call" for e in entries)
        if not ever_dair:
            return False, "cold start (DAIR not yet engaged)"
        recent_dair = any(e.get("type") == "dair_call" for e in entries[-DAIR_WINDOW:])
        if recent_dair:
            return False, "active DAIR batch"
        return True, "DAIR engaged earlier but no dair_call in recent window"
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


def _trace_exception(tool_name: str, exc: Exception, elapsed: float) -> None:
    tb = traceback.format_exc()
    try:
        from core.execution_log import log
        log.record_tool_call(
            cmd=f"<py>:{tool_name}",
            success=False,
            truncated=False,
            retries=0,
            exit_code=-1,
            stderr=f"Unhandled {type(exc).__name__} in {tool_name}:\n{tb}"[:4096],
            elapsed_seconds=elapsed,
            input_call_ids=_parent_cids(),
        )
    except Exception as log_err:
        print(
            f"[TRUDI FATAL] tool exception + trace-write failure for "
            f"{tool_name}: original={exc!r}; trace_err={log_err!r}\n{tb}",
            file=sys.stderr, flush=True,
        )


def _trace_success_baseline(tool_name: str, elapsed: float,
                             entries_before: int | None) -> None:
    """Write a baseline tool_call entry if the tool didn't self-log.

    Subprocess tools self-log via core.executor._log_tool. reason_*/dair_*
    self-log via record_reason_call/record_dair_call. Pure-Python tools
    (correlate_*, accuracy_*, etc.) don't — this baseline makes them visible.
    Self-logging is detected by whether log._entries grew during the call.
    """
    if entries_before is None:
        return
    try:
        from core.execution_log import log
        if len(log._entries) == entries_before:
            log.record_tool_call(
                cmd=f"<py>:{tool_name}",
                success=True,
                truncated=False,
                retries=0,
                exit_code=0,
                elapsed_seconds=elapsed,
                input_call_ids=_parent_cids(),
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
            if should_block:
                raise ToolError(
                    f"Tool {tool_name} blocked: no active DAIR batch ({reason}). "
                    f"Call dair_assess before forensic tools — its priority_tools "
                    f"is the work order for the next batch."
                )

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
            _trace_exception(tool_name, e, round(time.perf_counter() - start, 2))
            raise ToolError(f"{tool_name} raised {type(e).__name__}: {e}") from e

        _trace_success_baseline(tool_name, round(time.perf_counter() - start, 2),
                                entries_before)
        return result
