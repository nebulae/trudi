"""Watchdog timeout for in-process tool work.

Subprocess-based tools already enforce timeouts via `subprocess.run(timeout=…)`
in `core.executor.run`. Pure-Python tools (chunked hashing, in-process parsers)
have no such guard — they can chew a 19 GB memory image for ten minutes while
the MCP client gives up and the agent loses sight of the call.

`with_tool_timeout(seconds=…)` wraps a sync MCP tool function with a watchdog:
the body runs in a daemon thread, and if it doesn't return within the budget,
the wrapper returns a structured failure dict so the agent sees a real refusal
it can react to. The background thread is left to finish (Python has no clean
thread-kill primitive); any side effects like cache writes still complete and
benefit the next call.

The timeout entry is also logged via `execution_log.record_call_abandoned` so
the dashboard surfaces it as a `call_abandoned` event.
"""
from __future__ import annotations
import functools
import sys
import threading
from typing import Any, Callable


def with_tool_timeout(seconds: int, label: str | None = None) -> Callable:
    """Decorate a sync MCP tool body with a watchdog timeout.

    On timeout, returns:
        {
          "success": False,
          "error": "Tool exceeded <N>s budget — abandoned",
          "timed_out": True,
          "killed_after_seconds": <N>,
          "tool": "<label or fn.__name__>",
          "note": "Background work continues; cache may populate for next call",
        }
    """
    def deco(fn: Callable) -> Callable:
        tool_label = label or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            box: dict[str, Any] = {"result": None, "error": None}

            def _runner() -> None:
                try:
                    box["result"] = fn(*args, **kwargs)
                except BaseException as e:  # noqa: BLE001 — re-raised after join
                    box["error"] = e

            t = threading.Thread(
                target=_runner,
                daemon=True,
                name=f"trudi-timeout:{tool_label}",
            )
            t.start()
            t.join(seconds)

            if t.is_alive():
                try:
                    from core.execution_log import log as _elog
                    _parent = [_elog._last_dair_cid] if _elog._last_dair_cid else None
                    _elog.record_call_abandoned(
                        tool_label,
                        f"timeout after {seconds}s (watchdog)",
                        input_call_ids=_parent,
                    )
                except Exception as _e:
                    print(f"[TRUDI WARN] timeout trace log failed: {_e}",
                          file=sys.stderr)
                    # Trace the trace-write failure itself so it's not invisible.
                    try:
                        from core.execution_log import log as _elog
                        _elog.record_system_error(
                            "timeout_log",
                            f"record_call_abandoned failed for "
                            f"{tool_label} after {seconds}s: {_e!r}",
                        )
                    except Exception:
                        pass
                return {
                    "success": False,
                    "error": f"Tool exceeded {seconds}s budget — abandoned",
                    "timed_out": True,
                    "killed_after_seconds": seconds,
                    "tool": tool_label,
                    "note": ("Background work continues; cache may populate "
                             "for next call. Re-call with smaller scope or "
                             "raise the budget via env var if appropriate."),
                }

            if box["error"] is not None:
                raise box["error"]
            return box["result"]

        return wrapper
    return deco
