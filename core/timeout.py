"""Watchdog waits with owned continuation; a timeout does not kill Python work."""
import functools


def with_tool_timeout(seconds: int, label: str | None = None):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            from core.operations import execute
            return execute(fn, label or fn.__name__, seconds, args, kwargs)
        return wrapper
    return deco
