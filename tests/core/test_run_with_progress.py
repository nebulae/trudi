"""run_with_progress streams stderr progress (vol.* tools) — 2026-09-24 regression:
UnboundLocalError on `ctx` failed every Volatility call."""
import asyncio
import sys


class _Ctx:
    def __init__(self, fail=False):
        self.calls, self.fail = 0, fail

    async def report_progress(self, *a):
        self.calls += 1
        if self.fail:
            raise RuntimeError("request gone")


def _run(ctx):
    from core.executor import run_with_progress
    cmd = [sys.executable, "-c",
           "import sys; [print(f'Progress {i}', file=sys.stderr) for i in range(3)]; print('rows')"]
    return asyncio.run(run_with_progress(cmd, ctx, timeout=30))


def test_progress_lines_are_reported_and_run_succeeds():
    ctx = _Ctx()
    r = _run(ctx)
    assert r["success"] is True and "rows" in r["stdout"] and ctx.calls == 3


def test_a_failing_progress_report_stops_reporting_but_not_the_tool():
    ctx = _Ctx(fail=True)
    r = _run(ctx)
    assert r["success"] is True and "rows" in r["stdout"] and ctx.calls == 1


def test_no_ctx():
    assert _run(None)["success"] is True
