"""Shared fixtures for TRUDI test suite."""
import pytest
from unittest.mock import MagicMock, patch


def make_proc(returncode=0, stdout=b"output", stderr=b""):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


@pytest.fixture
def ok_proc():
    return make_proc(0, b"tool output", b"")


@pytest.fixture
def fail_proc():
    return make_proc(1, b"", b"error detail")


@pytest.fixture
def run_ok():
    return {
        "success": True,
        "stdout": "tool output",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "cmd": "tool arg",
    }


@pytest.fixture
def run_fail():
    return {
        "success": False,
        "stdout": "",
        "stderr": "error detail",
        "exit_code": 1,
        "truncated": False,
        "cmd": "tool arg",
    }


@pytest.fixture(autouse=True)
def isolate_session_file(tmp_path):
    """Redirect _SESSION_FILE so tests never overwrite the real TRUDI session.
    Also configure a per-test trace log so tests that hit core.executor.run()
    don't trip the new `_require_configured` raise (the global error-surfacing
    refactor turned silent drops into RuntimeErrors).

    The session + trace files live under a hidden subdir so they don't bleed
    into filesystem-walking tests that use tmp_path directly (e.g. hash_directory).
    """
    import core.execution_log as elog
    internal = tmp_path / ".pytest-trudi"
    internal.mkdir(exist_ok=True)
    fake_session = str(internal / "session.json")
    fake_trace = str(internal / "trace.json")
    fake_counter = str(internal / "call_id.counter")
    # Isolate the shared call_id counter too — otherwise tests that assert
    # call_id == 1 race against the real ~/.cache/trudi/call_id.counter (shared
    # with any live TRUDI session AND any concurrently-running pytest process).
    # The hook.lock is GLOBAL in production (the MCP server and the Claude
    # hooks serialize on it). Under pytest it must be per-test: otherwise every
    # flush contends with a live TRUDI session and with every other pytest
    # worker (xdist), and the suite serializes on one fcntl lock. fsync is off
    # for the same reason — durability is a production property, not a test
    # property (each fsync is ~80 ms on WSL2; the suite flushes ~100k times).
    fake_lock = str(internal / "hook.lock")
    with patch.object(elog, "_SESSION_FILE", fake_session), \
         patch.object(elog, "_CALL_ID_COUNTER_FILE", fake_counter), \
         patch.object(elog, "_TRACE_LOCK_FILE", fake_lock), \
         patch.object(elog, "_TRACE_FSYNC", False):
        # save_session=False is belt-and-suspenders alongside the
        # _SESSION_FILE patch: ensures even if the patch is bypassed (or
        # a test re-imports the module), the global session file stays
        # untouched. The root cause of one silent-failure incident was
        # an ad-hoc `python -c log.configure(...)` script outside any
        # fixture overwriting ~/.cache/trudi/session.json and silently
        # rerouting the active investigation's writes.
        elog.log.configure("PYTEST", fake_trace, save_session=False)
        yield


@pytest.fixture(autouse=True)
def typed_claims_env_off(monkeypatch):
    """Typed-claim enforcement (typed_claims gate) defaults ON in production;
    the legacy test corpus predates claim declarations, so default it OFF for
    tests. tests/tools/test_typed_claims.py switches it back on explicitly."""
    monkeypatch.setenv("TRUDI_REQUIRE_TYPED_CLAIMS", "0")


@pytest.fixture
def tmp_evidence(tmp_path):
    """A fake evidence file (not in a protected path)."""
    f = tmp_path / "image.raw"
    f.write_bytes(b"\x00" * 1024)
    return str(f)


@pytest.fixture
def tmp_output(tmp_path):
    """A writable output directory (not in evidence paths)."""
    d = tmp_path / "exports"
    d.mkdir()
    return str(d)
