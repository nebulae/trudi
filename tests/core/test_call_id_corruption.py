"""Regression tests for the call-id duplication bug (F1).

Scenario: `_next_shared_call_id` previously trusted the counter file
absolutely, so a stale counter (e.g. hand-edited to {"next": 1} while the
trace already had entries up to cid=261) would return cid=1 — colliding
with existing entries. F1 added validation against trace_max + in_memory_seq
so duplicates are impossible by construction.

These three tests would have caught the production corruption observed in
~/cases/srl-2018-demo/.trace-backups/20260523T202446Z/SRL-2018-DEMO_trace.json
(10 duplicate call_ids, 261→4 inflection point).
"""
import json
import os
import threading
import pytest
from unittest.mock import patch


@pytest.fixture
def isolated_cache(tmp_path, monkeypatch):
    """Point all cache paths at a tmp dir so tests don't trample the real cache."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    counter = str(cache_dir / "call_id.counter")
    lock = str(cache_dir / "hook.lock")
    monkeypatch.setattr("core.execution_log._CALL_ID_COUNTER_FILE", counter)
    monkeypatch.setattr("core.execution_log._TRACE_LOCK_FILE", lock)
    return {"dir": cache_dir, "counter": counter, "lock": lock}


def test_stale_counter_does_not_produce_duplicates(isolated_cache, tmp_path):
    """Counter file says {"next": 5} but trace already has entries up to cid=100.
    Five calls to _next_shared_call_id must return 101..105 (not 5..9)."""
    from core.execution_log import _next_shared_call_id

    # Trace with cids up to 100
    trace = tmp_path / "trace.json"
    entries = [{"call_id": i, "type": "tool_call"} for i in range(1, 101)]
    trace.write_text(json.dumps({"case_id": "STALE", "entries": entries}))

    # Stale counter file
    with open(isolated_cache["counter"], "w") as f:
        json.dump({"next": 5}, f)

    returned = [_next_shared_call_id(str(trace)) for _ in range(5)]
    assert returned == [101, 102, 103, 104, 105], (
        f"expected 101..105 (trace had max=100), got {returned}"
    )

    # Counter file ends pointing past the last allocation
    with open(isolated_cache["counter"]) as f:
        assert int(json.load(f)["next"]) == 106


def test_in_memory_seq_protects_against_external_reset(isolated_cache, tmp_path):
    """An ExecutionLog has self._seq=50 (50 entries in memory). External
    process resets counter to {"next": 1}. Next allocation must return 51,
    not 1 — using the in_memory_seq fallback."""
    from core.execution_log import ExecutionLog
    from core import execution_log as elog_mod

    trace_path = str(tmp_path / "trace.json")
    log = ExecutionLog()
    log.configure("RESET-TEST", trace_path)
    # Hand-build 50 entries to push _seq up
    for i in range(50):
        log.record_tool_call(f"cmd-{i}", True, False, 0, 0)
    assert log._seq == 50

    # Simulate external reset of the counter — should not produce duplicates
    with open(isolated_cache["counter"], "w") as f:
        json.dump({"next": 1}, f)

    # In-memory seq protects against this
    cid = elog_mod._next_shared_call_id(log._path, in_memory_seq=log._seq)
    assert cid == 51, f"expected 51 (in_memory_seq=50), got {cid}"

    # Counter file now reflects the corrected allocation
    with open(isolated_cache["counter"]) as f:
        assert int(json.load(f)["next"]) == 52


def test_concurrent_writers_no_duplicates(isolated_cache, tmp_path):
    """20 threads each call _next_shared_call_id simultaneously with the same
    trace_path (file has max cid = 100). All returned cids must be unique
    AND all ≥ 101."""
    from core.execution_log import _next_shared_call_id

    trace = tmp_path / "trace.json"
    entries = [{"call_id": i, "type": "tool_call"} for i in range(1, 101)]
    trace.write_text(json.dumps({"case_id": "CONCURRENT", "entries": entries}))

    # Stale counter
    with open(isolated_cache["counter"], "w") as f:
        json.dump({"next": 5}, f)

    N = 20
    results: list[int] = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(N)

    def worker():
        barrier.wait()
        cid = _next_shared_call_id(str(trace))
        with results_lock:
            results.append(cid)

    threads = [threading.Thread(target=worker) for _ in range(N)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert len(set(results)) == N, f"duplicates in concurrent allocation: {results}"
    assert all(c >= 101 for c in results), f"got cids below trace max+1: {[c for c in results if c < 101]}"


def test_trudi_reset_atomic(tmp_path, isolated_cache):
    """trudi_reset CLI clears all cache files and backs up the trace."""
    from tools.trudi_reset import reset

    # Set up a fake case dir
    case = tmp_path / "fake-case"
    (case / "analysis").mkdir(parents=True)
    (case / "CLAUDE.md").write_text("**Case ID**: FAKE-001")
    trace_path = case / "analysis" / "FAKE-001_trace.json"
    trace_path.write_text(json.dumps({"case_id": "FAKE-001", "entries": [
        {"call_id": 1, "type": "tool_call"}, {"call_id": 2, "type": "finding"},
    ]}))
    (case / "analysis" / "dashboard.url").write_text("http://localhost:8765/x")

    # Seed cache state
    with open(isolated_cache["counter"], "w") as f:
        json.dump({"next": 999}, f)
    # Patch the cache paths the reset CLI uses
    with patch("tools.trudi_reset._COUNTER_FILE", isolated_cache["counter"]), \
         patch("tools.trudi_reset._SESSION_FILE", str(isolated_cache["dir"] / "session.json")), \
         patch("tools.trudi_reset._HOOK_STATE_FILE", str(isolated_cache["dir"] / "hook_state.json")), \
         patch("tools.trudi_reset._LOCK_FILE", isolated_cache["lock"]), \
         patch("tools.trudi_reset._CACHE_DIR", str(isolated_cache["dir"])):
        result = reset(str(case))

    assert result["success"] is True
    assert result["case_id"] == "FAKE-001"
    # Counter reset to 1
    with open(isolated_cache["counter"]) as f:
        assert int(json.load(f)["next"]) == 1
    # Trace gone from analysis/
    assert not trace_path.exists()
    # Dashboard URL gone
    assert not (case / "analysis" / "dashboard.url").exists()
    # Backup created
    assert result.get("backup_dir"), "expected a backup dir in result"
    assert os.path.exists(os.path.join(result["backup_dir"], "FAKE-001_trace.json"))
