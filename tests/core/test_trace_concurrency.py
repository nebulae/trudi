"""Verify the trace flush is safe under concurrent record_* calls.

The audit flagged a hypothetical race in `_flush` (read trace JSON, merge with
in-memory, write back). In practice the read-merge-write critical section is
wrapped in an `fcntl.flock(_TRACE_LOCK_FILE, LOCK_EX)` + atomic temp-file
rename, so two callers serialise on the same lock file. This test exercises
that property: 20 concurrent record_tool_call calls all land in the trace
with unique, dense call_ids and no JSON corruption.
"""
import json
import os
import threading
import pytest

from core.execution_log import ExecutionLog


def test_concurrent_record_tool_call_no_corruption(tmp_path):
    """20 threads append simultaneously — every call_id unique, JSON intact."""
    p = str(tmp_path / "concurrent.json")
    log = ExecutionLog()
    log.configure("STRESS", p)

    N = 20
    barrier = threading.Barrier(N)
    errors: list[Exception] = []

    def worker(i: int):
        try:
            barrier.wait()  # release all threads at once
            log.record_tool_call(f"cmd-{i}", True, False, 0, 0)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"worker raised: {errors}"
    # All entries landed in memory
    assert len(log._entries) == N

    # All call_ids unique
    ids = [e["call_id"] for e in log._entries]
    assert len(set(ids)) == N, f"duplicate call_ids: {ids}"

    # Disk-state matches in-memory after final flush
    with open(p) as f:
        data = json.load(f)
    assert data["entry_count"] == N
    assert {e["call_id"] for e in data["entries"]} == set(ids)


def test_concurrent_findings_with_dair(tmp_path):
    """Mixed write workload — dair_calls + findings — still serialises correctly."""
    p = str(tmp_path / "mixed.json")
    log = ExecutionLog()
    log.configure("MIXED", p)
    # Prime a dair_call so dair_required gate is satisfiable if used elsewhere.
    log.record_dair_call(
        current_phase="Triage",
        phase_rationale="test",
        transition_recommended=False,
        next_phase="",
        transition_rationale="",
        stack_action="stay",
        investigation_focus="",
    )

    N = 10
    barrier = threading.Barrier(N)

    def worker(i: int):
        barrier.wait()
        log.record_finding(f"finding {i}", "SUSPECTED", source="test", linked_call_id=0)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 1 dair_call + 10 findings
    assert len(log._entries) == 11
    finding_ids = [e["call_id"] for e in log._entries if e.get("type") == "finding"]
    assert len(set(finding_ids)) == 10
