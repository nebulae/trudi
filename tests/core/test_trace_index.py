"""Tests for the lazy LogIndex on ExecutionLog."""
import pytest
from core.execution_log import ExecutionLog, LogIndex, _extract_tool_from_entry


@pytest.fixture
def log(tmp_path):
    l = ExecutionLog()
    l.configure("IDX-TEST", str(tmp_path / "trace.json"))
    return l


def test_index_empty(log):
    idx = log.index()
    assert isinstance(idx, LogIndex)
    assert idx.by_call_id == {}
    assert idx.by_type == {}


def test_index_by_call_id(log):
    log.record_tool_call("vol psscan", True, False, 0, 0)
    log.record_tool_call("vol netscan", True, False, 0, 0)
    idx = log.index()
    assert 1 in idx.by_call_id
    assert 2 in idx.by_call_id
    assert idx.by_call_id[1]["cmd"] == "vol psscan"


def test_index_by_type(log):
    log.record_tool_call("vol psscan", True, False, 0, 0)
    log.record_finding("test finding", "SUSPECTED")
    idx = log.index()
    assert len(idx.by_type["tool_call"]) == 1
    assert len(idx.by_type["finding"]) == 1


def test_index_by_tool(log):
    log.record_tool_call("vol psscan -f x.dmp", True, False, 0, 0)
    log.record_tool_call("vol netscan -f x.dmp", True, False, 0, 0)
    idx = log.index()
    # Both start with "vol" — basename of cmd[0]
    assert "vol" in idx.by_tool
    assert len(idx.by_tool["vol"]) == 2


def test_index_findings_by_linked(log):
    log.record_tool_call("vol psscan", True, False, 0, 0)  # call_id 1
    log.record_finding("evil proc", "CONFIRMED", source="vol", linked_call_id=1)
    idx = log.index()
    assert 1 in idx.findings_by_linked
    assert len(idx.findings_by_linked[1]) == 1


def test_index_invalidated_on_append(log):
    log.record_tool_call("a", True, False, 0, 0)
    idx1 = log.index()
    assert len(idx1.by_call_id) == 1
    log.record_tool_call("b", True, False, 0, 0)
    idx2 = log.index()
    assert len(idx2.by_call_id) == 2
    assert idx2 is not idx1  # rebuilt


def test_index_cached_when_unchanged(log):
    log.record_tool_call("a", True, False, 0, 0)
    idx1 = log.index()
    idx2 = log.index()
    assert idx1 is idx2  # same object — memoized


def test_last_n_window(log):
    for i in range(50):
        log.record_tool_call(f"cmd{i}", True, False, 0, 0)
    window = log.last_n_window(30)
    assert len(window) == 30
    assert window[0]["cmd"] == "cmd20"
    assert window[-1]["cmd"] == "cmd49"


def test_last_n_window_smaller_than_n(log):
    log.record_tool_call("a", True, False, 0, 0)
    log.record_tool_call("b", True, False, 0, 0)
    window = log.last_n_window(30)
    assert len(window) == 2


def test_extract_tool_prefers_explicit_field():
    e = {"tool": "reason_plan", "cmd": "ignored"}
    assert _extract_tool_from_entry(e) == "reason_plan"


def test_extract_tool_falls_back_to_cmd_basename():
    e = {"cmd": "/usr/local/bin/vol -f image.dmp pslist"}
    assert _extract_tool_from_entry(e) == "vol"


def test_index_on_configure_reload(tmp_path):
    p = str(tmp_path / "trace.json")
    l1 = ExecutionLog()
    l1.configure("R-TEST", p)
    l1.record_tool_call("first", True, False, 0, 0)
    # New log loads the persisted trace
    l2 = ExecutionLog()
    l2.configure("R-TEST", p)
    idx = l2.index()
    assert 1 in idx.by_call_id
