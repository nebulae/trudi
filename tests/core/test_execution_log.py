"""Tests for core/execution_log.py."""
import json
import os
import pytest
from core.execution_log import ExecutionLog


class TestExecutionLog:
    @pytest.fixture
    def log(self, tmp_path):
        l = ExecutionLog()
        l.configure("TEST-001", str(tmp_path / "trace.json"))
        return l

    def test_configure_sets_case_id(self, log):
        assert log._case_id == "TEST-001"

    def test_configure_creates_file(self, tmp_path):
        l = ExecutionLog()
        p = str(tmp_path / "new.json")
        l.configure("X", p)
        with open(p) as f:
            data = json.load(f)
        assert data["case_id"] == "X"

    def test_configure_resets_entries(self, tmp_path):
        l = ExecutionLog()
        l.configure("A", str(tmp_path / "a.json"))
        l.record_finding("test", "high")
        l.configure("B", str(tmp_path / "b.json"))
        assert l._entries == []
        assert l._case_id == "B"

    def test_record_tool_call_type(self, log):
        log.record_tool_call("vol psscan", True, False, 0, 0)
        assert log._entries[0]["type"] == "tool_call"

    def test_record_tool_call_fields(self, log):
        log.record_tool_call("vol psscan", True, True, 2, 0, "warn")
        e = log._entries[0]
        assert e["cmd"] == "vol psscan"
        assert e["success"] is True
        assert e["truncated"] is True
        assert e["retries"] == 2
        assert e["stderr"] == "warn"

    def test_record_reason_call_type(self, log):
        log.record_reason_call("reason_plan", True, "investigation plan", {})
        assert log._entries[0]["type"] == "reason_call"
        assert log._entries[0]["tool"] == "reason_plan"

    def test_record_reason_call_conclusion_capped(self, log):
        log.record_reason_call("reason_plan", True, "x" * 1000, {})
        assert len(log._entries[0]["conclusion"]) == 500

    def test_record_finding_type(self, log):
        log.record_finding("BlazingTools keylogger", "high", "Amcache")
        e = log._entries[0]
        assert e["type"] == "finding"
        assert e["confidence"] == "high"
        assert e["source"] == "Amcache"

    def test_flush_writes_to_path(self, log, tmp_path):
        log.record_finding("test finding", "medium")
        with open(str(tmp_path / "trace.json")) as f:
            data = json.load(f)
        assert any(e["type"] == "finding" for e in data["entries"])

    def test_to_json_structure(self, log):
        log.record_tool_call("cmd", True, False, 0, 0)
        j = log.to_json()
        assert j["case_id"] == "TEST-001"
        assert j["entry_count"] == 1
        assert len(j["entries"]) == 1

    def test_to_markdown_contains_tool_ok(self, log):
        log.record_tool_call("vol psscan", True, False, 0, 0)
        md = log.to_markdown()
        assert "TOOL" in md
        assert "vol psscan" in md
        assert "OK" in md

    def test_to_markdown_contains_tool_fail_with_stderr(self, log):
        log.record_tool_call("vol malfind", False, False, 0, 1, "permission denied")
        md = log.to_markdown()
        assert "FAIL" in md
        assert "permission denied" in md

    def test_to_markdown_truncated_flag(self, log):
        log.record_tool_call("vol pstree", True, True, 0, 0)
        assert "[TRUNCATED]" in log.to_markdown()

    def test_to_markdown_retries_shown(self, log):
        log.record_tool_call("vol netscan", True, False, 2, 0)
        assert "2 retries" in log.to_markdown()

    def test_to_markdown_reason_with_directives(self, log):
        log.record_reason_call(
            "reason_plan", True, "run psscan first", {"priority_tools": ["vol.psscan"]}
        )
        md = log.to_markdown()
        assert "REASON" in md
        assert "priority_tools" in md

    def test_to_markdown_finding_uppercase_confidence(self, log):
        log.record_finding("exfil via BITS", "high")
        assert "[HIGH]" in log.to_markdown()

    def test_export_writes_json_and_md(self, log, tmp_path):
        log.record_finding("test", "low")
        out = str(tmp_path / "export")
        log.export(out)
        assert os.path.exists(out + ".json")
        assert os.path.exists(out + ".md")

    def test_export_json_parseable(self, log, tmp_path):
        log.record_tool_call("cmd", True, False, 0, 0)
        out = str(tmp_path / "export")
        log.export(out)
        with open(out + ".json") as f:
            data = json.load(f)
        assert data["case_id"] == "TEST-001"

    def test_no_record_when_unconfigured(self):
        l = ExecutionLog()  # no configure() call
        l.record_tool_call("cmd", True, False, 0, 0)
        l.record_finding("test", "high")
        l.record_reason_call("r", True, "c", {})
        assert l._entries == []

    def test_bad_flush_path_does_not_raise(self):
        l = ExecutionLog()
        l._path = "/nonexistent/dir/trace.json"
        l._case_id = "X"
        l._entries = []
        l._flush()  # should not raise
