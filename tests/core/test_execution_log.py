"""Tests for core/execution_log.py."""
import json
import os
import pytest
from unittest.mock import patch
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

    def test_configure_resets_entries_for_new_path(self, tmp_path):
        l = ExecutionLog()
        l.configure("A", str(tmp_path / "a.json"))
        l.record_finding("test", "high")
        # Different path → always fresh (no prior file for "B")
        l.configure("B", str(tmp_path / "b.json"))
        assert l._entries == []
        assert l._case_id == "B"

    def test_configure_resets_seq(self, tmp_path):
        l = ExecutionLog()
        l.configure("A", str(tmp_path / "a.json"))
        l.record_finding("test", "high")
        l.configure("B", str(tmp_path / "b.json"))
        assert l._seq == 0

    # ── record_tool_call ───────────────────────────────────────────────────────

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

    def test_record_tool_call_has_call_id(self, log):
        log.record_tool_call("vol psscan", True, False, 0, 0)
        assert log._entries[0]["call_id"] == 1

    def test_record_tool_call_returns_call_id(self, log):
        cid = log.record_tool_call("vol psscan", True, False, 0, 0)
        assert cid == 1

    def test_record_tool_call_increments_call_id(self, log):
        cid1 = log.record_tool_call("vol psscan", True, False, 0, 0)
        cid2 = log.record_tool_call("vol netscan", True, False, 0, 0)
        assert cid2 == cid1 + 1

    # ── record_reason_call ─────────────────────────────────────────────────────

    def test_record_reason_call_type(self, log):
        log.record_reason_call("reason_plan", True, "investigation plan", {})
        assert log._entries[0]["type"] == "reason_call"
        assert log._entries[0]["tool"] == "reason_plan"

    def test_record_reason_call_full_conclusion_stored(self, log):
        long_text = "x" * 1000
        log.record_reason_call("reason_plan", True, long_text, {})
        assert log._entries[0]["conclusion"] == long_text

    def test_record_reason_call_has_call_id(self, log):
        log.record_reason_call("reason_plan", True, "plan", {})
        assert log._entries[0]["call_id"] == 1

    def test_record_reason_call_stores_tokens(self, log):
        log.record_reason_call("reason_hypothesize", True, "hyp", {}, input_tokens=500, output_tokens=200)
        e = log._entries[0]
        assert e["input_tokens"] == 500
        assert e["output_tokens"] == 200

    def test_record_reason_call_default_tokens_zero(self, log):
        log.record_reason_call("reason_plan", True, "plan", {})
        e = log._entries[0]
        assert e["input_tokens"] == 0
        assert e["output_tokens"] == 0

    # ── record_finding ─────────────────────────────────────────────────────────

    def test_record_finding_type(self, log):
        log.record_finding("BlazingTools keylogger", "high", "Amcache")
        e = log._entries[0]
        assert e["type"] == "finding"
        assert e["confidence"] == "high"
        assert e["source"] == "Amcache"

    def test_record_finding_has_call_id(self, log):
        log.record_finding("keylogger", "high")
        assert log._entries[0]["call_id"] == 1

    def test_record_finding_linked_call_id(self, log):
        log.record_finding("exfil via BITS", "CONFIRMED", "ez.mftecmd", linked_call_id=7)
        assert log._entries[0]["linked_call_id"] == 7

    def test_record_finding_linked_call_id_default_zero(self, log):
        log.record_finding("test", "high")
        assert log._entries[0]["linked_call_id"] == 0

    # ── call_id sequence across types ─────────────────────────────────────────

    def test_call_ids_sequence_across_types(self, log):
        log.record_tool_call("cmd", True, False, 0, 0)
        log.record_reason_call("reason_plan", True, "plan", {})
        log.record_finding("finding", "high")
        ids = [e["call_id"] for e in log._entries]
        assert ids == [1, 2, 3]

    # ── persistence ───────────────────────────────────────────────────────────

    def test_flush_writes_to_path(self, log, tmp_path):
        log.record_finding("test finding", "medium")
        with open(str(tmp_path / "trace.json")) as f:
            data = json.load(f)
        assert any(e["type"] == "finding" for e in data["entries"])

    # ── to_json ───────────────────────────────────────────────────────────────

    def test_to_json_structure(self, log):
        log.record_tool_call("cmd", True, False, 0, 0)
        j = log.to_json()
        assert j["case_id"] == "TEST-001"
        assert j["entry_count"] == 1
        assert len(j["entries"]) == 1

    def test_to_json_schema_version(self, log):
        j = log.to_json()
        assert j["schema_version"] == "2.0"

    # ── to_markdown ───────────────────────────────────────────────────────────

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

    def test_to_markdown_call_id_prefix(self, log):
        log.record_tool_call("vol psscan", True, False, 0, 0)
        md = log.to_markdown()
        assert "[#1]" in md

    def test_to_markdown_token_counts(self, log):
        log.record_reason_call("reason_hypothesize", True, "hyp", {}, input_tokens=300, output_tokens=150)
        md = log.to_markdown()
        assert "in=300" in md
        assert "out=150" in md

    def test_to_markdown_finding_linked_call_id(self, log):
        log.record_finding("PerfSvc.exe timestomped", "CONFIRMED", "ez.mftecmd", linked_call_id=5)
        md = log.to_markdown()
        assert "← tool call #5" in md

    def test_to_markdown_finding_no_link_when_zero(self, log):
        log.record_finding("test", "high")
        md = log.to_markdown()
        assert "← tool call" not in md

    # ── export ────────────────────────────────────────────────────────────────

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
        assert data["schema_version"] == "2.0"

    # ── edge cases ────────────────────────────────────────────────────────────

    def test_no_record_when_unconfigured(self):
        import core.execution_log as elog
        l = ExecutionLog()  # no configure() call
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            l.record_tool_call("cmd", True, False, 0, 0)
            l.record_finding("test", "high")
            l.record_reason_call("r", True, "c", {})
        assert l._entries == []

    def test_record_returns_zero_when_unconfigured(self):
        import core.execution_log as elog
        l = ExecutionLog()
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            assert l.record_tool_call("cmd", True, False, 0, 0) == 0
            assert l.record_finding("test", "high") == 0
            assert l.record_reason_call("r", True, "c", {}) == 0

    def test_bad_flush_path_does_not_raise(self):
        l = ExecutionLog()
        l._path = "/nonexistent/dir/trace.json"
        l._case_id = "X"
        l._entries = []
        l._flush()  # should not raise

    # ── configure auto-resume ─────────────────────────────────────────────────

    def test_configure_resumes_existing_trace(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-1", p)
        l1.record_tool_call("vol psscan", True, False, 0, 0)
        l1.record_finding("malware found", "CONFIRMED", "vol.malfind")

        l2 = ExecutionLog()  # simulates server restart
        recovered = l2.configure("CASE-1", p)
        assert recovered == 2
        assert l2._case_id == "CASE-1"
        assert len(l2._entries) == 2

    def test_configure_resumes_seq_counter(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-1", p)
        l1.record_tool_call("cmd", True, False, 0, 0)  # call_id=1
        l1.record_tool_call("cmd", True, False, 0, 0)  # call_id=2

        l2 = ExecutionLog()
        l2.configure("CASE-1", p)
        cid = l2.record_finding("new finding", "CONFIRMED")
        assert cid == 3

    def test_configure_resume_does_not_overwrite_disk(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-1", p)
        l1.record_tool_call("cmd", True, False, 0, 0)

        l2 = ExecutionLog()
        l2.configure("CASE-1", p)
        with open(p) as f:
            data = json.load(f)
        assert data["entry_count"] == 1

    def test_configure_resume_continues_appending(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-1", p)
        l1.record_tool_call("vol psscan", True, False, 0, 0)

        l2 = ExecutionLog()
        l2.configure("CASE-1", p)
        l2.record_finding("new finding after restart", "CONFIRMED")

        with open(p) as f:
            data = json.load(f)
        assert data["entry_count"] == 2
        assert any(e.get("description") == "new finding after restart" for e in data["entries"])

    def test_configure_resets_on_different_case_id(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-OLD", p)
        l1.record_tool_call("cmd", True, False, 0, 0)

        l2 = ExecutionLog()
        recovered = l2.configure("CASE-NEW", p)
        assert recovered == 0
        assert l2._case_id == "CASE-NEW"
        assert l2._entries == []

    def test_configure_returns_zero_for_new_case(self, tmp_path):
        p = str(tmp_path / "trace.json")
        l = ExecutionLog()
        recovered = l.configure("FRESH", p)
        assert recovered == 0

    def test_configure_missing_file_starts_fresh(self, tmp_path):
        p = str(tmp_path / "nonexistent.json")
        l = ExecutionLog()
        recovered = l.configure("CASE-X", p)
        assert recovered == 0
        assert l._case_id == "CASE-X"
        assert l._entries == []
