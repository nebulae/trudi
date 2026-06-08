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

    # ── call_initiated ────────────────────────────────────────────────────────

    def test_record_call_initiated_returns_call_id(self, log):
        cid = log.record_call_initiated("dair_assess", "claude", {"model": "haiku"})
        assert cid > 0

    def test_record_call_initiated_entry_fields(self, log):
        log.record_call_initiated("reason_plan", "openai-compat", {"model": "fs-8b", "url": "http://localhost:8000"})
        entry = log._entries[-1]
        assert entry["type"] == "call_initiated"
        assert entry["tool"] == "reason_plan"
        assert entry["backend"] == "openai-compat"
        assert entry["inputs"]["model"] == "fs-8b"
        assert "ts" in entry

    def test_record_call_initiated_unconfigured_raises(self):
        """Unconfigured trace must raise — old behaviour silently dropped
        entries and returned 0, which made silent failures undetectable."""
        import core.execution_log as elog
        l = ExecutionLog()
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            with pytest.raises(RuntimeError, match="trace log not configured"):
                l.record_call_initiated("dair_assess", "claude", {})

    def test_to_markdown_call_initiated_arrow(self, log):
        log.record_call_initiated("dair_assess", "claude", {"model": "haiku"})
        md = log.to_markdown()
        assert "→ CALL" in md
        assert "dair_assess" in md
        assert "claude" in md

    def test_to_markdown_call_initiated_inputs_shown(self, log):
        log.record_call_initiated("reason_plan", "claude", {"model": "opus"})
        md = log.to_markdown()
        assert "opus" in md

    def test_call_initiated_before_response_in_entries(self, log):
        log.record_call_initiated("dair_assess", "claude", {"model": "haiku"})
        log.record_dair_call(
            current_phase="Verification", phase_rationale="x",
            transition_recommended=False, next_phase="", transition_rationale="",
            stack_action="stay", investigation_focus="x",
            verification_challenges=[], recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        types = [e["type"] for e in log._entries]
        assert types.index("call_initiated") < types.index("dair_call")

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
        """Each record_* on an unconfigured log now raises RuntimeError so
        the caller (and ultimately the agent) sees a structured failure
        instead of a silent drop."""
        import core.execution_log as elog
        l = ExecutionLog()
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            with pytest.raises(RuntimeError, match="trace log not configured"):
                l.record_tool_call("cmd", True, False, 0, 0)
            with pytest.raises(RuntimeError, match="trace log not configured"):
                l.record_finding("test", "high")
            with pytest.raises(RuntimeError, match="trace log not configured"):
                l.record_reason_call("r", True, "c", {})
        assert l._entries == []

    def test_bad_flush_path_raises(self):
        """Trace flush failures must bubble up so the operator sees lost
        entries — old behaviour swallowed the OSError and silently
        corrupted the audit log."""
        l = ExecutionLog()
        l._path = "/nonexistent/dir/trace.json"
        l._case_id = "X"
        l._entries = []
        with pytest.raises(OSError):
            l._flush()

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


class TestAtomicFlush:
    def test_flush_writes_valid_json(self, tmp_path):
        l = ExecutionLog()
        l.configure("ATOMIC-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", True, False, 0, 0)
        with open(tmp_path / "trace.json") as f:
            data = json.load(f)
        assert data["case_id"] == "ATOMIC-001"
        assert len(data["entries"]) == 1

    def test_no_tmp_files_left_after_flush(self, tmp_path):
        l = ExecutionLog()
        l.configure("ATOMIC-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", True, False, 0, 0)
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert tmp_files == []

    def test_flush_warns_and_raises_on_bad_dir(self, tmp_path, capsys):
        """_flush still warns to stderr for visibility, but now also raises
        so the caller can surface a structured ToolError to the agent."""
        l = ExecutionLog()
        l.configure("ATOMIC-001", str(tmp_path / "trace.json"))
        l._path = "/nonexistent/dir/trace.json"
        with pytest.raises(OSError):
            l._flush()
        assert "[TRUDI WARN]" in capsys.readouterr().err


class TestThreadSafety:
    def test_concurrent_record_calls_no_duplicate_ids(self, tmp_path):
        import threading
        l = ExecutionLog()
        l.configure("THREAD-001", str(tmp_path / "trace.json"))
        ids = []
        errors = []

        def worker():
            try:
                cid = l.record_agent_message("concurrent message")
                ids.append(cid)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(ids) == 20
        assert len(set(ids)) == 20  # all unique

    def test_concurrent_flush_leaves_valid_json(self, tmp_path):
        import threading
        l = ExecutionLog()
        l.configure("THREAD-001", str(tmp_path / "trace.json"))

        def worker():
            for _ in range(10):
                l.record_tool_call("vol.pslist", True, False, 0, 0)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with open(tmp_path / "trace.json") as f:
            data = json.load(f)
        assert data["entry_count"] == 50
        assert len(data["entries"]) == 50


class TestUnconfiguredRecordRaises:
    """Unconfigured trace now raises RuntimeError on every record_*; the
    error message names the missing setup step so the agent can react."""

    def test_record_tool_call_raises(self):
        l = ExecutionLog()
        import core.execution_log as elog
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            with pytest.raises(RuntimeError,
                               match="trace log not configured.*tool_call"):
                l.record_tool_call("vol.pslist", True, False, 0, 0)

    def test_record_finding_raises(self):
        l = ExecutionLog()
        import core.execution_log as elog
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            with pytest.raises(RuntimeError,
                               match="trace log not configured.*finding"):
                l.record_finding("test finding", "CONFIRMED")

    def test_record_agent_message_raises(self):
        l = ExecutionLog()
        import core.execution_log as elog
        with patch.object(elog, "_SESSION_FILE", "/nonexistent/session.json"):
            with pytest.raises(RuntimeError,
                               match="trace log not configured.*agent_message"):
                l.record_agent_message("test message")

    def test_configure_warns_on_case_id_mismatch(self, tmp_path, capsys):
        p = str(tmp_path / "trace.json")
        l1 = ExecutionLog()
        l1.configure("CASE-OLD", p)
        l2 = ExecutionLog()
        l2.configure("CASE-NEW", p)
        captured = capsys.readouterr()
        assert "[TRUDI WARN]" in captured.err
        assert "CASE-OLD" in captured.err

    def test_configure_warns_on_corrupted_json(self, tmp_path, capsys):
        p = str(tmp_path / "trace.json")
        with open(p, "w") as f:
            f.write("{invalid json{{")
        l = ExecutionLog()
        l.configure("CASE-X", p)
        captured = capsys.readouterr()
        assert "[TRUDI WARN]" in captured.err
        assert "corrupted" in captured.err


class TestExportReturnValues:
    def test_export_reports_json_and_md_wrote(self, tmp_path):
        l = ExecutionLog()
        l.configure("EXP-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", True, False, 0, 0)
        result = l.export(str(tmp_path / "reports" / "trace"))
        # reports/ dir doesn't exist — both writes fail
        assert result["json_wrote"] is False
        assert result["md_wrote"] is False
        assert "entry_count" in result

    def test_export_reports_success_when_dir_exists(self, tmp_path):
        l = ExecutionLog()
        l.configure("EXP-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", True, False, 0, 0)
        reports = tmp_path / "reports"
        reports.mkdir()
        result = l.export(str(reports / "trace"))
        assert result["json_wrote"] is True
        assert result["md_wrote"] is True
        assert result["entry_count"] == 1

    def test_export_warns_on_write_failure(self, tmp_path, capsys):
        l = ExecutionLog()
        l.configure("EXP-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", True, False, 0, 0)
        result = l.export(str(tmp_path / "no_such_dir" / "trace"))
        captured = capsys.readouterr()
        assert "[TRUDI WARN]" in captured.err


class TestRenderUnknownType:
    def test_unknown_type_renders_fallback(self, tmp_path):
        l = ExecutionLog()
        l.configure("RENDER-001", str(tmp_path / "trace.json"))
        # Inject an unknown entry type directly
        with l._lock:
            l._entries.append({
                "call_id": 99,
                "type": "future_type",
                "ts": "2026-01-01T00:00:00+00:00",
                "data": "something",
            })
        md = l.to_markdown()
        assert "UNKNOWN TYPE" in md
        assert "future_type" in md


class TestTimeoutFlag:
    def test_timeout_renders_as_timeout_in_markdown(self, tmp_path):
        l = ExecutionLog()
        l.configure("TIMEOUT-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", False, False, 0, -1,
                            stderr="timed out", timed_out=True)
        md = l.to_markdown()
        assert "TIMEOUT" in md

    def test_timeout_flag_stored_in_entry(self, tmp_path):
        l = ExecutionLog()
        l.configure("TIMEOUT-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", False, False, 0, -1, timed_out=True)
        entry = l._entries[-1]
        assert entry.get("timed_out") is True

    def test_non_timeout_failure_renders_as_fail(self, tmp_path):
        l = ExecutionLog()
        l.configure("FAIL-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.pslist", False, False, 0, 1, stderr="permission denied")
        md = l.to_markdown()
        assert "→ FAIL" in md
        assert "→ TIMEOUT" not in md


class TestCallAbandoned:
    def test_record_call_abandoned_written(self, tmp_path):
        l = ExecutionLog()
        l.configure("ABANDON-001", str(tmp_path / "trace.json"))
        cid = l.record_call_abandoned("reason_plan", "APITimeoutError: 300s exceeded")
        assert cid > 0
        entry = l._entries[-1]
        assert entry["type"] == "call_abandoned"
        assert entry["tool"] == "reason_plan"
        assert "300s" in entry["reason"]

    def test_call_abandoned_renders_in_markdown(self, tmp_path):
        l = ExecutionLog()
        l.configure("ABANDON-001", str(tmp_path / "trace.json"))
        l.record_call_abandoned("dair_assess", "connection reset")
        md = l.to_markdown()
        assert "ABANDONED" in md
        assert "dair_assess" in md
        assert "connection reset" in md


class TestVerificationSatisfiedRendering:
    def test_satisfied_renders_marker(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("SAT-001", str(tmp_path / "trace.json"))
        l.record_dair_call(
            current_phase="Verification",
            phase_rationale="Primary IOCs confirmed",
            transition_recommended=True,
            next_phase="Scope",
            transition_rationale="Core claims verified",
            stack_action="push",
            investigation_focus="Map lateral movement",
            verification_satisfied=True,
            verification_challenges=[],
            recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        md = l.to_markdown()
        assert "✓ Verification Satisfied" in md

    def test_unsatisfied_does_not_render_marker(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("SAT-001", str(tmp_path / "trace.json"))
        l.record_dair_call(
            current_phase="Verification",
            phase_rationale="Still pending",
            transition_recommended=False,
            next_phase="",
            transition_rationale="",
            stack_action="stay",
            investigation_focus="Keep verifying",
            verification_satisfied=False,
            verification_challenges=[],
            recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        md = l.to_markdown()
        assert "✓ Verification Satisfied" not in md

    def test_satisfied_stored_in_entry(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("SAT-001", str(tmp_path / "trace.json"))
        l.record_dair_call(
            current_phase="Verification",
            phase_rationale="done",
            transition_recommended=True,
            next_phase="Scope",
            transition_rationale="satisfied",
            stack_action="push",
            investigation_focus="scope",
            verification_satisfied=True,
            verification_challenges=[],
            recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        assert l._entries[-1]["verification_satisfied"] is True


class TestProtocolViolationFlag:
    """tool_call entries are flagged when no recent dair_call exists."""

    def test_first_tool_call_not_flagged(self, tmp_path):
        # An empty log gets no flag — there's nothing before it to compare against.
        l = ExecutionLog()
        l.configure("PV-001", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        assert "protocol_violation" not in l._entries[0]

    def test_cold_start_tool_calls_not_flagged_before_any_dair(self, tmp_path):
        # R3b cold-start grace: the mandated pre-plan recon batch (hash verify,
        # image mount, hive reads) runs BEFORE the first dair_assess and must
        # NOT be flagged — flagging it was a self-contradiction. A missing-DAIR
        # violation only applies once DAIR has engaged at least once.
        l = ExecutionLog()
        l.configure("PV-002", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_tool_call("vol.netscan", True, False, 0, 0)
        assert "protocol_violation" not in l._entries[1]

    def test_tool_call_without_recent_dair_flagged_after_dair_aged_out(self, tmp_path):
        # Once DAIR has engaged, a later tool_call with no dair in the 20-entry
        # window IS flagged (the genuine "agent dropped DAIR mid-investigation").
        l = ExecutionLog()
        l.configure("PV-002b", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        for _ in range(20):
            l.record_reason_call("reason_hypothesize", True, "ok", {})
        l.record_tool_call("vol.netscan", True, False, 0, 0)
        assert l._entries[-1].get("protocol_violation") == "no_active_dair_batch"

    def test_tool_call_with_recent_dair_unflagged(self, tmp_path):
        l = ExecutionLog()
        l.configure("PV-003", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        tc = [e for e in l._entries if e["type"] == "tool_call"][0]
        assert "protocol_violation" not in tc

    def test_tool_call_beyond_20_entry_window_flagged(self, tmp_path):
        l = ExecutionLog()
        l.configure("PV-004", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        # 20 reason_calls push the dair_call out of the lookback window.
        for _ in range(20):
            l.record_reason_call("reason_hypothesize", True, "ok", {})
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        tc = [e for e in l._entries if e["type"] == "tool_call"][-1]
        assert tc.get("protocol_violation") == "no_active_dair_batch"

    def test_markdown_renders_violation_marker(self, tmp_path):
        l = ExecutionLog()
        l.configure("PV-005", str(tmp_path / "trace.json"))
        # DAIR engaged once, then aged out of the 20-entry window → the next
        # tool_call is a real violation that the markdown must render. (Under
        # R3b a tool_call before any dair is cold-start grace, not a violation.)
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        for _ in range(20):
            l.record_reason_call("reason_hypothesize", True, "ok", {})
        l.record_tool_call("vol.netscan", True, False, 0, 0)
        md = l.to_markdown()
        assert "PROTOCOL_VIOLATION" in md
        assert "no_active_dair_batch" in md

    def test_markdown_no_violation_when_dair_recent(self, tmp_path):
        l = ExecutionLog()
        l.configure("PV-006", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        md = l.to_markdown()
        assert "PROTOCOL_VIOLATION" not in md


class TestSelfCorrection:
    """Self-correction: record_self_correction creates first-class trace entries."""

    def test_self_correction_entry_type(self, tmp_path):
        l = ExecutionLog()
        l.configure("SC-001", str(tmp_path / "trace.json"))
        cid = l.record_self_correction(
            trigger="evaluate_challenged",
            prior_belief="STUN.exe is a CrimsonOsprey C2 implant",
            new_belief="STUN.exe identity refuted by missing API hooks",
            evidence="vol.malfind shows no inject markers",
        )
        assert cid > 0
        entry = l._entries[-1]
        assert entry["type"] == "self_correction"
        assert entry["trigger"] == "evaluate_challenged"
        assert entry["prior_belief"].startswith("STUN.exe")
        assert "API hooks" in entry["new_belief"]

    def test_self_correction_stores_linked_call_id(self, tmp_path):
        l = ExecutionLog()
        l.configure("SC-002", str(tmp_path / "trace.json"))
        cid = l.record_self_correction("hypothesis_refuted", "old", "new",
                                       linked_call_id=42)
        assert l._entries[-1]["linked_call_id"] == 42

    def test_self_correction_markdown_marker(self, tmp_path):
        l = ExecutionLog()
        l.configure("SC-003", str(tmp_path / "trace.json"))
        l.record_self_correction("dair_max_pass_cap", "Verification looping",
                                 "Forced transition to Collect", "3 stays")
        md = l.to_markdown()
        assert "SELF-CORRECTION" in md
        assert "dair_max_pass_cap" in md
        assert "Verification looping" in md
        assert "Forced transition to Collect" in md

    def test_self_correction_mcp_wrapper(self, tmp_path):
        from tools.misc import record_self_correction
        l = ExecutionLog()
        l.configure("SC-004", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = record_self_correction(
                trigger="tool_failure_recovery",
                prior_belief="vol.netscan would resolve PIDs",
                new_belief="vol.netscan returned empty — fall back to memmap",
            )
        assert r["success"] is True
        assert r["trigger"] == "tool_failure_recovery"
        sc = [e for e in l._entries if e["type"] == "self_correction"]
        assert len(sc) == 1


class TestHypothesisLineage:
    """Hypothesis lineage: reason_hypothesize gets a hypothesis_id; record_finding can link to it."""

    def test_reason_call_stores_hypothesis_id(self, tmp_path):
        l = ExecutionLog()
        l.configure("HL-001", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_hypothesize", True, "ok", {}, hypothesis_id="H0001")
        assert l._entries[-1]["hypothesis_id"] == "H0001"

    def test_reason_call_omits_hypothesis_id_when_unset(self, tmp_path):
        l = ExecutionLog()
        l.configure("HL-002", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_plan", True, "ok", {})
        assert "hypothesis_id" not in l._entries[-1]

    def test_finding_stores_tested_hypothesis_id(self, tmp_path):
        l = ExecutionLog()
        l.configure("HL-003", str(tmp_path / "trace.json"))
        l.record_finding("anomaly", "LIKELY", "vol.netscan",
                         linked_call_id=0, tested_hypothesis_id="H0042")
        assert l._entries[-1]["tested_hypothesis_id"] == "H0042"

    def test_finding_omits_tested_hypothesis_id_when_unset(self, tmp_path):
        l = ExecutionLog()
        l.configure("HL-004", str(tmp_path / "trace.json"))
        l.record_finding("anomaly", "LIKELY", "vol.netscan")
        assert "tested_hypothesis_id" not in l._entries[-1]

    def test_markdown_renders_hypothesis_lineage(self, tmp_path):
        l = ExecutionLog()
        l.configure("HL-005", str(tmp_path / "trace.json"))
        l.record_finding("rootkit confirmed", "LIKELY", "vol.malfind",
                         linked_call_id=0, tested_hypothesis_id="H0007")
        md = l.to_markdown()
        assert "tests hypothesis: H0007" in md


class TestMarkdownNavigability:
    """Markdown navigability: TOC, phase headers, and evidence chains."""

    def test_toc_lists_phases_encountered(self, tmp_path):
        l = ExecutionLog()
        l.configure("NAV-001", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_dair_call("Collect", "", False, "", "", "stay", "")
        l.record_tool_call("ez.mftecmd", True, False, 0, 0)
        md = l.to_markdown()
        assert "## Contents" in md
        assert "[Triage]" in md
        assert "[Collect]" in md

    def test_phase_anchor_emitted_at_first_dair_of_phase(self, tmp_path):
        l = ExecutionLog()
        l.configure("NAV-002", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        md = l.to_markdown()
        assert "<a id=\"phase-triage-1\"></a>" in md
        assert "## Phase: Triage" in md

    def test_phase_repeat_gets_distinct_anchor(self, tmp_path):
        l = ExecutionLog()
        l.configure("NAV-003", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_dair_call("Collect", "", False, "", "", "stay", "")
        l.record_dair_call("Triage", "", False, "", "", "stay", "")  # pivot loop
        md = l.to_markdown()
        assert "phase-triage-1" in md
        assert "phase-triage-2" in md

    def test_evidence_chain_for_finding_with_tool_call_link(self, tmp_path):
        l = ExecutionLog()
        l.configure("NAV-004", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        tid = l.record_tool_call(
            "vol.psscan", True, False, 0, 0,
            stdout_excerpt="PID=5024 PPID=2748 Process=cmd.exe",
        )
        l.record_reason_call("reason_evaluate_finding", True, "VERDICT: SUPPORTED", {})
        l.record_finding("orphan cmd.exe", "CONFIRMED", "vol.psscan", linked_call_id=tid)
        md = l.to_markdown()
        assert "Evidence Chain" in md
        assert "vol.psscan" in md
        assert "PID=5024" in md

    def test_evidence_chain_absent_when_linked_call_id_zero(self, tmp_path):
        l = ExecutionLog()
        l.configure("NAV-005", str(tmp_path / "trace.json"))
        l.record_finding("anomaly", "LIKELY", "vol.netscan", linked_call_id=0)
        md = l.to_markdown()
        # No evidence chain block when there's no linked call.
        finding_line_idx = next(i for i, line in enumerate(md.split("\n")) if "FINDING" in line)
        # The very next line shouldn't be an Evidence Chain entry.
        following = md.split("\n")[finding_line_idx + 1:finding_line_idx + 3]
        assert not any("Evidence Chain" in line for line in following)


class TestAutoRecoverFromCwd:
    """The log singleton lazily binds to ./analysis/<X>_trace.json under CWD
    when no session.json is available — so an MCP-server restart inside a
    case directory doesn't lose writes if the agent skips start_execution_log."""

    def _make_case(self, root, case_name, *, with_claude_md=True):
        case = root / case_name
        (case / "analysis").mkdir(parents=True)
        trace = case / "analysis" / f"{case_name}_trace.json"
        trace.write_text(
            '{"schema_version":"2.0","case_id":"' + case_name +
            '","entry_count":0,"entries":[]}'
        )
        if with_claude_md:
            (case / "CLAUDE.md").write_text(f"# {case_name}\n")
        return case, trace

    def test_cwd_recovery_when_no_session(self, tmp_path, monkeypatch):
        import core.execution_log as elog
        case, trace_path = self._make_case(tmp_path, "FOO-CASE")
        monkeypatch.chdir(case)
        monkeypatch.setattr(elog, "_SESSION_FILE", str(tmp_path / "no-session.json"))
        l = elog.ExecutionLog()
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._path == str(trace_path)
        assert l._case_id == "FOO-CASE"

    def test_no_recovery_when_no_claude_md(self, tmp_path, monkeypatch):
        """Defensive: only real case dirs (with CLAUDE.md) trigger recovery.
        Without recovery, record_* raises so silent drops are impossible."""
        import core.execution_log as elog
        case, _ = self._make_case(tmp_path, "BARE", with_claude_md=False)
        monkeypatch.chdir(case)
        monkeypatch.setattr(elog, "_SESSION_FILE", str(tmp_path / "no-session.json"))
        l = elog.ExecutionLog()
        with pytest.raises(RuntimeError, match="trace log not configured"):
            l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._path is None

    def test_session_recovery_takes_precedence_over_cwd(self, tmp_path, monkeypatch):
        import core.execution_log as elog
        cwd_case, _ = self._make_case(tmp_path, "CWD-CASE")
        monkeypatch.chdir(cwd_case)
        other_case, other_trace = self._make_case(tmp_path, "OTHER-CASE")
        sess = tmp_path / "session.json"
        sess.write_text(f'{{"case_id":"OTHER-CASE","path":"{other_trace}"}}')
        monkeypatch.setattr(elog, "_SESSION_FILE", str(sess))
        l = elog.ExecutionLog()
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        # Session wins
        assert l._case_id == "OTHER-CASE"

    def test_no_recovery_when_cwd_has_no_analysis_dir(self, tmp_path, monkeypatch):
        import core.execution_log as elog
        bare = tmp_path / "bare"
        bare.mkdir()
        (bare / "CLAUDE.md").write_text("# bare\n")
        monkeypatch.chdir(bare)
        monkeypatch.setattr(elog, "_SESSION_FILE", str(tmp_path / "no-session.json"))
        l = elog.ExecutionLog()
        with pytest.raises(RuntimeError, match="trace log not configured"):
            l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._path is None

    def test_cwd_recovery_picks_first_alphabetical_when_multiple(self, tmp_path, monkeypatch):
        import core.execution_log as elog
        case = tmp_path / "MULTI"
        (case / "analysis").mkdir(parents=True)
        (case / "CLAUDE.md").write_text("# multi\n")
        (case / "analysis" / "BBB_trace.json").write_text(
            '{"schema_version":"2.0","case_id":"BBB","entry_count":0,"entries":[]}'
        )
        (case / "analysis" / "AAA_trace.json").write_text(
            '{"schema_version":"2.0","case_id":"AAA","entry_count":0,"entries":[]}'
        )
        monkeypatch.chdir(case)
        monkeypatch.setattr(elog, "_SESSION_FILE", str(tmp_path / "no-session.json"))
        l = elog.ExecutionLog()
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._case_id == "AAA"


class TestReasonAndDairInputsField:
    """`inputs` round-trips on reason_call and dair_call entries."""

    def test_reason_call_with_inputs(self, tmp_path):
        l = ExecutionLog()
        l.configure("IN-L-001", str(tmp_path / "trace.json"))
        l.record_reason_call(
            "reason_plan", True, "plan", {},
            inputs={"user_message": "case desc",
                    "system_prompt_kind": "reason_plan",
                    "max_tokens": 2048},
        )
        e = l._entries[-1]
        assert "inputs" in e
        assert e["inputs"]["user_message"] == "case desc"
        assert e["inputs"]["system_prompt_kind"] == "reason_plan"

    def test_reason_call_without_inputs_omits_field(self, tmp_path):
        l = ExecutionLog()
        l.configure("IN-L-002", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_plan", True, "plan", {})
        assert "inputs" not in l._entries[-1]

    def test_dair_call_with_inputs(self, tmp_path):
        l = ExecutionLog()
        l.configure("IN-L-003", str(tmp_path / "trace.json"))
        l.record_dair_call(
            "Triage", "", False, "", "", "stay", "",
            inputs={"tool_results_summary": "stun",
                    "phase_stack": [],
                    "case_context": "ctx"},
        )
        e = l._entries[-1]
        assert "inputs" in e
        assert e["inputs"]["tool_results_summary"] == "stun"
        assert e["inputs"]["case_context"] == "ctx"

    def test_dair_call_without_inputs_omits_field(self, tmp_path):
        l = ExecutionLog()
        l.configure("IN-L-004", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert "inputs" not in l._entries[-1]


class TestDairPhaseStamping:
    """Per-entry dair_phase is auto-stamped from ExecutionLog state."""

    def test_first_dair_call_adopts_phase(self, tmp_path):
        l = ExecutionLog()
        l.configure("PHASE-001", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        assert l._current_phase == "Triage"
        assert l._entries[-1].get("dair_phase") == "Triage"

    def test_subsequent_records_inherit_phase(self, tmp_path):
        l = ExecutionLog()
        l.configure("PHASE-002", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_plan", True, "ok", {})
        l.record_agent_message("interpreting")
        for e in l._entries[1:]:
            assert e.get("dair_phase") == "Triage"
            assert e.get("dair_depth") == 1

    def test_push_advances_phase(self, tmp_path):
        l = ExecutionLog()
        l.configure("PHASE-003", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        # Now declare a transition
        l.record_dair_call("Triage", "", True, "Collect", "verified",
                           "push", "begin collection")
        # The dair_call entry that DECLARED the transition is itself in Collect
        assert l._entries[-1].get("dair_phase") == "Collect"
        assert l._current_phase == "Collect"
        # Subsequent entries are in Collect
        l.record_tool_call("ez.mftecmd", True, False, 0, 0)
        assert l._entries[-1].get("dair_phase") == "Collect"
        assert l._entries[-1].get("dair_depth") == 2

    def test_pop_restores_parent_phase(self, tmp_path):
        l = ExecutionLog()
        l.configure("PHASE-004", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        l.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
        assert l._current_phase == "Analyze"
        l.record_dair_call("Analyze", "", True, "Collect", "", "pop", "")
        assert l._current_phase == "Collect"
        l.record_tool_call("vol.netscan", True, False, 0, 0)
        assert l._entries[-1].get("dair_phase") == "Collect"

    def test_verification_satisfied_auto_advances(self, tmp_path):
        l = ExecutionLog()
        l.configure("PHASE-005", str(tmp_path / "trace.json"))
        # verification_satisfied=True while still in Triage with stay action
        l.record_dair_call("Triage", "", False, "", "", "stay", "",
                           verification_satisfied=True)
        assert l._current_phase == "Collect"
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        assert l._entries[-1].get("dair_phase") == "Collect"

    def test_rehydrate_replays_history(self, tmp_path):
        trace_path = str(tmp_path / "rehydrate.json")
        # Set up a trace with two transitions, then close the log.
        l1 = ExecutionLog()
        l1.configure("PHASE-006", trace_path)
        l1.record_dair_call("Triage", "", False, "", "", "stay", "")
        l1.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        l1.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
        assert l1._current_phase == "Analyze"

        # New log instance reloading the same trace should restore phase state.
        l2 = ExecutionLog()
        l2.configure("PHASE-006", trace_path)
        assert l2._current_phase == "Analyze"
        # Stack depth is 3 (Triage, Collect, Analyze)
        assert len(l2._phase_stack) == 3
        # New records inherit
        l2.record_tool_call("vol.malfind", True, False, 0, 0)
        assert l2._entries[-1].get("dair_phase") == "Analyze"

    def test_default_phase_before_first_dair_call_is_triage(self, tmp_path):
        """Per the DAIR spec — every investigation 'begins with a confirmed
        positive detection already in hand. Start at Triage unless the stack
        says otherwise.' So pre-DAIR entries get phase=Triage stamped, not
        an empty phase, so the chain view never has 'no phase' orphans."""
        l = ExecutionLog()
        l.configure("PHASE-007", str(tmp_path / "trace.json"))
        l.record_tool_call("hash.verify", True, False, 0, 0)
        assert l._entries[-1]["dair_phase"] == "Triage"
        # depth = len(phase_stack); root Triage push yields depth 1 per the
        # existing convention in _apply_dair_transition.
        assert l._entries[-1]["dair_depth"] == 1

    def test_pop_with_next_phase_targets_the_named_phase(self, tmp_path):
        """pop → Report should land on Report even if Collect/Analyze are on top.
        Matches the SRL-2018 live trace pattern: agent in Analyze pops → Report."""
        l = ExecutionLog()
        l.configure("PHASE-008", str(tmp_path / "trace.json"))
        # Build the stack: Triage → Collect → Analyze → Scan → Report → Collect → Analyze
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        l.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
        l.record_dair_call("Analyze", "", True, "Scan", "", "push", "")
        l.record_dair_call("Scan", "", True, "Report", "", "push", "")
        l.record_dair_call("Report", "", True, "Collect", "", "push", "")
        l.record_dair_call("Collect", "", True, "Analyze", "", "push", "")
        assert l._current_phase == "Analyze"
        # Now pop → Report (skipping over the intervening Collect)
        l.record_dair_call("Analyze", "", True, "Report", "", "pop", "")
        assert l._current_phase == "Report"
        assert l._entries[-1].get("dair_phase") == "Report"

    def test_stay_reconciles_with_agent_declared_phase(self, tmp_path):
        """If the agent declares phase=Report on stay but our state drifted,
        adopt the agent's declared phase. Mirrors trace entry #1122."""
        l = ExecutionLog()
        l.configure("PHASE-009", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_dair_call("Triage", "", True, "Collect", "", "push", "")
        # Agent declares stay in Report even though our state thinks Collect.
        # Adopt the agent's declaration.
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        assert l._current_phase == "Report"
        assert l._entries[-1].get("dair_phase") == "Report"
        # Subsequent records inherit Report
        l.record_tool_call("reason.synthesize", True, False, 0, 0)
        assert l._entries[-1].get("dair_phase") == "Report"


class TestFlushPreservesHookEntries:
    """The MCP server's _flush() merges in hook-written entries (marked with
    `_source_tool_use_id` / `_source_uuid`) that aren't in self._entries.
    Without this, hook-written Bash tool_call entries would be overwritten
    by the next MCP server flush.

    Hook entries are identified by `_source_*` markers — NOT by call_id range.
    MCP server and hook share a single monotonic counter."""

    def _write_disk_with_hook_entry(self, path, mcp_entries, hook_entry):
        """Simulate the on-disk state after a hook write."""
        data = {
            "schema_version": "2.0",
            "case_id": "FLUSH-MERGE",
            "entry_count": len(mcp_entries) + 1,
            "entries": list(mcp_entries) + [hook_entry],
        }
        path.write_text(json.dumps(data, indent=2))

    def test_hook_entries_preserved_after_mcp_flush(self, tmp_path):
        trace_path = tmp_path / "trace.json"
        l = ExecutionLog()
        l.configure("FLUSH-MERGE", str(trace_path))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        # Snapshot the MCP entries; pretend the hook then wrote one too
        # (id picked from the shared counter — here we just claim id 999 as
        # "what the hook claimed before our next write"; the merge logic
        # keys off _source_tool_use_id, not the id range).
        mcp_entries_snap = list(l._entries)
        hook_entry = {
            "call_id": 999,
            "type": "tool_call",
            "ts": "2026-05-21T10:00:00+00:00",
            "cmd": "bash echo hook",
            "success": True,
            "truncated": False,
            "retries": 0,
            "exit_code": 0,
            "elapsed_seconds": 0,
            "stderr": "",
            "source": "claude_code_bash",
            "_source_tool_use_id": "tool-use-xyz",
        }
        self._write_disk_with_hook_entry(trace_path, mcp_entries_snap, hook_entry)
        # MCP server records another entry → triggers _flush
        l.record_tool_call("vol.netscan", True, False, 0, 0)
        data = json.loads(trace_path.read_text())
        cmds = [e.get("cmd") for e in data["entries"] if e.get("type") == "tool_call"]
        assert "bash echo hook" in cmds, f"hook entry lost; cmds={cmds}"
        assert "vol.psscan" in cmds
        assert "vol.netscan" in cmds
        # The hook entry retains its own call_id; we don't renumber on merge
        hook_disk = [e for e in data["entries"] if e.get("_source_tool_use_id") == "tool-use-xyz"]
        assert hook_disk and hook_disk[0]["call_id"] == 999

    def test_no_hook_entries_clean_path(self, tmp_path):
        """Fast path: when no hook entries exist on disk, _flush behaves as
        before — fully overwrites with self._entries."""
        trace_path = tmp_path / "trace.json"
        l = ExecutionLog()
        l.configure("FLUSH-CLEAN", str(trace_path))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        data = json.loads(trace_path.read_text())
        assert data["entry_count"] == 2


class TestSharedCallIdCounter:
    """MCP server + hook share a single monotonic call_id counter so ids are
    dense and reflect global write order across both writers."""

    def test_configure_resets_counter_for_new_case(self, tmp_path):
        from core.execution_log import _CALL_ID_COUNTER_FILE
        l = ExecutionLog()
        l.configure("COUNTER-RESET", str(tmp_path / "trace.json"))
        # After fresh configure, counter file should advance from 1.
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        cids = [e["call_id"] for e in l._entries]
        assert cids == [1, 2], f"expected dense ids starting at 1, got {cids}"
        # Counter file should now point at 3 (next assignment)
        with open(_CALL_ID_COUNTER_FILE) as f:
            assert json.load(f)["next"] == 3

    def test_configure_resumes_counter_from_trace(self, tmp_path):
        """Reattaching to an existing trace picks up the counter past its
        highest id so we don't reuse an already-assigned id."""
        from core.execution_log import _CALL_ID_COUNTER_FILE
        trace_path = tmp_path / "trace.json"
        l1 = ExecutionLog()
        l1.configure("COUNTER-RESUME", str(trace_path))
        l1.record_dair_call("Triage", "", False, "", "", "stay", "")
        l1.record_tool_call("vol.psscan", True, False, 0, 0)
        l1.record_tool_call("vol.netscan", True, False, 0, 0)
        # Simulate process restart: new ExecutionLog, same path
        l2 = ExecutionLog()
        recovered = l2.configure("COUNTER-RESUME", str(trace_path))
        assert recovered == 3
        l2.record_tool_call("vol.cmdline", True, False, 0, 0)
        last = l2._entries[-1]
        assert last["call_id"] == 4, f"counter must continue past existing max; got {last['call_id']}"


