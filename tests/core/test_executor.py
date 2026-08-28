"""Tests for core/executor.py."""
import subprocess
import pytest
from unittest.mock import patch, MagicMock
from core.executor import run, run_dotnet, _apply_line_cap
from core.paths import OUTPUT_CAP, MAX_TOOL_OUTPUT_LINES

# Note: the autouse `isolate_session_file` fixture in tests/conftest.py now
# also configures the global trace log to a tmp path, so run() can call
# _log_tool() without tripping the new _require_configured raise.


def make_proc(returncode=0, stdout=b"", stderr=b""):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


@patch("core.executor.subprocess.run")
class TestRun:
    def test_success_returns_success_true(self, mock_sub):
        mock_sub.return_value = make_proc(0, b"hello", b"")
        r = run(["echo", "hello"])
        assert r["success"] is True
        assert r["exit_code"] == 0
        assert r["stdout"] == "hello"
        assert r["truncated"] is False
        assert r["retries"] == 0

    def test_failure_returns_success_false(self, mock_sub):
        mock_sub.return_value = make_proc(1, b"", b"fail")
        r = run(["false"])
        assert r["success"] is False
        assert r["exit_code"] == 1
        assert r["stderr"] == "fail"

    def test_needs_sudo_prepends_sudo(self, mock_sub):
        mock_sub.return_value = make_proc(0, b"ok", b"")
        run(["ls", "/root"], needs_sudo=True)
        called = mock_sub.call_args[0][0]
        assert called[0] == "sudo"
        assert called[1] == "ls"

    def test_already_sudo_not_doubled(self, mock_sub):
        mock_sub.return_value = make_proc(0, b"ok", b"")
        run(["sudo", "ls"], needs_sudo=True)
        called = mock_sub.call_args[0][0]
        assert called[:2] == ["sudo", "ls"]

    def test_string_cmd_is_split(self, mock_sub):
        mock_sub.return_value = make_proc(0, b"ok", b"")
        run("ls -la /tmp")
        called = mock_sub.call_args[0][0]
        assert called == ["ls", "-la", "/tmp"]

    def test_output_cap_truncates(self, mock_sub):
        big = b"x" * (OUTPUT_CAP + 100)
        mock_sub.return_value = make_proc(0, big, b"")
        r = run(["cat", "bigfile"], line_cap=None)
        assert r["truncated"] is True
        assert len(r["stdout"]) == OUTPUT_CAP

    def test_output_under_cap_not_truncated(self, mock_sub):
        mock_sub.return_value = make_proc(0, b"small", b"")
        r = run(["echo", "small"])
        assert r["truncated"] is False

    def test_line_cap_truncates_at_150(self, mock_sub):
        lines = "\n".join(f"line{i}" for i in range(200)) + "\n"
        mock_sub.return_value = make_proc(0, lines.encode(), b"")
        r = run(["vol", "psscan"])
        assert r["truncated"] is True
        assert "TRUNCATED" in r["stdout"]
        assert "50 lines omitted" in r["stdout"]

    def test_line_cap_not_triggered_under_150(self, mock_sub):
        lines = "\n".join(f"line{i}" for i in range(100)) + "\n"
        mock_sub.return_value = make_proc(0, lines.encode(), b"")
        r = run(["vol", "pslist"])
        assert r["truncated"] is False
        assert "TRUNCATED" not in r["stdout"]

    def test_line_cap_none_disables_truncation(self, mock_sub):
        lines = "\n".join(f"line{i}" for i in range(200)) + "\n"
        mock_sub.return_value = make_proc(0, lines.encode(), b"")
        r = run(["hashdeep", "-r", "/mnt"], line_cap=None)
        assert r["truncated"] is False
        assert "TRUNCATED" not in r["stdout"]

    def test_line_cap_footer_has_omitted_count(self, mock_sub):
        lines = "\n".join(f"line{i}" for i in range(170)) + "\n"
        mock_sub.return_value = make_proc(0, lines.encode(), b"")
        r = run(["vol", "pstree"])
        assert "20 lines omitted" in r["stdout"]

    def test_stderr_capped_at_4096(self, mock_sub):
        big_err = b"e" * 10000
        mock_sub.return_value = make_proc(1, b"", big_err)
        r = run(["fail"])
        assert len(r["stderr"]) <= 4096

    def test_elapsed_seconds_present(self, mock_sub):
        mock_sub.return_value = make_proc(0, b"ok", b"")
        r = run(["echo", "ok"])
        assert "elapsed_seconds" in r
        assert isinstance(r["elapsed_seconds"], float)

    def test_progress_lines_parsed_from_stderr(self, mock_sub):
        progress_stderr = b"Volatility 3 Framework 2.x\nProgress:   33.01\t\tscanning\nProgress:  100.00\t\tdone\n"
        mock_sub.return_value = make_proc(0, b"output", progress_stderr)
        r = run(["vol", "psscan"])
        assert r["progress_lines"]
        assert any("33.01" in line or "100.00" in line for line in r["progress_lines"])

    def test_progress_lines_stripped_from_stderr(self, mock_sub):
        mixed_stderr = b"Progress:   50.00\t\tscanning\nActual error: something failed\n"
        mock_sub.return_value = make_proc(1, b"", mixed_stderr)
        r = run(["vol", "bad"])
        assert "Actual error" in r["stderr"]
        assert "Progress:" not in r["stderr"]

    def test_timeout_returns_failure(self, mock_sub):
        mock_sub.side_effect = subprocess.TimeoutExpired(cmd="x", timeout=1)
        r = run(["sleep", "999"], timeout=1)
        assert r["success"] is False
        assert "timed out" in r["stderr"]

    def test_timeout_does_not_retry(self, mock_sub):
        # Timeouts should fail immediately — retrying a timed-out command wastes time
        mock_sub.side_effect = subprocess.TimeoutExpired(cmd="x", timeout=1)
        r = run(["sleep", "999"], timeout=1)
        assert r["retries"] == 0
        assert mock_sub.call_count == 1

    def test_non_timeout_error_not_retried(self, mock_sub):
        mock_sub.side_effect = FileNotFoundError("no such file")
        r = run(["nonexistent_tool"])
        assert mock_sub.call_count == 1

    def test_tool_not_found_returns_failure(self, mock_sub):
        mock_sub.side_effect = FileNotFoundError("no such file")
        r = run(["nonexistent_tool"])
        assert r["success"] is False
        assert "not found" in r["stderr"]

    def test_cmd_string_in_result(self, mock_sub):
        mock_sub.return_value = make_proc(0, b"ok", b"")
        r = run(["vol", "-f", "image.img"])
        assert "vol" in r["cmd"]

    def test_output_dir_evidence_path_raises(self, mock_sub, tmp_path):
        with pytest.raises(ValueError, match="protected evidence"):
            run(["ls"], output_dir="/cases/example/exports")

    def test_output_dir_safe_path_allowed(self, mock_sub, tmp_path):
        mock_sub.return_value = make_proc(0, b"ok", b"")
        safe = str(tmp_path / "exports")
        r = run(["ls"], output_dir=safe)
        assert r["success"] is True

    def test_tilde_expanded_in_arg(self, mock_sub):
        import os
        mock_sub.return_value = make_proc(0, b"ok", b"")
        run(["vol", "-f", "~/cases/image.img"])
        called = mock_sub.call_args[0][0]
        home = os.path.expanduser("~")
        assert called[2] == home + "/cases/image.img"
        assert "~" not in called[2]

    def test_absolute_path_not_modified(self, mock_sub):
        mock_sub.return_value = make_proc(0, b"ok", b"")
        run(["vol", "-f", "/absolute/cases/image.img"])
        called = mock_sub.call_args[0][0]
        assert called[2] == "/absolute/cases/image.img"

    def test_tilde_expanded_in_string_cmd(self, mock_sub):
        import os
        mock_sub.return_value = make_proc(0, b"ok", b"")
        run("vol -f ~/cases/image.img")
        called = mock_sub.call_args[0][0]
        home = os.path.expanduser("~")
        assert called[2] == home + "/cases/image.img"


class TestApplyLineCap:
    def test_under_limit_unchanged(self):
        text = "\n".join(f"line{i}" for i in range(10))
        result, truncated = _apply_line_cap(text, 150)
        assert result == text
        assert truncated is False

    def test_over_limit_trimmed(self):
        text = "\n".join(f"line{i}" for i in range(200))
        result, truncated = _apply_line_cap(text, 150)
        assert truncated is True
        assert "TRUNCATED" in result
        assert "50 lines omitted" in result

    def test_exactly_at_limit_unchanged(self):
        text = "\n".join(f"line{i}" for i in range(150))
        result, truncated = _apply_line_cap(text, 150)
        assert truncated is False

    def test_footer_content_is_correct(self):
        text = "\n".join(f"x" for _ in range(160))
        result, _ = _apply_line_cap(text, 150)
        assert "focus_paths or focus_pids" in result


@patch("core.executor.subprocess.run")
class TestRunDotnet:
    def test_prepends_dotnet(self, mock_sub):
        mock_sub.return_value = make_proc(0, b"ok", b"")
        run_dotnet("/opt/tools/MFTECmd.dll", ["-f", "/mnt/mft"])
        called = mock_sub.call_args[0][0]
        assert called[:2] == ["dotnet", "/opt/tools/MFTECmd.dll"]

    def test_passes_args(self, mock_sub):
        mock_sub.return_value = make_proc(0, b"ok", b"")
        run_dotnet("/opt/MFTECmd.dll", ["--csv", "/out"])
        called = mock_sub.call_args[0][0]
        assert "--csv" in called
        assert "/out" in called


# ── Phase E: full-stdout sidecar + exit-code policy ─────────────────────────

class TestStdoutSidecarAndExitPolicy:
    """`run()` persists the COMPLETE stdout to `<analysis>/.tool_output/<cid>.txt`
    via the trace (the agent-facing `stdout` keeps its caps) and maps exit
    codes through the wrapper's declared policy."""

    @patch("core.executor.subprocess.run")
    def test_private_keys_never_returned(self, mock_sub):
        mock_sub.return_value = make_proc(0, b"line\n" * 300, b"")
        r = run(["tool"])
        assert "_stdout_full" not in r and "_stdout_chars" not in r

    @patch("core.executor.subprocess.run")
    def test_sidecar_holds_full_stdout_past_the_excerpt(self, mock_sub):
        from core.execution_log import log
        body = "".join(f"row {i:04d} OK\n" for i in range(200)) + "LAST: FOUND\n"
        mock_sub.return_value = make_proc(0, body.encode(), b"")
        r = run(["scanner"], line_cap=None)
        e = next(x for x in log._entries if x.get("call_id") == r["_trudi_call_id"])
        assert e["stdout_chars"] == len(body)
        assert len(e["stdout_excerpt"]) == 600
        assert e["stdout_path"].endswith(f"/.tool_output/{r['_trudi_call_id']}.txt")
        with open(e["stdout_path"], encoding="utf-8") as fh:
            assert fh.read().endswith("LAST: FOUND\n")

    @patch("core.executor.subprocess.run")
    def test_short_stdout_has_no_sidecar_but_records_length(self, mock_sub):
        from core.execution_log import log
        mock_sub.return_value = make_proc(0, b"tiny", b"")
        r = run(["tool"])
        e = next(x for x in log._entries if x.get("call_id") == r["_trudi_call_id"])
        assert e["stdout_chars"] == 4 and "stdout_path" not in e

    @patch("core.executor.subprocess.run")
    def test_sidecar_keeps_stdout_the_agent_cap_dropped(self, mock_sub):
        # 150-line cap truncates the agent copy; the sidecar is complete.
        from core.execution_log import log
        body = "".join(f"{i}\n" for i in range(400))
        mock_sub.return_value = make_proc(0, body.encode(), b"")
        r = run(["tool"])
        assert r["truncated"] is True
        e = next(x for x in log._entries if x.get("call_id") == r["_trudi_call_id"])
        with open(e["stdout_path"], encoding="utf-8") as fh:
            assert fh.read() == body

    @patch("core.executor.subprocess.run")
    def test_exit_policy_maps_result_codes_to_success(self, mock_sub):
        from tools._exit_codes import policy
        mock_sub.return_value = make_proc(1, b"x: Eicar FOUND\n", b"")
        r = run(["clamscan", "x"], **policy("clamscan"))
        assert r["success"] is True and r["exit_code"] == 1
        assert "infected" in r["exit_meaning"]
        mock_sub.return_value = make_proc(2, b"", b"boom")
        r = run(["clamscan", "x"], **policy("clamscan"))
        assert r["success"] is False and r["exit_meaning"] == "error"

    @patch("core.executor.subprocess.run")
    def test_default_policy_unchanged(self, mock_sub):
        mock_sub.return_value = make_proc(1, b"", b"")
        r = run(["false"])
        assert r["success"] is False and "exit_meaning" not in r

    @patch("core.executor.subprocess.run")
    def test_exit_meaning_reaches_the_trace(self, mock_sub):
        from core.execution_log import log
        from tools._exit_codes import policy
        mock_sub.return_value = make_proc(1, b"", b"")
        r = run(["ngrep", "-q", "x"], **policy("ngrep"))
        e = next(x for x in log._entries if x.get("call_id") == r["_trudi_call_id"])
        assert e["success"] is True and e["exit_meaning"] == "no frames matched"

    def test_policy_unknown_binary_is_default(self):
        from tools._exit_codes import policy
        p = policy("nosuchtool")
        assert p["success_codes"] == frozenset({0}) and p["exit_meanings"] == {}
