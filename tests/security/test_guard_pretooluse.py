"""PreToolUse guard: denies bash reads of produced output and bash forensic
binaries — for the beacon-owner session only. Invoked as a real subprocess
with a synthetic HOME so the beacon/owner resolution is exercised end-to-end.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parents[2] / "claude" / "hooks" / "guard_pretooluse.py"


def _run(payload, home, extra_env=None):
    env = dict(os.environ, HOME=str(home))
    env.pop("TRUDI_GUARD_DISABLE", None)
    if extra_env:
        env.update(extra_env)
    p = subprocess.run([sys.executable, str(HOOK)],
                       input=payload if isinstance(payload, str) else json.dumps(payload),
                       capture_output=True, text=True, env=env, timeout=30)
    assert p.returncode == 0, p.stderr
    return p.stdout


def _decision(out):
    if not out.strip():
        return None
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"]


@pytest.fixture
def owner_env(tmp_path):
    home = tmp_path / "home"
    case_dir = home / "cases" / "case-x"
    trace = case_dir / "analysis" / "T_trace.json"
    trace.parent.mkdir(parents=True)
    trace.write_text('{"entries": []}')
    cache = home / ".cache" / "trudi"
    cache.mkdir(parents=True)
    (cache / "session.json").write_text(
        json.dumps({"case_id": "T", "path": str(trace)}))

    def payload(cmd, cwd=None, sid="OWNER"):
        return {"session_id": sid, "cwd": str(cwd or case_dir),
                "hook_event_name": "PreToolUse", "tool_name": "Bash",
                "tool_input": {"command": cmd}}

    return {"home": home, "case_dir": case_dir, "cache": cache, "payload": payload}


class TestProducedOutputReads:
    def test_python_mailbox_read_denied_names_read_mail(self, owner_env):
        out = _run(owner_env["payload"](
            "cd exports/mail\npython3 - <<'EOF'\nimport mailbox\n"
            "for m in mailbox.mbox('Inbox.mbox'): print(m['To'])\nEOF"),
            owner_env["home"])
        assert _decision(out) == "deny"
        assert "read.mail" in out

    def test_jq_analysis_json_denied_names_read_output(self, owner_env):
        out = _run(owner_env["payload"]("jq '.entries' analysis/foo.json"),
                   owner_env["home"])
        assert _decision(out) == "deny"
        assert "read.output" in out

    def test_cat_report_denied(self, owner_env):
        out = _run(owner_env["payload"]("cat reports/final.md"), owner_env["home"])
        assert _decision(out) == "deny"

    def test_sqlite_over_exports_denied(self, owner_env):
        out = _run(owner_env["payload"]("sqlite3 exports/chat/x.db '.tables'"),
                   owner_env["home"])
        assert _decision(out) == "deny"

    def test_mcp_result_cache_read_denied(self, owner_env):
        # The bypass: Claude Code caches each MCP result to a SECOND copy outside
        # the case sidecar; a bash read of it is the same untraced/uncitable read.
        cmd = ("f=/root/.claude/projects/-home-cases-x/0184de98-ebed-49c2-9d38-cc0/"
               "tool-results/mcp-trudi-sift-misc_parse_scheduled_tasks-178.txt; "
               "jq '.tasks[]?' \"$f\" | head -60")
        out = _run(owner_env["payload"](cmd), owner_env["home"])
        assert _decision(out) == "deny"
        assert "read.output" in out and "tool-results" in out

    def test_mcp_result_cache_python_read_denied(self, owner_env):
        cmd = ("python3 -c \"import json; d=json.load(open("
               "'/h/.claude/projects/proj/sess/tool-results/mcp-trudi-sift-t-1.txt')); "
               "print(d)\"")
        out = _run(owner_env["payload"](cmd), owner_env["home"])
        assert _decision(out) == "deny"

    def test_ls_find_enumeration_piped_to_reader_allowed(self, owner_env):
        # ls/find output is a filename LISTING; a downstream head/grep/sort filters
        # the listing, it does not read file CONTENTS — must not be denied even when
        # a .csv/.json glob is present (regression: false-denied by _DATA_EXT_RE).
        for cmd in ("find exports -name '*.csv' | head",
                    "ls exports/*.csv | grep foo",
                    "ls -la exports/ | head -20",
                    "find exports -type f | sort",
                    "ls exports/ | grep mail"):
            out = _run(owner_env["payload"](cmd), owner_env["home"])
            assert _decision(out) is None, cmd

    def test_enumeration_that_reads_contents_still_denied(self, owner_env):
        # -exec <reader>, xargs into a reader, or a compound command with a real
        # file read do read contents — still denied (no bypass via an ls/find lead).
        for cmd in ("find exports -name '*.json' -exec cat {} +",
                    "find exports -name '*.csv' | xargs cat",
                    "ls x && cat exports/y.csv"):
            out = _run(owner_env["payload"](cmd), owner_env["home"])
            assert _decision(out) == "deny", cmd

    def test_enumeration_and_dev_commands_allowed(self, owner_env):
        for cmd in ("ls -la exports/",
                    "find exports -name '*.csv'",   # no reader binary
                    "git status",
                    "python3 -m pytest tests -q",   # no produced path
                    "ls ~/.claude/projects/proj/sess/tool-results/",  # listing, no reader+match
                    "cat ~/.claude/projects/proj/sess/other-dir/notes.txt",  # not tool-results/mcp-
                    "mkdir -p analysis"):
            out = _run(owner_env["payload"](cmd), owner_env["home"])
            assert _decision(out) is None, cmd


class TestForensicBinaries:
    def test_mftecmd_denied_with_wrapper_hint(self, owner_env):
        out = _run(owner_env["payload"](
            "dotnet /opt/zimmermantools/MFTECmd.dll -f /mnt/x/$MFT --csv out"),
            owner_env["home"])
        assert _decision(out) == "deny"
        assert "ez.mftecmd" in out

    def test_vol_denied(self, owner_env):
        out = _run(owner_env["payload"](
            "/usr/local/bin/vol -f mem.raw windows.pslist"), owner_env["home"])
        assert _decision(out) == "deny"


class TestScoping:
    def test_cwd_outside_case_never_interfered_with(self, owner_env, tmp_path):
        dev = tmp_path / "elsewhere"
        dev.mkdir()
        out = _run(owner_env["payload"]("cat exports/mail/x.mbox", cwd=dev),
                   owner_env["home"])
        assert _decision(out) is None

    def test_other_sessions_owner_not_guarded(self, owner_env):
        # Owner file claims session A; a bash from session B is not guarded
        # (and, per the writing hooks, not traced either).
        from datetime import datetime, timezone
        sig = hashlib.sha256(
            (owner_env["cache"] / "session.json").read_bytes()).hexdigest()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        # A LIVE claim (fresh last_seen) — a silent/stale one is takeover-eligible.
        (owner_env["cache"] / "session_owner.json").write_text(
            json.dumps({"session_id": "A", "beacon_sig": sig,
                        "claimed_ts": now, "last_seen": now}))
        out = _run(owner_env["payload"]("cat exports/x.csv", sid="B"),
                   owner_env["home"])
        assert _decision(out) is None

    def test_read_tool_ignored(self, owner_env):
        p = owner_env["payload"]("anything")
        p["tool_name"] = "Read"
        p["tool_input"] = {"file_path": str(owner_env["case_dir"] / "reports" / "x.md")}
        assert _decision(_run(p, owner_env["home"])) is None

    def test_disable_env_bypasses(self, owner_env):
        out = _run(owner_env["payload"]("cat exports/x.csv"), owner_env["home"],
                   extra_env={"TRUDI_GUARD_DISABLE": "1"})
        assert out.strip() == ""

    def test_malformed_payload_fails_open(self, owner_env):
        out = _run("NOT JSON", owner_env["home"])
        assert out.strip() == ""

    def test_no_beacon_no_interference(self, owner_env):
        (owner_env["cache"] / "session.json").unlink()
        out = _run(owner_env["payload"]("cat exports/x.csv"), owner_env["home"])
        assert _decision(out) is None


class TestReportWrites:
    """Rule 4: the final report is written only via misc.write_final_report —
    raw Write/Edit/MultiEdit (and bash redirects) into <case>/reports/ are
    refused for the owner session."""

    def _wp(self, owner_env, tool, file_path, cwd=None, sid="OWNER"):
        return {"session_id": sid, "cwd": str(cwd or owner_env["case_dir"]),
                "hook_event_name": "PreToolUse", "tool_name": tool,
                "tool_input": {"file_path": file_path, "content": "x"}}

    def test_relative_write_into_reports_denied(self, owner_env):
        out = _run(self._wp(owner_env, "Write", "reports/final.md"), owner_env["home"])
        assert _decision(out) == "deny" and "write_final_report" in out

    def test_absolute_edit_and_multiedit_denied(self, owner_env):
        target = str(owner_env["case_dir"] / "reports" / "SCHARDT_report.md")
        for tool in ("Edit", "MultiEdit"):
            out = _run(self._wp(owner_env, tool, target), owner_env["home"])
            assert _decision(out) == "deny", tool

    def test_any_extension_denied(self, owner_env):
        out = _run(self._wp(owner_env, "Write", "reports/trace.json"), owner_env["home"])
        assert _decision(out) == "deny"

    def test_write_under_analysis_denied(self, owner_env):
        # Fix 1: the agent has no raw-write capability to analysis/ either — a
        # raw markdown write there is the pre_report_check bypass.
        out = _run(self._wp(owner_env, "Write", "analysis/notes.md"), owner_env["home"])
        assert _decision(out) == "deny"
        assert "record_agent_message" in out
        # the exact report-bypass shape observed in the wild
        out2 = _run(self._wp(owner_env, "Write", "analysis/CASE_report.md"), owner_env["home"])
        assert _decision(out2) == "deny"

    def test_writes_into_exports_and_tool_output_denied(self, owner_env):
        # Laundering path: an exports/ file authored with Write, then cited.
        for target in ("exports/titan_thread.txt", "analysis/.tool_output/99.txt",
                       str(owner_env["case_dir"] / "exports" / "mail" / "x.mbox")):
            out = _run(self._wp(owner_env, "Write", target), owner_env["home"])
            assert _decision(out) == "deny" and "agent_authored_source" in out, target
        out = _run(owner_env["payload"]("echo x > exports/thread.txt"), owner_env["home"])
        assert _decision(out) == "deny"
        out = _run(owner_env["payload"]("cat notes.md | tee analysis/.tool_output/1.txt"), owner_env["home"])
        assert _decision(out) == "deny"

    def test_reports_dir_outside_case_allowed(self, owner_env, tmp_path):
        other = tmp_path / "elsewhere"
        (other / "reports").mkdir(parents=True)
        out = _run(self._wp(owner_env, "Write", "reports/x.md", cwd=other), owner_env["home"])
        assert _decision(out) is None

    def test_non_owner_session_not_guarded(self, owner_env):
        from datetime import datetime, timezone
        sig = hashlib.sha256((owner_env["cache"] / "session.json").read_bytes()).hexdigest()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        (owner_env["cache"] / "session_owner.json").write_text(
            json.dumps({"session_id": "A", "beacon_sig": sig, "claimed_ts": now, "last_seen": now}))
        out = _run(self._wp(owner_env, "Write", "reports/x.md", sid="B"), owner_env["home"])
        assert _decision(out) is None

    def test_bash_redirect_tee_cp_into_reports_denied(self, owner_env):
        for cmd in ("echo hi > reports/final.md",
                    "cat draft.md >> ./reports/final.md",
                    "python3 gen.py | tee reports/out.md",
                    "cp analysis/draft.md reports/final.md",
                    "mv draft.md 'reports/final.md'"):
            out = _run(owner_env["payload"](cmd), owner_env["home"])
            assert _decision(out) == "deny", cmd
            assert "write_final_report" in out

    def test_bash_read_of_reports_still_uses_rule_1_message(self, owner_env):
        out = _run(owner_env["payload"]("cat reports/final.md"), owner_env["home"])
        assert _decision(out) == "deny" and "read.output" in out

    def test_bash_write_to_analysis_denied(self, owner_env):
        for cmd in ("echo hi > analysis/notes.md", "tee analysis/x.md", "cp a analysis/x.md"):
            out = _run(owner_env["payload"](cmd), owner_env["home"])
            assert _decision(out) == "deny", cmd

    def test_bash_writes_outside_evidence_dirs_allowed(self, owner_env):
        for cmd in ("cp a b", "echo hi > /tmp/scratch.md"):
            out = _run(owner_env["payload"](cmd), owner_env["home"])
            assert _decision(out) is None, cmd

    def test_write_into_operator_memory_denied(self, owner_env):
        # An active investigation session must not edit operator-level memory.
        for fp in ("/home/trin/.claude/projects/-home-trin/memory/MEMORY.md",
                   "/home/trin/.claude/projects/-home-trin/memory/feedback_x.md"):
            out = _run(self._wp(owner_env, "Write", fp), owner_env["home"])
            assert _decision(out) == "deny", fp
            assert "record_agent_message" in out

    def test_bash_write_into_operator_memory_denied(self, owner_env):
        for cmd in ("echo hi > /home/trin/.claude/projects/p/memory/x.md",
                    "cp a /home/trin/.claude/projects/p/memory/note.md"):
            out = _run(owner_env["payload"](cmd), owner_env["home"])
            assert _decision(out) == "deny", cmd

    def test_disable_env_bypasses_write_rule(self, owner_env):
        out = _run(self._wp(owner_env, "Write", "reports/final.md"), owner_env["home"],
                   extra_env={"TRUDI_GUARD_DISABLE": "1"})
        assert out.strip() == ""
