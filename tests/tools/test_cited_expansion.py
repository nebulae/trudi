"""Tests for fix (b): deterministic expansion of the raw output of the call_ids
a reviewer call cited, appended to the prompt. Scoped strictly to the declared
input_call_ids (no wider-trace browsing), so provenance is unchanged.
"""
import pytest
from unittest.mock import patch, MagicMock

import tools.reasoning as R


@pytest.fixture(autouse=True)
def _push_mode(monkeypatch):
    # These tests pin the legacy PUSH behaviour (term-ranked excerpts). The
    # default is now PULL (evidence inventory + EVIDENCE_REQUEST), covered in
    # tests/tools/test_evidence_request.py.
    monkeypatch.setattr(R, "COMPAT_EVIDENCE_MODE", "push")


@pytest.fixture
def trace(tmp_path):
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("TEST-CITE", str(tmp_path / "trace.json"))
    return l


def _expand(trace, cids, budget=6000):
    with patch("core.execution_log.log", trace), \
         patch.object(R, "COMPAT_EXPAND_CITED", True):
        return R._expand_cited_evidence(cids, budget)


class TestExpandCitedEvidence:
    def test_empty_when_no_ids(self, trace):
        assert _expand(trace, []) == ""
        assert _expand(trace, None) == ""

    def test_tool_call_contributes_cmd_and_stdout(self, trace):
        cid = trace.record_tool_call("ez.evtxecmd Security 4648", True, False, 0, 0,
                                     stdout_excerpt="4648 explicit-credential logon steve.rogers")
        out = _expand(trace, [cid])
        assert f"[call {cid}]" in out
        assert "ez.evtxecmd" in out and "steve.rogers" in out
        assert out.startswith("CITED TOOL OUTPUT")

    def test_reason_call_contributes_conclusion(self, trace):
        cid = trace.record_reason_call("reason_hypothesize", True, "H1: a second principal", {})
        out = _expand(trace, [cid])
        assert "a second principal" in out and "reason_hypothesize" in out

    def test_missing_cid_is_flagged_not_dropped(self, trace):
        out = _expand(trace, [999999])
        assert "NOT PRESENT" in out and "999999" in out

    def test_dedup_preserves_order(self, trace):
        a = trace.record_tool_call("tool.a", True, False, 0, 0, stdout_excerpt="AAA")
        b = trace.record_tool_call("tool.b", True, False, 0, 0, stdout_excerpt="BBB")
        out = _expand(trace, [a, b, a])
        assert out.count(f"[call {a}]") == 1
        assert out.index(f"[call {a}]") < out.index(f"[call {b}]")

    def test_floor_prevents_starvation_when_many_citations(self, trace):
        # Old math divided the pool (600//6=100 → floored 200) and truncated
        # every entry. The per-entry floor now guarantees FLOOR+200 chars, so
        # each ~600-char stored excerpt fits whole — while the expansion cap
        # keeps the total self-bounded.
        cids = [trace.record_tool_call(f"tool.{i}", True, False, 0, 0,
                                       stdout_excerpt="D" * 600) for i in range(6)]
        out = _expand(trace, cids, budget=600)  # per = max(FLOOR+200, 100)
        assert "[truncated]" not in out
        assert out.count("D" * 600) == 6
        assert len(out) < 6 * (R.COMPAT_CITED_FILE_FLOOR + 200) + 500

    def test_short_entry_not_truncated(self, trace):
        cid = trace.record_tool_call("evt.one", True, False, 0, 0,
                                     stdout_excerpt="the needle 4648")
        out = _expand(trace, [cid], budget=6000)
        assert "the needle 4648" in out and "[truncated]" not in out

    def test_empty_body_entry_skipped(self, trace):
        cid = trace.record_tool_call("tool.x", True, False, 0, 0)  # no stdout_excerpt
        # cmd still present -> body is the cmd; but a truly empty one skips.
        blank = trace.record_reason_call("reason_x", True, "", {})
        out = _expand(trace, [blank])
        assert out == ""

    def test_disabled_by_env(self, trace):
        cid = trace.record_tool_call("t", True, False, 0, 0, stdout_excerpt="data")
        with patch("core.execution_log.log", trace), \
             patch.object(R, "COMPAT_EXPAND_CITED", False):
            assert R._expand_cited_evidence([cid], 6000) == ""

    def test_no_active_log_is_silent(self):
        from core.execution_log import ExecutionLog
        with patch.object(R, "COMPAT_EXPAND_CITED", True), \
             patch("core.execution_log.log", ExecutionLog()):
            assert R._expand_cited_evidence([1], 6000) == ""


class TestExpansionCapAndFloor:
    def test_cap_expands_max_and_notes_elided(self, trace):
        cids = [trace.record_tool_call(f"t.{i}", True, False, 0, 0,
                                       stdout_excerpt=f"row{i}") for i in range(15)]
        out = _expand(trace, cids)
        assert out.count("[call ") == R.COMPAT_CITED_MAX_EXPAND
        assert "+3 more cited calls not expanded" in out
        for c in cids[R.COMPAT_CITED_MAX_EXPAND:]:   # elided ids are named
            assert str(c) in out

    def test_tool_calls_preferred_over_reason_calls_when_capped(self, trace):
        r = trace.record_reason_call("reason_hypothesize", True, "summary text", {})
        t1 = trace.record_tool_call("t.one", True, False, 0, 0, stdout_excerpt="raw1")
        t2 = trace.record_tool_call("t.two", True, False, 0, 0, stdout_excerpt="raw2")
        with patch.object(R, "COMPAT_CITED_MAX_EXPAND", 2):
            out = _expand(trace, [r, t1, t2])
        assert f"[call {t1}]" in out and f"[call {t2}]" in out
        assert f"[call {r}]" not in out
        assert f"not expanded: {r}" in out

    def test_floor_reaches_output_file_at_high_citation_count(self, tmp_path):
        # 30 cited banner calls, the first naming a CSV that holds the key row.
        # Old math gave the file read 6000//30 - 200 = 0 chars — skipped
        # entirely, reviewer saw banners only. Cap + floor now surface the row.
        from core.execution_log import ExecutionLog
        out_dir = tmp_path / "evtx"; out_dir.mkdir()
        (out_dir / "Security.csv").write_text(
            "EventId,Payload\n4624,noise\n4738,DisplayName: Anthony Vanko\n")
        log = ExecutionLog()
        log.configure("TEST-FLOOR", str(tmp_path / "trace.json"), save_session=False)
        cids = [log.record_tool_call(
            f"dotnet EvtxECmd.dll -d /in --csv {out_dir}" if i == 0 else f"t.{i}",
            True, False, 0, 0,
            stdout_excerpt="EvtxECmd version banner" if i == 0 else f"x{i}")
            for i in range(30)]
        with patch("core.execution_log.log", log), \
             patch.object(R, "COMPAT_EXPAND_CITED", True):
            block = R._expand_cited_evidence(cids, 6000,
                                             query_text="Anthony Vanko EID 4738")
        assert "[from output file]" in block
        assert "4738" in block and "Anthony Vanko" in block
        assert "more cited calls not expanded" in block


class TestCitationInjection:
    def test_with_citations_appends_for_reviewer_tools(self, trace):
        cid = trace.record_tool_call("t", True, False, 0, 0, stdout_excerpt="cited data")
        with patch("core.execution_log.log", trace), \
             patch.object(R, "COMPAT_EXPAND_CITED", True):
            out = R._with_citations("FINDING:\nx", "reason_evaluate_finding", [cid])
        assert out.startswith("FINDING:\nx")
        assert "CITED TOOL OUTPUT" in out and "cited data" in out

    def test_with_citations_skips_plan_and_audit(self, trace):
        cid = trace.record_tool_call("t", True, False, 0, 0, stdout_excerpt="d")
        with patch("core.execution_log.log", trace), \
             patch.object(R, "COMPAT_EXPAND_CITED", True):
            assert R._with_citations("CASE", "reason_plan", [cid]) == "CASE"
            assert R._with_citations("N", "reason_audit_findings", [cid]) == "N"

    def test_with_citations_noop_when_no_ids(self, trace):
        with patch("core.execution_log.log", trace), \
             patch.object(R, "COMPAT_EXPAND_CITED", True):
            assert R._with_citations("FINDING", "reason_evaluate_finding", []) == "FINDING"

    def test_reaches_request_payload_and_scope_also_present(self, trace):
        """End-to-end: both the scope header (a) and the cited block (b) land in
        the compat request, with the cited block after the finding."""
        cid = trace.record_tool_call("ewf.mount_full_image /ev/d.E01", True, False, 0, 0,
                                     stdout_excerpt="mounted ok")
        resp = MagicMock(); resp.raise_for_status = MagicMock()
        resp.json.return_value = {"choices": [{"finish_reason": "stop",
                                  "message": {"content": "VERDICT: SUPPORTED"}}],
                                  "usage": {"prompt_tokens": 5, "completion_tokens": 5}}
        http = MagicMock(return_value=resp)
        with patch("core.execution_log.log", trace), \
             patch.object(R, "COMPAT_EXPAND_CITED", True), \
             patch.object(R, "COMPAT_EVIDENCE_SCOPE", True), \
             patch.object(R, "REASON_BACKEND", "openai-compat"), \
             patch.object(R, "REASON_URL", "http://x.test"), \
             patch.object(R, "REASON_MODEL", "m"), \
             patch.object(R, "COMPAT_NO_THINK_TOOLS", frozenset()), \
             patch("httpx.post", http):
            R.reason_evaluate_finding("finding text", "evidence text", input_call_ids=[cid])
        sent = http.call_args[1]["json"]["messages"][1]["content"]
        assert "EVIDENCE COLLECTED THIS INVESTIGATION" in sent   # (a)
        assert "CITED TOOL OUTPUT" in sent and "mounted ok" in sent  # (b)
        assert sent.index("finding text") < sent.index("CITED TOOL OUTPUT")


# ── reading the tool's output file when stdout is a banner (relevance-aware) ──
class TestCitedOutputFileReading:
    def _log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-FILE", str(tmp_path / "trace.json"), save_session=False)
        return l

    def test_query_terms_extraction(self):
        terms = R._cited_query_terms(
            "PC User belongs to Anthony Vanko; Security EID 4738 DisplayName; "
            "mailbox anthony.vanko@icloud.example; SID S-1-5-21-1-2-3-1001")
        assert "anthony.vanko@icloud.example" in terms
        assert "4738" in terms
        assert any("anthony" in t for t in terms)
        assert "s-1-5-21-1-2-3-1001" in terms

    def test_three_char_proper_nouns_extracted_stop_words_dropped(self):
        # A ≤3-char suspect name must become a query term (previously the ≥4
        # regex + len filter silently dropped it, zero-scoring its key rows);
        # title-case function words and date abbreviations must not.
        terms = R._cited_query_terms("Bob copied the archive; sent Sat Jun 18")
        assert "bob" in terms
        for noise in ("the", "sat", "jun", "not", "was"):
            assert noise not in terms

    def test_cmd_output_paths_parsing(self):
        assert R._cmd_output_paths(
            "dotnet EvtxECmd.dll -d /in/logs --csv /out/evtx") == ["/out/evtx"]
        assert R._cmd_output_paths(
            "/usr/bin/pffexport -m items -t /out/ost /in/mail.ost") == ["/out/ost"]
        # input flags (-f, -d without --csv) are not output targets
        assert R._cmd_output_paths("exiftool /in/doc.docx") == []

    def test_banner_stdout_triggers_relevant_csv_read(self, tmp_path):
        # EZ-shaped: stdout excerpt is the version banner; records are in --csv.
        out = tmp_path / "evtx"; out.mkdir()
        csv = out / "Security.csv"
        csv.write_text(
            "RecordNumber,EventId,MapDescription,PayloadData1\n"
            "1,4624,Logon,noise noise noise\n"
            "2,4738,User account changed,DisplayName: Anthony Vanko\n"
            "3,4634,Logoff,more noise\n")
        log = self._log(tmp_path)
        cid = log.record_tool_call(
            f"dotnet EvtxECmd.dll -d /in/logs --csv {out}", True, False, 0, 0,
            stdout_excerpt="EvtxECmd version 1.5.2.0\n\nAuthor: Eric Zimmerman\nhttps://github…")
        with patch("core.execution_log.log", log), \
             patch.object(R, "COMPAT_EXPAND_CITED", True):
            block = R._expand_cited_evidence([cid], 6000,
                                             query_text="Anthony Vanko EID 4738 DisplayName")
        assert "[from output file]" in block
        assert "4738" in block and "Anthony Vanko" in block   # the relevant row
        assert "4624" not in block and "4634" not in block    # noise rows filtered out
        assert "Security.csv" in block

    def test_good_stdout_excerpt_skips_file_read(self, tmp_path):
        # When the excerpt already carries a query term, do not read a file.
        out = tmp_path / "d"; out.mkdir()
        (out / "x.csv").write_text("col\nSHOULD_NOT_BE_READ\n")
        log = self._log(tmp_path)
        cid = log.record_tool_call(
            f"tool --csv {out}", True, False, 0, 0,
            stdout_excerpt="DisplayName: Anthony Vanko present right here")
        with patch("core.execution_log.log", log), \
             patch.object(R, "COMPAT_EXPAND_CITED", True):
            block = R._expand_cited_evidence([cid], 6000, query_text="Anthony Vanko")
        assert "[from output file]" not in block
        assert "SHOULD_NOT_BE_READ" not in block

    def test_no_query_terms_does_not_read_file(self, tmp_path):
        out = tmp_path / "d"; out.mkdir()
        (out / "x.csv").write_text("a\nb\n")
        log = self._log(tmp_path)
        cid = log.record_tool_call(f"tool --csv {out}", True, False, 0, 0,
                                   stdout_excerpt="banner only")
        with patch("core.execution_log.log", log), \
             patch.object(R, "COMPAT_EXPAND_CITED", True):
            block = R._expand_cited_evidence([cid], 6000, query_text="")  # no terms
        assert "[from output file]" not in block

    def test_missing_output_file_fails_open_to_excerpt(self, tmp_path):
        log = self._log(tmp_path)
        cid = log.record_tool_call("tool --csv /nonexistent/dir", True, False, 0, 0,
                                   stdout_excerpt="banner text")
        with patch("core.execution_log.log", log), \
             patch.object(R, "COMPAT_EXPAND_CITED", True):
            block = R._expand_cited_evidence([cid], 6000, query_text="4738")
        assert "banner text" in block and "[from output file]" not in block

    def test_read_relevant_keeps_csv_header(self, tmp_path):
        f = tmp_path / "o.csv"
        f.write_text("EventId,Msg\n4738,hit here\n4624,other\n")
        got = R._read_relevant_from_file(str(f), ["4738"], 6000)
        assert got.startswith("EventId,Msg")   # header retained
        assert "4738,hit here" in got and "4624,other" not in got
