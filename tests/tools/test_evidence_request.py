"""EVIDENCE_REQUEST round-trip (pull mode): the reviewer sees an inventory of the
cited outputs, asks for the rows it needs, and must earn a SUPPORTED verdict."""
import json
from unittest.mock import MagicMock, patch

import pytest

import tools.reasoning as R
from tools import _output_reader as OR


def _http(content, finish_reason="stop"):
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json.return_value = {
        "choices": [{"finish_reason": finish_reason,
                     "message": {"content": content, "reasoning": ""}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 40},
    }
    return m


_REQ = ('Analysis pending.\nEVIDENCE_REQUEST:\n[{"call_id": %d, "query": "4720 defaultprinter", '
        '"columns": ["TimeCreated", "EventId", "PayloadData1"]}]\n')
_SUPPORTED = "1. EVIDENCE SUPPORT — the 4720 row is present.\nVERDICT: SUPPORTED — grounded."


@pytest.fixture
def pull_env(monkeypatch, tmp_path):
    monkeypatch.setattr(R, "REASON_BACKEND", "openai-compat")
    monkeypatch.setattr(R, "REASON_URL", "http://x.test")
    monkeypatch.setattr(R, "REASON_MODEL", "m")
    monkeypatch.setattr(R, "COMPAT_NO_THINK_TOOLS", frozenset())
    monkeypatch.setattr(R, "COMPAT_EVIDENCE_MODE", "pull")
    monkeypatch.setattr(R, "COMPAT_EXPAND_CITED", True)
    monkeypatch.setattr(R, "COMPAT_EVIDENCE_SCOPE", False)
    # A cited EvtxECmd call whose CSV holds the discriminating row among noise.
    out = tmp_path / "evtx"
    out.mkdir()
    rows = ["RecordNumber,TimeCreated,EventId,MapDescription,PayloadData1,Payload"]
    for i in range(40):
        rows.append(f"{i},2016-11-04 13:59:{i:02d},4799,Group membership enumerated,"
                    f"Target: Builtin\\Administrators,{'x' * 900}")
    rows.append("99,2016-06-18 20:40:54,4720,A user account was created,"
                "TargetUserName: defaultprinter,payload")
    (out / "Security.csv").write_text("\n".join(rows) + "\n")
    from core.execution_log import log
    cid = log.record_tool_call(f"dotnet EvtxECmd.dll -d /in --csv {out}", True, False, 0, 0,
                               stdout_excerpt="EvtxECmd version banner")
    return {"cid": cid, "csv": out / "Security.csv", "log": log}


def _payload(http, i):
    return http.call_args_list[i][1]["json"]["messages"][1]["content"]


class TestGrammar:
    def test_parse_and_strip(self):
        raw = ('prose\nEVIDENCE_REQUEST:\n[{"call_id": 7, "query": "4720", "columns": ["A"]}]\n'
               'VERDICT: SUPPORTED')
        reqs = R._parse_evidence_request(raw)
        assert reqs == [{"call_id": 7, "query": "4720", "columns": ["A"]}]
        stripped = R._strip_evidence_request(raw)
        assert "EVIDENCE_REQUEST" not in stripped and "VERDICT: SUPPORTED" in stripped

    def test_fenced_and_bad_items(self):
        raw = 'EVIDENCE_REQUEST:\n```json\n[{"call_id": "x", "query": "q"}, {"call_id": 3, "query": ""}, {"call_id": 4, "query": "ok"}]\n```'
        assert R._parse_evidence_request(raw) == [{"call_id": 4, "query": "ok", "columns": []}]

    def test_marker_lost_in_thinking_fallback(self):
        # A thinking model may leave the header in <think> and emit only the
        # array — accept a bare array whose items all carry call_id + query.
        raw = '[\n  {"call_id": 7, "query": "MSPAuth|rudy", "columns": ["ValueData"]}\n]'
        assert R._parse_evidence_request(raw) == [
            {"call_id": 7, "query": "MSPAuth|rudy", "columns": ["ValueData"]}]
        assert R._strip_evidence_request(raw) == ""

    def test_bare_array_that_is_not_a_request_ignored(self):
        raw = "scores: [1, 2, 3]\nVERDICT: SUPPORTED"
        assert R._parse_evidence_request(raw) == []
        assert R._strip_evidence_request(raw) == raw

    def test_colon_optional_and_plain_fence(self):
        raw = 'EVIDENCE_REQUEST\n```\n[{"call_id": 1, "query": "q"}]\n```\nmore'
        assert R._parse_evidence_request(raw) == [{"call_id": 1, "query": "q", "columns": []}]
        assert "EVIDENCE_REQUEST" not in R._strip_evidence_request(raw)

    def test_malformed_leaves_text_alone(self):
        raw = "EVIDENCE_REQUEST: [this is not json\nVERDICT: CHALLENGED"
        assert R._parse_evidence_request(raw) == []
        assert R._strip_evidence_request(raw) == raw   # never the marker-and-after strip

    def test_cap(self, monkeypatch):
        monkeypatch.setattr(R, "COMPAT_EVIDENCE_MAX_REQUESTS", 2)
        raw = "EVIDENCE_REQUEST: " + json.dumps(
            [{"call_id": i, "query": "q"} for i in range(5)])
        assert len(R._parse_evidence_request(raw)) == 2

    def test_boolean_operators_are_not_terms(self, pull_env):
        cid = pull_env["cid"]
        block, recs = R._resolve_evidence_requests(
            [{"call_id": cid, "query": "4720 OR (defaultprinter) AND notaword", "columns": []}],
            [cid], 4000)
        # 'or'/'and' dropped: only the one real row matches, counts not inflated
        assert recs[0]["rows_returned"] == 1
        assert "1 of 41 rows match [4720 defaultprinter notaword]" in block

    def test_pipe_alternation_is_split(self, pull_env):
        # Regex-style "a|b" kept whole can never match a row — split on '|'.
        cid = pull_env["cid"]
        block, recs = R._resolve_evidence_requests(
            [{"call_id": cid, "query": "zzz|defaultprinter", "columns": []}], [cid], 4000)
        assert recs[0]["rows_returned"] == 1
        assert "[zzz defaultprinter]" in block


class TestReader:
    def test_stats_and_row_cap(self, pull_env):
        r = OR.read_relevant_stats(str(pull_env["csv"]), ["4720", "defaultprinter"], 4000)
        assert r.total_rows == 41 and r.matched_rows == 1 and r.shown_rows == 1
        assert "defaultprinter" in r.body
        r2 = OR.read_relevant_stats(str(pull_env["csv"]), ["4799"], 4000)
        assert r2.matched_rows == 40
        assert all(len(ln) <= OR._ROW_CHARS + 20 for ln in r2.body.splitlines())  # per-row cap

    def test_column_projection_via_stats(self, pull_env):
        r = OR.read_relevant_stats(str(pull_env["csv"]), ["4720"], 4000,
                                   columns=["TimeCreated", "EventId", "PayloadData1"])
        assert r.body.splitlines()[0].replace(" ", "") == "TimeCreated,EventId,PayloadData1"
        assert "xxxx" not in r.body   # Payload column projected out

    def test_inventory_counts_columns_and_complete(self, pull_env, tmp_path):
        inv = OR.output_inventory(f"dotnet EvtxECmd.dll --csv {pull_env['csv'].parent}",
                                  ["4720"])
        assert inv and inv[0]["total_rows"] == 41 and inv[0]["term_hits"] == 1
        assert "EventId" in inv[0]["columns"] and inv[0]["complete"] is None
        small = tmp_path / "small.txt"
        small.write_text("one line")
        inv2 = OR.output_inventory(f"tool --output {small}", [])
        assert inv2[0]["complete"] == "one line"

    def test_inventory_cache_hit(self, pull_env):
        p = str(pull_env["csv"])
        OR._INVENTORY_CACHE.clear()
        OR._file_inventory(p)
        assert len(OR._INVENTORY_CACHE) == 1
        OR._file_inventory(p)
        assert len(OR._INVENTORY_CACHE) == 1


class TestInventoryRendering:
    def test_round1_shows_inventory_not_rows(self, pull_env):
        user, meta = R._with_citations_meta("FINDING:\nx 4720", "reason_evaluate_finding",
                                            [pull_env["cid"]])
        assert "EVIDENCE INVENTORY" in user
        assert "41 rows" in user and "EventId" in user
        assert "TargetUserName: defaultprinter" in user   # J-2: matching rows are pushed
        assert "showing 1 of 1 rows matching" in user and "source COMPLETE" in user
        assert meta["pushed_rows"] == 1 and meta["pushed_cids"] == [pull_env["cid"]]

    def test_stdout_only_call_is_inlined_complete(self, pull_env):
        cid = pull_env["log"].record_tool_call("misc.device_install_inventory /x/setupapi.dev.log",
                                               True, False, 0, 0, stdout_excerpt="1 FLAGGED device")
        user, meta = R._with_citations_meta("F", "reason_evaluate_finding", [cid])
        assert "COMPLETE" in user and "1 FLAGGED device" in user
        assert meta["pushed_rows"] == 0

    def test_no_citations_is_vacuously_complete(self, pull_env):
        user, meta = R._with_citations_meta("F", "reason_evaluate_finding", [])
        assert user == "F" and meta["pushed_rows"] == 0


class TestRoundTrip:
    def test_two_round_evaluate_fetches_rows_and_earns_supported(self, pull_env):
        cid = pull_env["cid"]
        http = MagicMock(side_effect=[_http(_REQ % cid), _http(_SUPPORTED)])
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("Account defaultprinter was created (EID 4720)",
                                          f"Security.evtx (cid{cid}): 4720", input_call_ids=[cid])
        assert http.call_count == 2
        assert "EVIDENCE INVENTORY" in _payload(http, 0)
        assert "TargetUserName: defaultprinter" in _payload(http, 0)   # pushed in round 1
        p2 = _payload(http, 1)
        assert "EVIDENCE_REQUEST RESULTS (round 1/" in p2
        assert "TargetUserName: defaultprinter" in p2
        assert "xxxx" not in p2                       # requested columns honoured
        assert r["verdict"] == "SUPPORTED" and r["evidence_rounds"] == 1
        assert r["evidence_fetches"][0]["rows_returned"] == 1
        log = pull_env["log"]
        evals = [e for e in log._entries if e.get("type") == "reason_call"
                 and e.get("tool") == "reason_evaluate_finding"]
        assert len(evals) == 1                        # one reason_call per review
        assert evals[0]["evidence_rounds"] == 1 and evals[0]["verdict"] == "SUPPORTED"
        assert evals[0]["input_tokens"] == 200        # summed across rounds
        fetches = [e for e in log._entries if e.get("type") == "reason_evidence_fetch"]
        assert fetches and fetches[0]["requests"][0]["rows_returned"] == 1
        assert fetches[0]["reason_call_id"] == evals[0]["call_id"]

    def test_round_one_pushes_the_matching_rows_and_supported_stands(self, pull_env):
        # J-2 push-then-pull: the 4720 row (past the excerpt, deep in a 40-row
        # CSV) is in the ROUND-1 message with its totals; a SUPPORTED that
        # rests on it needs no fetch (the earned-verdict flip is gone).
        cid = pull_env["cid"]
        http = MagicMock(side_effect=[_http(_SUPPORTED)])
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("defaultprinter created 4720", "x", input_call_ids=[cid])
        assert http.call_count == 1
        p = _payload(http, 0)
        assert "TargetUserName: defaultprinter" in p
        assert "showing 1 of 1 rows matching" in p and "41 rows scanned; source COMPLETE" in p
        assert "a selection with its totals" in p and "EVIDENCE_REQUEST" in p   # pull still offered
        assert r["verdict"] == "SUPPORTED" and "verdict_note" not in r
        assert r["evidence_pushed"] == {"rows": 1, "cids": [cid]}
        e = pull_env["log"].index().by_call_id[r["_trudi_call_id"]]
        assert e["verdict"] == "SUPPORTED" and e["evidence_pushed"]["rows"] == 1

    def test_push_states_totals_and_caps_the_selection(self, pull_env):
        cid = pull_env["cid"]
        http = MagicMock(side_effect=[_http(_SUPPORTED)])
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("4799 group membership enumerated", "x", input_call_ids=[cid])
        p = _payload(http, 0)
        assert f"showing {R.COMPAT_PUSH_ROWS_PER_CID} of 40 rows matching" in p
        assert "request more via EVIDENCE_REQUEST" in p
        assert r["evidence_pushed"]["rows"] == R.COMPAT_PUSH_ROWS_PER_CID

    def test_push_reads_the_sidecar_past_the_excerpt_and_labels_legacy_partial(self, pull_env):
        # E-02 case: the FOUND line sits past the 600-char excerpt. With a
        # sidecar it is pushed from the sidecar (source COMPLETE); a legacy
        # entry that kept only the excerpt pushes nothing and is PARTIAL.
        log = pull_env["log"]
        body = "x" * 700 + "\nFOUND: MSPAuth cookie for findme69@hotmail.example\n"
        full = log.record_tool_call("sudo ngrep -q -I x.pcap MSPAuth", True, False, 0, 0,
                                    stdout_excerpt=body[:600], stdout_full=body)
        legacy = log.record_tool_call("sudo ngrep -q -I y.pcap MSPAuth", True, False, 0, 0,
                                      stdout_excerpt=body[:600])
        le = log.index().by_call_id[legacy]
        le.pop("stdout_chars", None); le.pop("stdout_path", None)   # pre-sidecar shape
        http = MagicMock(side_effect=[_http(_SUPPORTED)])
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("MSPAuth cookie findme69 FOUND", "x", input_call_ids=[full, legacy])
        p = _payload(http, 0)
        assert "FOUND: MSPAuth cookie for findme69@hotmail.example" in p
        assert "source COMPLETE" in p
        assert "PARTIAL" in p and "a term missing here is NOT absent" in p
        assert r["evidence_pushed"]["cids"] == [full]

    def test_no_request_and_not_supported_stays_as_answered(self, pull_env):
        # H-5's auto-fetch round is gone: the rows were already pushed, so an
        # UNCERTAIN with no request is the reviewer's answer — one call.
        cid = pull_env["cid"]
        first = ("1. FACTS — raw rows for the cited sources are missing; the claim "
                 "cannot be verified.\n7. VERDICT: UNVERIFIABLE")
        with patch("httpx.post", MagicMock(side_effect=[_http(first)])) as http:
            r = R.reason_evaluate_finding("defaultprinter account created (4720)", "ev",
                                          input_call_ids=[cid], claim_kind="positive",
                                          category="persistence", act="account_creation",
                                          entities=["defaultprinter"], principal="defaultprinter")
        assert http.call_count == 1 and r["verdict"] == "UNCERTAIN"
        assert "auto_fetch_round" not in r and r.get("evidence_rounds", 0) == 0
        assert not hasattr(R, "_auto_requests")

    def test_supported_stands_when_nothing_was_cited(self, pull_env):
        with patch("httpx.post", MagicMock(side_effect=[_http(_SUPPORTED)])):
            r = R.reason_evaluate_finding("plain finding", "x")
        assert r["verdict"] == "SUPPORTED"

    def test_request_honored_even_with_a_verdict(self, pull_env):
        # The template ends in a VERDICT line; a reviewer that writes
        # "VERDICT: UNCERTAIN — pending rows" AND a request must get the rows.
        cid = pull_env["cid"]
        both = _REQ % cid + "\nVERDICT: UNCERTAIN — pending raw row retrieval."
        http = MagicMock(side_effect=[_http(both), _http(_SUPPORTED)])
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("defaultprinter created 4720", "x", input_call_ids=[cid])
        assert http.call_count == 2
        assert "TargetUserName: defaultprinter" in _payload(http, 1)
        assert r["verdict"] == "SUPPORTED" and r["evidence_rounds"] == 1

    def test_request_out_of_scope_cid_is_refused(self, pull_env):
        cid = pull_env["cid"]
        http = MagicMock(side_effect=[_http(_REQ % (cid + 999)), _http("VERDICT: UNCERTAIN")])
        with patch("httpx.post", http):
            R.reason_evaluate_finding("f", "x", input_call_ids=[cid])
        assert "not among the cited call_ids" in _payload(http, 1)

    def test_empty_result_reports_rows_scanned(self, pull_env):
        cid = pull_env["cid"]
        req = ('EVIDENCE_REQUEST: [{"call_id": %d, "query": "zzznomatch"}]' % cid)
        http = MagicMock(side_effect=[_http(req), _http("VERDICT: CHALLENGED — absent.")])
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("f", "x", input_call_ids=[cid])
        assert "no rows match 'zzznomatch'" in _payload(http, 1)
        assert "41 rows scanned" in _payload(http, 1)
        assert r["verdict"] == "CHALLENGED"

    def test_rounds_are_bounded(self, pull_env, monkeypatch):
        monkeypatch.setattr(R, "COMPAT_EVIDENCE_ROUNDS", 2)
        cid = pull_env["cid"]
        http = MagicMock(side_effect=[_http(_REQ % cid)] * 5)
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("f", "x", input_call_ids=[cid])
        assert http.call_count == 3                   # round 1 + 2 bounded re-asks
        assert "No further EVIDENCE_REQUEST will be honored" in _payload(http, 2)
        assert not r.get("verdict")

    def test_push_mode_keeps_legacy_excerpt(self, pull_env, monkeypatch):
        monkeypatch.setattr(R, "COMPAT_EVIDENCE_MODE", "push")
        user, _ = R._with_citations_meta("FINDING: defaultprinter 4720", "reason_evaluate_finding",
                                         [pull_env["cid"]])
        assert "CITED TOOL OUTPUT" in user and "defaultprinter" in user


# ── Phase E-02: partial sources, sidecars, per-field caps ───────────────────

class TestPartialSources:
    """The trace used to keep only 600 chars of stdout; a reviewer fetch over
    that excerpt reported "no rows match" and read it as absence. Now: the
    full stdout is a fetchable sidecar; a legacy excerpt-only entry is labelled
    PARTIAL and a miss over it is not absence."""

    def _legacy_partial(self, log):
        # A pre-sidecar entry: excerpt exactly at the cap, no stdout_chars.
        body = "\n".join(f"/x/COMMANDS/file{i:02d}.exe: OK" for i in range(40))
        return log.record_tool_call("clamscan --no-summary /x/COMMANDS", True, False, 0, 1,
                                    stdout_excerpt=body[:600])

    def test_sources_of_legacy_capped_entry_are_partial(self, pull_env):
        cid = self._legacy_partial(pull_env["log"])
        e = pull_env["log"].index().by_call_id[cid]
        e.pop("stdout_chars", None); e.pop("stdout_path", None)   # simulate legacy
        srcs = OR.entry_text_sources(e)
        assert [s.kind for s in srcs] == ["stdout_excerpt"]
        assert srcs[0].complete is False

    def test_inventory_labels_partial_and_does_not_inline(self, pull_env):
        cid = self._legacy_partial(pull_env["log"])
        e = pull_env["log"].index().by_call_id[cid]
        e.pop("stdout_chars", None); e.pop("stdout_path", None)
        user, meta = R._with_citations_meta("F", "reason_evaluate_finding", [cid])
        assert "PARTIAL" in user and "NOT absent" in user
        assert meta["pushed_rows"] == 0                  # nothing is pushed from an excerpt

    def test_miss_over_partial_source_is_not_absence(self, pull_env):
        cid = self._legacy_partial(pull_env["log"])
        e = pull_env["log"].index().by_call_id[cid]
        e.pop("stdout_chars", None); e.pop("stdout_path", None)
        block, recs = R._resolve_evidence_requests(
            [{"call_id": cid, "query": "FOUND snitch.exe", "columns": []}], [cid], 4000)
        assert "absence NOT established" in block
        assert recs[0]["status"] == "partial_source" and recs[0]["source_complete"] is False

    def test_miss_over_complete_source_is_absence(self, pull_env):
        cid = pull_env["log"].record_tool_call("tool", True, False, 0, 0,
                                               stdout_excerpt="a: OK\nb: OK\n")
        block, recs = R._resolve_evidence_requests(
            [{"call_id": cid, "query": "FOUND", "columns": []}], [cid], 4000)
        assert "source COMPLETE" in block and recs[0]["status"] == "ok"

    def test_sidecar_is_fetched_past_the_excerpt(self, pull_env):
        # E-01 sidecar: the FOUND line sits after 600 chars of OK lines.
        body = "\n".join(f"/x/COMMANDS/file{i:02d}.exe: OK" for i in range(40))
        body += "\n/x/COMMANDS/snitch.exe: Win.Tool.Snitch FOUND\n"
        cid = pull_env["log"].record_tool_call("clamscan --no-summary /x/COMMANDS", True, False, 0, 1,
                                               stdout_excerpt=body[:600], stdout_full=body)
        e = pull_env["log"].index().by_call_id[cid]
        assert e["stdout_path"]
        kinds = [s.kind for s in OR.entry_text_sources(e)]
        assert kinds[0] == "stdout_sidecar"
        user, meta = R._with_citations_meta("F", "reason_evaluate_finding", [cid])
        assert "stdout (complete)" in user
        block, recs = R._resolve_evidence_requests(
            [{"call_id": cid, "query": "FOUND", "columns": []}], [cid], 4000)
        assert "snitch.exe: Win.Tool.Snitch FOUND" in block
        assert recs[0]["rows_returned"] == 1 and recs[0]["source_kind"] == "stdout_sidecar"

    def test_short_stdout_is_complete(self, pull_env):
        cid = pull_env["log"].record_tool_call("misc.device_install_inventory /x", True, False, 0, 0,
                                               stdout_excerpt="1 FLAGGED device")
        user, meta = R._with_citations_meta("F", "reason_evaluate_finding", [cid])
        assert "COMPLETE" in user and meta["pushed_rows"] == 0

    def test_output_path_entry_is_a_file_source(self, pull_env, tmp_path):
        f = tmp_path / "icat.txt"; f.write_text("hdr\nrow with marker\n")
        cid = pull_env["log"].record_tool_call("icat -o 63 img.dd 1234", True, False, 0, 0,
                                               stdout_excerpt=f"Output written to {f}",
                                               output_path=str(f))
        e = pull_env["log"].index().by_call_id[cid]
        assert OR.entry_text_sources(e)[0].kind == "file"
        block, recs = R._resolve_evidence_requests(
            [{"call_id": cid, "query": "marker", "columns": []}], [cid], 4000)
        assert "row with marker" in block

    def test_challenge_on_partial_sources_is_stamped_and_not_sticky(self, pull_env):
        cid = self._legacy_partial(pull_env["log"])
        e = pull_env["log"].index().by_call_id[cid]
        e.pop("stdout_chars", None); e.pop("stdout_path", None)
        req = ('EVIDENCE_REQUEST:\n[{"call_id": %d, "query": "FOUND snitch"}]\n' % cid)
        chall = "1. EVIDENCE — nothing.\nVERDICT: CHALLENGED — no FOUND rows."
        http = MagicMock(side_effect=[_http(req), _http(chall)])
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("clamscan flagged snitch.exe", "x", input_call_ids=[cid])
        assert r["verdict"] == "CHALLENGED" and r["verdict_basis"] == "partial_source"
        ent = [x for x in pull_env["log"]._entries if x.get("call_id") == r["_trudi_call_id"]][0]
        assert ent["verdict_basis"] == "partial_source"
        from tools._gates import challenge_sticky as cs
        from tools._gates._match import normalize_desc
        from types import SimpleNamespace
        ctx = SimpleNamespace(idx=pull_env["log"].index(), tier="LIKELY",
                              description="clamscan flagged snitch.exe")
        assert cs._evaluates_for(ctx, normalize_desc("clamscan flagged snitch.exe")) == []


class TestFieldCaps:
    def test_late_column_survives_long_early_column(self, tmp_path):
        # A RECmd-shaped row: long KeyPath first, the discriminating ValueData last.
        f = tmp_path / "ntuser.csv"
        f.write_text("HivePath,KeyPath,ValueName,ValueData\n"
                     f"/h/NTUSER.DAT,{'K' * 900},UEME_RUNPATH,C:\\Tools\\cain.exe (7)\n")
        r = OR.read_relevant_stats(str(f), ["cain"], 4000)
        assert "cain.exe (7)" in r.body
        assert "[field truncated]" in r.body
        assert r.clipped_rows == 1 and r.truncated and r.truncation_reason == "row_clip"

    def test_projection_caps_per_cell(self, tmp_path):
        f = tmp_path / "t.csv"
        f.write_text("A,B,C\n" + f"{'a' * 900},{'b' * 900},keep\n")
        r = OR.read_relevant_stats(str(f), ["keep"], 4000, columns=["B", "C"])
        line = r.body.splitlines()[1]
        assert line.endswith(",keep") and "[field truncated]" in line
        assert r.clipped_rows == 1

    def test_missing_columns_fall_back_to_line_scan_and_say_so(self, tmp_path):
        # F-3a: a projection miss is reported AND the rows still come back —
        # "0 rows" for a bad column list blinded the reviewer six times in
        # one run (mbox with From/Body columns, mft.csv with 'Content').
        f = tmp_path / "t.csv"
        f.write_text("A,B\n1,hit\n")
        r = OR.read_relevant_stats(str(f), ["hit"], 4000, columns=["Nope", "Zip"])
        assert "1,hit" in r.body and r.columns_ignored
        assert r.missing_columns == ["Nope", "Zip"] and r.available_columns == ["A", "B"]
        # Non-delimited source: columns ignored, lines returned.
        m = tmp_path / "Inbox.mbox"
        m.write_text("From: a@x\nSubject: hit here\n\nbody hit\n")
        r = OR.read_relevant_stats(str(m), ["hit"], 4000, columns=["From", "Body"])
        assert r.columns_ignored and r.matched_rows == 2 and "hit" in r.body

    def test_resolver_tells_reviewer_about_missing_columns(self, pull_env):
        cid = pull_env["cid"]
        block, recs = R._resolve_evidence_requests(
            [{"call_id": cid, "query": "4720", "columns": ["NoSuchColumn"]}], [cid], 4000)
        # F-3a: told about the bad column AND given the rows anyway.
        assert "ignored" in block and "not present; available" in block and "EventId" in block
        assert recs[0]["missing_columns"] == ["NoSuchColumn"] and recs[0]["columns_ignored"] is True
        assert recs[0]["rows_returned"] >= 1 and "defaultprinter" in block

    def test_fetch_record_carries_clip_stats(self, pull_env):
        cid = pull_env["cid"]   # 900-char Payload cells → per-field clip
        block, recs = R._resolve_evidence_requests(
            [{"call_id": cid, "query": "4799", "columns": []}], [cid], 4000)
        assert recs[0]["clipped_rows"] >= 1 and recs[0]["truncation_reason"] in ("row_clip", "budget")
        assert "shortened per field" in block

    def test_push_mode_forwards_columns(self, pull_env):
        txt, stats = OR._resolve_cited_output_stats(
            f"dotnet EvtxECmd.dll --csv {pull_env['csv'].parent}", ["4720"], 4000,
            columns=["EventId", "PayloadData1"])
        assert txt.splitlines()[1].replace(" ", "").startswith("EventId,PayloadData1")
        assert "xxxx" not in txt


# ── Phase E-03: RESULT block is parsed first, legacy blocks second ──────────

class TestResultBlockFirst:
    def test_evaluate_verdict_and_fields_from_result(self, pull_env):
        cid = pull_env["cid"]
        ans = ('1. EVIDENCE — the 4720 row.\nRESULT:\n{"verdict": "SUPPORTED", "rationale": "ok", '
               '"weaknesses": ["single log"], "discriminators_missing": [], '
               '"directives": {"priority_tools": ["ez.evtxecmd"]}}')
        http = MagicMock(side_effect=[_http(_REQ % cid), _http(ans)])
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("defaultprinter created 4720", "x", input_call_ids=[cid])
        assert r["verdict"] == "SUPPORTED" and r["parse_path"] == "result_json"
        assert r["weaknesses"] == ["single log"]
        assert r["directives"]["priority_tools"] == ["ez.evtxecmd"]
        assert "RESULT" not in r["conclusion"]
        ent = [e for e in pull_env["log"]._entries if e.get("call_id") == r["_trudi_call_id"]][0]
        assert ent["parse_path"] == "result_json" and ent["result_block"]["verdict"] == "SUPPORTED"
        assert ent["weaknesses"] == ["single log"]

    def test_evidence_request_inside_result(self, pull_env):
        cid = pull_env["cid"]
        req = ('pending\nRESULT:\n{"verdict": "UNCERTAIN", "evidence_request": '
               '[{"call_id": %d, "query": "4720 defaultprinter"}]}' % cid)
        http = MagicMock(side_effect=[_http(req), _http(_SUPPORTED)])
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("defaultprinter created 4720", "x", input_call_ids=[cid])
        assert http.call_count == 2 and "TargetUserName: defaultprinter" in _payload(http, 1)
        assert r["verdict"] == "SUPPORTED" and r["evidence_rounds"] == 1

    def test_legacy_blocks_still_parse_with_path_stamp(self, pull_env):
        cid = pull_env["cid"]
        http = MagicMock(side_effect=[_http(_REQ % cid), _http(_SUPPORTED + "\nDIRECTIVES:\n{\"priority_tools\": []}")])
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("defaultprinter created 4720", "x", input_call_ids=[cid])
        assert r["verdict"] == "SUPPORTED" and r["parse_path"] == "legacy_block"

    def test_confidence_and_cite_stamp_typed_fields(self, pull_env):
        # J-1: confidence_score is a deterministic tier lookup over the cited
        # calls' artifact classes — no model round-trip, no httpx call.
        with patch("httpx.post", MagicMock(side_effect=AssertionError("no model call"))):
            cs = R.reason_confidence_score("defaultprinter created", "4720 row",
                                           intended_tier="CONFIRMED",
                                           input_call_ids=[pull_env["cid"]],
                                           claim_kind="positive", category="persistence",
                                           act="account_creation", entities=["defaultprinter"])
        assert cs["success"] and cs["deterministic"] is True
        assert cs["tier"] == "LIKELY" and cs["score"] == 0.7        # one creation-event class
        assert cs["downgrade_reasons"] and "reach LIKELY" in cs["downgrade_reasons"][0]
        assert "CONFIRMED for act=account_creation" in cs["tier_path"]
        assert "event_logs_security" in cs["artifact_classes"]
        e = [x for x in pull_env["log"]._entries if x.get("call_id") == cs["_trudi_call_id"]][0]
        assert e["tier"] == "LIKELY" and e["score"] == 0.7 and e["deterministic"] is True
        assert e["claim"]["act"] == "account_creation"
        # no act → no contract → UNCONFIRMED, explained
        cs0 = R.reason_confidence_score("f", "e", input_call_ids=[pull_env["cid"]])
        assert cs0["tier"] == "UNCONFIRMED" and "no typed act" in cs0["rationale"]
        with patch("httpx.post", MagicMock(side_effect=[_http(
                'RESULT:\n{"verdict": "UNCITED_CLAIMS_PRESENT", "cited_claims": [], "uncited_claims": ["/x"], "rationale": "r"}')])):
            cc = R.reason_cite_check("f", "e")
        assert cc["verdict"] == "UNCITED_CLAIMS_PRESENT" and cc["uncited_claims"] == ["/x"]
        e = [x for x in pull_env["log"]._entries if x.get("call_id") == cc["_trudi_call_id"]][0]
        assert e["cite_verdict"] == "UNCITED_CLAIMS_PRESENT"

    def test_synthesize_blockers_from_result(self, pull_env):
        pull_env["log"].record_dair_call("Report", "", False, "", "", "stay", "")
        ans = ('LOGICAL GAPS — none.\nRESULT:\n{"blockers": ["AV finding uncorroborated"], '
               '"under_tiered": ["F2 deserves CONFIRMED"], "advisories": ["note"]}')
        with patch("httpx.post", MagicMock(side_effect=[_http(ans)])):
            r = R.reason_synthesize("F1\nF2")
        assert r["blockers"] == ["AV finding uncorroborated"]
        assert r["under_tiered"] == ["F2 deserves CONFIRMED"] and r["advisories"] == ["note"]
        e = [x for x in pull_env["log"]._entries if x.get("call_id") == r["_trudi_call_id"]][0]
        assert e["blockers"] == ["AV finding uncorroborated"] and e["under_tiered"]

    def test_hypothesize_sub_hypotheses_from_result(self, pull_env):
        ans = ('H1 — insider (Likelihood: high)\nH2 — takeover (Likelihood: medium)\n'
               'RESULT:\n{"hypotheses": [{"label": "H1", "title": "insider", "likelihood": "high", '
               '"principals": ["jdoe"]}, {"label": "H2", "title": "takeover", "likelihood": "medium", '
               '"principals": ["svc_backup"]}], "directives": {"priority_tools": ["ez.evtxecmd"]}}')
        with patch("httpx.post", MagicMock(side_effect=[_http(ans)])):
            r = R.reason_hypothesize("who did it", input_call_ids=[pull_env["cid"]])
        subs = r["sub_hypotheses"]
        assert [s["label"] for s in subs] == ["H1", "H2"]
        assert subs[1]["entities"] == ["svc_backup"] and subs[1]["likelihood_tier"] == "MEDIUM"
        assert all(s.get("declared") for s in subs)


class TestClaimOnReasonCalls:
    def test_evaluate_stamps_declared_claim(self, pull_env):
        cid = pull_env["cid"]
        http = MagicMock(side_effect=[_http(_REQ % cid), _http(_SUPPORTED)])
        with patch("httpx.post", http):
            r = R.reason_evaluate_finding("defaultprinter created 4720", "x", input_call_ids=[cid],
                                          claim_kind="positive", category="persistence",
                                          act="account_creation", principal="DefaultPrinter")
        assert r["claim"]["principal_norm"] == "defaultprinter"
        ent = [e for e in pull_env["log"]._entries if e.get("call_id") == r["_trudi_call_id"]][0]
        assert ent["claim"]["act"] == "account_creation" and ent["claim"]["claim_version"] == 2

    def test_no_claim_no_stamp(self, pull_env):
        with patch("httpx.post", MagicMock(side_effect=[_http(
                'RESULT:\n{"tier": "LIKELY", "score": 0.7, "rationale": "r", "downgrade_reasons": []}')])):
            cs = R.reason_confidence_score("f", "e")
        assert "claim" not in cs


class TestSchardtFollowUps:
    """Server-side defects surfaced by live local-model runs."""

    def test_non_evidence_cid_is_not_an_empty_complete_source(self, pull_env):
        # cid 111 in that run: the agent cited a reason_evidence_fetch record;
        # the resolver answered "0 rows (source COMPLETE)" and the reviewer read
        # absence → CHALLENGED. Now: not_evidence, never COMPLETE.
        log = pull_env["log"]
        log.record_dair_call("Analyze", "", False, "", "", "stay", "")
        dcid = log.record_disposition("tool", "ez.pecmd", "inapplicable")
        block, recs = R._resolve_evidence_requests(
            [{"call_id": dcid, "query": "irunin LANUSER", "columns": []}], [dcid], 4000)
        assert recs[0]["status"] == "not_evidence" and recs[0]["source_complete"] is False
        assert "not an evidence tool call" in block and "COMPLETE" not in block
        inv = R._render_evidence_inventory([dcid], [], ["lanuser"], log.index().by_call_id)[0]
        assert "not an evidence tool call" in inv
        pcid = log.record_tool_call("<py>:misc_record_disposition x", True, False, 0, 0,
                                    stdout_excerpt="ok")
        _, recs = R._resolve_evidence_requests(
            [{"call_id": pcid, "query": "ok", "columns": []}], [pcid], 4000)
        assert recs[0]["status"] == "not_evidence"

    def test_read_output_selflog_writes_sidecar(self, pull_env):
        # read.output kept only a 600-char head → "excerpt omits the
        # MAC/MachineID columns". The full body now goes to the sidecar.
        from tools.read_output import _selflog
        body = "col_a,col_b\n" + "\n".join(f"row{i},{'v' * 40}" for i in range(40))
        cid = _selflog("read.output --output /x/a.csv", body)
        e = pull_env["log"].index().by_call_id[cid]
        assert e["stdout_chars"] == len(body) and e.get("stdout_path")

    def test_fact_check_verdicts_and_tier_contract_line(self, pull_env):
        # J-1: the reviewer fact-checks (SUPPORTED / CONTRADICTED /
        # UNVERIFIABLE → SUPPORTED / CHALLENGED / UNCERTAIN); the message
        # carries the server-computed TIER CONTRACT, never an INTENDED TIER.
        ans = ('1. FACTS — 4720 row shows TargetUserName defaultprinter.\n'
               '7. VERDICT: CONTRADICTED\nRESULT:\n{"verdict": "CONTRADICTED", '
               '"contradictions": [{"claim": "created by PC User", "row": "SubjectUserName: SYSTEM"}], '
               '"unverifiable": [], "rationale": "r"}')
        with patch("httpx.post", MagicMock(return_value=_http(ans))):
            r = R.reason_evaluate_finding("defaultprinter created by PC User", "e",
                                          input_call_ids=[pull_env["cid"]], intended_tier="likely",
                                          claim_kind="positive", category="persistence",
                                          act="account_creation", entities=["defaultprinter"])
        assert r["verdict"] == "CHALLENGED" and r["fact_verdict"] == "CONTRADICTED"
        assert r["contradictions"][0]["row"] == "SubjectUserName: SYSTEM"
        assert r["tier_contract"]["tier_achievable"] == "LIKELY"
        e = pull_env["log"].index().by_call_id[r["_trudi_call_id"]]
        assert e["verdict"] == "CHALLENGED" and e["fact_verdict"] == "CONTRADICTED"
        assert e["contradictions"] and e["tier_contract"]["rule"] == "account_creation"
        um = e["inputs"]["user_message"]
        assert "TIER CONTRACT" in um and "reach LIKELY" in um
        assert "INTENDED TIER" not in um and "intended_tier" not in e
        # UNVERIFIABLE → UNCERTAIN, with the unverifiable facts stamped
        ans2 = 'VERDICT: UNVERIFIABLE\nRESULT:\n{"verdict": "UNVERIFIABLE", "unverifiable": ["source IP"]}'
        with patch("httpx.post", MagicMock(return_value=_http(ans2))):
            r2 = R.reason_evaluate_finding("rdp from 173.73.166.249", "e", input_call_ids=[pull_env["cid"]])
        assert r2["verdict"] == "UNCERTAIN" and r2["fact_verdict"] == "UNVERIFIABLE"
        assert r2["unverifiable"] == ["source IP"]

    def test_reformulation_gate_keys_on_typed_claim(self, pull_env):
        # Repeated re-wordings of one attribution claim went through
        # because the gate matched the description only.
        kw = dict(claim_kind="positive", category="identity", act="attribution",
                  entities=["Greg Schardt", "Mr. Evil"], input_call_ids=[pull_env["cid"]])
        ch = 'VERDICT: CHALLENGED — thin.\nRESULT:\n{"verdict": "CHALLENGED", "rationale": "r"}'
        with patch("httpx.post", MagicMock(side_effect=[_http(ch), _http(ch), _http(ch)])):
            R.reason_evaluate_finding("Schardt is Mr. Evil", "ev", **kw)
            R.reason_evaluate_finding("The laptop's owner operates the Mr. Evil account", "ev", **kw)
            r = R.reason_evaluate_finding("Documentary linkage ties the owner to the account", "ev", **kw)
        assert r["success"] is False and r["gate"] == "reformulation_depth_limit"


class TestVankoFollowUps:
    """Defects surfaced by live local-model runs on Phase F code."""

    def test_nul_in_csv_does_not_become_no_rows_complete(self, pull_env, tmp_path):
        # F-3b: RECmd SYSTEM csv holds NUL bytes in binary values; csv.reader
        # aborted after 783 of 5600 rows, the matched heap was dropped and the
        # resolver printed "no rows match … source COMPLETE".
        f = tmp_path / "system.csv"
        rows = ["HivePath,KeyPath,ValueName,ValueData"]
        rows += [f"S,K{i},V,blob\x00\x00" for i in range(900)]
        rows.append("S,USBSTOR,FriendlyName,SanDisk Cruzer Glide USB Device")
        f.write_text("\n".join(rows) + "\n")
        r = OR.read_relevant_stats(str(f), ["sandisk", "cruzer"], 4000, columns=["KeyPath", "ValueData"])
        assert r.matched_rows == 1 and "SanDisk" in r.body and r.scan_complete
        assert not r.columns_ignored          # projection survived the NULs
        log = pull_env["log"]
        cid = log.record_tool_call(f"read.output --output {f}", True, False, 0, 0,
                                   stdout_excerpt="x")
        block, recs = R._resolve_evidence_requests(
            [{"call_id": cid, "query": "SanDisk Cruzer", "columns": ["KeyPath", "ValueData"]}], [cid], 4000)
        assert recs[0]["rows_returned"] == 1 and "COMPLETE" not in block

    def test_projected_scan_error_is_never_reported_complete(self, pull_env, monkeypatch):
        # Any projected-scan abort must surface as partial_scan, not COMPLETE.
        f = pull_env["csv"]
        import csv as _csv

        def _boom(*a, **k):
            raise _csv.Error("simulated parser abort")
        monkeypatch.setattr(OR.csv, "reader", _boom) if hasattr(OR, "csv") else None
        r = OR._scan_csv_columns(str(f), ["nomatchterm"], 4000, ["EventId"]) if hasattr(OR, "csv") else None
        if r is not None:
            assert r.scan_error and r.columns_ignored and not r.scan_complete

    def test_reviewer_tier_opinion_is_ignored(self, pull_env):
        # J-1 replaces F-5/G-6: a `tier_supported` / "only supports LIKELY" in
        # the answer neither downgrades nor flips the verdict — the tier is
        # not the reviewer's to give. CHALLENGED stays CHALLENGED.
        ans = ('1. FACTS — rows seen.\n7. VERDICT: CHALLENGED — the evidence only '
               'supports LIKELY.\nRESULT:\n{"verdict": "CHALLENGED", "tier_supported": "LIKELY", '
               '"rationale": "circumstantial", "weaknesses": ["no session artifact"]}')
        cid = pull_env["cid"]
        with patch("httpx.post", MagicMock(side_effect=[_http(_REQ % cid), _http(ans)])):
            r = R.reason_evaluate_finding("Vanko exfiltrated the archive", "ev",
                                          input_call_ids=[cid], intended_tier="CONFIRMED",
                                          claim_kind="positive", category="exfil", act="egress",
                                          entities=["Vanko"], channel="removable")
        assert r["verdict"] == "CHALLENGED"
        for k in ("supported_tier", "tier_downgrade", "intended_tier", "supported_tier_source"):
            assert k not in r
        e = pull_env["log"].index().by_call_id[r["_trudi_call_id"]]
        assert e["verdict"] == "CHALLENGED" and "supported_tier" not in e and "tier_downgrade" not in e
        assert not [x for x in pull_env["log"]._entries
                    if x.get("type") == "self_correction" and x.get("trigger") == "evaluate_tier_downgrade"]
        assert not hasattr(R, "_prose_supported_tier")

    def test_sidecar_not_rescanned_after_file_rows(self, pull_env, tmp_path):
        # A read_output call's sidecar duplicated the CSV
        # rows and its line-scan flags clobbered columns_ignored/source_kind.
        f = tmp_path / "mft.csv"
        f.write_text("EntryNumber,FileName,ParentPath\n1,vacation photos.7z,.\\Users\\PC User\\Downloads\n2,other,.\\x\n")
        body = "EntryNumber,FileName,ParentPath\n1,vacation photos.7z,.\\Users\\PC User\\Downloads\n"
        log = pull_env["log"]
        cid = log.record_tool_call(f"read.output --output {f}", True, False, 0, 0,
                                   stdout_excerpt=body[:600], stdout_full=body + "x" * 700)
        block, recs = R._resolve_evidence_requests(
            [{"call_id": cid, "query": "vacation photos.7z", "columns": ["EntryNumber", "FileName"]}], [cid], 4000)
        assert recs[0]["rows_returned"] == 1 and recs[0]["source_kind"] == "file"
        assert not recs[0].get("columns_ignored") and recs[0]["missing_columns"] == []

    def test_request_is_still_honoured_after_the_push(self, pull_env):
        cid = pull_env["cid"]
        with patch("httpx.post", MagicMock(side_effect=[_http(_REQ % cid), _http(_SUPPORTED)])) as http:
            r = R.reason_evaluate_finding("f2", "e", input_call_ids=[cid], entities=["defaultprinter"],
                                          claim_kind="positive", category="persistence", act="account_creation")
        assert http.call_count == 2 and r["evidence_rounds"] == 1
        assert not r["evidence_fetches"][0].get("auto_fetch")
        assert "EVIDENCE_REQUEST RESULTS" in _payload(http, 1)

    def test_fk_interpretation_block_reaches_the_reviewer(self, pull_env, monkeypatch):
        # H-7: the cited EvtxECmd run maps to the event_logs_security sheet;
        # its does_not_prove / corroborate_with lines reach the reviewer and
        # the sheet stems are stamped on the reason_call.
        import tools.reasoning as R
        cid = pull_env["cid"]
        with patch("httpx.post", MagicMock(side_effect=[_http(_REQ % cid), _http(_SUPPORTED)])) as http:
            r = R.reason_evaluate_finding("defaultprinter created (4720)", "ev", input_call_ids=[cid],
                                          claim_kind="positive", category="persistence", act="execution",
                                          entities=["defaultprinter"], intended_tier="LIKELY")
        p = _payload(http, 0)
        assert "EVIDENCE INTERPRETATION" in p and "[event_logs_security]" in p and "does NOT prove" in p
        assert "corroborate execution with" in p
        assert r["fk_sheets"] == ["event_logs_security"]
        e = pull_env["log"].index().by_call_id[r["_trudi_call_id"]]
        assert e["fk_sheets"] == ["event_logs_security"]
        monkeypatch.setattr(R, "REASON_FK", False)
        with patch("httpx.post", MagicMock(side_effect=[_http(_REQ % cid), _http(_SUPPORTED)])) as http:
            R.reason_evaluate_finding("defaultprinter created (4720) again", "ev", input_call_ids=[cid])
        assert "EVIDENCE INTERPRETATION" not in _payload(http, 0)

    def test_read_over_agent_authored_file_is_not_evidence(self, pull_env, tmp_path):
        # Laundering path: Write → read.output → cited as evidence.
        log = pull_env["log"]
        f = tmp_path / "exports" / "titan_thread.txt"
        f.parent.mkdir(parents=True)
        f.write_text("FROM vladimir.bulgakov@titan-biotech.example — copies of all research\n")
        log.record_tool_call(f"write {f}", True, False, 0, 0, source="claude_code_write") \
            if "source" in log.record_tool_call.__code__.co_varnames else None
        w = [e for e in log._entries if (e.get("cmd") or "").startswith("write ")]
        if not w:   # record_tool_call without a source kwarg: stamp it directly
            cid_w = log.record_tool_call(f"write {f}", True, False, 0, 0)
            for e in log._entries:
                if e.get("call_id") == cid_w:
                    e["source"] = "claude_code_write"
            log._index_version += 1
        cid_r = log.record_tool_call(f"read.output --output {f}", True, False, 0, 0,
                                     stdout_excerpt="bulgakov")
        block, recs = R._resolve_evidence_requests(
            [{"call_id": cid_r, "query": "bulgakov", "columns": []}], [cid_r], 4000)
        assert recs[0]["status"] == "not_evidence" and "AGENT-AUTHORED" in block
        inv = R._render_evidence_inventory([cid_r], [], ["bulgakov"], log.index().by_call_id)[0]
        assert "AGENT-AUTHORED" in inv

    def test_reviewer_conclusion_is_not_a_row_source(self, pull_env):
        # Rows requested from evaluate conclusions →
        # "0 rows, COMPLETE" → blocker "findings lack primary evidence".
        log = pull_env["log"]
        rc = log.record_reason_call("reason_evaluate_finding", True,
                                    "1. EVIDENCE SUPPORT — 4624 rows seen.\nVERDICT: SUPPORTED", {})
        block, recs = R._resolve_evidence_requests(
            [{"call_id": rc, "query": "4624 4720 security", "columns": []}], [rc], 4000)
        assert recs[0]["status"] == "not_evidence" and "reviewer conclusion" in block
        assert "COMPLETE" not in block

    def test_synthesize_citable_ids_include_finding_evidence(self, pull_env):
        from tools.reasoning import _synthesize_citable_ids
        log = pull_env["log"]
        cid = pull_env["cid"]
        log.record_dair_call("Report", "", False, "", "", "stay", "")
        f = log.record_finding("defaultprinter created", "LIKELY", "ez.evtxecmd", linked_call_id=cid,
                               claim={"kind": "positive", "category": "persistence", "act": "account_creation",
                                      "session_binding_call_ids": [cid], "transfer_call_ids": [77]})
        ids = _synthesize_citable_ids(log._entries, [999])
        assert ids[0] == 999 and f in ids and cid in ids and 77 in ids

    def test_evaluate_accepts_actor_kwargs(self, pull_env):
        # actor_kind on evaluate was an
        # "unexpected keyword argument"; the agent passes its record claim.
        cid = pull_env["cid"]
        with patch("httpx.post", MagicMock(side_effect=[_http(_REQ % cid), _http(_SUPPORTED)])):
            r = R.reason_evaluate_finding("defaultprinter operated remotely", "ev", input_call_ids=[cid],
                                          claim_kind="positive", category="identity", act="attribution",
                                          principal="defaultprinter", actor_kind="unknown", actor="")
        assert r["claim"]["actor_kind"] == "unknown" and r["claim"]["principal_norm"] == "defaultprinter"

    def test_empty_output_stamps_stdout_chars_zero(self, pull_env):
        cid = pull_env["log"].record_tool_call("strings -a -el x", True, False, 0, 0,
                                               stdout_excerpt="", stdout_full="")
        e = pull_env["log"].index().by_call_id[cid]
        assert e["stdout_chars"] == 0 and e["stdout_lines"] == 0
