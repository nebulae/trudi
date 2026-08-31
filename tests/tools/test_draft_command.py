"""reason.draft_command — task → candidate commands (never executes)."""
from unittest.mock import patch

import tools.reasoning as R


def _call(result):
    with patch.object(R, "_ask", return_value=result) as ask:
        fn = getattr(R.reason_draft_command, "fn", R.reason_draft_command)
        out = fn("pull MFT entry 12345 from evidence.csv into another csv",
                 "read.output — query produced CSV/JSON\n  params: path*, where")
        return out, ask


class TestDraftCommand:
    def test_result_block_candidates_parsed(self):
        out, ask = _call({"success": True, "conclusion": "",
                          "result_block": {"candidates": [
                              {"command": "read.output path=analysis/evidence.csv "
                                          "where=EntryNumber=12345",
                               "why": "structured filter"},
                              {"command": "  strings.grep x=1  ", "why": ""},
                              {"not_a": "dict"},
                              {"command": ""},
                          ]}})
        assert [c["command"] for c in out["candidates"]] == [
            "read.output path=analysis/evidence.csv where=EntryNumber=12345",
            "strings.grep x=1"]
        system, user = ask.call_args[0][0], ask.call_args[0][1]
        assert "TASK:" in user and "AVAILABLE TOOLS:" in user
        assert "never" in system.lower()  # never invent tools/params

    def test_no_result_block_yields_empty(self):
        out, _ = _call({"success": True, "conclusion": "use read.output maybe",
                        "result_block": None})
        assert out["candidates"] == []

    def test_candidates_capped_at_five(self):
        cands = [{"command": f"a.b x={i}", "why": ""} for i in range(9)]
        out, _ = _call({"success": True, "result_block": {"candidates": cands}})
        assert len(out["candidates"]) == 5


class TestAdvise:
    def _call(self, ask_result):
        with patch.object(R, "_ask", return_value=ask_result) as ask:
            fn = getattr(R.reason_advise, "fn", R.reason_advise)
            out = fn("what should I do next?",
                     "phase: Triage\nrecent results: 1 pcap listed")
            return out, ask

    def test_advice_from_result_block(self):
        out, ask = self._call({"success": True,
                               "conclusion": "prose fallback",
                               "result_block": {"advice": "Inventory HTTP sessions next."},
                               "directives": {"priority_tools": ["net.http_session_inventory"]}})
        assert out["advice"] == "Inventory HTTP sessions next."
        assert out["directives"]["priority_tools"] == ["net.http_session_inventory"]
        user = ask.call_args[0][1]
        assert "QUESTION:" in user and "SITUATION:" in user

    def test_falls_back_to_conclusion(self):
        out, _ = self._call({"success": True, "conclusion": "Check the DNS traffic.",
                             "result_block": None})
        assert out["advice"] == "Check the DNS traffic."


class TestSalvage:
    def test_commands_salvaged_from_prose(self):
        prose = (
            "1) Extract HTTP traffic from the PCAP\n"
            "net.tcpdump_extract_http pcap_file=/e/n.pcap output_path=analysis/http.txt\n"
            "\nThis gives you the raw pairs. Then:\n"
            "- `net.ngrep_search pcap_path=/e/n.pcap pattern=Cookie`\n"
            "You could also try net.tcpdump_read inline in a sentence.\n")
        out, _ = _call({"success": True, "conclusion": prose,
                        "result_block": None})
        assert [c["command"] for c in out["candidates"]] == [
            "net.tcpdump_extract_http pcap_file=/e/n.pcap output_path=analysis/http.txt",
            "net.ngrep_search pcap_path=/e/n.pcap pattern=Cookie"]
        assert all(c["why"] == "salvaged from prose" for c in out["candidates"])

    def test_result_block_wins_over_salvage(self):
        out, _ = _call({"success": True,
                        "conclusion": "tsk.fls image=/x other=1\n",
                        "result_block": {"candidates": [
                            {"command": "read.output path=x.csv", "why": "w"}]}})
        assert [c["command"] for c in out["candidates"]] == [
            "read.output path=x.csv"]


class TestExtractCase:
    def _call(self, ask_result):
        with patch.object(R, "_ask", return_value=ask_result) as ask:
            fn = getattr(R.reason_extract_case, "fn", R.reason_extract_case)
            return fn("# case doc\nsuspects: Amy Smith"), ask

    def test_result_block_fields(self):
        out, _ = self._call({"success": True, "result_block": {
            "case_id": "X-1", "case_question": "who?", "evidence_root": "/e",
            "roster": ["Amy Smith", 2], "scenario_summary": "s"}})
        assert out["case_question"] == "who?" and out["case_id"] == "X-1"
        assert out["roster"] == ["Amy Smith", "2"]

    def test_json_salvaged_from_prose(self):
        prose = ('Here is what I found:\n```json\n'
                 '{"case_question": "who sent it?", "roster": ["Amy Smith"],'
                 ' "case_id": "N", "evidence_root": "", '
                 '"scenario_summary": "x"}\n```\nHope that helps.')
        out, _ = self._call({"success": True, "conclusion": prose,
                             "result_block": None})
        assert out["case_question"] == "who sent it?"
        assert out["roster"] == ["Amy Smith"]

    def test_true_whiff_stays_empty(self):
        out, _ = self._call({"success": True, "conclusion": "I cannot say.",
                             "result_block": None})
        assert out["case_question"] == "" and out["roster"] == []
