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
