"""K-4: a zero-match answer must disclose what the OTHER calls over the same
artifact hold. Symmetric — a non-empty sibling prevents a false absence; empty
siblings strengthen absence. (Observed: an empty UTF-16 `strings -el` variant
was read as "0 matches, source COMPLETE" while its `strings -a` sibling held
the decisive transfer line.)"""
from unittest.mock import patch

from core.execution_log import ExecutionLog
from tools._output_reader import _cmd_input_paths, sibling_match_counts


def _log(tmp_path):
    l = ExecutionLog()
    l.configure("SIB", str(tmp_path / "trace.json"), save_session=False)
    return l


class TestInputPaths:
    def test_input_paths_exclude_outputs_and_binaries(self):
        assert _cmd_input_paths(
            "dotnet /opt/zimmermantools/MFTECmd.dll -f /mnt/vanko/$MFT --csv /case/exports/mft"
        ) == {"/mnt/vanko/$MFT"}
        assert _cmd_input_paths("strings -a -n 8 /mnt/vanko/Users/d/transfers.log") == \
            {"/mnt/vanko/Users/d/transfers.log"}
        assert _cmd_input_paths("") == set()


class TestSiblingCounts:
    def test_nonempty_sibling_surfaces_its_rows(self, tmp_path):
        l = _log(tmp_path)
        good = l.record_tool_call("strings -a -n 8 /mnt/x/transfers.log", True, False, 0, 0,
                                  stdout_excerpt="18/06/2016 Download temp.zip by defaultprinter")
        empty = l.record_tool_call("strings -a -el -n 8 /mnt/x/transfers.log", True, False, 0, 0,
                                   stdout_excerpt="")
        by = l.index().by_call_id
        sibs = sibling_match_counts(by, by[empty], ["temp.zip"])
        assert sibs == [{"call_id": good, "cmd": "strings -a -n 8 /mnt/x/transfers.log",
                         "rows": 1}]
        # symmetric: from the good call's view, the empty sibling reports 0
        sibs2 = sibling_match_counts(by, by[good], ["temp.zip"])
        assert sibs2[0]["call_id"] == empty and sibs2[0]["rows"] == 0

    def test_unrelated_artifacts_are_not_siblings(self, tmp_path):
        l = _log(tmp_path)
        l.record_tool_call("strings -a /mnt/x/other.log", True, False, 0, 0, stdout_excerpt="x")
        e = l.record_tool_call("strings -a /mnt/x/transfers.log", True, False, 0, 0, stdout_excerpt="")
        by = l.index().by_call_id
        assert sibling_match_counts(by, by[e], ["temp.zip"]) == []


class TestResolverDisclosure:
    def test_zero_match_answer_names_the_nonempty_sibling(self, tmp_path):
        import tools.reasoning as R
        l = _log(tmp_path)
        good = l.record_tool_call("strings -a -n 8 /mnt/x/transfers.log", True, False, 0, 0,
                                  stdout_excerpt="18/06/2016 Download temp.zip by defaultprinter")
        empty = l.record_tool_call("strings -a -el -n 8 /mnt/x/transfers.log", True, False, 0, 0,
                                   stdout_excerpt="")
        with patch("core.execution_log.log", l):
            block, recs = R._resolve_evidence_requests(
                [{"call_id": empty, "query": "temp.zip", "columns": []}], [empty, good], 4000)
        assert "no rows match" in block
        assert f"call {good} → 1 matching" in block
        assert recs[0]["siblings"][0]["call_id"] == good
        # ...and when every sibling is empty too, the absence is strengthened
        e2 = l.record_tool_call("strings -el /mnt/x/ftpd.ini", True, False, 0, 0, stdout_excerpt="")
        e3 = l.record_tool_call("strings -a /mnt/x/ftpd.ini", True, False, 0, 0, stdout_excerpt="nothing here")
        with patch("core.execution_log.log", l):
            block2, recs2 = R._resolve_evidence_requests(
                [{"call_id": e2, "query": "temp.zip", "columns": []}], [e2, e3], 4000)
        assert "every sibling also matches 0" in block2
