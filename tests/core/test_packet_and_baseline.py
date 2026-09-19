"""Regressions from the VANKO-2016-DEEPSEEK41 run (2026-09-19)."""
from unittest.mock import MagicMock


class TestPacketSelection:
    def test_csv_with_nul_bytes_is_searchable(self):
        from core.evidence_packets import _selection
        raw = b"Name,Path\nNinaResearch.zip,C:\\\\Users\\x00\\x00\nother,x\n"
        out = _selection(raw, ["ninaresearch"], {}, 10000, "/tmp/x.csv")
        assert out["columns"] == ["Name", "Path"]
        assert out["matched_lines"] == 1


class TestPyToolBaseline:
    def test_stamp_call_id_on_dict_result(self):
        from core.middleware import _stamp_call_id
        assert _stamp_call_id({"success": True}, 42)["_trudi_call_id"] == 42
        assert _stamp_call_id({"_trudi_call_id": 7}, 42)["_trudi_call_id"] == 7
        assert _stamp_call_id({"a": 1}, 0) == {"a": 1}

    def test_stamp_call_id_on_tool_result(self):
        from core.middleware import _stamp_call_id
        res = MagicMock()
        res.structured_content = {"matches": ["a"]}
        _stamp_call_id(res, 9)
        update = res.model_copy.call_args[1]["update"]
        assert update["structured_content"]["_trudi_call_id"] == 9

    def test_baseline_returns_cid_and_retains_output(self, tmp_path):
        from unittest.mock import patch
        from core.execution_log import ExecutionLog
        from core.middleware import _trace_success_baseline
        log = ExecutionLog()
        log.configure("BASELINE", str(tmp_path / "trace.json"), save_session=False)
        before = len(log._entries)
        with patch("core.execution_log.log", log):
            cid = _trace_success_baseline("yara_scan_strings", 0.1, before,
                                          {"success": True, "matches": ["NinaResearch"]})
        entry = [e for e in log._entries if e.get("call_id") == cid][0]
        assert cid and entry["cmd"] == "<py>:yara_scan_strings"
        assert "NinaResearch" in entry.get("stdout_excerpt", "")
