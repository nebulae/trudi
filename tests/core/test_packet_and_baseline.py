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

    def test_baseline_returns_self_logged_cid(self, tmp_path):
        """A self-logging tool that rebuilt its result dict (dropping the id)
        still gets its own tool_call id echoed — never another tool's."""
        from unittest.mock import patch
        from core.execution_log import ExecutionLog, current_mcp_tool
        from core.middleware import _trace_success_baseline, _stamp_call_id
        log = ExecutionLog()
        log.configure("BASELINE", str(tmp_path / "trace.json"), save_session=False)
        before = len(log._entries)
        tok = current_mcp_tool.set("strings_grep")
        try:
            own = log.record_tool_call(cmd="strings -a x", success=True, truncated=False,
                                       retries=0, exit_code=0, stderr="")
        finally:
            current_mcp_tool.reset(tok)
        with patch("core.execution_log.log", log):
            cid = _trace_success_baseline("strings_grep", 0.1, before, {"success": True})
            other = _trace_success_baseline("tsk_fls", 0.1, before, {"success": True})
        assert cid == own and other == 0
        assert _stamp_call_id({"success": True}, cid)["_trudi_call_id"] == own
        assert len(log._entries) == before + 1      # no duplicate baseline entry
