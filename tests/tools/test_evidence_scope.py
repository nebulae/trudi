"""Tests for fix (a): the evidence-scope header prepended to reviewer reason.*
calls. It states what evidence was COLLECTED in the investigation (provable
from tool_call trace entries) and what was not — never asserting ontological
absence — so the reviewer stops demanding artifact types nobody gathered.
"""
import pytest
from unittest.mock import patch

import tools.reasoning as R


@pytest.fixture
def trace(tmp_path):
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("TEST-SCOPE", str(tmp_path / "trace.json"))
    return l


def _scope(trace):
    with patch("core.execution_log.log", trace), \
         patch.object(R, "COMPAT_EVIDENCE_SCOPE", True):
        return R._evidence_scope()


class TestEvidenceScope:
    def test_empty_trace_is_silent(self, trace):
        assert _scope(trace) == ""

    def test_disk_only_marks_memory_and_pcap_not_collected(self, trace):
        trace.record_tool_call("ewf.mount_full_image /ev/surface.E01", True, False, 0, 0)
        trace.record_tool_call("ez.mftecmd -f /mnt/$MFT", True, False, 0, 0)
        s = _scope(trace)
        assert "disk image" in s
        assert "NOT COLLECTED" in s
        assert "memory image" in s and "network capture" in s
        # never asserts something was collected that wasn't
        assert "disk image" in s.split("NOT COLLECTED")[0]

    def test_memory_case_does_not_mark_memory_absent(self, trace):
        trace.record_tool_call("vol_pslist -f /ev/mem.raw", True, False, 0, 0)
        s = _scope(trace)
        assert "memory image" in s.split("NOT COLLECTED")[0]  # present, not absent
        assert "network capture" in s  # pcap still not collected

    def test_pcap_case(self, trace):
        trace.record_tool_call("net.tcpdump_read /ev/capture.pcap", True, False, 0, 0)
        s = _scope(trace)
        assert "network capture" in s.split("NOT COLLECTED")[0]
        assert "memory image" in s and "disk image" in s  # absent

    def test_failed_tool_call_does_not_count_as_collected(self, trace):
        # A vol call that errored must not make memory look collected.
        trace.record_tool_call("ewf.mount_full_image /ev/d.E01", True, False, 0, 0)
        trace.record_tool_call("vol_pslist -f /ev/mem.raw", False, False, 1, 0)
        s = _scope(trace)
        assert "memory image" in s.split("NOT COLLECTED")[1]  # in the absent clause

    def test_triage_collection_detected(self, trace):
        trace.record_tool_call("misc.regripper /ev/host.CYLR/.../SYSTEM", True, False, 0, 0)
        assert "triage collection" in _scope(trace)

    def test_disabled_by_env(self, trace):
        trace.record_tool_call("ewf.mount_full_image /ev/d.E01", True, False, 0, 0)
        with patch("core.execution_log.log", trace), \
             patch.object(R, "COMPAT_EVIDENCE_SCOPE", False):
            assert R._evidence_scope() == ""

    def test_no_active_log_is_silent(self):
        # Fail-open when no trace is configured.
        with patch.object(R, "COMPAT_EVIDENCE_SCOPE", True):
            from core.execution_log import ExecutionLog
            fresh = ExecutionLog()  # never .configure()d → _path is None
            with patch("core.execution_log.log", fresh):
                assert R._evidence_scope() == ""


class TestScopeInjection:
    def test_with_scope_prepends_for_reviewer_tools(self, trace):
        trace.record_tool_call("ewf.mount_full_image /ev/d.E01", True, False, 0, 0)
        with patch("core.execution_log.log", trace), \
             patch.object(R, "COMPAT_EVIDENCE_SCOPE", True):
            out = R._with_scope("FINDING:\nx", "reason_evaluate_finding")
        assert out.startswith("EVIDENCE COLLECTED THIS INVESTIGATION")
        assert out.rstrip().endswith("FINDING:\nx")

    def test_with_scope_skips_plan_and_audit(self, trace):
        trace.record_tool_call("ewf.mount_full_image /ev/d.E01", True, False, 0, 0)
        with patch("core.execution_log.log", trace), \
             patch.object(R, "COMPAT_EVIDENCE_SCOPE", True):
            assert R._with_scope("CASE:\nx", "reason_plan") == "CASE:\nx"
            assert R._with_scope("N", "reason_audit_findings") == "N"

    def test_with_scope_noop_when_silent(self, trace):
        # No evidence collected yet → user message unchanged.
        with patch("core.execution_log.log", trace), \
             patch.object(R, "COMPAT_EVIDENCE_SCOPE", True):
            assert R._with_scope("FINDING:\nx", "reason_evaluate_finding") == "FINDING:\nx"

    def test_reaches_the_request_payload(self, trace):
        """End-to-end: the scope line lands in the httpx JSON for a compat call."""
        import io
        from unittest.mock import MagicMock
        trace.record_tool_call("ewf.mount_full_image /ev/d.E01", True, False, 0, 0)
        resp = MagicMock(); resp.raise_for_status = MagicMock()
        resp.json.return_value = {"choices": [{"finish_reason": "stop",
                                  "message": {"content": "VERDICT: SUPPORTED"}}],
                                  "usage": {"prompt_tokens": 5, "completion_tokens": 5}}
        http = MagicMock(return_value=resp)
        with patch("core.execution_log.log", trace), \
             patch.object(R, "COMPAT_EVIDENCE_SCOPE", True), \
             patch.object(R, "REASON_BACKEND", "openai-compat"), \
             patch.object(R, "REASON_URL", "http://x.test"), \
             patch.object(R, "REASON_MODEL", "m"), \
             patch.object(R, "COMPAT_NO_THINK_TOOLS", frozenset()), \
             patch("httpx.post", http):
            R.reason_evaluate_finding("finding text", "evidence text", input_call_ids=[1])
        sent = http.call_args[1]["json"]["messages"][1]["content"]
        assert "EVIDENCE COLLECTED THIS INVESTIGATION" in sent
        assert "network capture" in sent
