"""Tests for tools/verdict.py — heading-tolerant evaluate verdict parsing.

Regression: Qwen3.6-35B-A3B rendered the verdict as a numbered heading
("7. VERDICT\\nSUPPORTED. …"); the old `VERDICT:\\s*(…)` regex missed it, so
the SUPPORTED verdict never reached the CONFIRMED gate.
"""
import pytest
from unittest.mock import patch, MagicMock

from tools.verdict import parse_verdict, EVALUATE_VERDICT_RE


@pytest.mark.parametrize("text,expected", [
    ("VERDICT: SUPPORTED — rationale", "SUPPORTED"),
    ("VERDICT: CHALLENGED. The UA is not an identity.", "CHALLENGED"),
    ("VERDICT:UNCERTAIN", "UNCERTAIN"),
    ("**VERDICT:** CHALLENGED", "CHALLENGED"),
    ("**VERDICT**: supported", "SUPPORTED"),
    ("7. VERDICT\nSUPPORTED. The finding is fully substantiated.", "SUPPORTED"),
    ("7. VERDICT\n\nCHALLENGED — cookie jar is not exclusive", "CHALLENGED"),
    ("VERDICT — UNCERTAIN", "UNCERTAIN"),
    ("VERDICT - SUPPORTED", "SUPPORTED"),
    ("Final verdict:\n**SUPPORTED**", "SUPPORTED"),
    # D1: tolerant renderings that previously read as UNPARSEABLE
    ("The verdict is SUPPORTED.", "SUPPORTED"),
    ("Final verdict of the review: CONTRADICTED", "CHALLENGED"),
    ("...my analysis.\nSUPPORTED — every fact present in the cited rows.", "SUPPORTED"),
    ("1. SUPPORTED", "SUPPORTED"),
    ("The finding is not SUPPORTED, so:\nCONTRADICTED", "CHALLENGED"),
    # D1: guards — a negated or mid-sentence mention is not a verdict
    ("My verdict is that this is not SUPPORTED", ""),
    ("the account was SUPPORTED by a service", ""),
    ("analysis only, no verdict section", ""),
    ("", ""),
    (None, ""),
])
def test_parse_verdict_forms(text, expected):
    assert parse_verdict(text) == expected


def test_first_verdict_wins():
    text = "VERDICT: CHALLENGED\n\nEarlier draft said VERDICT: SUPPORTED"
    assert parse_verdict(text) == "CHALLENGED"


def test_regex_is_case_insensitive_and_word_bounded():
    assert EVALUATE_VERDICT_RE.search("verdict: Supported").group(1).upper() == "SUPPORTED"
    assert parse_verdict("VERDICT: SUPPORTEDLY wrong") == ""  # \b guard


class TestEvaluateFindingUsesSharedParser:
    """reason_evaluate_finding must surface the verdict and trigger the
    CHALLENGED self-correction for the heading form too."""

    def _http(self, content):
        m = MagicMock(); m.raise_for_status = MagicMock()
        m.json.return_value = {"choices": [{"finish_reason": "stop",
                                            "message": {"content": content}}],
                               "usage": {"prompt_tokens": 10, "completion_tokens": 20}}
        return MagicMock(return_value=m)

    @pytest.fixture(autouse=True)
    def _compat(self):
        import tools.reasoning as R
        with patch.object(R, "REASON_BACKEND", "openai-compat"), \
             patch.object(R, "REASON_URL", "http://x.test"), \
             patch.object(R, "REASON_MODEL", "m"), \
             patch.object(R, "COMPAT_NO_THINK_TOOLS", frozenset()):
            yield

    def test_heading_supported_surfaces_verdict(self):
        from tools.reasoning import reason_evaluate_finding
        with patch("httpx.post", self._http("1. EVIDENCE SUPPORT\nok\n\n7. VERDICT\nSUPPORTED. solid.")):
            r = reason_evaluate_finding("finding", "evidence")
        assert r["success"] is True
        assert r["verdict"] == "SUPPORTED"

    def test_heading_challenged_triggers_self_correction(self):
        from tools.reasoning import reason_evaluate_finding
        from core.execution_log import log
        with patch("httpx.post", self._http("7. VERDICT\nCHALLENGED — UA is not an identity.")), \
             patch.object(log, "record_self_correction", return_value=9) as sc:
            r = reason_evaluate_finding("finding", "evidence")
        assert r["verdict"] == "CHALLENGED"
        sc.assert_called_once()

    def test_verdict_after_evidence_audit_block_is_recovered(self):
        """Observed on Qwen3.6-35B-A3B: EVIDENCE_AUDIT placed mid-answer, then
        sections 6-7. The legacy strip removed everything after the marker and
        lost the verdict (gate refused with 'VERDICT: unparseable')."""
        from tools.reasoning import reason_evaluate_finding
        content = (
            "1. EVIDENCE SUPPORT\nok\n\n"
            "5. FACT-CHECK\n- YARA limitation correctly noted in the finding.\n\n"
            "EVIDENCE_AUDIT:\n"
            '[{"claim": "c1", "tool": "net.tcpdump_read", "command": "x", '
            '"raw_output_excerpt": "y", "artifact_path": "z", '
            '"timestamp_source": "pcap", "proof_rationale": "r", '
            '"benign_alternatives": "NOT PROVIDED"}]\n\n'
            "6. ADDITIONAL INVESTIGATION\nnone\n\n"
            "7. VERDICT\nSUPPORTED. Fully substantiated.\n\n"
            'DIRECTIVES:\n{"priority_tools": ["net.tcpdump_read"]}'
        )
        with patch("httpx.post", self._http(content)):
            r = reason_evaluate_finding("finding", "evidence")
        assert r["verdict"] == "SUPPORTED"
        assert "_raw" not in r
        assert len(r["evidence_audit"]) == 1
        # sections after the audit block survive in the conclusion
        assert "6. ADDITIONAL INVESTIGATION" in r["conclusion"]
        assert "7. VERDICT" in r["conclusion"]
        assert "EVIDENCE_AUDIT" not in r["conclusion"]
        assert "DIRECTIVES" not in r["conclusion"]
        assert r["directives"]["priority_tools"] == ["net.tcpdump_read"]

    def test_verdict_only_after_directives_is_patched_into_conclusion(self):
        from tools.reasoning import reason_evaluate_finding
        content = ('analysis\n\nDIRECTIVES:\n{"priority_tools": []}\n\n'
                   "VERDICT: CHALLENGED — overreach")
        with patch("httpx.post", self._http(content)):
            r = reason_evaluate_finding("finding", "evidence")
        assert r["verdict"] == "CHALLENGED"
        assert r["conclusion"].rstrip().endswith("VERDICT: CHALLENGED")

    def test_raw_not_leaked_by_other_tools(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", self._http("Hypothesis.\nDIRECTIVES:\n{\"priority_tools\": []}")):
            r = reason_hypothesize("obs")
        assert "_raw" not in r

    def test_gate_accepts_heading_form(self):
        from tools._gates import confirmed_requires_supported_evaluate as g
        assert g.parse_verdict("7. VERDICT\nSUPPORTED.") == "SUPPORTED"
