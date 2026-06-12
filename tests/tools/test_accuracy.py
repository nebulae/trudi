"""Tests for tools/accuracy.py — ground-truth comparison."""
import json
import pytest
from unittest.mock import patch
from core.execution_log import ExecutionLog


def _gt_file(tmp_path, items, case_id="TEST", negatives=None):
    """Write a ground-truth JSON file and return its path."""
    p = tmp_path / "ground_truth.json"
    p.write_text(json.dumps({
        "case_id": case_id,
        "expected_findings": items,
        "negative_assertions": negatives or [],
    }))
    return str(p)


def _configure_log(tmp_path, findings):
    """Configure a fresh ExecutionLog with a dair_call seed and given findings."""
    l = ExecutionLog()
    l.configure("TEST", str(tmp_path / "trace.json"))
    l.record_dair_call("Triage", "", False, "", "", "stay", "")
    for desc, conf in findings:
        l.record_finding(desc, conf, "test")
    return l


class TestAccuracyCompareBasics:
    def test_perfect_match(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "STUN.exe at C:\\Windows\\Temp",
             "confidence_min": "CONFIRMED", "category": "implant"},
        ])
        l = _configure_log(tmp_path, [
            ("STUN.exe at C:\\Windows\\Temp confirmed", "CONFIRMED"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["success"] is True
        assert r["summary"]["true_positive_count"] == 1
        assert r["summary"]["false_positive_count"] == 0
        assert r["summary"]["false_negative_count"] == 0
        assert r["summary"]["precision"] == 1.0
        assert r["summary"]["recall"] == 1.0
        assert r["summary"]["f1"] == 1.0

    def test_missing_finding_counts_false_negative(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "STUN.exe at C:\\Windows\\Temp",
             "confidence_min": "CONFIRMED"},
            {"id": "F2", "description": "Mnemosyne.sys kernel rootkit",
             "confidence_min": "CONFIRMED"},
        ])
        l = _configure_log(tmp_path, [
            ("STUN.exe at C:\\Windows\\Temp", "CONFIRMED"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["false_negative_count"] == 1
        assert any(fn["id"] == "F2" for fn in r["false_negatives"])

    def test_extra_finding_counts_false_positive(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "STUN.exe at Windows Temp",
             "confidence_min": "CONFIRMED"},
        ])
        l = _configure_log(tmp_path, [
            ("STUN.exe at Windows Temp", "CONFIRMED"),
            ("Unrelated finding nobody asked for", "LIKELY"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["false_positive_count"] == 1
        assert any("Unrelated" in fp["description"] for fp in r["false_positives"])

    def test_confidence_downgrade_recorded(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "STUN.exe at Windows Temp",
             "confidence_min": "CONFIRMED"},
        ])
        l = _configure_log(tmp_path, [
            ("STUN.exe at Windows Temp", "SUSPECTED"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        # Match is found (TP) but at lower tier — recorded as downgrade.
        assert r["summary"]["true_positive_count"] == 1
        assert len(r["confidence_downgrades"]) == 1
        assert r["confidence_downgrades"][0]["expected_tier"] == "CONFIRMED"
        assert r["confidence_downgrades"][0]["actual_tier"] == "SUSPECTED"

    def test_higher_confidence_does_not_count_as_downgrade(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "STUN.exe at Windows Temp",
             "confidence_min": "LIKELY"},
        ])
        l = _configure_log(tmp_path, [
            ("STUN.exe at Windows Temp", "CONFIRMED"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["confidence_downgrades"] == []

    def test_missing_ground_truth_file(self):
        from tools.accuracy import accuracy_compare
        r = accuracy_compare("/nonexistent/gt.json")
        assert r["success"] is False
        assert "not found" in r["error"]

    def test_empty_trace_all_false_negatives(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "STUN.exe", "confidence_min": "CONFIRMED"},
            {"id": "F2", "description": "Mnemosyne rootkit", "confidence_min": "CONFIRMED"},
        ])
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["false_negative_count"] == 2
        assert r["summary"]["recall"] == 0.0


class TestAccuracyExportReport:
    def test_writes_markdown(self, tmp_path):
        from tools.accuracy import accuracy_export_report
        gt = _gt_file(tmp_path, [
            {"id": "F1", "description": "STUN.exe at Windows Temp",
             "confidence_min": "CONFIRMED"},
        ], case_id="WRITE-001")
        l = _configure_log(tmp_path, [
            ("STUN.exe at Windows Temp", "CONFIRMED"),
        ])
        out_dir = tmp_path / "analysis"
        out_dir.mkdir()
        out_path = str(out_dir / "accuracy.md")
        with patch("core.execution_log.log", l):
            r = accuracy_export_report(gt, out_path)
        assert r["success"] is True
        content = (out_dir / "accuracy.md").read_text()
        assert "Accuracy Report" in content
        assert "WRITE-001" in content
        assert "True positives: **1**" in content

    def test_refuses_output_inside_evidence(self, tmp_path):
        from tools.accuracy import accuracy_export_report
        gt = _gt_file(tmp_path, [])
        with pytest.raises(ValueError):
            accuracy_export_report(gt, "/mnt/host01/accuracy.md")


class TestGroundTruthSchema:
    """Any ground_truth.json present under ~/cases/* is well-formed.

    Case-agnostic: globs whatever ground-truth files exist and validates the
    schema; skips when none are present so the suite has no hard coupling to a
    particular dataset being installed."""

    def test_present_ground_truth_files_validate(self):
        import os, glob
        paths = glob.glob(os.path.expanduser("~/cases/*/ground_truth.json"))
        if not paths:
            pytest.skip("no ground_truth.json present under ~/cases/")
        for path in paths:
            with open(path) as f:
                gt = json.load(f)
            assert gt.get("case_id")
            assert isinstance(gt.get("expected_findings"), list)
            for item in gt["expected_findings"]:
                assert "id" in item
                assert "description" in item
                assert item.get("confidence_min") in ("CONFIRMED", "LIKELY", "SUSPECTED")


class TestNegativeAssertionScoring:
    """Negative-assertion scoring: negative_assertions in ground_truth are scored against
    UNCONFIRMED findings in the trace."""

    def test_unaddressed_negative_assertion(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(
            tmp_path,
            [{"id": "F1", "description": "STUN.exe", "confidence_min": "CONFIRMED"}],
            negatives=["No persistence via Run keys"],
        )
        l = _configure_log(tmp_path, [("STUN.exe", "CONFIRMED")])
        # Findings recorded but the negative assertion is never addressed.
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["negative_assertion_total"] == 1
        assert r["summary"]["negative_assertion_addressed"] == 0
        assert r["summary"]["negative_coverage"] == 0.0
        assert r["negative_assertions"][0]["addressed"] is False

    def test_addressed_negative_assertion(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(
            tmp_path,
            [],
            negatives=["No persistence via Run keys — verified via RECmd"],
        )
        l = _configure_log(tmp_path, [
            ("No persistence via Run keys — verified via RECmd", "UNCONFIRMED"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["negative_assertion_addressed"] == 1
        assert r["summary"]["negative_coverage"] == 1.0
        assert r["negative_assertions"][0]["addressed"] is True

    def test_no_negative_assertions_means_full_coverage(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(tmp_path, [], negatives=[])
        l = _configure_log(tmp_path, [])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["summary"]["negative_coverage"] == 1.0
        assert r["negative_assertions"] == []

    def test_likely_finding_does_not_count_as_negative_assertion(self, tmp_path):
        from tools.accuracy import accuracy_compare
        gt = _gt_file(
            tmp_path,
            [],
            negatives=["No persistence via Run keys"],
        )
        # LIKELY finding that matches text — should NOT satisfy negative
        # assertion (which expects UNCONFIRMED).
        l = _configure_log(tmp_path, [
            ("Persistence via Run keys exists", "LIKELY"),
        ])
        with patch("core.execution_log.log", l):
            r = accuracy_compare(gt)
        assert r["negative_assertions"][0]["addressed"] is False
