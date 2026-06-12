"""Tests for core/paths.py."""
import os
import pytest
from unittest.mock import patch
from core.paths import (
    is_evidence_path,
    assert_output_safe,
    vol3_bin,
    vol3_symbols,
    ez_tool,
    OUTPUT_CAP,
)


class TestIsEvidencePath:
    @pytest.mark.parametrize("path,expected", [
        ("/cases/example/image.E01", True),
        ("/mnt/ewf_wkstn01/ewf1", True),
        ("/media/usb/image.dd", True),
        ("/home/trin/cases/example/evidence/image.E01", True),
        ("/home/trin/cases/example/exports/result.csv", False),
        ("/home/trin/cases/example/analysis/data.json", False),
        ("/home/trin/cases/example/reports/report.md", False),
        ("/tmp/scratch.bin", False),
    ])
    def test_paths(self, path, expected):
        assert is_evidence_path(path) == expected


class TestAssertOutputSafe:
    def test_blocks_cases_prefix(self):
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/cases/example/output.csv")

    def test_blocks_mnt_prefix(self):
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/mnt/wkstn01/output.csv")

    def test_blocks_evidence_segment(self):
        with pytest.raises(ValueError, match="protected evidence"):
            assert_output_safe("/home/trin/cases/example/evidence/out.csv")

    def test_allows_analysis(self, tmp_path):
        safe = str(tmp_path / "analysis" / "out.csv")
        assert_output_safe(safe)  # should not raise

    def test_allows_exports(self, tmp_path):
        safe = str(tmp_path / "exports" / "out.csv")
        assert_output_safe(safe)

    def test_allows_reports(self, tmp_path):
        safe = str(tmp_path / "reports" / "out.md")
        assert_output_safe(safe)


class TestVol3Bin:
    def test_returns_string(self):
        assert isinstance(vol3_bin(), str)

    def test_returns_vol_path(self):
        assert "vol" in vol3_bin()


class TestVol3Symbols:
    def test_returns_default_when_env_unset(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VOLATILITY_SYMBOLS", raising=False)
        path = vol3_symbols()
        assert "volatility3" in path
        assert os.path.isdir(path)

    def test_respects_env_override(self, tmp_path, monkeypatch):
        override = str(tmp_path / "custom_symbols")
        monkeypatch.setenv("VOLATILITY_SYMBOLS", override)
        path = vol3_symbols()
        assert path == override
        assert os.path.isdir(path)

    def test_creates_directory(self, tmp_path, monkeypatch):
        new_dir = str(tmp_path / "vol_syms" / "nested")
        monkeypatch.setenv("VOLATILITY_SYMBOLS", new_dir)
        vol3_symbols()
        assert os.path.isdir(new_dir)


class TestEzTool:
    def test_no_subdir(self):
        result = ez_tool("MFTECmd")
        assert "dotnet" in result
        assert "MFTECmd.dll" in result

    def test_with_subdir(self):
        result = ez_tool("EvtxECmd", subdir="EvtxeCmd")
        assert "EvtxeCmd" in result
        assert "EvtxECmd.dll" in result

    def test_base_path(self):
        result = ez_tool("RECmd", subdir="RECmd")
        assert "/opt/zimmermantools" in result


class TestOutputCap:
    def test_output_cap_is_50kb(self):
        assert OUTPUT_CAP == 51_200
