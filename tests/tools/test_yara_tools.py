"""Tests for tools/yara_tools.py — uses real yara-python, no mocking needed."""
import os
import pytest
import yara
from tools.yara_tools import (
    yara_scan_file,
    yara_scan_directory,
    yara_scan_process_memory,
    yara_scan_memory_image,
    yara_compile_check,
    yara_scan_strings,
)

MATCH_RULE = 'rule TestMatch { strings: $s = "TRUDI_CANARY" condition: $s }'
NO_MATCH_RULE = 'rule TestNoMatch { strings: $s = "ZZZNOMATCH999" condition: $s }'
BAD_RULE = 'rule Bad { strings: $s = "x" condition: $missing }'


@pytest.fixture
def canary_file(tmp_path):
    f = tmp_path / "target.bin"
    f.write_bytes(b"header TRUDI_CANARY footer")
    return str(f)


@pytest.fixture
def empty_file(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"no match here")
    return str(f)


@pytest.fixture
def rule_file(tmp_path):
    r = tmp_path / "test.yar"
    r.write_text(MATCH_RULE)
    return str(r)


@pytest.fixture
def rule_dir(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "test.yar").write_text(MATCH_RULE)
    return str(d)


class TestYaraScanFile:
    def test_match_found(self, canary_file, rule_file):
        r = yara_scan_file(canary_file, rule_file)
        assert r["success"] is True
        assert r["match_count"] == 1
        assert r["matches"][0]["rule"] == "TestMatch"

    def test_no_match(self, empty_file, tmp_path):
        rf = str(tmp_path / "nomatch.yar")
        open(rf, "w").write(NO_MATCH_RULE)
        r = yara_scan_file(empty_file, rf)
        assert r["success"] is True
        assert r["match_count"] == 0

    def test_file_not_found(self, rule_file):
        r = yara_scan_file("/nonexistent/file.bin", rule_file)
        assert r["success"] is False
        assert "error" in r

    def test_invalid_rule_fails(self, canary_file, tmp_path):
        bad = str(tmp_path / "bad.yar")
        open(bad, "w").write(BAD_RULE)
        r = yara_scan_file(canary_file, bad)
        assert r["success"] is False

    def test_rule_dir_accepted(self, canary_file, rule_dir):
        r = yara_scan_file(canary_file, rule_dir)
        assert r["success"] is True
        assert r["match_count"] == 1

    def test_empty_rule_dir_fails(self, canary_file, tmp_path):
        empty_dir = str(tmp_path / "empty_rules")
        os.makedirs(empty_dir)
        r = yara_scan_file(canary_file, empty_dir)
        assert r["success"] is False

    def test_match_has_string_offset(self, canary_file, rule_file):
        r = yara_scan_file(canary_file, rule_file)
        strings = r["matches"][0]["strings"]
        assert len(strings) > 0
        assert strings[0]["identifier"] == "$s"


class TestYaraScanDirectory:
    def test_finds_matching_file(self, tmp_path, rule_file):
        scan_dir = tmp_path / "targets"
        scan_dir.mkdir()
        (scan_dir / "hit.bin").write_bytes(b"TRUDI_CANARY")
        (scan_dir / "miss.bin").write_bytes(b"nothing")
        r = yara_scan_directory(str(scan_dir), rule_file)
        assert r["success"] is True
        assert r["hits"] == 1
        assert "hit.bin" in r["results"][0]["file"]

    def test_no_hits_returns_empty(self, tmp_path, rule_file):
        scan_dir = tmp_path / "targets"
        scan_dir.mkdir()
        (scan_dir / "clean.bin").write_bytes(b"nothing here")
        r = yara_scan_directory(str(scan_dir), rule_file)
        assert r["hits"] == 0
        assert r["results"] == []

    def test_scanned_count(self, tmp_path, rule_file):
        scan_dir = tmp_path / "targets"
        scan_dir.mkdir()
        for i in range(5):
            (scan_dir / f"f{i}.bin").write_bytes(b"data")
        r = yara_scan_directory(str(scan_dir), rule_file)
        assert r["scanned"] == 5


class TestYaraScanMemoryImage:
    def test_match_in_image(self, tmp_path, rule_file):
        img = tmp_path / "memory.img"
        img.write_bytes(b"\x00" * 100 + b"TRUDI_CANARY" + b"\x00" * 100)
        r = yara_scan_memory_image(str(img), rule_file)
        assert r["success"] is True
        assert r["match_count"] == 1

    def test_image_not_found(self, rule_file):
        r = yara_scan_memory_image("/nonexistent/memory.img", rule_file)
        assert r["success"] is False


class TestYaraCompileCheck:
    def test_valid_rule_ok(self, rule_file):
        r = yara_compile_check(rule_file)
        assert r["success"] is True

    def test_invalid_rule_fails(self, tmp_path):
        bad = str(tmp_path / "bad.yar")
        open(bad, "w").write(BAD_RULE)
        r = yara_compile_check(bad)
        assert r["success"] is False
        assert "error" in r


class TestYaraScanStrings:
    def test_inline_rule_match(self, canary_file):
        r = yara_scan_strings(MATCH_RULE, canary_file)
        assert r["success"] is True
        assert r["match_count"] == 1

    def test_inline_rule_no_match(self, empty_file):
        r = yara_scan_strings(NO_MATCH_RULE, empty_file)
        assert r["success"] is True
        assert r["match_count"] == 0

    def test_inline_invalid_rule(self, empty_file):
        r = yara_scan_strings(BAD_RULE, empty_file)
        assert r["success"] is False


class TestBuiltInRulesCompile:
    """Verify all built-in TTP rule files compile without errors."""

    RULES = [
        "rules/cobalt_strike/cobalt_strike.yar",
        "rules/powershell/powershell_injection.yar",
        "rules/persistence/persistence.yar",
        "rules/anti_forensics/anti_forensics.yar",
        "rules/lateral_movement/lateral_movement.yar",
    ]

    @pytest.mark.parametrize("rule_path", RULES)
    def test_rule_compiles(self, rule_path):
        r = yara_compile_check(rule_path)
        assert r["success"] is True, f"{rule_path} failed: {r.get('error')}"
