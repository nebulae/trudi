"""Case-briefing parsing (pilot/bootstrap.py) — launcher-side pure logic."""
import os

from pilot.bootstrap import (
    CaseInfo, discover_evidence, is_case_dir, merge_extracted, parse_case_md,
)

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
M57 = os.path.join(REPO, "cases", "m57-jean")


class TestCaseDetection:
    def test_repo_root_is_not_a_case(self):
        # the repo root has a CLAUDE.md too — hackathon context, not a case
        assert not is_case_dir(REPO)

    def test_m57_is_a_case(self):
        assert is_case_dir(M57)

    def test_bare_dir_is_not(self, tmp_path):
        assert not is_case_dir(str(tmp_path))

    def test_evidence_dir_alone_qualifies(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text("# ad-hoc case")
        (tmp_path / "evidence").mkdir()
        assert is_case_dir(str(tmp_path))


class TestParse:
    def test_m57_fields(self):
        info = parse_case_md(M57)
        assert info.case_id == "M57-JEAN"
        assert "m57plan.xlsx" in info.question
        assert info.evidence_root.endswith("evidence/")
        assert len(info.roster) >= 2  # Jean Jones, Alison Smith at minimum
        assert any("Jean" in n for n in info.roster)

    def test_fallbacks(self, tmp_path):
        d = tmp_path / "adhoc-case"
        d.mkdir()
        info = parse_case_md(str(d))
        assert info.case_id == "ADHOC-CASE"
        assert info.question == "" and info.roster == []


class TestNitrobaShapedParse:
    DOC = (
        "## X Case Context\n\n**Case ID:** X-1\n\n"
        "### Dorm Room G24 — Suspects\n"
        "- Alice (last name unknown)\n- Barbara (last name unknown)\n\n"
        "### CHEM109 Class List (potential suspects)\n"
        "Amy Smith, Burt Greedom, Tuck Gorge, Johnny Coach, Jenny Kant\n\n"
        "### Other\nprose with Two Names, and A Comma, here\n")

    def test_multi_section_roster_with_comma_runs(self, tmp_path):
        (tmp_path / "CLAUDE.md").write_text(self.DOC)
        info = parse_case_md(str(tmp_path))
        assert "Amy Smith" in info.roster and "Johnny Coach" in info.roster
        assert len(info.roster) == 5
        # prose under a non-roster header is not a name list
        assert "Two Names" not in info.roster


class TestEvidenceDiscovery:
    def test_forensic_extensions_only_sorted(self, tmp_path):
        ev = tmp_path / "evidence"
        ev.mkdir()
        for name in ("b.E01", "a.pcap", "README.txt", "notes.md"):
            (ev / name).write_bytes(b"x")
        (ev / "mounted").mkdir()
        info = CaseInfo(case_dir=str(tmp_path), case_id="X")
        assert [os.path.basename(p) for p in discover_evidence(info)] == \
            ["a.pcap", "b.E01"]

    def test_parsed_root_wins_when_it_exists(self, tmp_path):
        other = tmp_path / "elsewhere"
        other.mkdir()
        (other / "disk.dd").write_bytes(b"x")
        info = CaseInfo(case_dir=str(tmp_path), case_id="X",
                        evidence_root=str(other))
        assert discover_evidence(info) == [str(other / "disk.dd")]

    def test_no_evidence_dir(self, tmp_path):
        info = CaseInfo(case_dir=str(tmp_path), case_id="X")
        assert discover_evidence(info) == []


class TestMergeExtracted:
    def test_merge_fills_only_gaps(self):
        info = CaseInfo(case_dir="/c", case_id="X", question="already set")
        filled = merge_extracted(info, {
            "case_question": "should not overwrite",
            "roster": [" Jean Jones ", "", "Alison Smith"],
            "evidence_root": "/e/root"})
        assert info.question == "already set"
        assert info.roster == ["Jean Jones", "Alison Smith"]
        assert info.evidence_root == "/e/root"
        assert set(filled) == {"roster", "evidence_root"}
