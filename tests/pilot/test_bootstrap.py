"""Pilot session bootstrap: case parsing, evidence discovery, banner."""
import json
import os

import pytest

from pilot.bootstrap import (
    BootState, CaseInfo, bootstrap, discover_evidence, is_case_dir,
    parse_case_md, render_banner,
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


class _FakeResult:
    def __init__(self, payload):
        self.structured_content = payload


class _FakeClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        return _FakeResult(self.responses[name])


class TestBootstrap:
    @pytest.mark.asyncio
    async def test_bookkeeping_calls_and_state(self, tmp_path):
        ev = tmp_path / "evidence"
        ev.mkdir()
        (ev / "disk.E01").write_bytes(b"x" * 100)
        info = CaseInfo(case_dir=str(tmp_path), case_id="CASE-1")
        client = _FakeClient({
            "misc_start_execution_log": {
                "success": True, "entries_recovered": 42, "resumed": True,
                "dashboard_url": "http://127.0.0.1:8765/x"},
            "hash_verify_evidence_hash": {
                "success": True, "sha256": "deadbeef" * 8},
        })
        state = await bootstrap(client, info, echo=lambda *a, **k: None)
        assert [c[0] for c in client.calls] == [
            "misc_start_execution_log", "hash_verify_evidence_hash"]
        assert client.calls[0][1]["case_id"] == "CASE-1"
        assert state.resumed and state.entry_count == 42
        assert state.dashboard_url.startswith("http")
        assert state.evidence[0][1].startswith("✓ sha256 deadbeef")

    @pytest.mark.asyncio
    async def test_hash_failure_surfaces_not_raises(self, tmp_path):
        ev = tmp_path / "evidence"
        ev.mkdir()
        (ev / "disk.dd").write_bytes(b"x")
        info = CaseInfo(case_dir=str(tmp_path), case_id="C")
        client = _FakeClient({
            "misc_start_execution_log": {"success": True},
            "hash_verify_evidence_hash": {"success": False,
                                          "error": "file unreadable"},
        })
        state = await bootstrap(client, info, echo=lambda *a, **k: None)
        assert state.evidence[0][1].startswith("✗") and \
            "file unreadable" in state.evidence[0][1]


class TestBanner:
    def test_renders_all_sections(self):
        info = CaseInfo(case_dir="/c", case_id="M57-JEAN",
                        question="Who exfiltrated the plan? " * 8,
                        roster=["Jean Jones", "Alison Smith"])
        state = BootState(trace_path="analysis/M57-JEAN_trace.json",
                          dashboard_url="http://127.0.0.1:8765/d",
                          resumed=True, entry_count=188,
                          evidence=[("/e/a.E01", "✓ sha256 aaaa…")])
        b = render_banner(info, state)
        for expect in ("TRUDI PILOT ── M57-JEAN", " Q: Who exfiltrated",
                       "a.E01", "resumed, 188 entries", "dashboard:",
                       "roster: 2 knowns", "dair.assess"):
            assert expect in b, expect
        assert all(len(line) <= 80 for line in b.splitlines())

    def test_new_session_shows_ritual(self):
        b = render_banner(CaseInfo(case_dir="/c", case_id="C"), BootState())
        assert "reason.hypothesize" in b and "none found" in b


class TestCaseExtraction:
    def test_merge_fills_only_gaps(self):
        from pilot.bootstrap import merge_extracted
        info = CaseInfo(case_dir="/c", case_id="X", question="already set")
        filled = merge_extracted(info, {
            "case_question": "should not overwrite",
            "roster": [" Jean Jones ", "", "Alison Smith"],
            "evidence_root": "/e/root"})
        assert info.question == "already set"
        assert info.roster == ["Jean Jones", "Alison Smith"]
        assert info.evidence_root == "/e/root"
        assert set(filled) == {"roster", "evidence_root"}

    @pytest.mark.asyncio
    async def test_extraction_called_once_then_cached(self, tmp_path,
                                                      monkeypatch):
        from pilot import bootstrap as B
        monkeypatch.setattr(B, "_EXTRACT_CACHE_DIR", str(tmp_path / "cache"))
        (tmp_path / "CLAUDE.md").write_text("# odd format\nsuspects: Jean")
        info = CaseInfo(case_dir=str(tmp_path), case_id="C")
        client = _FakeClient({"reason_extract_case": {
            "success": True, "case_question": "who did it?",
            "roster": ["Jean Jones"], "evidence_root": "",
            "case_id": "C", "scenario_summary": "s"}})
        await B.extract_case_info(client, info, echo=lambda *a, **k: None)
        assert info.question == "who did it?" and info.roster == ["Jean Jones"]
        assert len(client.calls) == 1
        # second boot: cache hit, no backend call
        info2 = CaseInfo(case_dir=str(tmp_path), case_id="C")
        await B.extract_case_info(client, info2, echo=lambda *a, **k: None)
        assert info2.question == "who did it?" and len(client.calls) == 1

    @pytest.mark.asyncio
    async def test_complete_regex_parse_skips_backend(self, tmp_path):
        from pilot.bootstrap import extract_case_info
        (tmp_path / "CLAUDE.md").write_text("x")
        info = CaseInfo(case_dir=str(tmp_path), case_id="C",
                        question="q", roster=["A B"])
        client = _FakeClient({})
        await extract_case_info(client, info, echo=lambda *a, **k: None)
        assert client.calls == []

    @pytest.mark.asyncio
    async def test_backend_failure_is_soft(self, tmp_path, monkeypatch):
        from pilot import bootstrap as B
        monkeypatch.setattr(B, "_EXTRACT_CACHE_DIR", str(tmp_path / "cache"))
        (tmp_path / "CLAUDE.md").write_text("y")

        class _Boom:
            async def call_tool(self, *a, **k):
                raise RuntimeError("backend down")
        info = CaseInfo(case_dir=str(tmp_path), case_id="C")
        await B.extract_case_info(_Boom(), info, echo=lambda *a, **k: None)
        assert info.question == ""  # gap remains, boot proceeds
