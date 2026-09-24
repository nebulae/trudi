"""Tests for FK-driven corroboration completeness (tools/_gates/fk_corroboration).

Synthetic: the check keys on the FK corpus (real sheets) + generic trace shapes,
so fabricated findings/tool-calls exercise the real logic. No scenario fixtures.

Principle under test: a finding is only nagged/blocked when its grounding
artifact's does_not_prove DISCLAIMS the claim class (shimcache/amcache/mft-for-
execution, lnk-for-presence, …) AND none of the FK-named corroborators ran.
Authoritative claims (prefetch/BAM execution, event-log logon, MFT presence) and
non-execution/presence/timeline claims (exfil/attribution) are left alone.
"""
from types import SimpleNamespace

from tools._gates import fk_corroboration as fkc


_EXEC = {"act": "execution"}


def _idx(cmds):
    return SimpleNamespace(
        by_type={"tool_call": [{"type": "tool_call", "cmd": c} for c in cmds]})


class TestHelpers:
    def test_extract_tool_tokens(self):
        toks = fkc._extract_tool_tokens([
            "Amcache (ez_amcacheparser / vol_amcache)",
            "BAM (ez_recmd_hive / misc_regripper_hive)",
        ])
        assert toks == {"ez_amcacheparser", "vol_amcache",
                        "ez_recmd_hive", "misc_regripper_hive"}

    def test_claim_category_from_declared_act(self):
        avail = {"for_execution", "for_presence", "for_timeline"}
        assert fkc._claim_category({"act": "execution"}, avail) == "for_execution"
        assert fkc._claim_category({"act": "presence"}, avail) == "for_presence"
        assert fkc._claim_category({"act": "timeline"}, avail) == "for_timeline"
        # egress / attribution / undeclared -> None (no wording force-fit).
        assert fkc._claim_category({"act": "egress"}, avail) is None
        assert fkc._claim_category({}, avail) is None
        assert fkc._claim_category({"act": "execution"}, {"for_presence"}) is None

    def test_cmd_regex_boundary_traps(self):
        assert not fkc._CORROBORATOR_CMD_RE["ez_lecmd"].search("dotnet /x/JLECmd.dll")
        assert fkc._CORROBORATOR_CMD_RE["ez_lecmd"].search("dotnet /x/LECmd.dll")
        assert fkc._CORROBORATOR_CMD_RE["ez_jlecmd"].search("dotnet /x/JLECmd.dll")

    def test_norm_dotted_and_doubled(self):
        assert fkc._norm("ez.pecmd") == "ez_pecmd"
        # legacy doubled wire name (pre mount-time dedup) still collapses
        assert fkc._norm("ez_ez_pecmd") == "ez_pecmd"

    def test_does_not_prove_gating(self):
        from tools import _fk
        # shimcache disclaims execution; prefetch does not (it proves it).
        assert fkc._category_disclaimed(_fk.load_artifact("shimcache"), "for_execution")
        assert not fkc._category_disclaimed(_fk.load_artifact("prefetch"), "for_execution")
        # MFT is authoritative for presence; LNK is not.
        assert not fkc._category_disclaimed(_fk.load_artifact("mft"), "for_presence")
        assert fkc._category_disclaimed(_fk.load_artifact("lnk_files"), "for_presence")


class TestCorroborationGap:
    def test_shimcache_execution_uncorroborated_flags(self):
        gap = fkc.corroboration_gap(
            "ez.appcompatcacheparser", _EXEC, ran_cmds=[])
        assert gap is not None
        assert gap["artifact"] == "shimcache"
        assert gap["category"] == "for_execution"
        assert gap["expected"]  # detectable corroborators exist

    def test_shimcache_execution_corroborated_by_prefetch_passes(self):
        gap = fkc.corroboration_gap(
            "ez.appcompatcacheparser", _EXEC,
            ran_cmds=["dotnet /opt/zimmermantools/PECmd.dll -d /pf"])
        assert gap is None  # ez_pecmd is a shimcache execution corroborator

    def test_prefetch_execution_is_authoritative_no_gap(self):
        # Prefetch PROVES execution — an execution claim on it must NOT be nagged.
        assert fkc.corroboration_gap(
            "ez.pecmd", _EXEC, ran_cmds=[]) is None

    def test_mft_exfil_claim_has_no_category_no_gap(self):
        # 'exfiltrated' is neither execution/presence/timeline — no category, no gap.
        assert fkc.corroboration_gap(
            "ez.mftecmd", {"act": "egress"}, ran_cmds=[]) is None

    def test_mft_presence_is_authoritative_no_gap(self):
        # MFT is authoritative for file presence — a 'copied to disk' claim on it
        # is not disclaimed, so no gap.
        assert fkc.corroboration_gap(
            "ez.mftecmd", {"act": "presence"}, ran_cmds=[]) is None

    def test_dotted_doubled_and_plain_source_all_resolve(self):
        for src in ("ez_ez_appcompatcacheparser", "ez.appcompatcacheparser",
                    "ez_appcompatcacheparser"):
            gap = fkc.corroboration_gap(src, _EXEC, ran_cmds=[])
            assert gap is not None and gap["artifact"] == "shimcache"

    def test_non_fk_source_no_gap(self):
        assert fkc.corroboration_gap(
            "net.tcpdump_read", _EXEC, ran_cmds=[]) is None


class TestNoteForFinding:
    def test_confirmed_uncorroborated_warns(self):
        note = fkc.note_for_finding(
            tier="CONFIRMED", description="evil.exe executed",
            source="ez.appcompatcacheparser", idx=_idx([]), claim=_EXEC)
        assert note and "SUSPECTED" in note and "shimcache" in note

    def test_suspected_tier_not_warned(self):
        assert fkc.note_for_finding(
            tier="SUSPECTED", description="evil.exe executed",
            source="ez.appcompatcacheparser", idx=_idx([]), claim=_EXEC) is None

    def test_authoritative_finding_not_warned(self):
        # prefetch execution — authoritative, no warn even with an empty trace.
        assert fkc.note_for_finding(
            tier="CONFIRMED", description="evil.exe executed",
            source="ez.pecmd", idx=_idx([]), claim=_EXEC) is None

    def test_corroborated_no_warn(self):
        note = fkc.note_for_finding(
            tier="LIKELY", description="evil.exe executed",
            source="ez.appcompatcacheparser",
            idx=_idx(["dotnet /x/AmcacheParser.dll -f Amcache.hve"]), claim=_EXEC)
        assert note is None


class TestReportGaps:
    def test_uncorroborated_confirmed_finding_reported(self):
        entries = [
            {"type": "tool_call", "cmd": "dotnet /x/AppCompatCacheParser.dll"},
            {"type": "finding", "confidence": "CONFIRMED",
             "source": "ez.appcompatcacheparser", "claim": _EXEC,
             "description": "evil.exe executed on the host"},
        ]
        gaps = fkc.report_gaps(entries)
        assert len(gaps) == 1 and gaps[0][1]["artifact"] == "shimcache"

    def test_corroborated_finding_not_reported(self):
        entries = [
            {"type": "tool_call", "cmd": "dotnet /x/AppCompatCacheParser.dll"},
            {"type": "tool_call", "cmd": "dotnet /x/AmcacheParser.dll"},
            {"type": "finding", "confidence": "CONFIRMED",
             "source": "ez.appcompatcacheparser", "claim": _EXEC,
             "description": "evil.exe executed on the host"},
        ]
        assert fkc.report_gaps(entries) == []

    def test_authoritative_finding_not_reported(self):
        # A CONFIRMED logon finding grounded on event logs is authoritative.
        entries = [
            {"type": "finding", "confidence": "CONFIRMED",
             "source": "ez.evtxecmd", "claim": {"act": "logon"},
             "description": "account X logged on via RDP type 10"},
        ]
        assert fkc.report_gaps(entries) == []

    def test_suspected_finding_ignored(self):
        entries = [
            {"type": "finding", "confidence": "SUSPECTED",
             "source": "ez.appcompatcacheparser", "claim": _EXEC, "description": "evil.exe executed"},
        ]
        assert fkc.report_gaps(entries) == []

    def test_exfil_claim_on_mft_not_reported(self):
        # The regression that broke the pre_report tests: an exfil claim on MFT
        # has no execution/presence/timeline category and must not block.
        entries = [
            {"type": "finding", "confidence": "CONFIRMED", "source": "mft",
             "claim": {"act": "egress"}, "description": "Dana exfiltrated the classified data"},
        ]
        assert fkc.report_gaps(entries) == []
