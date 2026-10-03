"""2026-09-24 BELKA/Titus: DAIR prescribed tools that do not exist
(ez.tidh_extractor, ez.accounts3_parser) and the work-order gate then held the
phase for a tool no one could run."""
import pytest

import tools.tool_capabilities as TC

REG = {"ez.pecmd", "ez.recmd_hive", "ez.recmd_batch", "strings.grep",
       "misc.record_disposition", "vol.pslist"}


@pytest.fixture(autouse=True)
def registry():
    saved = set(TC._REGISTERED)
    TC.set_registered_tools(REG)
    yield
    TC.set_registered_tools(saved)


def test_invented_tool_in_a_real_namespace_does_not_exist():
    assert not TC.tool_exists("ez.tidh_extractor")
    assert not TC.tool_exists("mcp__trudi-sift__ez_accounts3_parser")


def test_registered_spellings_and_families_exist():
    for t in ("ez.pecmd", "ez_pecmd", "mcp__trudi-sift__vol_pslist", "ez.recmd",
              "strings.grep(pattern='x')"):
        assert TC.tool_exists(t), t


def test_loose_words_and_unknown_namespaces_are_not_judged():
    for t in ("sam", "roster", "tcpdump.read", "record.finding"):
        assert TC.tool_exists(t), t


def test_empty_registry_treats_everything_as_existing():
    TC.set_registered_tools(set())
    assert TC.tool_exists("ez.tidh_extractor")


def test_dair_filter_drops_invented_tools_even_without_evidence_kinds():
    from tools.dair import _filter_tools
    kept, dropped = _filter_tools(["ez.pecmd", "ez.tidh_extractor"], [])
    assert kept == ["ez.pecmd"]
    assert dropped == [{"tool": "ez.tidh_extractor", "reason": "not_a_tool"}]


def test_dair_filter_drops_challenges_whose_only_method_is_invented():
    from tools.dair import _filter_challenges
    kept, dropped = _filter_challenges(
        [{"claim": "a", "challenge_method": "ez.accounts3_parser", "verified": None},
         {"claim": "b", "challenge_method": "ez.pecmd", "verified": None}], [])
    assert [c["claim"] for c in kept] == ["b"]
    assert dropped[0]["not_a_tool"] == ["ez.accounts3_parser"]


def test_recorded_invented_tool_is_not_an_unrun_work_order_item():
    from tools._gates.work_order import unrun_from_list
    entries = [{"type": "tool_call", "call_id": 1, "cmd": "PECmd -d x", "success": True}]
    assert unrun_from_list(entries, ["ez.tidh_extractor", "strings.grep"]) == ["strings.grep"]


def test_recorded_challenge_with_invented_method_is_not_open():
    from tools._gates.max_pass_cap import open_challenges
    d = {"type": "dair_call", "call_id": 5, "verification_challenges": [
        {"claim": "apple id", "challenge_method": "ez.accounts3_parser", "verified": None},
        {"claim": "prefetch", "challenge_method": "ez.pecmd", "verified": None}]}
    assert [c["challenge_method"] for c in open_challenges([d], d)] == ["ez.pecmd"]


def test_packet_spans_render_binary_as_dots_and_keep_signatures():
    """2026-09-24 BELKA: icat of a BitLocker VHDX cited as evidence rendered
    ~8k chars of binary as ~50k of \\u00XX escapes and overflowed the reviewer."""
    import json
    from core.evidence_packets import _printable_spans
    blob = "\x00\x03\x1b-FVE-FS-\x00�\x7fdata\tok\n"
    r = _printable_spans({"spans": [{"text": blob}]})
    text = r["spans"][0]["text"]
    assert "-FVE-FS-" in text and "\tok\n" in text
    assert len(json.dumps(text)) < 2 * len(text) + 10
