"""Tests for the curated tool capability manifest."""


def test_manifest_exposes_core_dair_tools():
    from tools.tool_capabilities import allowed_tool_names, capability_for_tool

    allowed = allowed_tool_names()
    for tool in (
        "reason.plan",
        "vol.psscan",
        "ez.evtxecmd",
        "net.ngrep_search",
        "net.pcap_identity_timeline",
        "strings.stat_file",
        "yara.scan_directory",
        "coverage.coverage_report",
    ):
        assert tool in allowed
        assert capability_for_tool(tool)


def test_unknown_priority_tools_are_annotated_not_removed():
    from tools.tool_capabilities import annotate_directives_with_manifest

    directives = {
        "priority_tools": ["vol.psscan", "vol.fake_plugin"],
        "skip_tools": [],
    }
    out = annotate_directives_with_manifest(directives)

    assert out["priority_tools"] == ["vol.psscan", "vol.fake_plugin"]
    assert out["unknown_priority_tools"] == ["vol.fake_plugin"]
    assert out["priority_tool_capabilities"][0] == {
        "tool": "vol.psscan",
        "capability": "memory_process_network",
    }


def test_prompt_manifest_is_compact_and_includes_substitution_rules():
    from tools.tool_capabilities import format_tool_manifest_for_prompt

    text = format_tool_manifest_for_prompt(max_tools_per_capability=3)
    assert "TOOL CAPABILITY MANIFEST" in text
    assert "network_pcap" in text
    assert "pcap_only" in text
    assert "Use only these tool IDs" in text
