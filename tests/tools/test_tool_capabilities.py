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
        "coverage.report",
        "read.output",
        "read.mail",
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


def test_binary_probe_skips_wsl_drive_mounts(monkeypatch):
    """A Windows-inherited PATH carries dozens of /mnt/<drive>/ entries at ~1 ms a
    stat; probing ~250 binaries against them made the MCP handshake time out."""
    import tools.tool_capabilities as tc

    monkeypatch.setenv("PATH", "/usr/bin:/mnt/c/Windows/system32:/mnt/c/Program Files/X:/usr/local/bin")
    monkeypatch.delenv("TRUDI_PROBE_FULL_PATH", raising=False)
    assert tc._probe_path() == "/usr/bin:/usr/local/bin"
    monkeypatch.setenv("TRUDI_PROBE_FULL_PATH", "1")
    assert tc._probe_path().count("/mnt/c/") == 2
    monkeypatch.delenv("TRUDI_PROBE_FULL_PATH")
    monkeypatch.setenv("PATH", "/mnt/c/Windows")      # nothing else: keep what there is
    assert tc._probe_path() == "/mnt/c/Windows"

    seen = {}
    monkeypatch.setattr(tc.shutil, "which", lambda name, path=None: seen.setdefault(name, path) and None)
    monkeypatch.setenv("PATH", "/usr/bin:/mnt/d/tools")
    tc.optional_binary("misc.chainsaw_hunt")
    assert all(p == "/usr/bin" for p in seen.values())


def test_unavailable_tools_probe_once_per_which_and_path(monkeypatch):
    import tools.tool_capabilities as tc

    calls = []
    monkeypatch.setattr(tc.shutil, "which", lambda name: calls.append(name) or f"/usr/bin/{name}")
    first = tc.unavailable_tools()
    probes = len(calls)
    assert probes > 0 and first == set()
    tc.unavailable_tools()
    tc.allowed_tool_names()
    assert len(calls) == probes                      # cached: no second probe pass

    monkeypatch.setattr(tc.shutil, "which", lambda name: None if name == "chainsaw" else f"/usr/bin/{name}")
    assert "misc.chainsaw_hunt" in tc.unavailable_tools()   # a new which ⇒ fresh probe
    monkeypatch.setenv("PATH", "/nowhere")
    assert "misc.chainsaw_hunt" in tc.unavailable_tools()   # a new PATH ⇒ fresh probe, same answer
