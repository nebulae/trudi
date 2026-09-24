"""Evidence-kind detection (core.evidence_kinds) and the tool → evidence-kind
map (tools.tool_capabilities) DAIR filters its prescriptions with."""
import os

import pytest

from core import evidence_kinds as EK
from core.execution_log import ExecutionLog


def _case(tmp_path, name="CASE"):
    case = tmp_path / name
    (case / "evidence").mkdir(parents=True)
    (case / "analysis").mkdir()
    return case


def _profile(case, entries=None, ctx=""):
    return EK.evidence_profile(entries or [], str(case), ctx)


# ── detection, one kind at a time ─────────────────────────────────────────────

@pytest.mark.parametrize("fname,kind", [
    ("capture.pcap", "pcap"), ("x.pcapng", "pcap"),
    ("host.mem", "memory"), ("host.vmem", "memory"), ("dump.lime", "memory"),
    ("disk.E01", "disk_image"), ("disk.Ex01", "disk_image"), ("disk.dd", "disk_image"),
    ("disk.vmdk", "disk_image"), ("disk.vhdx", "disk_image"), ("disk.img", "disk_image"),
])
def test_file_extension_kinds(tmp_path, fname, kind):
    case = _case(tmp_path)
    (case / "evidence" / fname).write_bytes(b"")
    p = _profile(case)
    assert p["kinds"] == [kind] and p["determined"] is True
    assert EK.filter_kinds(p) == {kind}


def test_raw_is_ambiguous_counts_memory_and_disk(tmp_path):
    case = _case(tmp_path)
    (case / "evidence" / "image.raw").write_bytes(b"")
    assert set(_profile(case)["kinds"]) == {"memory", "disk_image"}


def test_triage_collection_by_config_dir_and_by_mft(tmp_path):
    case = _case(tmp_path)
    (case / "evidence" / "host.CYLR" / "C" / "Windows" / "System32" / "config").mkdir(parents=True)
    assert _profile(case)["kinds"] == ["triage"]
    case2 = _case(tmp_path, "C2")
    (case2 / "evidence" / "col" / "C").mkdir(parents=True)
    (case2 / "evidence" / "col" / "C" / "$MFT").write_bytes(b"")
    assert _profile(case2)["kinds"] == ["triage"]


def test_mobile_ios_android_and_backup(tmp_path):
    ios = _case(tmp_path, "IOS")
    (ios / "evidence" / "fs" / "private" / "var" / "mobile" / "Library").mkdir(parents=True)
    os.symlink("private/var", ios / "evidence" / "fs" / "var")        # iOS /var link
    assert _profile(ios)["kinds"] == ["mobile"]
    android = _case(tmp_path, "AND")
    (android / "evidence" / "ext" / "data" / "data" / "com.whatsapp").mkdir(parents=True)
    assert _profile(android)["kinds"] == ["mobile"]
    backup = _case(tmp_path, "BK")
    (backup / "evidence" / "Manifest.db").write_bytes(b"")
    assert _profile(backup)["kinds"] == ["mobile"]


def test_mounted_image_under_case_mnt_is_disk_image(tmp_path):
    case = tmp_path / "M"
    (case / "analysis").mkdir(parents=True)
    (case / "mnt" / "vol").mkdir(parents=True)
    assert _profile(case)["determined"] is False          # empty mount point
    (case / "mnt" / "vol" / "pagefile.sys").write_bytes(b"")
    p = _profile(case)
    assert p["kinds"] == ["disk_image"] and p["determined"] is True


def test_symlinked_evidence_dir_is_followed_and_loops_terminate(tmp_path):
    store = tmp_path / "store"
    (store / "sub").mkdir(parents=True)
    (store / "sub" / "net.pcap").write_bytes(b"")
    os.symlink(store, store / "sub" / "loop")               # a cycle
    case = tmp_path / "L"
    (case / "analysis").mkdir(parents=True)
    os.symlink(store, case / "evidence")
    assert _profile(case)["kinds"] == ["pcap"]


def test_combined_case(tmp_path):
    case = _case(tmp_path)
    (case / "evidence" / "disk.E01").write_bytes(b"")
    (case / "evidence" / "ram.vmem").write_bytes(b"")
    (case / "evidence" / "ios" / "private" / "var" / "mobile").mkdir(parents=True)
    assert set(_profile(case)["kinds"]) == {"disk_image", "memory", "mobile"}


# ── trace signals only ADD kinds; they never determine the inventory ─────────

def _log(tmp_path):
    (tmp_path / "t" / "analysis").mkdir(parents=True)
    l = ExecutionLog()
    l.configure("EK", str(tmp_path / "t" / "analysis" / "trace.json"), save_session=False)
    return l


def _tool(log, cmd, mcp_tool, source=None):
    cid = log.record_tool_call(cmd, True, False, 0, 0)
    e = log.index().by_call_id[cid]
    e["mcp_tool"] = mcp_tool
    if source:
        e["source"] = source
    return cid


def test_trace_adds_kinds_but_trace_alone_is_undetermined(tmp_path):
    l = _log(tmp_path)
    _tool(l, "vol -f /x/host.mem windows.pslist", "vol_pslist")
    p = EK.evidence_profile(l._entries, str(tmp_path / "nocase"))
    assert p["kinds"] == ["memory"] and p["determined"] is False
    assert EK.filter_kinds(p) == set()                      # fail-open: filter nothing
    case = _case(tmp_path)
    (case / "evidence" / "disk.E01").write_bytes(b"")
    assert set(EK.evidence_profile(l._entries, str(case))["kinds"]) == {"memory", "disk_image"}


def test_produced_dumps_and_agent_bash_are_not_evidence(tmp_path):
    l = _log(tmp_path)
    _tool(l, "strings -a /c/exports/dump/file.0x1.ImageSectionObject.cmd.exe.img", "strings_extract")
    _tool(l, "strings -a /c/exports/carved/part.E01", "strings_extract")
    _tool(l, "python3 x.py /scratch/vault.raw", "", source="claude_code_bash")
    assert EK.evidence_profile(l._entries, str(tmp_path / "nocase"))["kinds"] == []
    _tool(l, "strings -a /c/exports/unzipped/host.mem", "strings_extract")   # extracted RAM
    assert EK.evidence_profile(l._entries, str(tmp_path / "nocase"))["kinds"] == ["memory"]


def test_live_monitoring_trace_is_live_and_never_filtered(tmp_path):
    l = _log(tmp_path)
    l.record_tool_call("monitor_start_investigation INV-001", True, False, 0, 0)
    case = _case(tmp_path)
    (case / "evidence" / "x.pcap").write_bytes(b"")
    p = EK.evidence_profile(l._entries, str(case))
    assert "live" in p["kinds"] and p["live_monitoring"] is True
    assert EK.filter_kinds(p) == set()


def test_live_endpoint_named_in_case_context(tmp_path):
    case = _case(tmp_path)
    (case / "evidence" / "x.pcap").write_bytes(b"")
    assert "live" in _profile(case, ctx="endpoint_host=ubuntu-endpoint")["kinds"]


# ── tool → evidence-kind map ──────────────────────────────────────────────────

def test_tool_needs_and_fit():
    from tools.tool_capabilities import tool_evidence_needs, tool_fits_evidence
    assert tool_evidence_needs("vol.pslist") == {"memory"}
    assert tool_evidence_needs("vol_vol_pslist") == {"memory"}
    assert tool_evidence_needs("mcp__trudi-sift__net_ngrep_search") == {"pcap"}
    assert tool_evidence_needs({"tool": "tsk.fls", "args": {}}) == {"disk_image"}
    assert tool_evidence_needs("ez.pecmd(-d /x)") == {"disk_image", "triage"}
    assert tool_evidence_needs("correlate.network_to_process") == {"memory"}
    assert tool_evidence_needs("live.recent_logins") == {"live"}
    assert tool_evidence_needs("misc.evtx_filter") == {"disk_image", "triage"}
    for generic in ("strings.grep", "yara.scan_file", "hash.file", "read.output",
                    "reason.plan", "misc.knowns_pattern_generate", "misc.readpst_extract",
                    "correlate.mitre_map", "enrich.vt_lookup_ip"):
        assert tool_evidence_needs(generic) is None, generic
    assert tool_fits_evidence("ez.pecmd", {"triage"})
    assert not tool_fits_evidence("tsk.fls", {"triage"})
    assert tool_fits_evidence("ez.sqlecmd", {"mobile"})
    assert tool_fits_evidence("vol.pslist", set())             # undetermined: fail-open


def test_challenge_method_tools_splits_lists_not_arguments():
    from tools.tool_capabilities import challenge_method_tools
    assert challenge_method_tools("ez.mftecmd (dir), misc.usnparser_parse, tsk.fls") == \
        ["ez.mftecmd", "misc.usnparser_parse", "tsk.fls"]
    assert challenge_method_tools('misc.evtx_filter(event_ids="4720,4624"), vol.netscan') == \
        ["misc.evtx_filter", "vol.netscan"]


def test_manifest_lists_only_tools_the_evidence_can_feed():
    from tools.tool_capabilities import format_tool_manifest_for_prompt, allowed_tool_names
    text = format_tool_manifest_for_prompt(evidence_kinds={"pcap"})
    assert "net.ngrep_search" in text and "strings.grep" in text
    for absent in ("vol.psscan", "ez.evtxecmd", "tsk.fls", "live.processes",
                   "correlate.network_to_process", "memory_process_network |"):
        assert absent not in text, absent
    assert "vol.psscan" in format_tool_manifest_for_prompt()          # undetermined: full
    allowed = allowed_tool_names({"memory"})
    assert "vol.psscan" in allowed and "ez.evtxecmd" not in allowed and "net.tcpdump_read" not in allowed
    assert "ez.evtxecmd" in allowed_tool_names()


def test_ambiguous_raw_resolved_by_the_tool_that_read_it(tmp_path):
    l = _log(tmp_path)
    _tool(l, "mmls /scratch/vault.raw", "tsk_mmls")
    assert EK.evidence_profile(l._entries, str(tmp_path / "nocase"))["kinds"] == ["disk_image"]
