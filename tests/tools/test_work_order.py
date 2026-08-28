"""Tests for work-order completion (tools/_gates/work_order).

A tool blocked by the DAIR-batch gate leaves a `tool_blocked` audit entry; at
report time, one that was never re-run nor dispositioned is a dropped work-order
item and must block. Synthetic trace entries exercise the real matching logic.
"""
from tools._gates import work_order as wo


def _blocked(tool):
    return {"type": "tool_blocked", "tool": tool, "reason": "no_active_dair_batch"}


def _call(cmd, success=True):
    return {"type": "tool_call", "cmd": cmd, "success": success}


def _msg(content):
    # Narration entries are type 'investigation_narration' — the fixture used
    # to synthesize the nonexistent 'agent_message' type, which masked the
    # consumer-side bug this suite now guards against.
    return {"type": "investigation_narration", "content": content}


class TestBinarySig:
    def test_first_segment_after_namespace(self):
        assert wo._binary_sig("ez_sbecmd") == "sbecmd"
        assert wo._binary_sig("ez_recmd_hive") == "recmd"       # not 'hive'
        assert wo._binary_sig("vol_pslist") == "pslist"

    def test_handles_doubled_and_dotted(self):
        assert wo._binary_sig("ez_ez_sbecmd") == "sbecmd"
        assert wo._binary_sig("ez.sbecmd") == "sbecmd"

    def test_binary_aliases_for_differently_named_wrappers(self):
        # Tools whose wrapped binary is named differently from the 2nd name
        # segment: the signature must be the keyword the COMMAND contains, not
        # the tool-name word (else the tool that ran is reported as never-run).
        assert wo._binary_sig("misc.regripper_hive") == "rip.pl"        # runs rip.pl
        assert wo._binary_sig("misc.regripper_list_plugins") == "rip.pl"
        assert wo._binary_sig("plaso.plaso_create_timeline") == "log2timeline"
        assert wo._binary_sig("plaso.plaso_export_csv") == "psort"
        assert wo._binary_sig("plaso.plaso_info") == "pinfo"

    def test_arg_laden_tool_names_strip_to_correct_sig(self):
        # A verbose model may append call args to a tool name; the signature must
        # ignore them. Generic — holds for EVERY tool, not a per-command patch.
        assert wo._binary_sig('tsk.fls(input_path="/x", depth=2)') == "fls"
        assert wo._binary_sig("vol.pslist(pid=4)") == "pslist"
        assert wo._binary_sig('ez.recmd_hive(hive="SYSTEM")') == "recmd"
        assert wo._binary_sig('misc.regripper_hive(hive="SAM")') == "rip.pl"   # alias still applies
        assert wo._binary_sig('plaso.plaso_create_timeline(src="/x")') == "log2timeline"

    def test_arg_laden_work_order_tool_matches_its_run(self):
        # The Qwen deadlock: tsk.fls(args) ran (as `sudo fls`) but read as unrun.
        entries = [{"type": "tool_call", "success": True,
                    "cmd": "sudo fls -o 1411072 /x/surface.E01"}]
        assert wo.unrun_from_list(
            entries, ['tsk.fls(input_path="/x", depth=2)']) == []

    def test_bare_disposition_waives_arg_laden_work_order_tool(self):
        # A plain tsk.fls disposition must waive the arg-laden work-order token
        # (both sides normalize through _binary_sig).
        disp = [{"type": "disposition", "target_kind": "tool",
                 "target_id": "tsk.fls", "target_norm": "tsk.fls",
                 "reason": "inapplicable"}]
        assert wo.unrun_from_list(
            disp, ['tsk.fls(input_path="/x", depth=2)']) == []

    def test_aliased_tool_run_is_recognized(self):
        # The regression: a regripper run (as rip.pl) must satisfy the
        # misc.regripper_hive work-order entry; a genuinely-unrun tool stays flagged.
        entries = [
            {"type": "tool_call", "success": True,
             "cmd": "/usr/local/bin/rip.pl -r /mnt/x/SYSTEM"},
            {"type": "tool_call", "success": True,
             "cmd": "log2timeline.py --storage-file /x/out.plaso /mnt"},
        ]
        unrun = wo.unrun_from_list(
            entries, ["misc.regripper_hive", "plaso.plaso_create_timeline", "tsk.fls"])
        assert "regripper" not in str(unrun).lower()       # ran as rip.pl
        assert not any("plaso" in u.lower() for u in unrun)  # ran as log2timeline
        assert any("fls" in u.lower() for u in unrun)        # genuinely never ran


class TestUnretriedBlocks:
    def test_blocked_and_never_retried_flags(self):
        issues = wo.unretried_blocks([_blocked("ez_ez_sbecmd")])
        assert len(issues) == 1 and "ez.sbecmd" in issues[0]

    def test_blocked_then_retried_clears(self):
        entries = [
            _blocked("ez_ez_sbecmd"),
            _call("dotnet /opt/zimmermantools/SBECmd.dll -d /UsrClass"),  # sig 'sbecmd'
        ]
        assert wo.unretried_blocks(entries) == []

    def test_recmd_hive_block_cleared_by_recmd_run(self):
        # first-segment sig 'recmd' must match a later RECmd cmd (not 'hive').
        entries = [
            _blocked("ez_ez_recmd_hive"),
            _call("dotnet /opt/zimmermantools/RECmd/RECmd.dll -f SOFTWARE"),
        ]
        assert wo.unretried_blocks(entries) == []

    def test_retry_must_be_after_the_block(self):
        # a success BEFORE the block does not count as a retry of it.
        entries = [
            _call("dotnet /x/SBECmd.dll -d /a"),
            _blocked("ez_ez_sbecmd"),
        ]
        assert len(wo.unretried_blocks(entries)) == 1

    def test_failed_retry_does_not_count(self):
        entries = [
            _blocked("ez_ez_sbecmd"),
            _call("dotnet /x/SBECmd.dll -d /a", success=False),
        ]
        assert len(wo.unretried_blocks(entries)) == 1

    def test_prose_waiver_no_longer_clears(self):
        entries = [
            _blocked("ez_ez_sbecmd"),
            _msg("ShellBags (sbecmd) inapplicable — UsrClass.dat absent from evidence."),
        ]
        assert len(wo.unretried_blocks(entries)) == 1

    def test_typed_tool_disposition_clears(self):
        entries = [
            _blocked("ez_ez_sbecmd"),
            {"type": "disposition", "call_id": 9, "target_kind": "tool", "target_id": "ez.sbecmd",
             "target_norm": "ez.sbecmd", "reason": "inapplicable"},
        ]
        assert wo.unretried_blocks(entries) == []
        # a disposition for a different tool does not clear it
        entries[1]["target_id"] = "ez.jlecmd"
        assert len(wo.unretried_blocks(entries)) == 1
        # nor a non-waiver reason
        entries[1]["target_id"] = "ez.sbecmd"; entries[1]["reason"] = "refuted"
        assert len(wo.unretried_blocks(entries)) == 1

    def test_multiple_blocks_same_tool_dedup(self):
        entries = [_blocked("ez_ez_jlecmd"), _blocked("ez_ez_jlecmd")]
        assert len(wo.unretried_blocks(entries)) == 1

    def test_two_distinct_dropped_tools_two_issues(self):
        entries = [_blocked("ez_ez_sbecmd"), _blocked("ez_ez_jlecmd")]
        assert len(wo.unretried_blocks(entries)) == 2

    def test_no_blocks_no_issues(self):
        assert wo.unretried_blocks([_call("dotnet /x/MFTECmd.dll")]) == []

    def test_control_plane_block_is_not_a_work_order_item(self):
        # Observed: record_finding blocked by the Report-phase gate,
        # then dispositioned "inapplicable" purely to clear this check.
        entries = [_blocked("misc_record_finding"), _blocked("misc_misc_record_disposition"),
                   _blocked("misc_export_execution_log"), _blocked("reason_reason_synthesize"),
                   _blocked("ez_ez_sbecmd")]
        issues = wo.unretried_blocks(entries)
        assert len(issues) == 1 and "ez.sbecmd" in issues[0]


class TestFailedToolClosure:
    """K-8: a FAILED MCP forensic tool carries the same closure duty as a
    gate-blocked one — retry, named fallback + disposition, or typed waiver."""

    def _entries(self, retried=False, waived_rows=None):
        es = [{"type": "tool_call", "call_id": 3, "success": False,
               "cmd": "dotnet /opt/zimmermantools/PECmd.dll -d /mnt/c/Windows/Prefetch --csv /o",
               "stderr": "tool_unavailable", "exit_code": 145}]
        if retried:
            es.append({"type": "tool_call", "call_id": 9, "success": True,
                       "cmd": "dotnet /opt/zimmermantools/PECmd.dll -d /mnt/c/Windows/Prefetch --csv /o"})
        for w in (waived_rows or []):
            es.append(w)
        return es

    def test_failed_tool_never_closed_blocks(self):
        from tools._gates.work_order import unretried_blocks
        issues = unretried_blocks(self._entries())
        assert len(issues) == 1 and "FAILED" in issues[0] and "pecmd" in issues[0].lower()

    def test_retry_or_disposition_clears(self):
        from tools._gates.work_order import unretried_blocks
        assert unretried_blocks(self._entries(retried=True)) == []
        disp = {"type": "disposition", "call_id": 5, "target_kind": "tool",
                "target_id": "ez.pecmd", "target_norm": "ez.pecmd",
                "reason": "inapplicable"}
        assert unretried_blocks(self._entries(waived_rows=[disp])) == []

    def test_bash_and_control_plane_failures_out_of_scope(self):
        from tools._gates.work_order import unretried_blocks
        es = [{"type": "tool_call", "call_id": 3, "success": False,
               "cmd": "sudo fls -r /mnt/x", "source": "claude_code_bash"},
              {"type": "tool_call", "call_id": 4, "success": False,
               "cmd": "<py>:misc_export_execution_log ./reports/x"}]
        assert unretried_blocks(es) == []


def _dair(priority_tools, **kw):
    return {"type": "dair_call", "directives": {"priority_tools": list(priority_tools)}, **kw}


def _disp(tool, reason="inapplicable"):
    return {"type": "disposition", "target_kind": "tool", "target_id": tool, "reason": reason}


class TestUnrunPriorityTools:
    """A1: prescribed priority_tools must run somewhere OR be dispositioned —
    entering a phase does not satisfy its work order (K-1 counts entry only)."""

    def test_prescribed_but_never_run_flags(self):
        # DAIR prescribed usnparser + pecmd; neither ran anywhere.
        issues = wo.unrun_priority_tools([_dair(["misc.usnparser_parse", "ez.pecmd"])])
        assert len(issues) == 1
        assert "usnparser" in issues[0] and "pecmd" in issues[0]

    def test_run_anywhere_clears_even_across_phases(self):
        # Front-load: the prescribed tools ran (in an earlier phase); passes.
        entries = [
            _dair(["ez.evtxecmd", "misc.usnparser_parse"]),
            _call("dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -d /x"),  # evtxecmd
            _call("misc.usnparser_parse /mnt/x/$Extend/$UsnJrnl"),           # usnparser
        ]
        assert wo.unrun_priority_tools(entries) == []

    def test_typed_disposition_clears(self):
        entries = [_dair(["ez.pecmd"]), _disp("ez.pecmd", "absent_from_evidence")]
        assert wo.unrun_priority_tools(entries) == []

    def test_control_plane_and_reason_tools_never_flag(self):
        # reason.* / coverage.* / dair.* / record_* are not forensic work orders.
        issues = wo.unrun_priority_tools([_dair([
            "reason.hypothesize", "reason.pre_report_check", "reason.synthesize",
            "coverage.coverage_report", "dair.dair_assess", "misc.record_finding"])])
        assert issues == []

    def test_no_dair_directives_no_duty(self):
        assert wo.unrun_priority_tools([_call("dotnet MFTECmd.dll -f /x")]) == []
