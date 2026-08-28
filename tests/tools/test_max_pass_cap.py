"""max_pass_cap — no Triage override while concrete verification challenges are open."""
from unittest.mock import patch

from tools._gates import max_pass_cap as mpc


def _dair(cid, challenges):
    return {"type": "dair_call", "call_id": cid, "current_phase": "Triage",
            "verification_challenges": challenges}


def _ch(claim, method, verified=None):
    return {"claim": claim, "challenge_method": method, "verified": verified}


def _tool(cid, cmd, success=True):
    return {"type": "tool_call", "call_id": cid, "cmd": cmd, "success": success}


def _narr(cid, content):
    return {"type": "investigation_narration", "call_id": cid, "content": content}


class TestOpenChallenges:
    def test_open_when_nothing_ran(self):
        entries = [_dair(5, [_ch("account created 06-18", "ez.evtxecmd")])]
        assert [c["challenge_method"] for c in mpc.open_challenges(entries, entries[0])] == ["ez.evtxecmd"]

    def test_later_matching_tool_run_clears(self):
        entries = [_dair(5, [_ch("x", "ez.evtxecmd")]),
                   _tool(6, "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f Security.evtx")]
        assert mpc.open_challenges(entries, entries[0]) == []

    def test_later_run_must_overlap_the_claim(self):
        # F-1: signature alone is too coarse — a stat of the E01 image does not
        # verify "Rubber Ducky volume in MountedDevices".
        ch = _ch("USB Rubber Ducky (ATMEL Ducky_Storage) volume in MountedDevices", "strings.stat_file")
        entries = [_dair(5, [ch]), _tool(6, "stat /cases/x/evidence/surface_physical.E01")]
        assert len(mpc.open_challenges(entries, entries[0])) == 1
        entries.append({"type": "tool_call", "call_id": 7, "success": True,
                        "cmd": "stat /mnt/ntfs/Windows/System32/config/SYSTEM",
                        "stdout_excerpt": "MountedDevices … Ducky_Storage"})
        assert mpc.open_challenges(entries, entries[0]) == []
        toks = mpc.claim_tokens(ch["claim"])
        assert "ducky_storage" in toks and "mounteddevices" in toks and "volume" not in toks

    def test_parametrised_method_uses_the_tool_name(self):
        # challenge_method written as a call expression.
        ch = _ch("defaultprinter account created 2016-06-18 20:40:54 UTC",
                 'misc.evtx_filter(event_ids="4720", start_time="2016-06-18T20:30:00")')
        entries = [_dair(5, [ch])]
        assert len(mpc.open_challenges(entries, entries[0])) == 1
        # K-2: the verifying run must TOUCH the claim (a token in its output),
        # not merely be the same tool family.
        entries.append({"type": "tool_call", "call_id": 6, "success": True,
                        "cmd": "/usr/local/bin/evtx_dump.py /mnt/ntfs/Windows/System32/winevt/Logs/Security.evtx",
                        "stdout_excerpt": "4720 TargetUserName: defaultprinter 2016-06-18 20:40:54"})
        assert mpc.open_challenges(entries, entries[0]) == []

    def test_extractor_run_must_touch_the_named_hive(self):
        # H-8: "VeraCrypt uninstall key in SOFTWARE" is not verified by a RECmd
        # run over SAM; a run over SOFTWARE (or with no hive named) is.
        ch = _ch("VeraCrypt 1.17 uninstall key LastWrite in SOFTWARE hive", "ez.recmd_hive")
        entries = [_dair(5, [ch]), _tool(6, "dotnet /opt/zimmermantools/RECmd/RECmd.dll -f /mnt/c/Windows/System32/config/SAM --csv /o")]
        assert len(mpc.open_challenges(entries, entries[0])) == 1
        entries.append(_tool(7, "dotnet /opt/zimmermantools/RECmd/RECmd.dll -f /mnt/c/Windows/System32/config/SOFTWARE --csv /o"))
        assert mpc.open_challenges(entries, entries[0]) == []
        ch2 = _ch("defaultprinter account (RID 1006) created 2016-06-18", "ez.recmd_hive")
        entries2 = [_dair(5, [ch2]), _tool(6, "dotnet /opt/zimmermantools/RECmd/RECmd.dll -f /mnt/c/Windows/System32/config/SAM --csv /o")]
        # K-2: no hive named, but the run still has to touch the claim.
        assert len(mpc.open_challenges(entries2, entries2[0])) == 1
        entries2.append({"type": "tool_call", "call_id": 7, "success": True,
                         "cmd": "dotnet /opt/zimmermantools/RECmd/RECmd.dll -f /mnt/c/Windows/System32/config/SAM --csv /o",
                         "stdout_excerpt": "SAM users: defaultprinter RID 1006"})
        assert mpc.open_challenges(entries2, entries2[0]) == []

    def test_tool_run_before_the_dair_call_does_not_count(self):
        entries = [_tool(4, "dotnet EvtxECmd.dll -f x"), _dair(5, [_ch("x", "ez.evtxecmd")])]
        assert len(mpc.open_challenges(entries, entries[1])) == 1

    def test_later_dair_marking_verified_clears(self):
        entries = [_dair(5, [_ch("x", "ez.evtxecmd")]),
                   _dair(9, [_ch("x", "ez.evtxecmd", verified=True)])]
        assert mpc.open_challenges(entries, entries[0]) == []

    def test_prose_waiver_no_longer_clears(self):
        entries = [_dair(5, [_ch("x", "ez.pecmd")]),
                   _narr(7, "pecmd inapplicable — no Prefetch directory on this image")]
        assert len(mpc.open_challenges(entries, entries[0])) == 1

    def test_typed_tool_disposition_clears(self):
        entries = [_dair(5, [_ch("x", "ez.pecmd")]),
                   {"type": "disposition", "call_id": 7, "target_kind": "tool",
                    "target_id": "ez.pecmd", "target_norm": "ez.pecmd", "reason": "inapplicable"}]
        assert mpc.open_challenges(entries, entries[0]) == []

    def test_typed_challenge_disposition_clears(self):
        entries = [_dair(5, [_ch("Prefetch files confirm tool usage", "ez.pecmd")]),
                   {"type": "disposition", "call_id": 7, "target_kind": "challenge",
                    "target_id": "5:Prefetch files confirm tool usage",
                    "target_norm": "5:prefetchfilesconfirmtoolusage", "reason": "absent_from_evidence"}]
        assert mpc.open_challenges(entries, entries[0]) == []
        # a disposition scoped to a different dair call does not clear it
        entries[1]["target_id"] = "9:Prefetch files confirm tool usage"
        assert len(mpc.open_challenges(entries, entries[0])) == 1

    def test_reason_methods_and_unparseable_skipped(self):
        entries = [_dair(5, [_ch("a", "reason.hypothesize"), _ch("b", "x"),
                             _ch("c", "ez.evtxecmd", verified=False)])]
        assert mpc.open_challenges(entries, entries[0]) == []

    def test_failed_tool_run_does_not_clear(self):
        entries = [_dair(5, [_ch("x", "ez.evtxecmd")]),
                   _tool(6, "dotnet EvtxECmd.dll -f x", success=False)]
        assert len(mpc.open_challenges(entries, entries[0])) == 1


class TestGateAndPreReport:
    def test_issue_strings_deduplicated(self):
        entries = [_dair(5, [_ch("x", "ez.evtxecmd")]), _dair(8, [_ch("x", "ez.evtxecmd")])]
        issues = mpc.open_challenge_issues(entries)
        assert len(issues) == 1 and "ez.evtxecmd" in issues[0]

    def test_self_correction_wrapper_refuses_then_allows(self):
        from core.execution_log import log
        from tools.misc import record_self_correction
        log.record_dair_call("Triage", "", False, "", "", "stay", "",
                             verification_challenges=[_ch("acct created", "ez.evtxecmd")])
        fn = getattr(record_self_correction, "fn", record_self_correction)
        r = fn(trigger="dair_max_pass_cap", prior_belief="stay x3", new_belief="push Collect",
               input_call_ids=[1])
        assert r["success"] is False and r["gate"] == "max_pass_cap"
        assert "ez.evtxecmd" in r["error"]
        # Other triggers are untouched.
        r2 = fn(trigger="evaluate_challenged", prior_belief="a", new_belief="b", input_call_ids=[1])
        assert r2.get("success", True) is not False or r2.get("gate") != "max_pass_cap"
        # Run the challenge_method (touching the claim) → the cap may now fire.
        log.record_tool_call("dotnet EvtxECmd.dll -f Security.evtx", True, False, 0, 0,
                             stdout_excerpt="4720 acct created rows")
        r3 = fn(trigger="dair_max_pass_cap", prior_belief="stay x3", new_belief="push Collect",
                input_call_ids=[1])
        assert r3.get("gate") != "max_pass_cap"

    def test_pre_report_blocks_on_open_challenge(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_pre_report_check
        l = ExecutionLog()
        l.configure("MPC", str(tmp_path / "t.json"), save_session=False)
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        l.record_dair_call("Triage", "", False, "", "", "stay", "",
                           verification_challenges=[_ch("acct created", "ez.evtxecmd")])
        with patch("core.execution_log.log", l):
            r = reason_pre_report_check()
        assert any("verification challenge never run" in i for i in r["blocking_issues"])
        l.record_tool_call("dotnet EvtxECmd.dll -f Security.evtx", True, False, 0, 0,
                           stdout_excerpt="4720 acct created rows")
        with patch("core.execution_log.log", l):
            r = reason_pre_report_check()
        assert not any("verification challenge never run" in i for i in r["blocking_issues"])


class TestClaimTouchVerification:
    """K-2: an extractor run verifies a token-bearing challenge only when it
    TOUCHED the claim — a token in its cmd, stored output, or sidecar. An
    unrelated parse of the same tool no longer verifies by association."""

    def test_extractor_without_claim_token_does_not_verify(self):
        from tools._gates.max_pass_cap import run_matches_challenge, claim_tokens
        toks = claim_tokens("TaskCache task created 2016-10-30")
        run = {"cmd": "dotnet EvtxECmd.dll -f Security.evtx --csv /out",
               "stdout_excerpt": "4624 4720 rows parsed"}
        assert run_matches_challenge(run, "evtxecmd", toks) is False

    def test_extractor_touching_the_claim_verifies(self):
        from tools._gates.max_pass_cap import run_matches_challenge, claim_tokens
        toks = claim_tokens("defaultprinter account created (4720)")
        run = {"cmd": "dotnet EvtxECmd.dll -f Security.evtx --csv /out",
               "stdout_excerpt": "TargetUserName: defaultprinter 4720"}
        assert run_matches_challenge(run, "evtxecmd", toks) is True

    def test_sidecar_text_counts(self, tmp_path):
        from tools._gates.max_pass_cap import run_matches_challenge, claim_tokens
        side = tmp_path / "s.txt"
        side.write_text("x" * 700 + "\nTaskCache \\Tree entry 2016-10-30\n")
        toks = claim_tokens("TaskCache task created 2016-10-30")
        run = {"cmd": "dotnet RECmd.dll -f SYSTEM --csv /out",
               "stdout_excerpt": "head only", "stdout_path": str(side)}
        assert run_matches_challenge(run, "recmd", toks) is True

    def test_tokenless_claim_keeps_legacy_behaviour(self):
        from tools._gates.max_pass_cap import run_matches_challenge
        run = {"cmd": "dotnet EvtxECmd.dll -f Security.evtx"}
        assert run_matches_challenge(run, "evtxecmd", set()) is True

    def test_hive_mismatch_still_refuses(self):
        from tools._gates.max_pass_cap import run_matches_challenge, claim_tokens
        toks = claim_tokens("fDenyTSConnections written in SYSTEM software hive")
        run = {"cmd": "dotnet RECmd.dll -f /x/SAM --csv /out",
               "stdout_excerpt": "fdenytsconnections software"}
        assert run_matches_challenge(run, "recmd", toks) is False
