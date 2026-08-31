"""Work-order state machine (pilot/workorder.py)."""
from pilot import workorder as wo


def _state(**kw):
    return wo.SessionState(**kw)


class TestOpeningQueues:
    def test_ritual_ends_in_assess_and_carries_question(self):
        items = wo.ritual_items('Who sent the "harassing" email?')
        assert len(items) == 3
        assert items[0].text.startswith("reason.hypothesize")
        assert "harassing" in items[0].text and '"' not in items[0].text[25:-1].replace(
            'observation="', "").rsplit('"', 1)[0][:0]  # quotes escaped
        assert items[1].text.startswith("reason.plan")
        assert items[2].text == "assess"

    def test_resume_is_a_single_assess(self):
        items = wo.resume_items()
        assert [i.text for i in items] == ["assess"]


class TestApplyAssess:
    def test_push_updates_stack_and_items(self):
        s = _state()
        wo.apply_assess(s, {"stack_action": "push", "next_phase": "Collect",
                            "transition_rationale": "plan satisfied",
                            "directives": {"priority_tools": ["ez.mftecmd",
                                                              "tsk.fls image"]}})
        assert s.phase == "Collect" and len(s.phase_stack) == 1
        assert [i.text for i in s.items] == ["ez.mftecmd", "tsk.fls image"]
        assert all(i.cue == "dair" for i in s.items)

    def test_pop_and_stay(self):
        s = _state(phase_stack=[{"phase": "Triage", "depth": 0},
                                {"phase": "Analyze", "depth": 1}])
        wo.apply_assess(s, {"stack_action": "pop", "directives": {}})
        assert s.phase == "Triage"
        wo.apply_assess(s, {"stack_action": "stay", "directives": {}})
        assert s.phase == "Triage"

    def test_done_items_kept_open_replaced_ran_reset(self):
        s = _state()
        s.items = [wo.WorkItem("ez.pecmd", status="done"),
                   wo.WorkItem("net.ngrep_search", status="open")]
        s.ran = [{"cmd": "x", "ok": True, "cid": 1}]
        wo.apply_assess(s, {"directives": {"priority_tools": ["ez.evtxecmd"]}})
        assert [(i.text, i.status) for i in s.items] == \
            [("ez.pecmd", "done"), ("ez.evtxecmd", "open")]
        assert s.ran == []


class TestPrefillAndMerge:
    def test_apply_assess_prefills_items(self):
        s = _state()
        wo.apply_assess(s, {"directives": {"priority_tools": ["tsk.fls"]}},
                        prefill=lambda t: t + " image=/e/disk.E01")
        assert s.items[0].text == "tsk.fls image=/e/disk.E01"
        assert s.items[0].label == "tsk.fls image=/e/disk.E01"

    def test_merge_directives_appends_prefilled_no_dupes(self):
        s = _state(items=[wo.WorkItem("net.ngrep_search pattern=x")])
        added = wo.merge_directives(
            s, ["net.ngrep_search other", "ez.pecmd"],
            prefill=lambda t: t + " prefilled=1")
        assert added == 1  # ngrep already open → not duplicated
        assert s.items[-1].text == "ez.pecmd prefilled=1"
        assert s.items[-1].cue == "reason"

    def test_reason_items_survive_assess(self):
        s = _state()
        wo.merge_directives(s, ["ez.pecmd"])
        wo.apply_assess(s, {"directives": {"priority_tools": ["tsk.fls"]}})
        assert [i.text for i in s.items if i.status == "open"] == \
            ["ez.pecmd", "tsk.fls"]


class TestRunTracking:
    def test_success_retires_matching_item(self):
        s = _state(items=[wo.WorkItem("ez.mftecmd --csv analysis/")])
        wo.record_ran(s, "ez.mftecmd file=/x", True, cid=7)
        assert s.items[0].status == "done"
        assert wo.ran_cids(s) == [7]

    def test_failure_keeps_item_open(self):
        s = _state(items=[wo.WorkItem("ez.mftecmd")])
        wo.record_ran(s, "ez.mftecmd file=/x", False)
        assert s.items[0].status == "open"
        assert wo.ran_cids(s) == []

    def test_opening_summary_follows_resumption_contract(self):
        assert "starting" in wo.opening_summary(_state())
        assert "Resuming after interruption" in \
            wo.opening_summary(_state(resumed=True))

    def test_draft_summary_and_nag(self):
        s = _state(nag_after=2)
        assert "no tools" in wo.draft_summary(s).lower()
        wo.record_ran(s, "ez.mftecmd f=/x", True, cid=1)
        wo.record_ran(s, "tsk.fls i=/y", False)
        d = wo.draft_summary(s)
        assert "ez.mftecmd ok" in d and "tsk.fls FAILED" in d
        assert wo.needs_nag(s)


class TestSelectDismiss:
    def test_select_counts_open_only(self):
        s = _state(items=[wo.WorkItem("a.b", status="done"),
                          wo.WorkItem("c.d"), wo.WorkItem("e.f")])
        assert wo.select(s, 1) == "c.d"
        assert wo.select(s, 2) == "e.f"
        assert wo.select(s, 3) is None and wo.select(s, 0) is None

    def test_dismiss_validates_reason_and_range(self):
        s = _state(items=[wo.WorkItem("ez.pecmd prefetch")])
        assert wo.dismiss(s, 1, "not_a_reason") is None
        assert wo.dismiss(s, 9, "inapplicable") is None
        item = wo.dismiss(s, 1, "inapplicable")
        assert item is not None and item.status == "dismissed"
        assert wo.select(s, 1) is None  # no longer selectable


class TestRender:
    def test_render_shows_numbers_status_and_help(self):
        s = _state(phase_stack=[{"phase": "Collect", "depth": 0}],
                   items=[wo.WorkItem("ez.mftecmd", status="done"),
                          wo.WorkItem("net.ngrep_search pattern=jean"),
                          wo.WorkItem("ez.pecmd", status="dismissed")])
        out = wo.render(s)
        assert "Collect" in out
        assert "✓" in out and "▸ 1  net.ngrep_search" in out
        assert "ez.pecmd" not in out  # dismissed items hidden
        assert "dismiss N" in out

    def test_render_empty(self):
        out = wo.render(_state())
        assert "no open items" in out and "assess" in out

    def test_render_color_wraps_plain(self):
        s = _state(items=[wo.WorkItem("net.ngrep_search pattern=jean")])
        colored = wo.render(s, color=True)
        assert "\x1b[" in colored and "net.ngrep_search" in colored
        assert "\x1b[" not in wo.render(s)

    def test_fit_keeps_the_filename(self):
        long = "net.tcpdump_extract_ips pcap_file=/home/trin/cases/nitroba/evidence/nitroba.pcap"
        fitted = wo._fit(long)
        assert len(fitted) <= 75
        assert fitted.endswith("nitroba.pcap") and fitted.startswith("net.tcpdump")


class TestSituation:
    def test_build_situation_packages_state(self):
        s = _state(case_context="Case X. Question: who?",
                   phase_stack=[{"phase": "Collect", "depth": 0}],
                   items=[wo.WorkItem("ez.pecmd"),
                          wo.WorkItem("tsk.fls", status="done")])
        wo.record_ran(s, "net.ngrep_search p=x", True, cid=4)
        sit = wo.build_situation(s)
        assert "Case X" in sit and "phase: Collect" in sit
        assert "net.ngrep_search ok" in sit
        assert "open work order: ez.pecmd" in sit
        assert "tsk.fls" not in sit.split("open work order:")[1]


class TestBaseline:
    def test_baseline_typed_by_evidence(self):
        items = wo.baseline_items(["/e/nitroba.pcap", "/e/disk.E01"])
        texts = [i.text for i in items]
        assert "net.tcpdump_read pcap_file=/e/nitroba.pcap" in texts
        assert "net.tcpdump_list_connections pcap_file=/e/nitroba.pcap" in texts
        assert "ewf.info image=/e/disk.E01" in texts
        assert all(i.cue == "baseline" for i in items)
        assert wo.baseline_items([]) == []

    def test_ritual_opens_with_baseline_and_roster_hunt(self):
        items = wo.ritual_items("Who used the network?",
                                evidence=["/e/n.pcap"],
                                roster=["Jean Jones", "Alison Smith"])
        texts = [i.text for i in items]
        assert texts[0].startswith("net.")            # baseline first
        knowns = next(t for t in texts if "knowns_pattern_generate" in t)
        assert 'reference_set="Jean Jones,Alison Smith"' in knowns
        assert "derivation_type=person_username" in knowns
        plan = next(t for t in texts if t.startswith("reason.plan"))
        assert 'evidence_available="/e/n.pcap"' in plan  # no placeholder
        assert texts[-1] == "assess"

    def test_ritual_without_roster_or_evidence_still_reasons(self):
        items = wo.ritual_items("q?")
        texts = [i.text for i in items]
        assert not any("knowns" in t for t in texts)
        assert texts[0].startswith("reason.hypothesize")


class TestShakedownFixes:
    def test_merge_never_readds_done_or_dismissed(self):
        s = _state(items=[wo.WorkItem("net.tcpdump_list_connections x=1",
                                      status="done"),
                          wo.WorkItem("misc.evtx_filter", status="dismissed")])
        added = wo.merge_directives(
            s, ["net.tcpdump_list_connections", "misc.evtx_filter",
                "net.tcpdump_extract_dns"])
        assert added == 1
        assert s.items[-1].text == "net.tcpdump_extract_dns"

    def test_opening_summary_honest_mid_investigation(self):
        s = _state()
        s.items = [wo.WorkItem("net.tcpdump_read p=x", status="done")]
        wo.record_ran(s, "net.tcpdump_read p=x", True, cid=1)
        wo.apply_assess(s, {"directives": {}})  # resets ran, total stays
        summary = wo.opening_summary(s)
        assert "No new tool results" in summary
        assert "net.tcpdump_read" in summary
        assert "starting" not in summary.lower()
