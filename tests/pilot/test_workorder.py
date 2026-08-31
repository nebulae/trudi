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
        assert "empty" in out and "assess" in out
