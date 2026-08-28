"""Repeat-call gate (core/middleware.py): identical call + identical result.

Observed live: a compaction-driven closed loop re-ran the same two ngrep
searches 147/146 times (each identical empty result; each compaction dropped
the negative; OpenCode's auto-continue restarted the cycle). The gate fires
ONLY on provable redundancy — same args AND same result — so a re-read of a
changed file or a legitimate single retry never blocks.
"""
import pytest

import core.middleware as M


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    monkeypatch.setattr(M, "_repeat_state", {})
    monkeypatch.setattr(M, "REPEAT_GATE_ENABLED", True)
    monkeypatch.setattr(M, "REPEAT_BLOCK_AFTER", 4)


ARGS = {"pcap_file": "/e/n.pcap", "pattern": "CHEM109"}
RESULT = {"success": True, "stdout": "", "exit_code": 0}


def _key(args=ARGS, tool="net_ngrep_search"):
    return M._repeat_key(tool, args)


class TestNotice:
    def test_first_call_is_silent(self):
        assert M._repeat_update(_key(), "net_ngrep_search", dict(RESULT)) == ""

    def test_identical_call_and_result_notices_with_finding_shape(self):
        k = _key()
        M._repeat_update(k, "net_ngrep_search", dict(RESULT))
        msg = M._repeat_update(k, "net_ngrep_search", dict(RESULT))
        assert "2x" in msg
        assert "record_finding" in msg and "negative" in msg
        assert "dair.dair_assess" in msg

    def test_different_args_are_different_keys(self):
        M._repeat_update(_key(), "t", dict(RESULT))
        other = _key(args={"pattern": "lilytuckrige"})
        assert M._repeat_update(other, "t", dict(RESULT)) == ""

    def test_changed_result_resets(self):
        k = _key()
        M._repeat_update(k, "t", dict(RESULT))
        # the produced file grew / new packets matched — result differs
        assert M._repeat_update(k, "t", {**RESULT, "stdout": "match!"}) == ""
        # and the identical-counter restarted from the new result
        assert "2x" in M._repeat_update(k, "t", {**RESULT, "stdout": "match!"})

    def test_volatile_keys_do_not_break_identity(self):
        k = _key()
        M._repeat_update(k, "t", {**RESULT, "_trudi_call_id": 7,
                                  "elapsed_seconds": 0.4})
        msg = M._repeat_update(k, "t", {**RESULT, "_trudi_call_id": 9,
                                        "elapsed_seconds": 1.7})
        assert "2x" in msg

    def test_note_and_notice_fields_excluded_from_hash(self):
        k = _key()
        M._repeat_update(k, "t", {**RESULT, "dair_notice": "x"})
        assert "2x" in M._repeat_update(k, "t", {**RESULT, "dair_notice": "y"})


class TestBlock:
    def test_blocks_after_threshold_identical_results(self):
        k = _key()
        for _ in range(5):                     # 1 baseline + 4 identical
            M._repeat_update(k, "net_ngrep_search", dict(RESULT))
        msg = M._repeat_precheck(k, "net_ngrep_search")
        assert "repeat_call_gate" in msg
        assert "record_finding" in msg

    def test_no_block_below_threshold(self):
        k = _key()
        for _ in range(4):                     # 1 baseline + 3 identical
            M._repeat_update(k, "net_ngrep_search", dict(RESULT))
        assert M._repeat_precheck(k, "net_ngrep_search") == ""

    def test_block_disabled_by_zero_threshold(self, monkeypatch):
        monkeypatch.setattr(M, "REPEAT_BLOCK_AFTER", 0)
        k = _key()
        for _ in range(10):
            M._repeat_update(k, "t", dict(RESULT))
        assert M._repeat_precheck(k, "t") == ""

    def test_kill_switch(self, monkeypatch):
        monkeypatch.setattr(M, "REPEAT_GATE_ENABLED", False)
        k = _key()
        for _ in range(10):
            M._repeat_update(k, "t", dict(RESULT))
        assert M._repeat_update(k, "t", dict(RESULT)) == ""
        assert M._repeat_precheck(k, "t") == ""


class TestBounds:
    def test_state_is_bounded(self):
        for i in range(M._REPEAT_MAX_KEYS + 50):
            M._repeat_update(_key(args={"i": i}), "t", dict(RESULT))
        assert len(M._repeat_state) <= M._REPEAT_MAX_KEYS

    def test_fail_open_on_weird_payload(self):
        # default=str serializes odd objects; an outright failure returns ""
        class Weird:
            def __str__(self):  # noqa: D105
                raise RuntimeError("boom")
        k = _key()
        assert M._repeat_update(k, "t", {"x": Weird()}) == ""


class TestEnrichRotationCannotDefeatGate:
    """Regression: enrich() adds a ROTATING discipline_reminder to every
    result; the gate must hash the RAW tool output, so identical calls still
    register as identical. (This is why the wiring passes result-BEFORE-enrich
    to _repeat_update — a unit-level guard that the raw payload is what's
    hashed.)"""

    def test_rotating_enrich_field_does_not_reset_identity(self):
        k = _key()
        # Simulate the raw tool output being identical each call; the rotating
        # enrich field never reaches _repeat_update because we hash raw.
        M._repeat_update(k, "net_ngrep_search", dict(RESULT))
        msg = M._repeat_update(k, "net_ngrep_search", dict(RESULT))
        assert "2x" in msg

    def test_rotating_enrich_field_excluded_from_hash_too(self):
        # Defense in depth: even if a decorated result reaches the gate, the
        # rotating interpretive fields are in the strip set, so identity holds.
        k = _key()
        M._repeat_update(k, "t", {**RESULT, "discipline_reminder": "A",
                                  "data_provenance": "p"})
        msg = M._repeat_update(k, "t", {**RESULT, "discipline_reminder": "B",
                                        "data_provenance": "p"})
        assert "2x" in msg

    def test_wiring_hashes_raw_before_enrich(self):
        import inspect
        import core.middleware as MM
        src = inspect.getsource(MM.NarrationMiddleware.on_call_tool)
        assert "BEFORE enrich" in src


class TestPollAdvisory:
    """job_status busy-wait: async carves free the agent to work while the
    carve runs, but a literal model busy-polls (observed: 86 consecutive
    job_status calls). Advisory-only — never blocks (polling is legitimate and
    the loop self-terminates when the job finishes)."""

    def _reset(self, monkeypatch):
        monkeypatch.setattr(M, "_poll_run", {"count": 0})
        monkeypatch.setattr(M, "POLL_ADVISORY_AFTER", 2)

    RUNNING = {"success": True, "status": "running",
               "output_files_so_far": 900, "elapsed_seconds": 120.0}

    def test_first_polls_silent_then_advises(self, monkeypatch):
        self._reset(monkeypatch)
        assert M._note_poll_and_advise(dict(self.RUNNING)) == ""   # 1
        assert M._note_poll_and_advise(dict(self.RUNNING)) == ""   # 2
        msg = M._note_poll_and_advise(dict(self.RUNNING))          # 3
        assert "POLLING LOOP" in msg and "dair.dair_assess" in msg

    def test_finished_job_never_advises(self, monkeypatch):
        self._reset(monkeypatch)
        for _ in range(5):
            M._note_poll_and_advise(dict(self.RUNNING))
        done = {"success": True, "status": "finished", "output_files": 1673}
        assert M._note_poll_and_advise(done) == ""

    def test_real_tool_call_resets_the_run(self, monkeypatch):
        self._reset(monkeypatch)
        for _ in range(4):
            M._note_poll_and_advise(dict(self.RUNNING))
        M._reset_poll_run()                     # a net.* call happened
        assert M._note_poll_and_advise(dict(self.RUNNING)) == ""   # count back to 1

    def test_fail_open(self, monkeypatch):
        self._reset(monkeypatch)
        # non-dict payload must not raise
        for _ in range(3):
            assert M._note_poll_and_advise(None) == ""
