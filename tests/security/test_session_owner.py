"""Session-ownership scoping for the TRUDI hooks (the trace-pollution fix).

A machine-global beacon + globally-registered hooks meant EVERY concurrent
Claude Code session wrote into the one active trace. _session_owner.py scopes
writes to the beacon-owning session: cwd containment + a race-free ownership
claim under the shared hook.lock flock.
"""
import importlib.util
import json
import threading
from pathlib import Path

import pytest


def _load(name):
    hook_path = Path(__file__).resolve().parents[2] / "claude" / "hooks" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"trudi_{name}", hook_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def case(tmp_path):
    trace = tmp_path / "cases" / "case-x" / "analysis" / "T_trace.json"
    trace.parent.mkdir(parents=True)
    trace.write_text('{"entries": []}')
    beacon = tmp_path / "session.json"
    beacon.write_text(json.dumps({"case_id": "T", "path": str(trace)}))
    return {"trace": trace, "beacon": beacon,
            "owner": tmp_path / "session_owner.json",
            "case_dir": trace.parent.parent}


class TestResolveOwner:
    def test_first_session_claims(self, case):
        so = _load("_session_owner")
        p = {"session_id": "A", "cwd": str(case["case_dir"])}
        tp, reason = so.resolve_owner(p, session_file=case["beacon"],
                                      owner_file=case["owner"])
        assert tp == str(case["trace"]) and reason == "claimed"
        assert json.loads(case["owner"].read_text())["session_id"] == "A"

    def test_second_session_refused(self, case):
        so = _load("_session_owner")
        so.resolve_owner({"session_id": "A", "cwd": str(case["case_dir"])},
                         session_file=case["beacon"], owner_file=case["owner"])
        tp, reason = so.resolve_owner(
            {"session_id": "B", "cwd": str(case["case_dir"])},
            session_file=case["beacon"], owner_file=case["owner"])
        assert tp is None and reason == "not_owner"

    def test_beacon_rotation_reopens_claim(self, case):
        so = _load("_session_owner")
        so.resolve_owner({"session_id": "A", "cwd": str(case["case_dir"])},
                         session_file=case["beacon"], owner_file=case["owner"])
        # A new investigation rewrites the beacon (different bytes).
        case["beacon"].write_text(json.dumps(
            {"case_id": "T", "path": str(case["trace"]), "v": 2}))
        tp, reason = so.resolve_owner(
            {"session_id": "B", "cwd": str(case["case_dir"])},
            session_file=case["beacon"], owner_file=case["owner"])
        assert tp is not None and reason == "claimed"
        assert json.loads(case["owner"].read_text())["session_id"] == "B"

    def test_stale_owner_is_taken_over(self, case, monkeypatch):
        # A closed (or case-clear) session that claimed first must not hold
        # the trace hostage: after OWNER_TTL_SEC without a hook, a same-case
        # session takes over. Live owners refresh last_seen on every hook.
        so = _load("_session_owner")
        pa = {"session_id": "A", "cwd": str(case["case_dir"])}
        pb = {"session_id": "B", "cwd": str(case["case_dir"])}
        so.resolve_owner(pa, session_file=case["beacon"], owner_file=case["owner"])
        # Age the claim past the TTL.
        o = json.loads(case["owner"].read_text())
        o["last_seen"] = o["claimed_ts"] = "2000-01-01T00:00:00+00:00"
        case["owner"].write_text(json.dumps(o))
        # Read-only probe (guard) sees it as stale but does not claim.
        tp, reason = so.resolve_owner(pb, claim=False, session_file=case["beacon"],
                                      owner_file=case["owner"])
        assert tp is not None and reason == "stale_owner"
        assert json.loads(case["owner"].read_text())["session_id"] == "A"
        # Writing hook takes over.
        tp, reason = so.resolve_owner(pb, session_file=case["beacon"],
                                      owner_file=case["owner"])
        assert tp is not None and reason == "claimed_stale_takeover"
        assert json.loads(case["owner"].read_text())["session_id"] == "B"
        # And the displaced session is now refused.
        tp, reason = so.resolve_owner(pa, session_file=case["beacon"],
                                      owner_file=case["owner"])
        assert tp is None and reason == "not_owner"

    def test_live_owner_refreshes_last_seen(self, case):
        so = _load("_session_owner")
        pa = {"session_id": "A", "cwd": str(case["case_dir"])}
        so.resolve_owner(pa, session_file=case["beacon"], owner_file=case["owner"])
        o = json.loads(case["owner"].read_text())
        o["last_seen"] = "2000-01-01T00:00:00+00:00"
        case["owner"].write_text(json.dumps(o))
        tp, reason = so.resolve_owner(pa, session_file=case["beacon"],
                                      owner_file=case["owner"])
        assert reason == "owner"
        assert json.loads(case["owner"].read_text())["last_seen"] != "2000-01-01T00:00:00+00:00"

    def test_cwd_outside_case_refused_even_unclaimed(self, case, tmp_path):
        # The dev-session-in-the-repo scenario: never write into the case.
        so = _load("_session_owner")
        dev = tmp_path / "trudi-repo"
        dev.mkdir()
        tp, reason = so.resolve_owner(
            {"session_id": "DEV", "cwd": str(dev)},
            session_file=case["beacon"], owner_file=case["owner"])
        assert tp is None and reason == "cwd_outside_case"
        assert not case["owner"].exists()   # a refused session never claims

    def test_cwd_inside_case_subdir_allowed(self, case):
        so = _load("_session_owner")
        sub = case["case_dir"] / "exports" / "mail"
        sub.mkdir(parents=True)
        tp, _ = so.resolve_owner({"session_id": "A", "cwd": str(sub)},
                                 session_file=case["beacon"], owner_file=case["owner"])
        assert tp is not None

    def test_legacy_payload_fails_open(self, case):
        # Older harness payloads without session_id/cwd behave as before.
        so = _load("_session_owner")
        tp, reason = so.resolve_owner({}, session_file=case["beacon"],
                                      owner_file=case["owner"])
        assert tp == str(case["trace"]) and reason == "no_session_id"

    def test_claim_false_never_writes(self, case):
        so = _load("_session_owner")
        tp, reason = so.resolve_owner(
            {"session_id": "A", "cwd": str(case["case_dir"])}, claim=False,
            session_file=case["beacon"], owner_file=case["owner"])
        assert tp is not None and reason == "unclaimed"
        assert not case["owner"].exists()

    def test_no_beacon_no_case(self, tmp_path):
        so = _load("_session_owner")
        tp, reason = so.resolve_owner(
            {"session_id": "A"},
            session_file=tmp_path / "nope.json", owner_file=tmp_path / "o.json")
        assert tp is None and reason == "no_active_case"


class TestResetClearsOwner:
    def test_reset_clears_owner_file(self, tmp_path, monkeypatch):
        import tools.trudi_reset as tr
        cache = tmp_path / "cache"
        cache.mkdir()
        monkeypatch.setattr(tr, "_CACHE_DIR", str(cache))
        monkeypatch.setattr(tr, "_LOCK_FILE", str(cache / "hook.lock"))
        monkeypatch.setattr(tr, "_COUNTER_FILE", str(cache / "call_id.counter"))
        monkeypatch.setattr(tr, "_SESSION_FILE", str(cache / "session.json"))
        monkeypatch.setattr(tr, "_HOOK_STATE_FILE", str(cache / "hook_state.json"))
        monkeypatch.setattr(tr, "_SESSION_OWNER_FILE", str(cache / "session_owner.json"))
        (cache / "session_owner.json").write_text("{}")
        case_dir = tmp_path / "case"
        (case_dir / "analysis").mkdir(parents=True)
        r = tr.reset(str(case_dir), no_backup=True)
        assert r["success"]
        assert not (cache / "session_owner.json").exists()
        assert any("session_owner.json" in a for a in r["actions"])


class TestResetUnderLiveServer:
    def _tr(self, tmp_path, monkeypatch):
        import tools.trudi_reset as tr
        cache = tmp_path / "cache"
        cache.mkdir()
        for name in ("_LOCK_FILE", "_COUNTER_FILE", "_SESSION_FILE", "_HOOK_STATE_FILE",
                     "_SESSION_OWNER_FILE"):
            monkeypatch.setattr(tr, name, str(cache / Path(getattr(tr, name)).name))
        monkeypatch.setattr(tr, "_CACHE_DIR", str(cache))
        case_dir = tmp_path / "case"
        (case_dir / "analysis").mkdir(parents=True)
        return tr, cache, case_dir

    def _owner(self, cache, last_seen, beacon_path=None):
        (cache / "session_owner.json").write_text(json.dumps(
            {"session_id": "LIVE", "beacon_sig": "x", "claimed_ts": last_seen,
             "last_seen": last_seen}))
        if beacon_path is not None:
            (cache / "session.json").write_text(json.dumps(
                {"case_id": "X", "path": str(beacon_path)}))

    def _now(self):
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def test_refused_with_live_owner(self, tmp_path, monkeypatch):
        tr, cache, case_dir = self._tr(tmp_path, monkeypatch)
        self._owner(cache, self._now(), beacon_path=case_dir / "analysis" / "T_trace.json")
        r = tr.reset(str(case_dir), no_backup=True)
        assert r["success"] is False and "LIVE" in r["error"]
        assert (cache / "session_owner.json").exists()   # nothing was cleared

    def test_live_owner_of_another_case_does_not_block(self, tmp_path, monkeypatch):
        # The owner file is machine-global; a live claim on case B must not
        # refuse resetting case A.
        tr, cache, case_dir = self._tr(tmp_path, monkeypatch)
        other = tmp_path / "other-case" / "analysis"
        other.mkdir(parents=True)
        self._owner(cache, self._now(), beacon_path=other / "O_trace.json")
        assert tr.reset(str(case_dir), no_backup=True)["success"] is True

    def test_live_owner_without_beacon_does_not_block(self, tmp_path, monkeypatch):
        tr, cache, case_dir = self._tr(tmp_path, monkeypatch)
        self._owner(cache, self._now())          # no session.json at all
        assert tr.reset(str(case_dir), no_backup=True)["success"] is True

    def test_allowed_with_stale_owner(self, tmp_path, monkeypatch):
        tr, cache, case_dir = self._tr(tmp_path, monkeypatch)
        self._owner(cache, "2000-01-01T00:00:00+00:00")
        assert tr.reset(str(case_dir), no_backup=True)["success"] is True

    def test_force_overrides(self, tmp_path, monkeypatch):
        tr, cache, case_dir = self._tr(tmp_path, monkeypatch)
        self._owner(cache, self._now(), beacon_path=case_dir / "analysis" / "T_trace.json")
        r = tr.reset(str(case_dir), no_backup=True, force=True)
        assert r["success"] is True and any("--force" in a for a in r["actions"])


class TestFlushWithMissingTrace:
    def test_missing_file_is_recorded_not_fatal(self, tmp_path, monkeypatch):
        import core.execution_log as elog
        monkeypatch.setattr(elog, "_CALL_ID_COUNTER_FILE", str(tmp_path / "c.counter"))
        monkeypatch.setattr(elog, "_TRACE_LOCK_FILE", str(tmp_path / "hook.lock"))
        trace = tmp_path / "case" / "analysis" / "T_trace.json"
        trace.parent.mkdir(parents=True)
        (tmp_path / "case" / ".trace-backups" / "20990101T000000Z").mkdir(parents=True)
        l = elog.ExecutionLog()
        l.configure("T", str(trace), save_session=False)
        l.record_tool_call("a", True, False, 0, 0)
        trace.unlink()                                   # a reset moved it away
        l.record_tool_call("b", True, False, 0, 0)       # next flush
        assert trace.exists()
        errs = [e for e in l._entries if e.get("category") == "trace_file_missing_at_flush"]
        assert len(errs) == 1 and "20990101T000000Z" in errs[0]["detail"]
        l.record_tool_call("c", True, False, 0, 0)       # noted once only
        assert len([e for e in l._entries if e.get("category") == "trace_file_missing_at_flush"]) == 1


class TestCounterDiscipline:
    def test_sync_never_moves_counter_backwards(self, tmp_path, monkeypatch):
        # A second session's configure() must not rewind the shared counter
        # under a session that already advanced it.
        import core.execution_log as elog
        counter = tmp_path / "call_id.counter"
        counter.write_text(json.dumps({"next": 500}))
        monkeypatch.setattr(elog, "_CALL_ID_COUNTER_FILE", str(counter))
        monkeypatch.setattr(elog, "_TRACE_LOCK_FILE", str(tmp_path / "hook.lock"))
        l = elog.ExecutionLog()
        l.configure("SYNC-T", str(tmp_path / "t.json"), save_session=False)  # _seq=0
        assert json.loads(counter.read_text())["next"] == 500

    def test_concurrent_allocations_stay_dense(self, tmp_path, monkeypatch):
        import core.execution_log as elog
        monkeypatch.setattr(elog, "_CALL_ID_COUNTER_FILE", str(tmp_path / "c.counter"))
        monkeypatch.setattr(elog, "_TRACE_LOCK_FILE", str(tmp_path / "hook.lock"))
        got = []
        def alloc():
            for _ in range(25):
                got.append(elog._next_shared_call_id())
        threads = [threading.Thread(target=alloc) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(got) == list(range(1, 101))


class TestResetScopedToBeaconCase:
    """H-4: a reset of case A never clears the machine-global owner/hook_state/
    session files while the beacon points at case B."""

    def _tr(self, tmp_path, monkeypatch):
        import tools.trudi_reset as tr
        cache = tmp_path / "cache"
        cache.mkdir()
        for name in ("_LOCK_FILE", "_COUNTER_FILE", "_SESSION_FILE", "_HOOK_STATE_FILE",
                     "_SESSION_OWNER_FILE"):
            monkeypatch.setattr(tr, name, str(cache / Path(getattr(tr, name)).name))
        monkeypatch.setattr(tr, "_CACHE_DIR", str(cache))
        return tr, cache

    def test_foreign_beacon_keeps_cache_files(self, tmp_path, monkeypatch):
        tr, cache = self._tr(tmp_path, monkeypatch)
        case_a = tmp_path / "caseA"; (case_a / "analysis").mkdir(parents=True)
        case_b = tmp_path / "caseB"; (case_b / "analysis").mkdir(parents=True)
        (cache / "session.json").write_text(json.dumps({"case_id": "B", "path": str(case_b / "analysis" / "B_trace.json")}))
        (cache / "session_owner.json").write_text(json.dumps({"session_id": "LIVE-B", "beacon_sig": "x",
                                                              "claimed_ts": "2000-01-01T00:00:00+00:00",
                                                              "last_seen": "2000-01-01T00:00:00+00:00"}))
        (cache / "hook_state.json").write_text("{}")
        r = tr.reset(str(case_a), no_backup=True)
        assert r["success"]
        assert (cache / "session_owner.json").exists() and (cache / "session.json").exists()
        assert any("kept session_owner.json" in a for a in r["actions"])
        # Own case: cleared as before.
        r = tr.reset(str(case_b), no_backup=True, force=True)
        assert not (cache / "session_owner.json").exists()
