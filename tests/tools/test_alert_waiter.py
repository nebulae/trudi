"""Tests for bin/trudi-alert-waiter.py — the event-driven alert blocker that
backs /trudi-watch-alerts. Loaded via importlib because the filename is
hyphenated (not a normal module name)."""
import importlib.util
import json
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

_WAITER = Path(__file__).resolve().parents[2] / "bin" / "trudi-alert-waiter.py"


@pytest.fixture(scope="module")
def waiter():
    spec = importlib.util.spec_from_file_location("trudi_alert_waiter", _WAITER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def case(tmp_path):
    alerts = tmp_path / "CASEX" / "monitoring" / "alerts"
    alerts.mkdir(parents=True)
    return tmp_path, "CASEX", alerts


class TestSeqHelpers:
    def test_new_seqs_filters_and_sorts(self, waiter, case):
        root, _cid, alerts = case
        (alerts / "5_NewNetwork.json").write_text("{}")
        (alerts / "6_NewProcess.json").write_text("{}")
        (alerts / "10_YaraProcess.json").write_text("{}")
        (alerts / "_seq.txt").write_text("10")  # non-matching helper file ignored
        assert waiter._new_seqs(alerts, since=5) == [6, 10]
        assert waiter._new_seqs(alerts, since=0) == [5, 6, 10]
        assert waiter._new_seqs(alerts, since=10) == []

    def test_new_seqs_missing_dir(self, waiter, tmp_path):
        assert waiter._new_seqs(tmp_path / "nope", since=0) == []

    def test_last_check_seq_reads_file(self, waiter, case):
        root, cid, _alerts = case
        (root / cid / "monitoring" / "_last_check_seq.txt").write_text("7")
        assert waiter._last_check_seq(root, cid) == 7

    def test_last_check_seq_defaults_zero(self, waiter, case):
        root, cid, _alerts = case
        assert waiter._last_check_seq(root, cid) == 0


class TestMain:
    def test_alerts_path_returns_immediately(self, waiter, case, capsys):
        root, cid, alerts = case
        (root / cid / "monitoring" / "_last_check_seq.txt").write_text("5")
        (alerts / "5_NewNetwork.json").write_text("{}")
        (alerts / "6_NewProcess.json").write_text("{}")
        rc = waiter.main(["--case-id", cid, "--cases-root", str(root),
                          "--interval", "0.2", "--timeout", "5"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out.strip())
        assert out["status"] == "ALERTS"
        assert out["new_seqs"] == [6]  # only seq > last_check_seq(5)

    def test_heartbeat_on_timeout(self, waiter, case, capsys):
        root, cid, _alerts = case
        rc = waiter.main(["--case-id", cid, "--cases-root", str(root),
                          "--interval", "0.2", "--timeout", "0.3"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out.strip())
        assert out["status"] == "HEARTBEAT"

    def test_explicit_since_overrides_file_oneshot(self, waiter, case, capsys):
        root, cid, alerts = case
        (root / cid / "monitoring" / "_last_check_seq.txt").write_text("0")
        (alerts / "3_NewProcess.json").write_text("{}")
        rc = waiter.main(["--case-id", cid, "--cases-root", str(root),
                          "--since-seq", "3", "--interval", "0.2", "--timeout", "0.3"])
        out = json.loads(capsys.readouterr().out.strip())
        assert out["status"] == "HEARTBEAT"  # since=3 means seq 3 is not "new"


def _readline_timeout(proc, timeout):
    """Read one stdout line from a Popen within `timeout`s, or fail."""
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([proc.stdout], [], [], 0.2)
        if r:
            line = proc.stdout.readline()
            if line:
                return line
    raise AssertionError("no output line within timeout")


class TestFollowMode:
    """--follow runs persistently (for the Monitor tool), emitting one line per
    new-alert batch with no re-arm — the fix for the dropped-re-arm gap."""

    def test_emits_initial_then_only_new(self, case):
        root, cid, alerts = case
        (alerts / "00000001_NewProcess.json").write_text("{}")
        proc = subprocess.Popen(
            [sys.executable, str(_WAITER), "--follow", "--case-id", cid,
             "--cases-root", str(root), "--interval", "0.3"],
            stdout=subprocess.PIPE, text=True)
        try:
            d1 = json.loads(_readline_timeout(proc, 6))
            assert d1["status"] == "ALERTS" and d1["new_seqs"] == [1]
            # A new alert arriving later is reported as its own event (cursor
            # advanced — seq 1 is not re-reported).
            (alerts / "00000002_NewNetwork.json").write_text("{}")
            d2 = json.loads(_readline_timeout(proc, 6))
            assert d2["new_seqs"] == [2]
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
