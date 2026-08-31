"""Background jobs (core/jobs.py): detached carve-class execution + polling."""
import json
import os
import time
from unittest.mock import patch

import pytest

from core import jobs


@pytest.fixture
def jobs_dir(tmp_path, monkeypatch):
    d = tmp_path / "jobs"
    monkeypatch.setattr(jobs, "JOBS_DIR", str(d))
    return d


def _wait_done(job_id, timeout=10):
    for _ in range(int(timeout * 20)):
        state = json.load(open(jobs._job_path(job_id)))
        if os.path.exists(state["exit_file"]):
            return
        time.sleep(0.05)
    raise AssertionError("job did not finish in time")


class TestStartJob:
    def test_returns_running_handle_immediately(self, jobs_dir, tmp_path):
        t0 = time.time()
        r = jobs.start_job(["sleep", "2"], tool="t", timeout=30,
                           output_dir=str(tmp_path / "out"))
        assert time.time() - t0 < 1.0  # did not block
        assert r["success"] and r["status"] == "running"
        assert r["job_id"] and "job_status" in r["hint"]

    def test_running_poll_reports_progress(self, jobs_dir, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        (out / "a.bin").write_text("x")
        r = jobs.start_job(["sleep", "2"], tool="t", timeout=30,
                           output_dir=str(out))
        s = jobs.job_status(r["job_id"])
        assert s["status"] == "running"
        assert s["output_files_so_far"] == 1

    def test_unknown_job_id(self, jobs_dir):
        s = jobs.job_status("deadbeef0000")
        assert s["success"] is False and "unknown job_id" in s["error"]


class TestCollection:
    def test_success_collects_output_and_logs_once(self, jobs_dir, tmp_path):
        r = jobs.start_job(["sh", "-c", "echo carved-42"], tool="t",
                           timeout=30, output_dir="")
        _wait_done(r["job_id"])
        with patch.object(jobs, "_count_outputs", return_value=0), \
             patch("core.executor._log_tool") as log:
            log.side_effect = lambda res: res.__setitem__("_trudi_call_id", 77)
            s = jobs.job_status(r["job_id"])
            assert s["success"] is True and s["status"] == "finished"
            assert "carved-42" in s["stdout"]
            assert s["_trudi_call_id"] == 77
            assert log.call_count == 1
            # second poll must NOT re-log — cid reused
            s2 = jobs.job_status(r["job_id"])
            assert log.call_count == 1
            assert s2["_trudi_call_id"] == 77
            assert "already collected" in s2["note"]

    def test_timeout_reports_partials(self, jobs_dir, tmp_path):
        out = tmp_path / "carved"
        out.mkdir()
        (out / "f1").write_text("x")
        (out / "f2").write_text("y")
        r = jobs.start_job(["sleep", "30"], tool="t", timeout=1,
                           output_dir=str(out))
        _wait_done(r["job_id"], timeout=15)
        with patch("core.executor._log_tool") as log:
            log.side_effect = lambda res: res.__setitem__("_trudi_call_id", 78)
            s = jobs.job_status(r["job_id"])
        assert s["success"] is False and s["timed_out"] is True
        assert "timed out after 1s" in s["stderr"]
        assert "2 files already produced" in s["partial_output"]

    def test_sidecar_full_stdout_passed_to_log(self, jobs_dir):
        r = jobs.start_job(["sh", "-c", "echo full-output"], tool="t",
                           timeout=30, output_dir="")
        _wait_done(r["job_id"])
        seen = {}
        with patch("core.executor._log_tool") as log:
            def grab(res):
                seen.update(res)
                res["_trudi_call_id"] = 79
            log.side_effect = grab
            jobs.job_status(r["job_id"])
        assert "full-output" in seen["_stdout_full"]


class TestTcpxtractIsAJob:
    def test_tool_returns_job_handle(self, jobs_dir, tmp_path):
        from tools.network import tcpxtract_streams
        with patch("core.jobs.subprocess.Popen") as popen:
            popen.return_value.pid = 4242
            r = tcpxtract_streams("/captures/x.pcap", str(tmp_path / "st"))
        assert r["status"] == "running" and r["job_id"]
        shell = popen.call_args[0][0][2]
        assert "tcpxtract" in shell and "timeout 1800" in shell and "sudo" in shell
