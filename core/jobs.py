"""Background job runner for carve-class forensic tools.

A full-pcap tcpxtract carve (or bulk_extractor / foremost / photorec) runs for
tens of minutes. Run synchronously it blocks the driving agent's whole turn and,
on a client whose MCP call is time-bounded, invites a mid-run cancellation that
can tear down the connection. A human analyst starts a long carve and keeps
working other artifacts; `start_job` gives the agent the same option.

`start_job` spawns the command detached (its own session, an exit-code sentinel
file) and returns a `job_id` immediately. `job_status(job_id)` polls: while
running it reports elapsed time and files-so-far; on completion it records the
underlying command as a normal, citable `tool_call` (carrying the full stdout
sidecar) exactly once, so a finding cites the job's collection the same way it
would a synchronous run — the audit trail is identical. Partial output from a
timed-out carve remains in `output_dir` and is surfaced as usable evidence.

Stdlib only — nothing here drags a heavy import into the PreToolUse guard.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

# Overridable in tests. One JSON state file per job: JOBS_DIR/<job_id>.json.
JOBS_DIR = os.path.expanduser("~/.cache/trudi/jobs")


def _job_path(job_id: str) -> str:
    return os.path.join(JOBS_DIR, f"{job_id}.json")


def _new_job_id(tool: str) -> str:
    stem = (tool or "job").replace("/", "_").replace(".", "_")
    return f"{stem}-{os.urandom(6).hex()}"


def _count_outputs(output_dir: str) -> int:
    """Files produced in a carve's output dir so far (patchable in tests)."""
    try:
        return sum(1 for _ in os.scandir(output_dir))
    except OSError:
        return 0


def start_job(cmd: list[str], tool: str, timeout: int, output_dir: str,
              needs_sudo: bool = False) -> dict:
    """Spawn `cmd` detached under a hard `timeout` budget; return immediately
    with a running-job handle. Never blocks."""
    os.makedirs(JOBS_DIR, exist_ok=True)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    job_id = _new_job_id(tool)
    jdir = os.path.join(JOBS_DIR, f"{job_id}.d")
    os.makedirs(jdir, exist_ok=True)
    stdout_file = os.path.join(jdir, "stdout")
    stderr_file = os.path.join(jdir, "stderr")
    exit_file = os.path.join(jdir, "exit")

    import shlex
    # `timeout` (coreutils) enforces the budget and exits 124 on expiry; run it
    # under sudo so it can signal a root-owned carve child. The sentinel write
    # (`echo $? > exit`) is what job_status polls for completion.
    inner = " ".join(shlex.quote(c) for c in cmd)
    prefix = ("sudo timeout" if needs_sudo else "timeout") + f" {int(timeout)}"
    script = (f"{prefix} {inner} > {shlex.quote(stdout_file)} "
              f"2> {shlex.quote(stderr_file)}; echo $? > {shlex.quote(exit_file)}")
    proc = subprocess.Popen(
        ["sh", "-c", script], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)

    state = {
        "job_id": job_id, "tool": tool, "cmd": inner, "timeout": int(timeout),
        "output_dir": output_dir, "pid": proc.pid,
        "stdout_file": stdout_file, "stderr_file": stderr_file,
        "exit_file": exit_file, "started": time.time(),
        "status": "running", "collected": False, "call_id": None,
    }
    with open(_job_path(job_id), "w") as f:
        json.dump(state, f)
    return {
        "success": True, "status": "running", "job_id": job_id,
        "output_dir": output_dir, "pid": proc.pid,
        "hint": (f"BACKGROUND JOB STARTED (job_id={job_id}). This returned "
                 f"immediately — the carve runs detached. Poll "
                 f"misc.job_status(job_id='{job_id}') and keep investigating "
                 f"other artifacts meanwhile; carved files appear in "
                 f"{output_dir or '(stdout)'} and the finished job_status "
                 f"result is the citable record."),
    }


def _read(path: str, cap: int = 8 * 1024 * 1024) -> str:
    try:
        with open(path, "rb") as f:
            return f.read(cap).decode("utf-8", "replace")
    except OSError:
        return ""


def job_status(job_id: str) -> dict:
    """Poll a job. Running → progress; finished → the collected tool result
    (logged once with a citable _trudi_call_id)."""
    path = _job_path(job_id)
    if not os.path.exists(path):
        return {"success": False, "status": "unknown",
                "error": f"unknown job_id {job_id!r}"}
    with open(path) as f:
        state = json.load(f)
    elapsed = round(time.time() - state["started"], 1)

    if state.get("collected"):
        return _finished_result(state, elapsed, cached=True)

    if not os.path.exists(state["exit_file"]):
        return {"success": True, "status": "running", "job_id": job_id,
                "elapsed_seconds": elapsed,
                "output_files_so_far": _count_outputs(state["output_dir"]),
                "output_dir": state["output_dir"]}

    # Completed — collect once.
    rc_text = _read(state["exit_file"]).strip()
    try:
        rc = int(rc_text)
    except ValueError:
        rc = -1
    timed_out = rc == 124
    stdout = _read(state["stdout_file"])
    stderr = _read(state["stderr_file"])
    if timed_out:
        stderr = (f"Command timed out after {state['timeout']}s"
                  + (f"\n{stderr}" if stderr else ""))

    # Log the underlying command as a normal, citable tool_call (once).
    res = {
        "success": rc == 0, "stdout": stdout[:2000], "stderr": stderr[:2000],
        "exit_code": rc, "truncated": len(stdout) > 2000, "retries": 0,
        "elapsed_seconds": elapsed, "timed_out": timed_out,
        "cmd": state["cmd"], "output_path": state["output_dir"],
        "_stdout_full": stdout, "_stdout_chars": len(stdout),
    }
    try:
        from core.executor import _log_tool
        _log_tool(res)
        cid = res.get("_trudi_call_id")
    except Exception:
        cid = None

    state["status"] = "finished"
    state["collected"] = True
    state["call_id"] = cid
    state["stdout_excerpt"] = stdout[:2000]
    state["stderr_final"] = stderr[:2000]
    state["exit_code"] = rc
    state["timed_out"] = timed_out
    with open(path, "w") as f:
        json.dump(state, f)
    return _finished_result(state, elapsed, cached=False)


def _finished_result(state: dict, elapsed: float, cached: bool) -> dict:
    n = _count_outputs(state["output_dir"])
    out = {
        "success": state["exit_code"] == 0, "status": "finished",
        "job_id": state["job_id"], "exit_code": state["exit_code"],
        "elapsed_seconds": elapsed, "timed_out": state["timed_out"],
        "stdout": state.get("stdout_excerpt", ""),
        "stderr": state.get("stderr_final", ""),
        "output_files": n, "output_dir": state["output_dir"],
        "_trudi_call_id": state.get("call_id"),
        "note": ("already collected — cite _trudi_call_id for findings from "
                 "this carve" if cached else
                 "collected. Cite _trudi_call_id for findings from this carve; "
                 "read specific carved files with read.read_output."),
    }
    if state["timed_out"]:
        out["partial_output"] = (
            f"{n} files already produced in {state['output_dir']} — usable "
            f"despite the timeout")
    return out


def list_jobs() -> dict:
    out = []
    try:
        for name in sorted(os.listdir(JOBS_DIR)):
            if name.endswith(".json"):
                with open(os.path.join(JOBS_DIR, name)) as f:
                    s = json.load(f)
                out.append({"job_id": s["job_id"], "status": s["status"],
                            "cmd": s["cmd"][:80], "output_dir": s["output_dir"]})
    except OSError:
        pass
    return {"success": True, "jobs": out, "count": len(out)}
