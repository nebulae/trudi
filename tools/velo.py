"""Velociraptor API surface — read-only VQL gateway.

Wraps `velociraptor --api_config <path> query --format=jsonl <VQL>` for the
live-monitoring case family. Same audit posture as `live.py`: every call
produces a `tool_call` trace entry with `source: "velo_runner"` and a
real `_trudi_call_id` that findings, alerts, and response actions can cite.

Configuration is environment-driven so the SIFT host can point at the
demo Velociraptor server or a real deployment without touching the code:

    TRUDI_VELO_BIN          path to the velociraptor binary
                            (default: `velociraptor` on PATH)
    TRUDI_VELO_API_CONFIG   API config YAML
                            (default: ~/.config/trudi/velociraptor/api.config.yaml)

The `velo.*` namespace is read-only with respect to evidence; nothing
in this module ever touches `/cases/.../evidence/`. Response actions
that *do* write to the live host go through `respond.*`, which calls
`velo.collect_artifact` on `Custom.TRUDI.Respond.*` artifacts and is
itself gated against approval.

VQL passed via `velo.query` is sandboxed only by Velociraptor's own
artifact ACLs — operators should issue an API config with the
`administrator` role only on isolated demo deployments.
"""
from __future__ import annotations
import json
import os
import shlex
import subprocess
import time
from typing import Any, Optional

from fastmcp import FastMCP

from core import output_safe
from core.paths import DEFAULT_TIMEOUT, OUTPUT_CAP, MAX_TOOL_OUTPUT_LINES

mcp = FastMCP("velo")

DEFAULT_VELO_BIN = "velociraptor"
DEFAULT_API_CONFIG = os.path.expanduser(
    "~/.config/trudi/velociraptor/api.config.yaml"
)


def _resolve_bin() -> str:
    return os.environ.get("TRUDI_VELO_BIN") or DEFAULT_VELO_BIN


def _resolve_api_config() -> str:
    return os.path.expanduser(
        os.environ.get("TRUDI_VELO_API_CONFIG") or DEFAULT_API_CONFIG
    )


def _log_velo_tool(result: dict) -> None:
    """Write a tool_call trace entry — mirror of core.executor._log_tool /
    core.ssh._log_ssh_tool. On failure we still set _trudi_call_id=0 so the
    caller's result dict stays well-formed."""
    try:
        from core.execution_log import log
        cid = log.record_tool_call(
            cmd=result["cmd"],
            success=result["success"],
            truncated=result["truncated"],
            retries=result["retries"],
            exit_code=result["exit_code"],
            stderr=result["stderr"],
            elapsed_seconds=result.get("elapsed_seconds", 0.0),
            stdout_excerpt=result.get("stdout", ""),
            timed_out=result.get("timed_out", False),
        )
        result["_trudi_call_id"] = cid
    except Exception as e:  # noqa: BLE001
        import sys
        print(f"[TRUDI WARN] _log_velo_tool failed: {e}", file=sys.stderr)
        result.setdefault("_trudi_call_id", 0)


def _velo_run(
    argv: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    line_cap: int | None = MAX_TOOL_OUTPUT_LINES,
) -> dict[str, Any]:
    """Run velociraptor CLI with fixed argv; capture + trace + return.

    `argv` is the velociraptor sub-command + operands (binary path and
    `--api_config` are prepended here). Never raises — all failure modes
    are captured in the returned dict, same as `ssh_run`.
    """
    bin_path = _resolve_bin()
    api_config = _resolve_api_config()

    full_argv = [bin_path, "--api_config", api_config] + argv

    # Redact api_config in the recorded cmd — its path is sensitive on a
    # real deployment; the operator can recover it from env if needed.
    safe_cmd = (
        f"{bin_path} --api_config <redacted> " +
        " ".join(shlex.quote(a) for a in argv)
    )

    result: dict[str, Any] = {
        "success": False,
        "stdout": "",
        "stderr": "",
        "exit_code": -1,
        "elapsed_seconds": 0.0,
        "truncated": False,
        "cmd": safe_cmd,
        "retries": 0,
        "progress_lines": [],
        "source": "velo_runner",
    }

    if not os.path.exists(api_config):
        result["stderr"] = (
            f"Velociraptor API config not found at {api_config}. "
            f"Set TRUDI_VELO_API_CONFIG or run "
            f"`docker compose cp velo-server:/config/api.config.yaml {api_config}`."
        )
        _log_velo_tool(result)
        return result

    start = time.perf_counter()
    try:
        proc = subprocess.run(full_argv, capture_output=True, timeout=timeout)
        result["exit_code"] = proc.returncode
        result["success"] = proc.returncode == 0
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        if len(stdout) > OUTPUT_CAP:
            stdout = stdout[:OUTPUT_CAP]
            result["truncated"] = True
        if line_cap is not None:
            lines = stdout.splitlines(keepends=True)
            if len(lines) > line_cap:
                omitted = len(lines) - line_cap
                stdout = (
                    "".join(lines[:line_cap])
                    + f"\n[TRUNCATED — {omitted} lines omitted]\n"
                )
                result["truncated"] = True
        result["stdout"] = stdout
        result["stderr"] = stderr[:4096]
    except subprocess.TimeoutExpired:
        result["stderr"] = f"velociraptor timed out after {timeout}s"
        result["timed_out"] = True
    except FileNotFoundError:
        result["stderr"] = (
            f"velociraptor binary not found at {bin_path!r}. "
            f"Set TRUDI_VELO_BIN or install the binary."
        )
    except Exception as e:  # noqa: BLE001
        result["stderr"] = f"_velo_run error: {e}"

    result["elapsed_seconds"] = round(time.perf_counter() - start, 1)
    _log_velo_tool(result)
    return result


def _velo_query(
    vql: str,
    *,
    fmt: str = "jsonl",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Run a single VQL statement via `velociraptor query`."""
    return _velo_run(["query", "--format", fmt, vql], timeout=timeout)


def _parse_jsonl(stdout: str) -> list[dict]:
    rows: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            # Velociraptor occasionally prints a trailing summary line that
            # isn't JSON. Surface as a synthetic row so the caller can
            # see it without blowing up.
            rows.append({"_raw": line})
    return rows


# ── Client inventory ─────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def list_clients() -> dict:
    """List all clients enrolled with the Velociraptor server.

    Returns rows with client_id, hostname, OS, and last_seen timestamp.
    Use first to resolve an opaque hostname like "victim" or the
    docker container name to its Velociraptor `C.xxx` id.
    """
    res = _velo_query(
        "SELECT client_id, os_info.hostname AS hostname, "
        "os_info.system AS os, last_seen_at "
        "FROM clients()"
    )
    if res["success"]:
        res["rows"] = _parse_jsonl(res["stdout"])
    return res


@mcp.tool()
@output_safe
def client_info(client_id: str) -> dict:
    """Full record for a single client (id, OS, labels, last_seen_at, IP)."""
    if not client_id.startswith("C."):
        return {"success": False, "error": f"client_id must look like 'C.xxx', got {client_id!r}"}
    res = _velo_query(
        f"SELECT * FROM clients() WHERE client_id = {json.dumps(client_id)}"
    )
    if res["success"]:
        res["rows"] = _parse_jsonl(res["stdout"])
    return res


# ── One-shot collection ──────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def collect_artifact(
    client_id: str,
    artifact: str,
    parameters: Optional[dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """Kick off a one-shot artifact collection on a client.

    Returns a `flow_id` you can pass to `wait_for_flow` and
    `get_collection_results`. Does not block on completion — the flow
    runs asynchronously on the server.

    `parameters` is a dict of artifact env vars (artifact-specific).
    """
    if not client_id.startswith("C."):
        return {"success": False, "error": f"client_id must look like 'C.xxx', got {client_id!r}"}
    if not artifact or "/" in artifact:
        return {"success": False, "error": f"artifact name invalid: {artifact!r}"}

    env_clause = ""
    if parameters:
        # Velociraptor wants env as a dict-as-VQL-expression. Best path
        # is to render as a JSON-shaped dict; VQL accepts that syntax.
        env_clause = f", env=dict({', '.join(f'`{k}`={json.dumps(v)}' for k, v in parameters.items())})"

    # `collect_client` is a VQL *function* in 0.74+, not a plugin — so it
    # goes in the SELECT clause with FROM scope(), not as the FROM target.
    vql = (
        f"SELECT collect_client("
        f"client_id={json.dumps(client_id)}, "
        f"artifacts=[{json.dumps(artifact)}]"
        f"{env_clause}"
        f") AS flow FROM scope()"
    )
    res = _velo_query(vql, timeout=timeout)
    if res["success"]:
        rows = _parse_jsonl(res["stdout"])
        res["rows"] = rows
        for row in rows:
            # rows shaped as {"flow": {"flow_id": "F.xxx", ...}}
            flow = row.get("flow") if isinstance(row.get("flow"), dict) else None
            fid = (flow or {}).get("flow_id") or row.get("flow_id")
            if fid:
                res["flow_id"] = fid
                break
    return res


@mcp.tool()
@output_safe
def wait_for_flow(
    client_id: str,
    flow_id: str,
    timeout_seconds: int = 120,
    poll_interval_seconds: int = 2,
) -> dict:
    """Block until a flow reaches a terminal state (FINISHED or ERROR).

    Returns the final flow record. Polls `flows()` every
    poll_interval_seconds; gives up after timeout_seconds.
    """
    if not flow_id.startswith("F."):
        return {"success": False, "error": f"flow_id must look like 'F.xxx', got {flow_id!r}"}
    deadline = time.time() + timeout_seconds
    last_state = None
    while time.time() < deadline:
        # `flows()` exposes session_id (= flow_id) and state. The filter
        # has to match session_id, not flow_id.
        res = _velo_query(
            f"SELECT session_id AS flow_id, state, total_collected_rows, status "
            f"FROM flows(client_id={json.dumps(client_id)}) "
            f"WHERE session_id = {json.dumps(flow_id)}",
        )
        rows = _parse_jsonl(res["stdout"]) if res["success"] else []
        if rows:
            last_state = rows[0].get("state")
            if last_state in ("FINISHED", "ERROR"):
                res["rows"] = rows
                res["final_state"] = last_state
                return res
        time.sleep(poll_interval_seconds)
    return {
        "success": False,
        "error": f"flow {flow_id} did not terminate within {timeout_seconds}s "
                 f"(last_state={last_state!r})",
        "_trudi_call_id": 0,
    }


@mcp.tool()
@output_safe
def get_collection_results(
    client_id: str,
    flow_id: str,
    artifact: str,
) -> dict:
    """Fetch rows produced by a completed flow's artifact source.

    Call after `wait_for_flow` returns FINISHED. The artifact name must
    match what was collected (e.g. "Linux.Sys.Pslist").
    """
    if not flow_id.startswith("F."):
        return {"success": False, "error": f"flow_id must look like 'F.xxx', got {flow_id!r}"}
    res = _velo_query(
        f"SELECT * FROM source("
        f"client_id={json.dumps(client_id)}, "
        f"flow_id={json.dumps(flow_id)}, "
        f"artifact={json.dumps(artifact)}"
        f")",
    )
    if res["success"]:
        res["rows"] = _parse_jsonl(res["stdout"])
    return res


# ── Client monitoring (event tables) ────────────────────────────────────────

@mcp.tool()
@output_safe
def get_client_event_table(client_id: str) -> dict:
    """Show the artifacts currently in the global client monitoring table.

    Note: in Velociraptor 0.74+ the monitoring table is a single global
    state applied to all clients in a label group, not per-client. The
    `client_id` argument is retained for trace clarity but not used in
    the underlying VQL.
    """
    if not client_id.startswith("C."):
        return {"success": False, "error": f"client_id must look like 'C.xxx', got {client_id!r}"}
    # get_client_monitoring is a function in 0.74+, not a plugin.
    res = _velo_query(
        "SELECT get_client_monitoring() AS state FROM scope()"
    )
    if res["success"]:
        rows = _parse_jsonl(res["stdout"])
        res["rows"] = rows
        if rows:
            arts = (rows[0].get("state") or {}).get("artifacts") or {}
            res["artifacts"] = arts.get("artifacts") or []
    return res


@mcp.tool()
@output_safe
def update_client_event_table(
    client_id: str,
    artifacts: list[str],
    parameters: Optional[dict] = None,
) -> dict:
    """Replace the global client monitoring table with the given artifact set.

    Keeps the existing baseline artifact (`Generic.Client.Stats`) plus the
    `artifacts` you pass — this matters because the table is global, and
    blowing away Generic.Client.Stats would break the rest of the demo.

    `client_id` is informational (the change is global) but recorded so
    the trace clearly shows which run pushed the change.

    Implementation note: `set_client_monitoring(value=dict(...))` is
    silently rejected in Velociraptor 0.74+ — the function wants a value
    derived from `patch(item=get_client_monitoring(), patch=[...])` so
    the proto type is preserved. We compute a JSON-Patch (RFC 6902)
    against the current state and apply.
    """
    if not client_id.startswith("C."):
        return {"success": False, "error": f"client_id must look like 'C.xxx', got {client_id!r}"}
    if not artifacts:
        return {"success": False, "error": "artifacts list cannot be empty"}

    keep = ["Generic.Client.Stats"]
    desired = list(dict.fromkeys(keep + list(artifacts)))  # de-dup, preserve order

    # Read current artifact list to compute the diff.
    cur_res = _velo_query(
        "SELECT get_client_monitoring().artifacts.artifacts AS a FROM scope()"
    )
    if not cur_res.get("success"):
        return cur_res
    cur_rows = _parse_jsonl(cur_res["stdout"])
    current_list: list[str] = (cur_rows[0].get("a") if cur_rows else None) or []

    # Compute removes (by index, reversed to keep earlier indices stable
    # as items shift) and adds (appended via the "-" sentinel).
    ops: list[dict] = []
    for i in range(len(current_list) - 1, -1, -1):
        if current_list[i] not in desired:
            ops.append({"op": "remove", "path": f"/artifacts/artifacts/{i}"})
    existing_set = set(current_list)
    for name in desired:
        if name not in existing_set:
            ops.append({"op": "add", "path": "/artifacts/artifacts/-", "value": name})

    if not ops:
        return {
            "success": True,
            "artifacts": current_list,
            "noop": True,
            "_trudi_call_id": cur_res.get("_trudi_call_id"),
        }

    # Render the ops as a VQL list of dict() literals.
    def _render_op(op: dict) -> str:
        if "value" in op:
            return (
                f'dict(op={json.dumps(op["op"])}, '
                f'path={json.dumps(op["path"])}, '
                f'value={json.dumps(op["value"])})'
            )
        return (
            f'dict(op={json.dumps(op["op"])}, '
            f'path={json.dumps(op["path"])})'
        )

    ops_vql = "[" + ", ".join(_render_op(op) for op in ops) + "]"

    vql = (
        "SELECT set_client_monitoring(value=patch("
        "item=get_client_monitoring(), "
        f"patch={ops_vql}"
        ")) AS r FROM scope()"
    )
    res = _velo_query(vql)
    if res["success"]:
        res["rows"] = _parse_jsonl(res["stdout"])
        res["applied_ops"] = ops
        # Read-back to confirm.
        verify = _velo_query(
            "SELECT get_client_monitoring().artifacts.artifacts AS a FROM scope()"
        )
        verify_rows = _parse_jsonl(verify.get("stdout", "")) if verify.get("success") else []
        res["artifacts"] = (verify_rows[0].get("a") if verify_rows else None) or []
    return res


@mcp.tool()
@output_safe
def upload_artifact_yaml(yaml_text: str) -> dict:
    """Register (or update) a custom artifact on the Velociraptor server.

    yaml_text: the complete artifact YAML document. Must start with `name:`
               and the name MUST begin with `Custom.TRUDI.` — enforced here
               to keep TRUDI-managed artifacts namespaced and easy to audit.
    """
    head = yaml_text.lstrip().splitlines()[0] if yaml_text.strip() else ""
    if not head.startswith("name:"):
        return {"success": False, "error": "artifact YAML must start with `name:`"}
    # Crude but effective namespace gate.
    if "Custom.TRUDI." not in yaml_text.splitlines()[0]:
        return {
            "success": False,
            "error": "artifact name must begin with 'Custom.TRUDI.' — TRUDI manages "
                     "its own artifacts in that namespace to avoid clobbering "
                     "operator-authored content.",
        }
    vql = f"SELECT artifact_set(definition={json.dumps(yaml_text)}) FROM scope()"
    return _velo_query(vql)


# ── Read-only generic VQL gateway ───────────────────────────────────────────

@mcp.tool()
@output_safe
def query(vql: str, fmt: str = "jsonl") -> dict:
    """Run an arbitrary VQL statement.

    Read-only by intent — this tool does not enforce read-only at the VQL
    level (Velociraptor's own ACLs do that on the server side). Use for
    ad-hoc lookups. Findings citing the result must reference this call's
    `_trudi_call_id`.

    fmt: 'jsonl' (default), 'json', or 'csv'.
    """
    if fmt not in ("jsonl", "json", "csv"):
        return {"success": False, "error": f"fmt must be jsonl/json/csv, got {fmt!r}"}
    res = _velo_run(["query", "--format", fmt, vql])
    if res["success"] and fmt == "jsonl":
        res["rows"] = _parse_jsonl(res["stdout"])
    return res
