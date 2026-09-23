"""Typed indicators of compromise and their ATT&CK-driven coverage.

An IOC is a normalised, typed value (an IP, an account, a scheduled task, a
device VID:PID ...) recorded as it surfaces, grounded in the tool calls that
showed it and mapped to ATT&CK techniques. Each technique's detection strategy
(ATT&CK v18 analytics, built offline into mitre_detection.json) names the data
components that would confirm or scope it; data/fk/attack_coverage.yaml maps
those components to the TRUDI tools that examine their forensic equivalents on
a disk image. A (technique, component) pair is COVERED once any mapped tool
has run successfully in the trace, or when a typed `coverage` disposition
settles it. Open items are Scan leads for DAIR and report warnings — they never
block a phase change or the report.
"""
from __future__ import annotations

import ipaddress
import os
import re
from functools import lru_cache
from pathlib import Path

IOC_TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256",
             "file_path", "file_name", "registry_key", "account", "sid", "device",
             "volume_serial", "scheduled_task", "service", "process", "command_line",
             "hostname")
STATUSES = ("observed", "malicious", "suspicious", "benign", "unknown")

_HEX = re.compile(r"^[0-9a-f]+$")
_SID = re.compile(r"^s-1-\d+(-\d+)+$")
_VIDPID = re.compile(r"^(?:vid_)?([0-9a-f]{4})[:&/_ -]+(?:pid_)?([0-9a-f]{4})$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize(ioc_type: str, value: str) -> str:
    """Canonical form used for de-duplication. Raises ValueError when the value
    is not a valid instance of its type."""
    v = str(value or "").strip().strip("'\"")
    if not v:
        raise ValueError("empty IOC value")
    t = ioc_type
    if t not in IOC_TYPES:
        raise ValueError(f"unknown ioc_type {t!r}; one of {', '.join(IOC_TYPES)}")
    if t in ("ipv4", "ipv6"):
        ip = ipaddress.ip_address(v)
        if (t == "ipv4") != (ip.version == 4):
            raise ValueError(f"{v} is not an {t} address")
        return str(ip)
    if t == "domain" or t == "hostname":
        d = v.lower().rstrip(".")
        if t == "domain" and not _DOMAIN.match(d):
            raise ValueError(f"{v} is not a domain name")
        return d
    if t == "email":
        if not _EMAIL.match(v):
            raise ValueError(f"{v} is not an email address")
        return v.lower()
    if t in ("md5", "sha1", "sha256"):
        h, n = v.lower(), {"md5": 32, "sha1": 40, "sha256": 64}[t]
        if len(h) != n or not _HEX.match(h):
            raise ValueError(f"{v} is not a {t} hash")
        return h
    if t == "sid":
        if not _SID.match(v.lower()):
            raise ValueError(f"{v} is not a SID")
        return v.upper()
    if t == "device":
        m = _VIDPID.match(v.lower().replace("vid_", "vid_").strip())
        if not m:
            raise ValueError(f"{v} is not a VID:PID pair (e.g. 03EB:2422)")
        return f"{m.group(1).upper()}:{m.group(2).upper()}"
    if t in ("file_path", "registry_key", "scheduled_task"):
        # Windows paths and keys are case-insensitive; one separator.
        return re.sub(r"\\+", r"\\", v.replace("/", "\\")).rstrip("\\").lower()
    if t == "volume_serial":
        return v.replace("-", "").upper()
    if t in ("account", "file_name", "service", "process"):
        return v.lower()
    return v                                   # url, command_line: kept verbatim


def ioc_key(ioc_type: str, normalized: str) -> str:
    return f"{ioc_type}:{normalized}"


def ioc_state(entries) -> dict:
    """{key: merged IOC} — later records update status and extend techniques
    and evidence; the first record dates it."""
    out: dict = {}
    for e in entries or []:
        if not isinstance(e, dict) or e.get("type") != "ioc":
            continue
        k = ioc_key(e.get("ioc_type", ""), e.get("normalized", ""))
        cur = out.get(k)
        if cur is None:
            out[k] = {"key": k, "ioc_type": e.get("ioc_type"), "value": e.get("value"),
                      "normalized": e.get("normalized"), "status": e.get("status", "observed"),
                      "techniques": list(e.get("techniques") or []),
                      "evidence_call_ids": list(e.get("evidence_call_ids") or []),
                      "aliases": list(e.get("aliases") or []),
                      "note": e.get("note", ""), "first_call_id": e.get("call_id"),
                      "last_call_id": e.get("call_id")}
            continue
        cur["status"] = e.get("status") or cur["status"]
        cur["techniques"] = sorted(set(cur["techniques"]) | set(e.get("techniques") or []))
        cur["evidence_call_ids"] = sorted(set(cur["evidence_call_ids"]) | set(e.get("evidence_call_ids") or []))
        cur["aliases"] = sorted(set(cur.get("aliases") or []) | set(e.get("aliases") or []))
        cur["note"] = e.get("note") or cur["note"]
        cur["last_call_id"] = e.get("call_id")
    return out


# ── coverage ───────────────────────────────────────────────────────────────────

_COVERAGE_YAML = Path(__file__).resolve().parents[1] / "data" / "fk" / "attack_coverage.yaml"


@lru_cache(maxsize=2)
def _load_map(path: str, mtime: float) -> dict:
    import yaml
    with open(path) as f:
        return (yaml.safe_load(f) or {}).get("components", {}) or {}


def component_map(path: str | None = None) -> dict:
    p = str(path or _COVERAGE_YAML)
    try:
        return _load_map(p, os.path.getmtime(p))
    except OSError:
        return {}


def _tool_name(e: dict) -> str:
    return str(e.get("mcp_tool") or "").strip()


def ioc_tokens(ioc: dict) -> set:
    """Lower-cased strings whose presence in a command or read query means the
    examination was ABOUT this IOC."""
    toks = {str(ioc.get("normalized") or "").lower(), str(ioc.get("value") or "").lower()}
    toks |= {str(a).lower() for a in ioc.get("aliases") or []}
    if ioc.get("ioc_type") == "device" and ":" in str(ioc.get("normalized") or ""):
        vid, pid = str(ioc["normalized"]).lower().split(":")
        toks |= {f"vid_{vid}&pid_{pid}", f"vid_{vid}", f"{vid}:{pid}"}
    if ioc.get("ioc_type") in ("file_path", "scheduled_task", "registry_key"):
        leaf = str(ioc.get("normalized") or "").rsplit("\\", 1)[-1]
        if len(leaf) >= 4:
            toks.add(leaf)
    return {t.strip() for t in toks if len(t.strip()) >= 3}


def _reads(entries) -> list:
    """(target path, lower-cased command incl. query) for traced reads."""
    out = []
    for e in entries or []:
        if not isinstance(e, dict) or e.get("type") != "tool_call" or e.get("success") is not True:
            continue
        cmd = str(e.get("cmd") or "")
        if _tool_name(e) in ("read_output", "read_mail") or cmd.startswith(("read.output", "read.mail")):
            m = re.search(r"(?:--output|-o)\s+(\S+)", cmd)
            if m:
                out.append((m.group(1), cmd.lower()))
    return out


_WRITTEN = re.compile(r"(/\S+/(?:exports|analysis|reports)/\S+?)(?=[\s'\",;)]|$)")


def _stdout_text(e: dict, cap: int = 2_000_000) -> str:
    """The tool's own retained output: the full sidecar when kept, else the excerpt."""
    path = e.get("stdout_path")
    if path:
        try:
            with open(path, "r", errors="replace") as fh:
                return fh.read(cap)
        except OSError:
            pass
    return str(e.get("stdout_excerpt") or "")


def _produced_paths(e: dict, stdout: str) -> list:
    """Where a call's output lives: output flags in its command, its stdout
    sidecar, an output_path field, and files its own output reports writing
    (in-process tools write to a path their command line does not name)."""
    from tools._output_reader import _cmd_output_paths
    paths = [p for p in _cmd_output_paths(str(e.get("cmd") or "")) if p.startswith("/")]
    for k in ("stdout_path", "output_path", "output_file"):
        if e.get(k):
            paths.append(str(e[k]))
    paths += _WRITTEN.findall(stdout or "")
    return paths


def _call_views(entries) -> list:
    """One pass over the trace: (call_id, tool, cmd, stdout, produced paths)
    for every successful tool call, lower-cased once."""
    views = []
    for e in entries or []:
        if not isinstance(e, dict) or e.get("type") != "tool_call" or e.get("success") is not True:
            continue
        stdout = _stdout_text(e)
        views.append((e.get("call_id"), _tool_name(e), str(e.get("cmd") or "").lower(),
                      stdout.lower(), _produced_paths(e, stdout)))
    return views


def _examined_for(views, spec: dict, tokens: set, reads: list) -> list:
    """Successful calls of a mapped tool that examined its data FOR this IOC:
    its command or its own output names the IOC, or a traced read over its
    output queried for it. A tool that merely ran somewhere does not count."""
    tools = set(spec.get("tools") or [])
    where = [w.lower() for w in spec.get("where") or []]
    scoped = set(spec.get("where_applies_to") or tools)
    hits = []
    for cid, name, cmd, stdout, produced in views:
        if name not in tools:
            continue
        if where and name in scoped and not any(w in cmd for w in where):
            continue
        if any(t in cmd or t in stdout for t in tokens) or any(
                any(path == p or path.startswith(p.rstrip("/") + "/") for p in produced)
                and any(t in rcmd for t in tokens) for path, rcmd in reads):
            hits.append(cid)
    return hits


def coverage(entries, platform: str = "Windows") -> dict:
    """Per IOC x technique x ATT&CK data component (for `platform`): covered
    when a mapped tool's data was examined for that IOC, dispositioned by a
    `coverage` disposition (technique:component, any IOC), or open.
    Components with no forensic mapping are `unmapped`, never open."""
    from tools.mitre import detection_for
    from tools._gates._dispositions import find_disposition, index_from_entries
    from core.findings import current_entries
    entries = current_entries(entries)
    cmap = component_map()
    idx = index_from_entries(entries)
    reads = _reads(entries)
    views = _call_views(entries)
    items = []
    for ioc in ioc_state(entries).values():
        tokens = ioc_tokens(ioc)
        for tid in ioc["techniques"]:
            det = detection_for(tid, platform)
            comps = sorted({s["component"] for a in det["analytics"] for s in a["log_sources"]
                            if s.get("component")})
            for comp in comps:
                spec = cmap.get(comp)
                row = {"technique": tid, "technique_name": det["name"], "component": comp,
                       "iocs": [ioc["key"]]}
                if not spec:
                    row["status"] = "unmapped"
                else:
                    row["examine_with"] = spec.get("tools", [])
                    row["artifacts"] = spec.get("artifacts", "")
                    hits = _examined_for(views, spec, tokens, reads)
                    disp = find_disposition(idx, "coverage", f"{tid}:{comp}")
                    if hits:
                        row.update(status="covered", examined_by=hits[:5])
                    elif disp is not None:
                        row.update(status="dispositioned", disposition=disp.get("reason"))
                    else:
                        row["status"] = "open"
                items.append(row)
            if det["related"]:
                items.append({"technique": tid, "technique_name": det["name"],
                              "component": None, "status": "advisory",
                              "related_techniques": det["related"], "iocs": [ioc["key"]]})
    open_items = [i for i in items if i["status"] == "open"]
    return {"platform": platform, "items": items, "open": open_items,
            "counts": {s: sum(1 for i in items if i["status"] == s)
                       for s in ("covered", "dispositioned", "open", "unmapped", "advisory")}}
