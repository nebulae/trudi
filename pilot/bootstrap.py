"""Pilot session bootstrap — the auto-run half of the walkthrough.

The dividing rule (docs/pilot.md): bookkeeping auto-runs, anything
interpretive is only ever suggested. This module is the bookkeeping:

1. parse the case CLAUDE.md → case id, question, evidence root, roster
2. `misc.start_execution_log` (prints the dashboard URL, resumes an
   existing trace)
3. `hash.verify_evidence_hash` per evidence file (the tool caches — a
   file already recorded this case is a fast no-op)
4. render the banner

No reason.* or forensic call happens here — the Triage ritual
(hypothesize → plan → assess) is interpretive and belongs to the
suggestion queue, never the bootstrap.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

# evidence files worth auto-hashing: forensic images / captures / stores.
# Anything else in the evidence root is listed but not hashed unless it is
# one of these (a README or a mount point should not block boot).
EVIDENCE_EXTS = {
    ".e01", ".e02", ".ex01", ".aff", ".dd", ".raw", ".img", ".bin",
    ".vmdk", ".vhd", ".vhdx", ".mem", ".vmem", ".lime", ".dmp",
    ".pcap", ".pcapng", ".ost", ".pst", ".zip", ".tar", ".gz", ".7z",
}


@dataclass
class CaseInfo:
    case_dir: str
    case_id: str
    question: str = ""
    evidence_root: str = ""
    roster: list[str] = field(default_factory=list)


@dataclass
class BootState:
    trace_path: str = ""
    dashboard_url: str = ""
    resumed: bool = False
    entry_count: int = 0
    evidence: list[tuple[str, str]] = field(default_factory=list)  # (path, status)


_CASE_ID = re.compile(r"\*\*Case ID:\*\*\s*(\S+)")
_EVIDENCE_ROOT = re.compile(r"\*\*Evidence root:\*\*\s*`?([^`\n]+)`?")
_QUESTION = re.compile(r"\*\*CASE_QUESTION:\*\*\s*(.+)")
_ROSTER_HEAD = re.compile(r"^#+\s*(?:Roster|.*\broster\b.*)$", re.I | re.M)
_ROSTER_NAME = re.compile(r"^[-*|]\s*\*?\*?([A-Z][a-z]+(?: [A-Z][a-z]+)+)")


def is_case_dir(case_dir: str) -> bool:
    """A prepared case dir, not just any dir with a CLAUDE.md (the repo root
    has one too): the case marker or an evidence/ dir must be present."""
    md_path = os.path.join(case_dir, "CLAUDE.md")
    if not os.path.exists(md_path):
        return False
    if os.path.isdir(os.path.join(case_dir, "evidence")):
        return True
    text = open(md_path, encoding="utf-8", errors="replace").read()
    return bool(_CASE_ID.search(text))


def parse_case_md(case_dir: str) -> CaseInfo:
    """Best-effort parse of the case CLAUDE.md; everything is optional
    except an identity — case_id falls back to the directory name."""
    info = CaseInfo(case_dir=case_dir,
                    case_id=os.path.basename(os.path.abspath(case_dir)).upper())
    md_path = os.path.join(case_dir, "CLAUDE.md")
    if not os.path.exists(md_path):
        return info
    text = open(md_path, encoding="utf-8", errors="replace").read()

    if m := _CASE_ID.search(text):
        info.case_id = m.group(1)
    if m := _QUESTION.search(text):
        info.question = m.group(1).strip()
    if m := _EVIDENCE_ROOT.search(text):
        info.evidence_root = m.group(1).strip()

    if m := _ROSTER_HEAD.search(text):
        section = text[m.end():]
        nxt = re.search(r"^#+\s", section, re.M)
        if nxt:
            section = section[:nxt.start()]
        info.roster = [n.group(1) for line in section.splitlines()
                       if (n := _ROSTER_NAME.match(line.strip()))]
    return info


def discover_evidence(info: CaseInfo) -> list[str]:
    """Evidence files to hash: the parsed evidence root when it exists,
    else <case>/evidence. Non-recursive; forensic extensions only."""
    root = info.evidence_root if os.path.isdir(info.evidence_root or "") \
        else os.path.join(info.case_dir, "evidence")
    if not os.path.isdir(root):
        return []
    files = []
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if os.path.isfile(path) and os.path.splitext(name)[1].lower() in EVIDENCE_EXTS:
            files.append(path)
    return files


def _payload(result) -> dict:
    """fastmcp CallToolResult -> dict, tolerant of shape differences."""
    payload = getattr(result, "structured_content", None)
    if isinstance(payload, dict):
        return payload
    try:
        return json.loads(result.content[0].text)
    except Exception:
        return {}


async def bootstrap(client, info: CaseInfo, echo=print) -> BootState:
    """Run the bookkeeping against a connected fastmcp client."""
    state = BootState(
        trace_path=os.path.join("analysis", f"{info.case_id}_trace.json"))
    state.resumed = os.path.exists(os.path.join(info.case_dir, state.trace_path))

    r = _payload(await client.call_tool("misc_start_execution_log", {
        "case_id": info.case_id,
        "output_path": os.path.join(".", state.trace_path),
        "case_dir": info.case_dir,
    }))
    state.dashboard_url = r.get("dashboard_url", "") or ""
    state.entry_count = int(r.get("entries_recovered") or 0)
    state.resumed = bool(r.get("resumed", state.resumed))

    for path in discover_evidence(info):
        size_mb = os.path.getsize(path) / 1e6
        echo(f"  hashing {os.path.basename(path)} ({size_mb:.0f} MB)…", flush=True)
        v = _payload(await client.call_tool("hash_verify_evidence_hash",
                                            {"evidence_path": path}))
        sha = (v.get("sha256") or v.get("hashes", {}).get("sha256") or "")[:12]
        status = f"✓ sha256 {sha}…" if v.get("success") else \
            f"✗ {str(v.get('error', 'hash failed'))[:60]}"
        state.evidence.append((path, status))
    return state


def render_banner(info: CaseInfo, state: BootState, width: int = 76) -> str:
    bar = "─" * width
    lines = [f"TRUDI PILOT ── {info.case_id} {bar[len(info.case_id) + 16:]}"]
    if info.question:
        import textwrap
        q = textwrap.wrap(info.question, width - 5)
        lines.append(f" Q: {q[0]}")
        lines.extend(f"    {cont}" for cont in q[1:3])
    if state.evidence:
        for path, status in state.evidence:
            lines.append(f" evidence: {os.path.basename(path)}  {status}")
    else:
        lines.append(" evidence: none found — point tools at paths manually")
    trace_note = f"resumed, {state.entry_count} entries" if state.resumed \
        else "new session"
    lines.append(f" trace: {state.trace_path} ({trace_note})")
    if state.dashboard_url:
        lines.append(f" dashboard: {state.dashboard_url}")
    if info.roster:
        lines.append(f" roster: {len(info.roster)} knowns loaded")
    if state.resumed:
        lines.append(" resume contract: first call is dair.assess with the "
                     "last-known phase stack")
    else:
        lines.append(" ritual: reason.hypothesize (case question) → reason.plan "
                     "→ dair.assess")
    lines.append(bar)
    return "\n".join(lines)
