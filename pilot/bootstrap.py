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
_ROSTER_HEAD = re.compile(
    r"^#+\s*.*\b(?:roster|suspects?|class list|people of interest|"
    r"persons of interest|occupants|personnel)\b.*$", re.I | re.M)
_ROSTER_NAME = re.compile(r"^[-*|]\s*\*?\*?([A-Z][a-z]+(?: [A-Z][a-z]+)+)")
_NAME_RUN = re.compile(r"\b([A-Z][a-z]+ [A-Z][a-z]+)\b")


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

    # roster: union of EVERY roster-ish section (a case file can carry both
    # a suspects section and a class list — nitroba does), bullet names plus
    # comma-separated name runs ("Amy Smith, Burt Greedom, Tuck Gorge, …")
    names: list[str] = []
    for m in _ROSTER_HEAD.finditer(text):
        section = text[m.end():]
        nxt = re.search(r"^#+\s", section, re.M)
        if nxt:
            section = section[:nxt.start()]
        for line in section.splitlines():
            line = line.strip()
            if n := _ROSTER_NAME.match(line):
                names.append(n.group(1))
            elif line.count(",") >= 2:
                run = _NAME_RUN.findall(line)
                if len(run) >= 3:  # a genuine name list, not prose
                    names.extend(run)
    info.roster = list(dict.fromkeys(names))
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


_EXTRACT_CACHE_DIR = os.path.expanduser("~/.cache/trudi/pilot_case_info")


def merge_extracted(info: CaseInfo, extracted: dict) -> list[str]:
    """Fill CaseInfo gaps from an LLM extraction — the regex parse wins
    wherever it found something; the extraction fills what it missed.
    Returns the field names that were filled."""
    filled = []
    if not info.question and extracted.get("case_question"):
        info.question = str(extracted["case_question"]).strip()
        filled.append("question")
    if not info.roster and extracted.get("roster"):
        info.roster = [str(n).strip() for n in extracted["roster"]
                       if str(n).strip()]
        if info.roster:
            filled.append("roster")
    if not info.evidence_root and extracted.get("evidence_root"):
        info.evidence_root = str(extracted["evidence_root"]).strip()
        filled.append("evidence_root")
    return filled


async def extract_case_info(client, info: CaseInfo, echo=print) -> None:
    """When the regex parse left gaps (question/roster), ask the reason
    backend to read the case CLAUDE.md — once per file content, cached
    under ~/.cache/trudi so later boots are instant."""
    md_path = os.path.join(info.case_dir, "CLAUDE.md")
    if (info.question and info.roster) or not os.path.exists(md_path):
        return
    text = open(md_path, encoding="utf-8", errors="replace").read()
    import hashlib
    key = hashlib.sha256(text.encode()).hexdigest()[:24]
    cache = os.path.join(_EXTRACT_CACHE_DIR, f"{key}.json")
    extracted = None
    try:
        extracted = json.load(open(cache, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    if extracted is not None:
        echo("  case briefing: cached extraction")
    else:
        echo("  reading the case briefing via the reason backend "
             "(cached once it extracts something)…", flush=True)
        try:
            r = await client.call_tool("reason_extract_case",
                                       {"case_md": text})
            payload = _payload(r)
            if payload.get("success"):
                extracted = {k: payload.get(k, "") for k in
                             ("case_id", "case_question", "evidence_root",
                              "scenario_summary")}
                extracted["roster"] = payload.get("roster") or []
                if any(extracted.get(k) for k in
                       ("case_question", "roster", "evidence_root")):
                    os.makedirs(_EXTRACT_CACHE_DIR, exist_ok=True)
                    json.dump(extracted, open(cache, "w", encoding="utf-8"))
                else:
                    # an all-empty extraction is a backend whiff, not a fact
                    # about the document — never cache it (observed live:
                    # a cached empty silently disabled extraction for good)
                    extracted = None
                    echo("  (briefing extraction returned nothing — will "
                         "retry next boot)")
        except Exception as e:
            echo(f"  (case extraction unavailable: {str(e)[:80]})")
    if extracted:
        filled = merge_extracted(info, extracted)
        if filled:
            echo(f"  case briefing filled: {', '.join(filled)}")


async def bootstrap(client, info: CaseInfo, echo=print) -> BootState:
    """Run the bookkeeping against a connected fastmcp client. The trace
    log opens FIRST — every later call (extraction included) must land in
    the trace, not spray 'trace log not configured' warnings (observed
    live when extraction ran before start_execution_log)."""
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

    await extract_case_info(client, info, echo)

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
