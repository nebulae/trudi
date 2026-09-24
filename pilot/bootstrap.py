"""Case-briefing parsing for the trudi launcher — pure logic, no I/O
beyond reading the case CLAUDE.md.

Pilot mode is hosted by the agent clients (Claude Code / OpenCode) with
the analyst-driven profile — see docs/pilot.md. The client itself reads
the briefing natively during the session; these helpers exist for the
LAUNCHER: the pre-exec case banner and the --mirror trace path.
`merge_extracted` supports callers of the server-side
`reason.extract_case` tool.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# evidence files worth surfacing: forensic images / captures / stores.
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
    """Evidence files: the parsed evidence root when it exists, else
    <case>/evidence. Non-recursive; forensic extensions only."""
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


def merge_extracted(info: CaseInfo, extracted: dict) -> list[str]:
    """Fill CaseInfo gaps from a `reason.extract_case` result — the regex
    parse wins wherever it found something; the extraction fills what it
    missed. Returns the field names that were filled."""
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
