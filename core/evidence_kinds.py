"""Evidence KINDS a case holds — what DAIR may prescribe tools for.

    memory      a RAM image (.mem/.vmem/.lime/.dmp/…)
    pcap        a packet capture (.pcap/.pcapng/.cap)
    disk_image  a disk image (.E01/.Ex01/.dd/.img/.vmdk/.vhd/…) or a filesystem
                mounted under the case's mnt/
    triage      a collected Windows artifact tree (CyLR-style: a folder holding
                Windows/System32/config or a $MFT)
    mobile      an iOS/Android filesystem extraction (private/var/mobile,
                data/data) or an iTunes-style backup (Manifest.db)
    live        a live endpoint: a live-monitoring investigation trace, a
                successful live.*/velo.* call, or a case context naming one

Sources: the case's evidence/ directory (symlinks followed, bounded
breadth-first walk), the case's mnt/ directory, and the trace (successful
tool calls of a kind-specific namespace; evidence file names on command
lines). Detection only ever ADDS kinds. Tool filtering acts only on a
DETERMINED inventory (evidence/ or mnt/ showed something) outside
live-monitoring traces — otherwise nothing is filtered (fail-open).
"""
from __future__ import annotations

import os
import re
import time
from collections import deque

KINDS = ("memory", "pcap", "disk_image", "triage", "mobile", "live")

_PCAP_EXT = (".pcap", ".pcapng", ".cap")
_MEM_EXT = (".vmem", ".mem", ".lime", ".dmp", ".vmss", ".vmsn", ".mddramimage", ".crash",
            ".hpak")
_DISK_EXT = (".e01", ".ex01", ".l01", ".lx01", ".dd", ".001", ".vmdk", ".vhd", ".vhdx",
             ".dmg", ".aff", ".s01", ".qcow2")
_AMBIGUOUS_EXT = (".raw", ".aff4", ".bin")       # a RAM or a disk image — count both

_MAX_DEPTH = 8
_MAX_DIRS = 2000
_MAX_SECONDS = 1.5
_CACHE: dict = {}
_CACHE_TTL = 300.0


def classify_name(name: str) -> set:
    """Kinds a single evidence file NAME implies (by extension)."""
    n = str(name or "").strip().strip("'\"").lower()
    if not n or "." not in n:
        return set()
    if n.endswith(_PCAP_EXT):
        return {"pcap"}
    if n.endswith(_MEM_EXT):
        return {"memory"}
    if n.endswith(".img"):
        return {"memory"} if "mem" in os.path.basename(n) else {"disk_image"}
    if n.endswith(_DISK_EXT):
        return {"disk_image"}
    if n.endswith(_AMBIGUOUS_EXT):
        if n.endswith(".bin") and "mem" not in os.path.basename(n):
            return set()
        return {"memory", "disk_image"}
    if n.endswith("$mft") or os.path.basename(n) == "$mft":
        return {"triage"}
    return set()


def _dir_marker(rel_lower: str) -> str:
    """Kind a directory's relative path (lower-case, '/'-joined) marks, or ''."""
    if rel_lower.endswith("windows/system32/config"):
        return "triage"
    # iOS /var is a symlink to /private/var: either spelling may be reached first.
    if rel_lower.endswith("var/mobile") or rel_lower.endswith("data/data"):
        return "mobile"
    return ""


def _scan_evidence_dir(root: str) -> set:
    """Bounded breadth-first walk of evidence/ (symlinks followed, each real
    directory visited once): file extensions + directory markers."""
    kinds: set = set()
    seen: set = set()
    q = deque([(root, "", 0)])
    visited = 0
    deadline = time.monotonic() + _MAX_SECONDS
    while q and visited < _MAX_DIRS and time.monotonic() < deadline:
        path, rel, depth = q.popleft()
        try:
            real = os.path.realpath(path)
        except OSError:
            continue
        if real in seen:
            continue
        seen.add(real)
        visited += 1
        try:
            it = list(os.scandir(path))
        except OSError:
            continue
        for de in it:
            name = de.name
            low = name.lower()
            try:
                is_dir = de.is_dir(follow_symlinks=True)
            except OSError:
                is_dir = False
            if not is_dir:
                if low == "$mft":
                    kinds.add("triage")
                elif low == "manifest.db":
                    kinds.add("mobile")
                else:
                    kinds |= classify_name(low)
                continue
            crel = f"{rel}/{low}" if rel else low
            mark = _dir_marker(crel)
            if mark:
                kinds.add(mark)
                continue                          # the kind is known; do not descend
            if depth + 1 < _MAX_DEPTH:
                q.append((de.path, crel, depth + 1))
    return kinds


def _evidence_dir_kinds(case_dir: str) -> set:
    evd = os.path.join(case_dir, "evidence")
    if not os.path.isdir(evd):
        return set()
    try:
        key = (os.path.realpath(evd), os.stat(evd).st_mtime)
    except OSError:
        return set()
    hit = _CACHE.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < _CACHE_TTL:
        return set(hit[1])
    kinds = _scan_evidence_dir(evd)
    _CACHE[key] = (now, frozenset(kinds))
    return kinds


def _mounted_kinds(case_dir: str) -> set:
    """A filesystem mounted under <case>/mnt/ is a disk image in hand. A
    mount point the SIFT user cannot list (a root FUSE ewf/bde mount) or one
    os.path.ismount recognises counts; an empty directory does not."""
    mnt = os.path.join(case_dir, "mnt")
    try:
        subs = list(os.scandir(mnt))
    except OSError:
        return set()
    for de in subs:
        try:
            if not de.is_dir(follow_symlinks=True):
                continue
            if os.path.ismount(de.path):
                return {"disk_image"}
            with os.scandir(de.path) as inner:
                if next(inner, None) is not None:
                    return {"disk_image"}
        except PermissionError:
            return {"disk_image"}
        except OSError:
            continue
    return set()


def is_live_monitoring_trace(entries) -> bool:
    """Per-investigation live-monitoring traces (a SUCCESSFUL
    monitor.start_investigation — the call itself refuses outside a
    baselined live-monitoring case)."""
    return any(isinstance(e, dict)
               and "monitor_start_investigation" in str(e.get("cmd") or "")
               and e.get("success") is not False
               for e in entries or [])


# A successful call in one of these namespaces proves its kind is in hand.
_NS_KIND = {"vol": "memory", "net": "pcap", "tsk": "disk_image", "ewf": "disk_image",
            "img": "disk_image", "ez": "triage", "af": "triage", "live": "live",
            "velo": "live"}
_LIVE_CTX = re.compile(r"\blive\s*=\s*true\b|\bendpoint_host\b", re.IGNORECASE)


def _trace_kinds(entries) -> set:
    kinds: set = set()
    for e in entries or []:
        if not isinstance(e, dict) or e.get("type") != "tool_call" or e.get("success") is not True:
            continue
        if str(e.get("source") or "").startswith("claude_code"):
            continue                    # agent shell commands are not evidence signals
        mcp = str(e.get("mcp_tool") or "").lower()
        ns_kind = _NS_KIND.get(mcp.split("_", 1)[0]) if mcp else None
        if ns_kind:
            kinds.add(ns_kind)
        for tok in str(e.get("cmd") or "").split():
            if "sectionobject" in tok.lower():
                continue                # vol.dumpfiles output (…ImageSectionObject….img)
            k = classify_name(tok)
            if k == {"memory", "disk_image"} and ns_kind in ("memory", "disk_image"):
                k = {ns_kind}           # an ambiguous .raw fed to vol/tsk/img says which
            # Produced output is not evidence — except a capture or RAM image
            # the agent extracted from an archive in evidence/ (a disk-image
            # extension there is a carved/dumped file, never a new image).
            if any(p in tok for p in _PRODUCED_DIRS):
                k = {x for x in k if x in ("pcap", "memory")} \
                    if tok.lower().endswith(_PCAP_EXT + _MEM_EXT) else set()
            kinds |= k
    return kinds


_PRODUCED_DIRS = ("/exports/", "/analysis/", "/reports/")


def case_dir_from_log() -> str | None:
    """<case> for the active trace at <case>/analysis/<trace>.json."""
    try:
        from core.execution_log import log
        if log._path:
            return os.path.dirname(os.path.dirname(os.path.abspath(log._path)))
    except Exception:
        pass
    return None


def evidence_profile(entries=None, case_dir: str | None = None, case_context: str = "") -> dict:
    """{"kinds": sorted kinds, "determined": bool, "live_monitoring": bool}.

    `determined` is True only when the case's evidence/ or mnt/ directory
    showed at least one kind — the trace alone is a PARTIAL view (a memory
    tool that ran first says nothing about the disk image not yet touched),
    so trace signals only ever add kinds to a determined inventory. Callers
    filter tools only when determined and not live-monitoring."""
    if case_dir is None:
        case_dir = case_dir_from_log()
    base: set = set()
    if case_dir:
        base |= _evidence_dir_kinds(case_dir)
        base |= _mounted_kinds(case_dir)
    kinds = base | _trace_kinds(entries)
    live_mon = is_live_monitoring_trace(entries)
    if live_mon or _LIVE_CTX.search(case_context or ""):
        kinds.add("live")
    return {"kinds": sorted(kinds), "determined": bool(base), "live_monitoring": live_mon}


def evidence_kinds(entries=None, case_dir: str | None = None, case_context: str = "") -> set:
    """The evidence kinds the case holds (a subset of KINDS)."""
    return set(evidence_profile(entries, case_dir, case_context)["kinds"])


def filter_kinds(profile: dict) -> set:
    """The kind set tool filtering may act on: empty (filter nothing) unless
    the inventory is determined and this is not a live-monitoring trace."""
    if not profile or not profile.get("determined") or profile.get("live_monitoring"):
        return set()
    return set(profile.get("kinds") or [])
