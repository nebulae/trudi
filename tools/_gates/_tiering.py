"""Deterministic tier contract.

The confidence tier a CONFIRMED / LIKELY finding may carry is a function of
the ARTIFACT CLASSES present among the tool calls it cites — computed from
the cited entries' commands, tool output and server-stamped markers. It is
never read from the finding's wording and never decided by the reviewer
model (whose role narrows to fact-checking the cited rows).

    classes = artifact_classes(by_call_id, cids)      # {class: [cids]}
    res     = tier_for(claim, set(classes))            # TierResult

`data/fk/tiering.yaml` holds the contract: how each class is recognised,
the named groups, and per act (per channel for egress) the clauses each
tier needs. `tier_path()` renders, for the next tier up, exactly which
classes are missing and which tools produce them — the CONFIRMED path the
analyst is otherwise left to guess at.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable

import yaml

from ._evidence_calls import is_evidence_tool_call, read_target_path

TIERING_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "fk" / "tiering.yaml"
_RANK = {"CONFIRMED": 3, "LIKELY": 2, "SUSPECTED": 1, "UNCONFIRMED": 0}
_ORDER = ("CONFIRMED", "LIKELY", "SUSPECTED")
_SIDECAR_READ_CHARS = 200_000
_TEXT_SCAN_CHARS = 60_000


@dataclass
class TierResult:
    tier: str                                   # highest tier the cited classes reach
    act: str
    channel: str = ""
    rule_key: str = ""                          # e.g. "egress/ftp"
    classes: dict = field(default_factory=dict)  # class -> [cids]
    # For the tier ABOVE `tier` (when one exists): the unsatisfied clauses of
    # the closest alternative — [{group, need, have: [classes], candidates:
    # [classes], tools: [..]}]
    missing: list = field(default_factory=list)
    next_tier: str = ""
    origins: dict = field(default_factory=dict)  # class -> {origin cids}

    def as_dict(self) -> dict:
        return {"tier_achievable": self.tier, "rule": self.rule_key,
                "artifact_classes": {k: sorted(v) for k, v in self.classes.items()},
                "next_tier": self.next_tier, "missing": self.missing}


# ── contract loading ─────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def load_contract() -> dict:
    with open(TIERING_PATH, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    classes = data.get("classes") or {}
    compiled = {}
    for cid, spec in classes.items():
        spec = dict(spec or {})
        spec["_cmd"] = re.compile(spec["cmd"], re.IGNORECASE) if spec.get("cmd") else None
        spec["_text"] = re.compile(spec["text"], re.IGNORECASE) if spec.get("text") else None
        compiled[cid] = spec
    data["classes"] = compiled
    groups = dict(data.get("groups") or {})
    groups["ANY"] = sorted(compiled)
    data["groups"] = groups
    return data


def class_tools(class_id: str) -> list[str]:
    spec = load_contract()["classes"].get(class_id) or {}
    return [str(t) for t in (spec.get("tools") or [])]


def class_label(class_id: str) -> str:
    spec = load_contract()["classes"].get(class_id) or {}
    return str(spec.get("label") or class_id)


# ── artifact classification ──────────────────────────────────────────────────

def _entry_text(entry: dict) -> str:
    parts = [str(entry.get("cmd") or ""), str(entry.get("stdout_excerpt") or "")]
    sp = entry.get("stdout_path")
    if sp:
        try:
            with open(sp, "r", errors="replace") as fh:
                parts.append(fh.read(_SIDECAR_READ_CHARS))
        except OSError:
            pass
    return "\n".join(p for p in parts if p)[:_TEXT_SCAN_CHARS]


def classify_entry(entry: dict) -> set[str]:
    """Artifact classes ONE tool_call entry carries (cmd signature, output
    text markers, server-stamped markers). Empty for non-evidence entries."""
    if not is_evidence_tool_call(entry):
        return set()
    cmd = str(entry.get("cmd") or "")
    text = None
    out: set[str] = set()
    for cid, spec in load_contract()["classes"].items():
        marker = spec.get("marker")
        if marker and entry.get(marker):
            out.add(cid)
            continue
        rx = spec.get("_cmd")
        if rx is not None and rx.search(cmd):
            out.add(cid)
            continue
        tx = spec.get("_text")
        if tx is not None:
            if text is None:
                text = _entry_text(entry)
            if tx.search(text):
                out.add(cid)
    return out


def _producer_of(read_entry: dict, by_call_id: dict) -> dict | None:
    """For a read.* entry, the earlier tool_call that PRODUCED the file it
    read (its cmd names the path, its basename, or its parent dir)."""
    path = read_target_path(read_entry)
    if not path:
        return None
    base = os.path.basename(path)
    parent = os.path.dirname(path)
    rid = int(read_entry.get("call_id") or 0)
    best = None
    for cid, e in by_call_id.items():
        try:
            cid = int(cid)
        except (TypeError, ValueError):
            continue
        if cid >= rid or not is_evidence_tool_call(e):
            continue
        cmd = str(e.get("cmd") or "")
        if cmd.startswith("read."):
            continue
        if (path in cmd or (base and base in cmd)
                or (parent and len(parent) > 8 and parent in cmd)):
            if best is None or cid > int(best.get("call_id") or 0):
                best = e
    return best


def artifact_classes(by_call_id: dict, cids: Iterable[int],
                     with_origins: bool = False):
    """{class: [cids]} over the cited entries. A read.* entry contributes the
    classes of the extractor that produced the file it read, plus any text
    markers (transfer / receipt / …) found in what it returned.

    with_origins=True also returns {class: {origin cids}} where a read.* entry
    counts as its PRODUCER's run — independence (two artifacts, not two reads
    of one) is measured over origins."""
    out: dict[str, list[int]] = {}
    origins: dict[str, set[int]] = {}
    seen: set[int] = set()
    for c in cids or []:
        try:
            c = int(c)
        except (TypeError, ValueError):
            continue
        if c in seen:
            continue
        seen.add(c)
        e = by_call_id.get(c) or by_call_id.get(str(c))
        if not isinstance(e, dict):
            continue
        classes = classify_entry(e)
        origin = c
        if str(e.get("cmd") or "").startswith("read."):
            prod = _producer_of(e, by_call_id)
            if prod is not None:
                classes |= classify_entry(prod)
                origin = int(prod.get("call_id") or c)
                # a bare "file content" read of an extractor's CSV is that
                # extractor's artifact, not a generic content read
                if len(classes) > 1:
                    classes.discard("file_content")
        for k in classes:
            out.setdefault(k, []).append(c)
            origins.setdefault(k, set()).add(origin)
    if with_origins:
        return out, origins
    return out


# ── tier arithmetic ──────────────────────────────────────────────────────────

def _rules_for(act: str, channel: str = "") -> tuple[dict, str]:
    acts = load_contract().get("acts") or {}
    act = (act or "").lower()
    rules = acts.get(act)
    if not rules:
        return {}, ""
    if "channels" in rules:
        ch = (channel or "").lower()
        chans = rules["channels"] or {}
        picked = chans.get(ch) or chans.get("default") or {}
        return picked, f"{act}/{ch or 'default'}"
    return rules, act


def _alternatives(tier_rules) -> list[list[dict]]:
    """Normalise a tier's rule value to a list of alternatives (each a list of
    clauses). Accepts [] (unreachable), [[clause,..],..] or [clause,..]."""
    if not tier_rules:
        return []
    if isinstance(tier_rules, list) and tier_rules and isinstance(tier_rules[0], dict):
        return [list(tier_rules)]
    return [list(alt or []) for alt in tier_rules]


def _clause_state(clause: dict, present: set[str]) -> dict:
    groups = load_contract()["groups"]
    g = str(clause.get("group") or "")
    members = list(groups.get(g) or ([g] if g in load_contract()["classes"] else []))
    need = int(clause.get("min") or 1)
    have = sorted(m for m in members if m in present)
    candidates = [m for m in members if m not in present]
    return {"group": g, "need": need, "have": have,
            "satisfied": len(have) >= need,
            "candidates": candidates,
            "tools": sorted({t for m in candidates for t in class_tools(m)})[:12]}


def _independent(chosen: list[str], origins: dict) -> bool:
    """True when every chosen class can be assigned its OWN origin call
    (distinct representatives) — one tool run backing two classes is one
    artifact, not two. Classes with no origin info count as independent."""
    if not origins:
        return True
    match: dict[int, str] = {}                         # origin -> class

    def _try(cls: str, seen: set) -> bool:
        for o in origins.get(cls) or {f"free:{cls}"}:
            if o in seen:
                continue
            seen.add(o)
            if o not in match or _try(match[o], seen):
                match[o] = cls
                return True
        return False

    return all(_try(c, set()) for c in chosen)


def _alt_satisfied(states: list[dict], origins: dict) -> bool:
    """All clauses satisfied by MUTUALLY independent classes."""
    import itertools
    if any(not st["satisfied"] for st in states):
        return False
    pools = [list(itertools.combinations(st["have"], st["need"])) for st in states]
    total = 1
    for p in pools:
        total *= max(1, len(p))
    if total > 5000:                                   # pathological — greedy
        chosen = [c for st in states for c in st["have"][:st["need"]]]
        return _independent(chosen, origins)
    for pick in itertools.product(*pools):
        chosen = [c for grp in pick for c in grp]
        if len(set(chosen)) == len(chosen) and _independent(chosen, origins):
            return True
    return False


def _reaches(alts: list[list[dict]], present: set[str],
             origins: dict | None = None) -> tuple[bool, list[dict]]:
    """(True, []) if any alternative is fully satisfied by independent
    artifacts; else (False, the unsatisfied clauses of the alternative closest
    to satisfied — or an `independence` clause when only independence fails)."""
    if not alts:
        return False, [{"group": "unreachable", "need": 0, "have": [], "satisfied": False,
                        "candidates": [], "tools": []}]
    origins = origins or {}
    best_missing: list[dict] | None = None
    for alt in alts:
        states = [_clause_state(c, present) for c in alt]
        missing = [st for st in states if not st["satisfied"]]
        if not missing:
            if _alt_satisfied(states, origins):
                return True, []
            missing = [{"group": "independence", "need": len(alt), "have": [],
                        "satisfied": False, "candidates": [],
                        "tools": [], "note": (
                            "the clauses are backed by the SAME tool run — "
                            "one run is one artifact; cite a second, "
                            "independent call")}]
        if best_missing is None or len(missing) < len(best_missing):
            best_missing = missing
    return False, (best_missing or [])


def tier_for(claim: dict, classes: dict | set | None,
             origins: dict | None = None) -> TierResult:
    """Highest tier the artifact classes reach for the claim's act/channel.
    SUSPECTED is the floor (always achievable). An act with no rules yields
    CONFIRMED-unreachable-unknown: tier '' so callers can skip."""
    claim = claim or {}
    act = str(claim.get("act") or "").lower()
    channel = str(claim.get("channel") or "").lower()
    rules, key = _rules_for(act, channel)
    cls_map = dict(classes) if isinstance(classes, dict) else {c: [] for c in (classes or [])}
    present = set(cls_map)
    res = TierResult(tier="", act=act, channel=channel, rule_key=key, classes=cls_map)
    res.origins = {k: set(v) for k, v in (origins or {}).items()}
    if not rules:
        return res
    reached = "SUSPECTED"
    for t in _ORDER:                                  # CONFIRMED, LIKELY, SUSPECTED
        ok, _ = _reaches(_alternatives(rules.get(t)), present, res.origins)
        if ok:
            reached = t
            break
    res.tier = reached
    if reached != "CONFIRMED":
        nxt = "CONFIRMED" if reached == "LIKELY" else "LIKELY"
        _, missing = _reaches(_alternatives(rules.get(nxt)), present, res.origins)
        res.next_tier = nxt
        res.missing = missing
    return res


def tier_path(res: TierResult, target: str = "") -> str:
    """One paragraph: what the target (default: next) tier still needs."""
    target = (target or res.next_tier or "").upper()
    if not res.act or not target or res.tier == "CONFIRMED":
        return ""
    rules, _ = _rules_for(res.act, res.channel)
    _, missing = _reaches(_alternatives(rules.get(target)), set(res.classes), res.origins)
    have = ", ".join(sorted(res.classes)) or "none"
    if not missing:
        return f"{target} is reachable with the cited classes ({have})."
    bits = []
    for m in missing:
        if m["group"] == "unreachable":
            bits.append(f"{target} is not defined for act={res.act}")
            continue
        if m["group"] == "independence":
            bits.append(m.get("note") or "independent artifacts required")
            continue
        short = int(m["need"]) - len(m["have"])
        cands = ", ".join(f"{class_label(c)} [{'; '.join(class_tools(c)[:3]) or c}]"
                          for c in m["candidates"][:8])
        bits.append(f"{short} more of group '{m['group']}' — any of: {cands}")
    return (f"{target} for act={res.act}{('/' + res.channel) if res.channel else ''} needs "
            + "; AND ".join(bits) + f". Cited classes: {have}.")
