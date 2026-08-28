"""FK-driven corroboration completeness — warn-early + block-late.

A CONFIRMED/LIKELY finding grounded on a single forensic artifact is weak when
the corroborators the forensic-knowledge corpus names for that artifact were
never run. Each FK sheet's ``corroborate_with`` block already lists, per artifact
and per claim class (execution / presence / timeline), the TRUDI tools that
corroborate it — retargeted to real tool names during derivation (see
``data/fk/ATTRIBUTION.md``). This module reads that same data (via ``tools._fk``,
the shared loader the response enricher also uses) and checks it against the
trace, so the *guidance the agent was shown* and the *contract it is held to*
come from one corpus and cannot drift.

Two call sites, both deterministic (no model round-trip):

  * warn-early  — ``record_finding`` calls :func:`note_for_finding` after the
    hard gates pass and, for a CONFIRMED/LIKELY finding whose grounding
    artifact has its whole relevant corroboration category unrun, attaches a
    non-blocking ``completeness_note`` to the successful result.
  * block-late  — ``reason.pre_report_check`` calls :func:`report_gaps` to turn
    any still-uncorroborated CONFIRMED/LIKELY finding into a blocking issue.

This is NOT a member of the ``record_finding`` GATES list (those are block-only);
it is invoked directly by the two sites above so it can *warn* on success.

Matching note: ``tool_call`` trace entries carry the shell ``cmd`` (e.g.
``dotnet …/AmcacheParser.dll``), not an MCP tool name — so a corroborator is
detected by matching its cmd signature, exactly as ``_manifests.py`` does. A
finding's grounding artifact is resolved from its declared ``source``.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

from tools import _fk

# FK corroborator tool token -> a regex over the trace `cmd` that proves it ran.
# The token set is the closed set present in data/fk/**/corroborate_with (14
# tools); each maps to its binary/plugin signature. Boundaries guard the two
# substring traps: `lecmd` inside `jlecmd`, `pecmd`/`recmd`/`mftecmd` overlap.
_CORROBORATOR_CMD_RE: dict[str, "re.Pattern"] = {
    tok: re.compile(pat, re.IGNORECASE) for tok, pat in {
        "ez_amcacheparser": r"amcache",
        "vol_amcache": r"amcache",
        "ez_appcompatcacheparser": r"appcompatcache|shimcache",
        "ez_evtxecmd": r"evtxecmd|\.evtx",
        "ez_jlecmd": r"jlecmd",
        "ez_lecmd": r"(?<![a-z])lecmd",
        "ez_mftecmd": r"mftecmd",
        "ez_pecmd": r"(?<![a-z])pecmd|prefetch",
        "ez_recmd_hive": r"recmd",
        "ez_sbecmd": r"sbecmd",
        "ez_sqlecmd": r"sqlecmd|srudb|srum",
        "misc_regripper_hive": r"regripper|rip\.pl",
        "tsk_indxparse": r"indxparse|indx",
        "vol_userassist": r"userassist",
    }.items()
}

# Typed claim act -> FK corroboration category. No wording cues: a finding
# whose claim (v1, no act) does not declare one is not corroboration-checked.
_ACT_CATEGORY = {"execution": "for_execution", "presence": "for_presence",
                 "timeline": "for_timeline"}


def _norm(name: str) -> str:
    """Canonical MCP tool name: lowercase, dotted→underscore, de-doubled
    ('ez.pecmd'/'ez_ez_pecmd' → 'ez_pecmd')."""
    return _fk.normalize_tool_name((name or "").strip().lower().replace(".", "_"))


def _extract_tool_tokens(strings: Iterable[str]) -> set:
    """Corroborator tool tokens embedded in a corroborate_with list, e.g.
    'Amcache (ez_amcacheparser / vol_amcache)' → {ez_amcacheparser, vol_amcache}."""
    out: set = set()
    for s in strings or []:
        for m in re.findall(
            r"((?:ez|vol|misc|tsk|net|strings|hash|carve|plaso)_[a-z0-9_]+)", str(s)
        ):
            out.add(_norm(m))
    return out


def _claim_category(claim, available: set) -> Optional[str]:
    """The FK corroboration category the finding's DECLARED act falls in,
    restricted to categories the sheet defines — or None (an egress /
    attribution / undeclared claim has nothing to corroborate here)."""
    act = str((claim or {}).get("act") or "").lower() if isinstance(claim, dict) else ""
    cat = _ACT_CATEGORY.get(act)
    return cat if cat and cat in available else None


# A does_not_prove entry DISCLAIMS a claim class when it says the artifact cannot
# establish the EVENT itself — not merely who/what/when-detail. Entries that lead
# with who/what/how are attribution/detail disclaimers (e.g. prefetch "Who
# executed the program"), not event disclaimers, so they are skipped: prefetch and
# BAM remain authoritative for execution, event logs for logon, MFT for presence.
_DISCLAIM_LEAD_SKIP = re.compile(r"^\s*(?:who|what|how)\b", re.IGNORECASE)
_DISCLAIM_RE = {
    "for_execution": re.compile(r"\b(?:was|been|actually)\s+execut|execution via",
                                re.IGNORECASE),
    "for_presence": re.compile(r"\b(?:still |currently )?exist|no longer",
                               re.IGNORECASE),
    "for_timeline": re.compile(r"timestamp|accurate|specific time|aggregated"
                               r"|hourly interval", re.IGNORECASE),
}


def _category_disclaimed(sheet: dict, category: str) -> bool:
    """True when the artifact's does_not_prove says it cannot establish this claim
    class alone — i.e. corroboration is genuinely required. An authoritative
    record (event-log logon, prefetch/BAM execution, MFT presence) does not
    disclaim its own claim class and needs none."""
    rx = _DISCLAIM_RE.get(category)
    if not rx:
        return False
    for x in (sheet.get("does_not_prove") or []):
        s = str(x)
        if _DISCLAIM_LEAD_SKIP.match(s):
            continue
        if rx.search(s):
            return True
    return False


def corroboration_gap(source: str, claim, ran_cmds: Iterable[str]) -> Optional[dict]:
    """The corroboration gap for one finding, or None if satisfied / N/A.

    source   : the finding's declared grounding tool (dotted or underscored).
    claim    : the finding's typed claim (claim.act selects the category).
    ran_cmds : `cmd` strings of the tool_call entries in the trace.

    Fires only when ALL hold: the source maps to an FK artifact; the claim is
    clearly an execution/presence/timeline assertion; the artifact's
    does_not_prove DISCLAIMS that claim class (so it is weak alone); and NONE of
    the FK-named corroborators for that class ran.
    """
    stem = _fk.artifact_stem_for_tool(_norm(source))
    if not stem:
        return None  # source is not an FK-mapped artifact — nothing to check
    sheet = _fk.load_artifact(stem)
    corr = sheet.get("corroborate_with") or {}
    if not corr:
        return None
    category = _claim_category(claim, set(corr))
    if category is None:
        return None  # not an execution/presence/timeline claim
    if not _category_disclaimed(sheet, category):
        return None  # artifact is authoritative for this claim class
    expected = _extract_tool_tokens(corr.get(category, []))
    checkable = [t for t in expected if t in _CORROBORATOR_CMD_RE]
    if not checkable:
        return None  # no corroborator we can detect from cmds — do not nag
    cmds = list(ran_cmds or [])
    if any(_CORROBORATOR_CMD_RE[t].search(c) for t in checkable for c in cmds):
        return None  # at least one corroborator ran
    what = category.replace("for_", "")
    return {
        "artifact": stem,
        "category": category,
        "expected": sorted(checkable),
        "message": (
            f"grounded on {stem} but no FK corroborator for {what} ran — none of "
            f"{', '.join(sorted(checkable))} appear in the trace; {stem} does not "
            f"prove {what} alone."
        ),
    }


def _ran_cmds(entries) -> list:
    return [e.get("cmd", "") for e in (entries or [])
            if e.get("type") == "tool_call" and e.get("cmd")]


def note_for_finding(*, tier: str, description: str, source: str, idx,
                     claim=None) -> Optional[str]:
    """warn-early: a non-blocking completeness note for a just-recorded
    CONFIRMED/LIKELY finding, or None. `idx` is the ExecutionLog LogIndex."""
    if (tier or "").upper() not in {"CONFIRMED", "LIKELY"}:
        return None
    by_type = getattr(idx, "by_type", {}) or {}
    gap = corroboration_gap(source, claim, _ran_cmds(by_type.get("tool_call", [])))
    if not gap:
        return None
    return (f"Finding {gap['message']} Corroborate with one of "
            f"{', '.join(gap['expected'])}, or downgrade to SUSPECTED.")


def report_gaps(entries) -> list:
    """block-late: [(finding_description, gap_dict), …] for every CONFIRMED/LIKELY
    finding still uncorroborated at report time. `entries` is log._entries."""
    cmds = _ran_cmds(entries)
    out = []
    for e in entries or []:
        if e.get("type") != "finding":
            continue
        if (e.get("confidence") or "").upper() not in {"CONFIRMED", "LIKELY"}:
            continue
        gap = corroboration_gap(e.get("source", ""), e.get("claim") or {}, cmds)
        if gap:
            out.append((e.get("description", ""), gap))
    return out
