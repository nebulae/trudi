"""Shared reader for the TRUDI forensic-knowledge corpus (``data/fk/``).

Single source of truth for locating FK sheets, mapping a TRUDI tool to its FK
artifact/tool sheet, and reading the ``corroborate_with`` pointers. Both the
response enricher (``tools/_enrich.py``) and the completeness gates import from
here, so the tool→artifact map and the corroboration data have exactly one
definition. Loading is cached and fails soft (missing sheet ⇒ ``{}``).

Provenance of the sheets themselves: see ``data/fk/ATTRIBUTION.md``.
"""
from __future__ import annotations

import functools
from pathlib import Path

import yaml

FK_DIR = Path(__file__).resolve().parent.parent / "data" / "fk"

# --- TRUDI tool -> FK artifact sheet (does_not_prove / corroborate_with / …) ---
ARTIFACT_MAP: dict[str, str] = {
    "vol_userassist": "userassist",
    "ez_appcompatcacheparser": "shimcache",
    "ez_amcacheparser": "amcache",
    "vol_amcache": "amcache",
    "ez_pecmd": "prefetch",
    "ez_mftecmd": "mft",
    "ez_mftecmd_dir": "mft",
    "ez_lecmd": "lnk_files",
    "ez_jlecmd": "jump_lists",
    "ez_rbcmd": "recycle_bin",
    "ez_sbecmd": "shellbags",
    "ez_evtxecmd": "event_logs_security",
}

# --- TRUDI tool -> FK tool sheet (caveats / field_meanings / exit_code_hints) --
# Explicit overrides; every other vol_* falls through to the volatility3 sheet.
TOOL_MAP: dict[str, str] = {}


def normalize_tool_name(tool_name: str) -> str:
    """Collapse a namespace-DOUBLED tool name (``ez_ez_mftecmd``,
    ``vol_vol_pslist``) to its single-namespace form (``ez_mftecmd``,
    ``vol_pslist``). Wire names have been single-namespace since the
    mount-time dedup (core/normalize_names.py); this stays as the compat
    shim for names read from OLD traces. Idempotent on already-normal
    names."""
    parts = tool_name.split("_", 2)
    if len(parts) >= 2 and parts[0] == parts[1]:
        return tool_name[len(parts[0]) + 1:]
    return tool_name


def artifact_stem_for_tool(tool_name: str) -> str | None:
    """FK artifact-sheet stem produced by a TRUDI tool, or None."""
    return ARTIFACT_MAP.get(normalize_tool_name(tool_name))


def tool_stem_for_tool(tool_name: str) -> str | None:
    """FK tool-sheet stem for a TRUDI tool, or None. Any ``vol_*`` without an
    explicit override falls through to the shared volatility3 sheet."""
    name = normalize_tool_name(tool_name)
    if name in TOOL_MAP:
        return TOOL_MAP[name]
    if name.startswith("vol_"):
        return "volatility3"
    return None


@functools.lru_cache(maxsize=None)
def load_artifact(stem: str) -> dict:
    for plat in ("windows", "linux", "macos"):
        p = FK_DIR / "artifacts" / plat / f"{stem}.yaml"
        if p.is_file():
            return yaml.safe_load(p.read_text()) or {}
    return {}


@functools.lru_cache(maxsize=None)
def load_tool(stem: str) -> dict:
    for p in (FK_DIR / "tools").rglob(f"{stem}.yaml"):
        return yaml.safe_load(p.read_text()) or {}
    return {}


def corroborators_for_tool(tool_name: str) -> dict:
    """The ``corroborate_with`` block for the artifact a tool produces, or ``{}``.

    Shape (as authored in the FK sheets, values are human "Name (trudi_tool)"
    strings)::

        {"for_execution": ["Amcache (ez_amcacheparser / vol_amcache)", ...],
         "for_presence":  ["$MFT (ez_mftecmd)", ...],
         "for_timeline":  ["USN journal (tsk_indxparse)", ...]}
    """
    stem = artifact_stem_for_tool(tool_name)
    if not stem:
        return {}
    return load_artifact(stem).get("corroborate_with", {}) or {}
