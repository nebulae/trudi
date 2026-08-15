#!/usr/bin/env python3
"""Regenerate TRUDI's FK sheets from AppliedIR forensic-knowledge (MIT).

Provenance / reproducibility for data/fk/. The sheets under artifacts/ and
tools/ are DERIVED from AppliedIR's forensic-knowledge package by this script:
it allowlists only neutral forensic fields, scrubs any coupled list items,
retargets corroborate_with to TRUDI tools, and stamps an SPDX header.
See ATTRIBUTION.md.

To regenerate (e.g. to add sheets or refresh from a newer upstream):

    git clone https://github.com/AppliedIR/sift-mcp   # pin the commit below
    UPSTREAM_FK_DIR=/path/to/sift-mcp/packages/forensic-knowledge/data \\
        python3 data/fk/derive_from_upstream.py

Upstream pinned at commit c67a860 (forensic-knowledge 0.6.1).
"""
from __future__ import annotations
import os
from pathlib import Path
import yaml

SRC = Path(os.environ.get("UPSTREAM_FK_DIR", ""))
DST = Path(__file__).resolve().parent
UPSTREAM_COMMIT = "c67a860"

KEEP_ARTIFACT = {"name", "description", "platform", "locations", "proves", "does_not_prove",
                 "timestamps", "common_misinterpretations", "corroborate_with", "caveats"}
KEEP_TOOL = {"name", "description", "platform", "caveats", "advisories", "field_meanings",
             "exit_code_hints", "output_notes", "plugins", "quick_start"}
import re
COUPLED_RE = re.compile(r"cross-mcp|via sift-mcp|via forensic|wintools|remnux|opencti|opensearch|windows-triage|forensic-rag|case-\*", re.I)

ARTIFACT_TO_TOOL = {
    "prefetch": "Prefetch (ez_pecmd)",
    "bam": "BAM (ez_recmd_hive / misc_regripper_hive)",
    "amcache": "Amcache (ez_amcacheparser / vol_amcache)",
    "mft": "$MFT (ez_mftecmd)",
    "shimcache": "Shimcache (ez_appcompatcacheparser)",
    "userassist": "UserAssist (vol_userassist / ez_recmd_hive)",
    "event_logs_security": "Security event logs (ez_evtxecmd)",
    "srum": "SRUM (ez_sqlecmd)",
    "shellbags": "Shellbags (ez_sbecmd)",
    "lnk_files": "LNK files (ez_lecmd)",
    "jump_lists": "Jump lists (ez_jlecmd)",
    "recycle_bin": "Recycle Bin (ez_rbcmd)",
    "usn_journal": "USN journal (tsk_indxparse)",
    "registry_run_keys": "Run keys (ez_recmd_hive)",
    "scheduled_tasks": "Scheduled tasks (ez_evtxecmd 4698)",
}
SHEET_TO_TRUDI_TOOLS = {
    "userassist": ["vol_userassist", "ez_recmd_hive"],
    "shimcache": ["ez_appcompatcacheparser"],
    "amcache": ["ez_amcacheparser", "vol_amcache"],
    "prefetch": ["ez_pecmd"],
    "mft": ["ez_mftecmd", "ez_mftecmd_dir"],
    "lnk_files": ["ez_lecmd"],
    "jump_lists": ["ez_jlecmd"],
    "recycle_bin": ["ez_rbcmd"],
    "shellbags": ["ez_sbecmd"],
    "usn_journal": ["tsk_indxparse"],
    "event_logs_security": ["ez_evtxecmd"],
    "bam": ["ez_recmd_hive"],
    "registry_run_keys": ["ez_recmd_hive"],
    "scheduled_tasks": ["ez_evtxecmd"],
    "srum": ["ez_sqlecmd"],
}
ARTIFACTS = list(SHEET_TO_TRUDI_TOOLS)
TOOLS = {"volatility/volatility3": None}


def scrub_lists(v):
    if isinstance(v, dict):
        return {k: scrub_lists(x) for k, x in v.items()}
    if isinstance(v, list):
        return [scrub_lists(x) for x in v if not COUPLED_RE.search(yaml.safe_dump(x))]
    return v


def keep_only(data, allow):
    return {k: scrub_lists(v) for k, v in data.items() if k in allow}


def retarget(cw):
    if not isinstance(cw, dict):
        return cw
    return {k: [ARTIFACT_TO_TOOL.get(x, x) if isinstance(x, str) else x for x in (v or [])]
            for k, v in cw.items()}


def header():
    return ("# SPDX-License-Identifier: MIT\n"
            f"# Derived-From: AppliedIR forensic-knowledge @ {UPSTREAM_COMMIT} "
            "(Copyright (c) 2026 AppliedIncidentResponse.com)\n"
            "# Modifications: stripped Valhuntir platform-wiring fields; "
            "corroboration retargeted to TRUDI tools.\n"
            "# See ATTRIBUTION.md and THIRD_PARTY/forensic-knowledge/LICENSE.\n")


def transform(src_path, stem, kind):
    data = keep_only(yaml.safe_load(src_path.read_text()), KEEP_ARTIFACT if kind == "artifact" else KEEP_TOOL)
    if "corroborate_with" in data:
        data["corroborate_with"] = retarget(data["corroborate_with"])
    if stem in SHEET_TO_TRUDI_TOOLS:
        data["trudi_tools"] = SHEET_TO_TRUDI_TOOLS[stem]
    return header() + yaml.safe_dump(data, sort_keys=False, width=100, allow_unicode=True)


def main():
    if not SRC.is_dir():
        raise SystemExit("Set UPSTREAM_FK_DIR to a cloned forensic-knowledge/data directory. See module docstring.")
    (DST / "artifacts/windows").mkdir(parents=True, exist_ok=True)
    (DST / "tools/volatility").mkdir(parents=True, exist_ok=True)
    n = 0
    for stem in ARTIFACTS:
        src = SRC / "artifacts/windows" / f"{stem}.yaml"
        if src.exists():
            (DST / "artifacts/windows" / f"{stem}.yaml").write_text(transform(src, stem, "artifact")); n += 1
    for rel in TOOLS:
        src = SRC / "tools" / f"{rel}.yaml"
        if src.exists():
            (DST / "tools/volatility" / f"{Path(rel).stem}.yaml").write_text(transform(src, Path(rel).stem, "tool")); n += 1
    print(f"wrote {n} sheets to {DST}")


if __name__ == "__main__":
    main()
