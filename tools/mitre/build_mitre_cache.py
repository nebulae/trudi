"""Fetch + filter MITRE CTI enterprise-attack.json and write the local tables.

Usage:
    python -m tools.mitre.build_mitre_cache [--output-dir DIR] [--source URL]

The script:
  1. Downloads enterprise-attack.json (~30MB) from the MITRE CTI repo.
  2. Filters `attack-pattern` objects to DFIR-relevant tactics (drops Reconnaissance,
     Resource Development; trims Discovery to the most common entries).
  3. Filters `intrusion-set` objects to those with non-empty aliases.
  4. Joins via `relationship` objects (`relationship_type == "uses"`) to build
     `{group_id: [technique_ids]}` map.
  5. MERGES into existing `mitre_techniques.json` — pre-existing T-IDs retain
     their already-tuned keywords; new T-IDs get keywords from
     `tools/mitre/keywords.py`.
  6. Writes `mitre_techniques.json` and `mitre_groups.json` under --output-dir.

Run once, commit the resulting JSON files. Do NOT bake live MITRE API calls
into the runtime — too slow and too flaky during a demo.
"""
from __future__ import annotations
import argparse
import datetime
import json
import os
import re
import sys
import urllib.request
from typing import Optional

MITRE_CTI_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# DFIR-relevant tactics. Skip Reconnaissance / Resource Development entirely
# (those are pre-compromise and not observable from disk/memory forensics).
DFIR_TACTICS = {
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}

DEFAULT_OUTPUT_DIR = os.path.expanduser("~/cases/.common")


def _tactic_human(name: str) -> str:
    """`credential-access` → `Credential Access`."""
    return " ".join(w.capitalize() for w in name.split("-"))


def _extract_technique_id(obj: dict) -> Optional[str]:
    """Pull the `T1059.001`-style id from a STIX object's external_references."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_group_id(obj: dict) -> Optional[str]:
    """Pull the `G0050`-style id from a STIX intrusion-set's external_references."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _load_existing_techniques(path: str) -> dict[str, dict]:
    """Read the existing mitre_techniques.json so we can preserve hand-tuned
    `keywords` for T-IDs that already had them. Returns {} if missing."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f).get("techniques", {}) or {}
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def fetch(source_url: str) -> dict:
    print(f"[build_mitre_cache] downloading {source_url} ...", file=sys.stderr)
    with urllib.request.urlopen(source_url, timeout=60) as resp:
        data = json.load(resp)
    print(f"[build_mitre_cache] got {len(data.get('objects', []))} STIX objects", file=sys.stderr)
    return data


def build_tables(stix: dict, existing_techniques: dict) -> tuple[dict, dict]:
    """Return (techniques_table, groups_table) as serializable dicts."""
    from . import keywords as kw_mod

    objects = stix.get("objects", []) or []

    # Pass 1: collect techniques + groups by their STIX id so we can join.
    technique_by_stix_id: dict[str, dict] = {}
    group_by_stix_id: dict[str, dict] = {}

    for obj in objects:
        otype = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if otype == "attack-pattern":
            tid = _extract_technique_id(obj)
            if not tid:
                continue
            phases = obj.get("kill_chain_phases", []) or []
            tactics = sorted({
                p.get("phase_name", "")
                for p in phases
                if p.get("kill_chain_name") == "mitre-attack"
            })
            # Every LIVE enterprise technique is kept: the table is the
            # VALIDATION reference for T-ids in findings, and a tactic filter
            # dropped 230 of 697 (the CTI bundle now uses phase names such as
            # 'stealth' / 'defense-impairment' that the DFIR_TACTICS allowlist
            # never contained — T1027 and T1562 were "unknown" for months).
            # DFIR_TACTICS still drives keyword/ranking emphasis downstream.
            tactic_human = " ".join(_tactic_human(t) for t in tactics) or "unclassified"
            technique_by_stix_id[obj["id"]] = {
                "_tid": tid,
                "name": obj.get("name", "")[:120],
                "tactic": tactic_human,
                "description": (obj.get("description", "") or "").split("\n", 1)[0][:400],
            }
        elif otype == "intrusion-set":
            aliases = obj.get("aliases", []) or []
            if not aliases:
                continue
            gid = _extract_group_id(obj)
            if not gid:
                continue
            group_by_stix_id[obj["id"]] = {
                "_gid": gid,
                "name": obj.get("name", "")[:120],
                "aliases": [a for a in aliases if a != obj.get("name", "")][:20],
                "description": (obj.get("description", "") or "").split("\n", 1)[0][:400],
                "technique_ids": [],
            }

    # Pass 2: relationships → group_id → [technique_ids]
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        group = group_by_stix_id.get(src)
        tech = technique_by_stix_id.get(tgt)
        if not group or not tech:
            continue
        group["technique_ids"].append(tech["_tid"])

    # Build final dicts.
    techniques_out: dict[str, dict] = {}
    for stix_id, info in technique_by_stix_id.items():
        tid = info["_tid"]
        # Carry forward existing keywords; seed new T-IDs from the curated list.
        existing = existing_techniques.get(tid) or {}
        existing_kw = existing.get("keywords") if existing else None
        seed_kw = kw_mod.KEYWORD_SEEDS.get(tid, [])
        if existing_kw:
            keywords = existing_kw
        elif seed_kw:
            keywords = seed_kw
        else:
            keywords = []
        techniques_out[tid] = {
            "name": info["name"],
            "tactic": info["tactic"],
            "description": info["description"],
            "keywords": keywords,
        }

    groups_out: dict[str, dict] = {}
    for stix_id, g in group_by_stix_id.items():
        gid = g["_gid"]
        # Sort + dedupe technique_ids for stable output
        tids = sorted(set(g["technique_ids"]))
        if not tids:
            continue
        groups_out[gid] = {
            "name": g["name"],
            "aliases": g["aliases"],
            "description": g["description"],
            "technique_ids": tids,
        }

    return techniques_out, groups_out


def write_outputs(output_dir: str, techniques: dict, groups: dict, source_url: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    built_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    techniques_path = os.path.join(output_dir, "mitre_techniques.json")
    groups_path = os.path.join(output_dir, "mitre_groups.json")

    techniques_doc = {
        "_meta": {
            "source": source_url,
            "version": "v15",
            "format": "{technique_id: {name, tactic, description, keywords}}",
            "built_at": built_at,
        },
        "techniques": techniques,
    }
    groups_doc = {
        "_meta": {
            "source": source_url,
            "version": "v15",
            "format": "{group_id: {name, aliases, description, technique_ids}}",
            "built_at": built_at,
        },
        "groups": groups,
    }

    # Pretty-print to keep diffs reviewable.
    with open(techniques_path, "w") as f:
        json.dump(techniques_doc, f, indent=2, sort_keys=True)
    with open(groups_path, "w") as f:
        json.dump(groups_doc, f, indent=2, sort_keys=True)

    print(f"[build_mitre_cache] wrote {len(techniques)} techniques → {techniques_path}", file=sys.stderr)
    print(f"[build_mitre_cache] wrote {len(groups)} groups → {groups_path}", file=sys.stderr)


def build_detection(stix: dict, related_top: int = 6) -> dict:
    """Per technique: its detection strategies -> per-platform analytics -> log
    sources (data component, log source name, channel), plus the techniques
    most often used alongside it by the same groups/software (co-use, Jaccard).

    ATT&CK v18+ carries detection guidance as x-mitre-detection-strategy /
    x-mitre-analytic objects linked by `detects`; the legacy
    x_mitre_detection / x_mitre_data_sources fields are gone.
    """
    objs = [o for o in stix.get("objects", [])
            if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in objs}
    tech = {o["id"]: _extract_technique_id(o) for o in objs if o["type"] == "attack-pattern"}
    out: dict = {}
    for rel in objs:
        if rel["type"] != "relationship" or rel.get("relationship_type") != "detects":
            continue
        strat, tid = by_id.get(rel.get("source_ref")), tech.get(rel.get("target_ref"))
        if not strat or not tid:
            continue
        entry = out.setdefault(tid, {"name": by_id[rel["target_ref"]].get("name", ""),
                                     "strategies": [], "analytics": [], "related": []})
        entry["strategies"].append({"id": _extract_technique_id(strat), "name": strat.get("name", "")})
        for aref in strat.get("x_mitre_analytic_refs", []) or []:
            an = by_id.get(aref)
            if not an:
                continue
            sources = []
            for ls in an.get("x_mitre_log_source_references", []) or []:
                dc = by_id.get(ls.get("x_mitre_data_component_ref"))
                sources.append({"component": dc.get("name", "") if dc else "",
                                "source": ls.get("name", ""), "channel": ls.get("channel", "")})
            entry["analytics"].append({"id": _extract_technique_id(an),
                                       "platforms": an.get("x_mitre_platforms", []) or [],
                                       "description": (an.get("description") or "")[:600],
                                       "log_sources": sources})
    # Co-use: which techniques the same groups / software also use.
    users: dict = {}
    for rel in objs:
        if rel["type"] == "relationship" and rel.get("relationship_type") == "uses":
            t = tech.get(rel.get("target_ref"))
            if t and by_id.get(rel.get("source_ref"), {}).get("type") in (
                    "intrusion-set", "malware", "tool", "campaign"):
                users.setdefault(t, set()).add(rel["source_ref"])
    for tid, entry in out.items():
        mine = users.get(tid) or set()
        if not mine:
            continue
        scores = []
        for other, theirs in users.items():
            if other == tid or other.split(".")[0] == tid.split(".")[0]:
                continue
            inter = len(mine & theirs)
            if inter >= 2:
                scores.append((inter / len(mine | theirs), other))
        entry["related"] = [t for _, t in sorted(scores, reverse=True)[:related_top]]
    return out


def write_detection(output_dir: str, detection: dict, source: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "mitre_detection.json")
    doc = {"_meta": {"source": source,
                     "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                     "format": "{technique_id: {name, strategies, analytics[{id, platforms, "
                               "description, log_sources[{component, source, channel}]}], related}}"},
           "detection": detection}
    with open(path, "w") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
    print(f"[build_mitre_cache] wrote detection for {len(detection)} techniques → {path}", file=sys.stderr)
    return path


def main():
    parser = argparse.ArgumentParser(description="Build MITRE ATT&CK cache for TRUDI.")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--source", default=MITRE_CTI_URL)
    parser.add_argument("--input-file", help="Optional local STIX JSON to use instead of downloading")
    parser.add_argument("--detection-only", action="store_true",
                        help="Write only mitre_detection.json; leave the technique/group tables untouched")
    args = parser.parse_args()

    if args.input_file:
        with open(args.input_file) as f:
            stix = json.load(f)
    else:
        stix = fetch(args.source)

    write_detection(args.output_dir, build_detection(stix), args.input_file or args.source)
    if args.detection_only:
        return

    existing_techniques_path = os.path.join(args.output_dir, "mitre_techniques.json")
    existing = _load_existing_techniques(existing_techniques_path)
    print(f"[build_mitre_cache] preserving keywords for {sum(1 for t in existing.values() if t.get('keywords'))} existing T-IDs", file=sys.stderr)

    techniques, groups = build_tables(stix, existing)
    write_outputs(args.output_dir, techniques, groups, args.source)


if __name__ == "__main__":
    main()
