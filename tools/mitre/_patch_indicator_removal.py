"""One-shot patch: backfill the T1070 Indicator Removal family into the
local mitre_techniques.json table.

The local v15 table can be missing the T1070 family even though investigations
and tools legitimately cite entries such as T1070.004 (File Deletion). That
turns the MITRE validation gate into a false-refusal path: it blocks a real
technique ID because the local cache is incomplete.

Names/tactics/descriptions are ATT&CK v15-compatible definitions. Group to
technique mappings are NOT touched here -- those must come from authoritative
MITRE CTI via build_mitre_cache, not hand-authored.

Idempotent: re-running only adds entries that are still missing.
"""
from __future__ import annotations
import datetime
import json
import os

PATH = os.path.expanduser("~/cases/.common/mitre_techniques.json")

TACTIC = "Defense Evasion"

FAMILY = {
    "T1070": {
        "name": "Indicator Removal",
        "description": "Adversaries may delete or modify artifacts generated on a host system to remove evidence of their presence or hinder defenses.",
        "keywords": ["indicator removal", "clear logs", "delete evidence", "remove artifacts", "anti-forensics"],
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "description": "Adversaries may clear Windows Event Logs to hide activity from defenders and security tools.",
        "keywords": ["clear windows event logs", "wevtutil cl", "event log cleared", "security log cleared"],
    },
    "T1070.002": {
        "name": "Clear Linux or Mac System Logs",
        "description": "Adversaries may clear system logs on Linux or macOS systems to hide activity from defenders and security tools.",
        "keywords": ["clear linux logs", "clear mac logs", "rm /var/log", "wtmp"],
    },
    "T1070.003": {
        "name": "Clear Command History",
        "description": "Adversaries may clear command history to hide commands they executed on a compromised system.",
        "keywords": ["clear command history", ".bash_history", "history -c", "powershell history"],
    },
    "T1070.004": {
        "name": "File Deletion",
        "description": "Adversaries may delete files left behind by the actions of their intrusion activity to remove indicators of their presence.",
        "keywords": ["file deletion", "deleted files", "del", "rm", "shred"],
    },
    "T1070.005": {
        "name": "Network Share Connection Removal",
        "description": "Adversaries may remove network share connections that are no longer useful to clean up traces of activity.",
        "keywords": ["network share connection removal", "net use /delete", "remove share connection"],
    },
    "T1070.006": {
        "name": "Timestomp",
        "description": "Adversaries may modify file time attributes to hide new or changed files from forensic analysis.",
        "keywords": ["timestomp", "timestamp manipulation", "file time changed", "time attribute modified"],
    },
    "T1070.007": {
        "name": "Clear Network Connection History and Configurations",
        "description": "Adversaries may clear or modify network history or configuration artifacts to hide connections and activity.",
        "keywords": ["clear network connection history", "clear network configuration", "ipconfig /flushdns"],
    },
    "T1070.008": {
        "name": "Clear Mailbox Data",
        "description": "Adversaries may delete or modify mailbox data to hide email activity or remove evidence.",
        "keywords": ["clear mailbox data", "delete inbox", "delete email", "mailbox rule"],
    },
}


def main() -> None:
    with open(PATH) as f:
        table = json.load(f)
    techniques = table.setdefault("techniques", {})

    added = []
    for tid, info in FAMILY.items():
        if tid in techniques:
            continue
        techniques[tid] = {
            "description": info["description"],
            "keywords": info["keywords"],
            "name": info["name"],
            "tactic": TACTIC,
        }
        added.append(tid)

    if not added:
        print("No change -- T1070 family already present.")
        return

    meta = table.setdefault("_meta", {})
    meta.setdefault("patches", []).append({
        "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "added": added,
        "reason": "T1070 Indicator Removal family absent in local v15 table; real T1070.004 File Deletion citations were refused by the mitre_technique_validation gate.",
        "by": "manual",
    })

    with open(PATH, "w") as f:
        json.dump(table, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"Added {len(added)} techniques: {', '.join(added)}")
    print(f"Total techniques now: {len(techniques)}")


if __name__ == "__main__":
    main()
