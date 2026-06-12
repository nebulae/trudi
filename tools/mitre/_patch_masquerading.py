"""One-shot patch: backfill the T1036 Masquerading family into the local
mitre_techniques.json table.

The v15 build shipped with the entire T1036 family absent (0 of 467
techniques, and cascaded to 0 of 165 groups). Investigations citing T1036.005
(Match Legitimate Name or Location, e.g. a binary masquerading under /tmp) and
T1036.008 (Masquerade File Type) were therefore refused by the
`mitre_technique_validation` gate on record_finding.

Names/tactics/descriptions are factual ATT&CK v15 definitions. Keywords reuse
the seeds in tools/mitre/keywords.py plus the artifacts actually observed in
the runs (kworker, ppid=1, signature/extension mismatch). Group->technique
mappings are NOT touched here -- those must come from authoritative MITRE CTI
via build_mitre_cache, not hand-authored.

Idempotent: re-running only adds entries that are still missing.
"""
from __future__ import annotations
import datetime
import json
import os

PATH = os.path.expanduser("~/cases/.common/mitre_techniques.json")

TACTIC = "Defense Evasion"

FAMILY = {
    "T1036": {
        "name": "Masquerading",
        "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation.",
        "keywords": ["masquerading", "masquerade", "disguised process", "impersonated process name", "appears legitimate"],
    },
    "T1036.001": {
        "name": "Invalid Code Signature",
        "description": "Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with.",
        "keywords": ["invalid code signature", "forged signature", "spoofed signature", "invalid authenticode", "copied signature"],
    },
    "T1036.002": {
        "name": "Right-to-Left Override",
        "description": "Adversaries may abuse the right-to-left override (RTLO or RLO) character (U+202E) to disguise a string and/or file name to make it appear benign. RTLO is a non-printing Unicode character that causes the text that follows it to be displayed in reverse.",
        "keywords": ["right-to-left override", "rtlo", "rlo", "u+202e", "unicode filename reversal"],
    },
    "T1036.003": {
        "name": "Rename System Utilities",
        "description": "Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities. Security monitoring and control mechanisms may be in place for system utilities adversaries are capable of abusing.",
        "keywords": ["rename system utilities", "renamed cmd", "renamed powershell", "renamed system binary"],
    },
    "T1036.004": {
        "name": "Masquerade Task or Service",
        "description": "Adversaries may attempt to manipulate the name of a task or service to make it appear legitimate or benign. Tasks/services executed by the Task Scheduler or systemd will typically be given a name and/or description.",
        "keywords": ["masquerade task or service", "fake service name", "fake scheduled task", "spoofed service name", "fake systemd unit"],
    },
    "T1036.005": {
        "name": "Match Legitimate Name or Location",
        "description": "Adversaries may match or approximate the name or location of legitimate files or resources when naming/placing their files. This is done for the sake of evading defenses and observation, e.g. placing an executable in a commonly trusted directory or giving it the name of a legitimate, trusted program.",
        "keywords": ["match legitimate name or location", "legitimate name or location", "kworker", "kworkerd", "fake kernel worker", "fake system process name", "executable in /tmp", "svchost in temp", "hidden dotfile binary"],
    },
    "T1036.006": {
        "name": "Space after Filename",
        "description": "Adversaries can hide a program's true file type by changing the extension of a file, optionally adding a space to the end of a filename to change how the operating system processes it. There are two ways to disguise a file's purpose using a space after the filename.",
        "keywords": ["space after filename", "trailing space filename", "filename trailing whitespace"],
    },
    "T1036.007": {
        "name": "Double File Extension",
        "description": "Adversaries may abuse a double extension in the filename as a means of masquerading the true file type. A file name may include a secondary file type extension that may cause only the first extension to be displayed.",
        "keywords": ["double extension", "double file extension", ".pdf.exe", ".doc.exe", ".jpg.exe"],
    },
    "T1036.008": {
        "name": "Masquerade File Type",
        "description": "Adversaries may masquerade malicious payloads as legitimate files through changes to the payload's formatting, including the file's signature, extension, and contents. Various file types have a typical standard format, including how they are encoded and organized.",
        "keywords": ["masquerade file type", "spoofed magic bytes", "mismatched file signature", "extension content mismatch", "fake file type", "signature mismatch"],
    },
    "T1036.009": {
        "name": "Break Process Trees",
        "description": "An adversary may attempt to evade process tree-based analysis by modifying their malware to have a different parent process. Adversaries may use techniques such as re-parenting executed payloads to a different process so that the malicious lineage is broken or obscured.",
        "keywords": ["break process tree", "reparent process", "spoofed ppid", "parent pid spoofing", "orphaned to init", "ppid=1", "detached parent"],
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
        print("No change -- T1036 family already present.")
        return

    meta = table.setdefault("_meta", {})
    meta.setdefault("patches", []).append({
        "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "added": added,
        "reason": "T1036 Masquerading family absent in v15 build; T1036.005/T1036.008 citations were refused by the mitre_technique_validation gate. Definitions from ATT&CK v15; group mappings deferred to authoritative CTI rebuild.",
        "by": "manual",
    })

    with open(PATH, "w") as f:
        json.dump(table, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"Added {len(added)} techniques: {', '.join(added)}")
    print(f"Total techniques now: {len(techniques)}")


if __name__ == "__main__":
    main()
