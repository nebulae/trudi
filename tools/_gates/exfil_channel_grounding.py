"""Gate: a CONFIRMED/LIKELY finding asserting data *left the host* via a named
channel must cite a *transfer* artifact — not tool-execution or file-presence.

Root-cause failure this closes (generic, not scenario-specific): an
investigation promotes an exfiltration channel into the verdict on the strength
of a tool being installed or a file sitting in a sync/staging folder ("Dropbox
client present + archive in the Dropbox folder ⇒ cloud exfil"), while the actual
transfer is never evidenced and a competing channel with stronger evidence is
downranked. "The tool was here" and "the file was in the folder" are *presence*,
not *egress*. A channel claim must rest on a record that bytes actually moved.

Trigger (description prose):
  tier ∈ {CONFIRMED, LIKELY}
  AND the description asserts egress (exfiltrated / uploaded / transferred /
      sent to / copied to / transmitted / leaked)
  AND it names a channel (cloud / Dropbox / OneDrive / GDrive / FTP / USB /
      removable / email / attachment / web upload / C2 / Telegram / SMTP).

Pass condition (evidence, NOT prose): a transfer marker appears in
lineage_evidence_text(ctx) — the agent's supporting_evidence plus the cmd /
stdout_excerpt of the linked_call_id and input_call_ids entries. Transfer
markers: an FTP/transfer log (transfers.log), a byte-count of data sent/written/
transferred, a USN $J write/rename record, a removable-volume LNK / MountedDevices
/ DEVPKEY binding (the file physically resided on removable media), a mail record
carrying an attachment, netflow/pcap egress, or SRUM per-app network bytes.

Explicitly NON-satisfying (presence only): a file in a sync/staging folder, a
cloud-client ADS such as :com.dropbox.attributes, or tool-execution alone
("VeraCrypt ran", "Dropbox.exe present"). These describe staging, not egress.
"""
import re
from typing import Optional

from ._match import lineage_evidence_text

# Asserts data left the host.
_EGRESS_RE = re.compile(
    r"\b(?:exfil\w*|uploaded|upload\b|transferred|transmit\w*|sent to\b"
    r"|copied to\b|leaked|egress\w*)\b",
    re.IGNORECASE,
)

# Names a channel the egress used.
_CHANNEL_RE = re.compile(
    r"\b(?:cloud\b|dropbox|onedrive|gdrive|google drive|mega\b|box\.com"
    r"|ftp\b|sftp\b|tftp\b|usb\b|removable\b|thumb ?drive|flash drive"
    r"|e-?mail\b|webmail|attachment|web upload|http upload|c2\b|telegram|smtp)\b",
    re.IGNORECASE,
)

# Evidence that bytes actually moved (a transfer record), as opposed to mere
# staging/presence. A removable-volume binding counts: it is positive evidence
# the file resided on media that physically left the host.
_TRANSFER_RE = re.compile(
    r"(?:\btransfers?\.log\b|\bftp log\b"
    r"|\b\d[\d,]*\s*bytes?\s*(?:sent|written|read|transferred|uploaded)\b"
    r"|\bbytes[_ ](?:sent|written|read)\b"
    r"|\busn\b|\$j\b|\$usnjrnl|\busnjrnl\b"
    r"|\b(?:data ?extend|filecreate|file ?write|rename)\b"
    r"|\bmounteddevices\b|\bdevpkey\b|\bremovable\b|\bdisk ?\[usbstor\]"
    r"|\battachment\b|\battached file\b|\bcontent-disposition\b"
    r"|\bnetflow\b|\bpcap\b|\bpackets?\b|\bsrum\b|\bsrudb\b|\bbytessent\b)",
    re.IGNORECASE,
)


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None

    desc = ctx.description or ""
    if not (_EGRESS_RE.search(desc) and _CHANNEL_RE.search(desc)):
        return None

    evidence = lineage_evidence_text(ctx)
    if _TRANSFER_RE.search(evidence):
        return None

    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding claims data was exfiltrated over a named channel "
            f"but its evidence (supporting_evidence or the linked_call_id / "
            f"input_call_ids entries) shows only presence/staging, not a transfer. "
            f"A file in a sync folder, a :com.dropbox.attributes ADS, or "
            f"tool-execution alone is not egress. Cite a transfer artifact — an "
            f"FTP/transfer log, a byte count sent/written, a USN $J write/rename, "
            f"a removable-volume LNK / MountedDevices binding, a mail attachment "
            f"record, or SRUM/netflow egress — and link it (input_call_ids), or "
            f"downgrade this finding to SUSPECTED. Enumerate ALL candidate channels "
            f"and headline only the strongest-evidenced one."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "exfil_channel_grounding",
    }
