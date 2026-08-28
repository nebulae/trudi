"""Gate: a CONFIRMED/LIKELY finding asserting data *left the host* must cite a
*transfer* artifact — not tool-execution or file-presence.

Trigger (typed claim, never wording): tier ∈ {CONFIRMED, LIKELY} AND
claim.act == "egress" (typed_claims already requires a channel for it).

Pass: claim.transfer_call_ids name successful evidence tool calls (the record
that bytes moved — an FTP/transfer log, USN $J write/rename, removable-volume
LNK / MountedDevices binding, mail attachment record, SRUM/netflow egress); or
— legacy validator — a transfer marker appears in the cited evidence TEXT.

Explicitly NON-satisfying (presence only): a file in a sync/staging folder, a
cloud-client ADS such as :com.dropbox.attributes, or tool-execution alone
("VeraCrypt ran", "Dropbox.exe present"). These describe staging, not egress.

The gate does not read the description.
"""
import re
from typing import Optional

from ._claims import FIELD_HELP
from ._evidence_calls import is_evidence_tool_call
from ._match import lineage_evidence_text

# Evidence that bytes actually moved (a transfer record), as opposed to mere
# staging/presence. A removable-volume binding counts: it is positive evidence
# the file resided on media that physically left the host.
_TRANSFER_RE = re.compile(
    # STRUCTURAL tokens only (artifact names, opcodes, byte counts, status
    # codes) — vocabulary like "attachment"/"removable"/"packets" must never
    # ground a transfer/receipt class (evidence-class inflation).
    r"""(?:\btransfers?\.log\b|\bftp log\b|\b\d[\d,]*\s*bytes?\s*(?:sent|written|read|transferred|uploaded)\b|\bbytes[_ ](?:sent|written|read)\b|\$j\b|\$usnjrnl|\busnjrnl\b|\busn[ _]journal\b|\b(?:data ?extend|filecreate|file ?write)\b|\bmounteddevices\b|\bdisk ?\[usbstor\]|content-disposition:\s*attachment|\bnetflow\b|\bsrudb\b|\bbytessent\b)""",
    re.IGNORECASE,
)


def _cited_evidence_calls(ctx, cids) -> bool:
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    cids = [int(c) for c in (cids or []) if c]
    return bool(cids) and all(is_evidence_tool_call(by_id.get(c) or {}) for c in cids)


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    claim = getattr(ctx, "claim", None) or {}
    if claim.get("act") != "egress":
        return None
    if _cited_evidence_calls(ctx, claim.get("transfer_call_ids")):
        return None
    if _TRANSFER_RE.search(lineage_evidence_text(ctx)):
        return None
    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding claims data left the host over {claim.get('channel') or 'a channel'} "
            f"but its evidence shows only presence/staging, not a transfer. A file in a "
            f"sync folder, a :com.dropbox.attributes ADS, or tool-execution alone is not "
            f"egress. Cite a transfer artifact — an FTP/transfer log, a byte count "
            f"sent/written, a USN $J write/rename, a removable-volume LNK / MountedDevices "
            f"binding, a mail attachment record, or SRUM/netflow egress — and pass "
            f"{FIELD_HELP['transfer_call_ids']}, or downgrade to SUSPECTED. Enumerate ALL "
            f"candidate channels and headline only the strongest-evidenced one."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "exfil_channel_grounding",
        "missing": ["transfer_call_ids"],
    }
