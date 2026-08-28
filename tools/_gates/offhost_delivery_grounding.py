"""Gate: a CONFIRMED/LIKELY finding asserting data was *received / delivered /
possessed at the far end* must cite a destination-side receipt artifact — a host
image alone cannot establish what happened off the host.

Trigger (typed claim, never wording): tier ∈ {CONFIRMED, LIKELY} AND
claim.act ∈ {delivery, possession} (typed_claims already requires recipients).

Pass: claim.receipt_call_ids name successful evidence tool calls carrying the
destination-side receipt (an HTTP 2xx the server returned, FTP 226, SMTP 250 /
DSN / read receipt, a server access / download log); or — legacy validator — a
receipt marker appears in the cited evidence TEXT.

Remediation: cite the receipt; OR re-scope to on-host egress (act="egress",
backed by a transfer artifact — exfil_channel_grounding); OR downgrade.
"""
import re
from typing import Optional

from ._claims import FIELD_HELP
from ._evidence_calls import is_evidence_tool_call
from ._match import lineage_evidence_text

# Destination-side proof that the bytes actually arrived / were received.
_RECEIPT_RE = re.compile(
    # STRUCTURAL tokens only (artifact names, opcodes, byte counts, status
    # codes) — vocabulary like "attachment"/"removable"/"packets" must never
    # ground a transfer/receipt class (evidence-class inflation).
    r"""(?:\bhttp/\d(?:\.\d)?\s+2\d\d\b|\b(?:response|status)(?:[ _]code)?\s*[:=]\s*2\d\d\b|\b226\b[^.\n]{0,30}complete|\btransfer complete\b|\b250\b[^.\n]{0,20}(?:ok|queued|accepted|delivered|2\.\d)|\bmessage (?:accepted for delivery|delivered|queued)\b|\bdsn\b|\bdelivery status notification\b|\bdiagnostic-code\b|\bdelivery receipt\b|\bread receipt\b|\baccess\.log\b)""",
    re.IGNORECASE,
)


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None
    claim = getattr(ctx, "claim", None) or {}
    if claim.get("act") not in ("delivery", "possession"):
        return None
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    cids = [int(c) for c in (claim.get("receipt_call_ids") or []) if c]
    if cids and all(is_evidence_tool_call(by_id.get(c) or {}) for c in cids):
        return None
    if _RECEIPT_RE.search(lineage_evidence_text(ctx)):
        return None
    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding asserts {claim.get('act')} to "
            f"{', '.join(claim.get('recipients') or []) or 'a recipient'}, but the evidence "
            f"is host-side only. A single host's disk or memory can show data LEAVING "
            f"(egress) but cannot prove it ARRIVED or is possessed at the far end. Cite a "
            f"destination-side receipt (an HTTP 2xx the server returned, an FTP 226 / SMTP "
            f"250 completion, a delivery/read receipt, a server/access/download log) and "
            f"pass {FIELD_HELP['receipt_call_ids']}; OR re-scope to act='egress' backed "
            f"by a transfer artifact; OR downgrade to SUSPECTED."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "offhost_delivery_grounding",
        "missing": ["receipt_call_ids"],
    }
