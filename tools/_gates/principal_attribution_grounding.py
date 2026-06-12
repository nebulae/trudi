"""Gate: a CONFIRMED/LIKELY finding that binds an *account / identity* to a
*named principal* performing actions must be grounded in an authentication or
session artifact — not asserted from assumption.

Trigger (description prose):
  tier ∈ {CONFIRMED, LIKELY}
  AND the description references an account/identity (RID/SID/account/user/
      credential/logon account)
  AND it binds that account to an actor via an attribution copula
      (operated by, controlled by, belongs to, created by, logged in as,
       used by, attributed to, "= <Name>", "is <Name>").

Only CONFIRMED/LIKELY are gated — SUSPECTED/UNCONFIRMED account-actor
hypotheses in narrative findings are acceptable as open propositions.
"""
import re
from typing import Optional

from ._match import lineage_evidence_text

# References an account / identity as the *subject* of the attribution.
_ACCOUNT_RE = re.compile(
    r"\b(?:RID\s*\d+|SID\b|S-1-5-\S+|account\b|user account\b|local admin(?:istrator)?\b"
    r"|logon account\b|service account\b|credential\b|identity\b)\b",
    re.IGNORECASE,
)

# Binds that account to an actor/principal.
_ATTRIB_RE = re.compile(
    r"(?:\boperated by\b|\bcontrolled by\b|\bbelongs to\b|\bcreated by\b"
    r"|\blogged ?in as\b|\bwas used by\b|\bused by\b|\battributed to\b"
    r"|\bacted as\b|\bis\s+[A-Z][a-z]+|=\s*[A-Z][a-z]+)",
)

# Authentication / session evidence that grounds the binding.
_SESSION_RE = re.compile(
    r"(?:\blogon\b|\blog-on\b|\b4624\b|\b4625\b|\blogon type\s*\d+"
    r"|\btype\s*(?:3|10)\b|\binteractive session\b|\bremote session\b|\brdp\b"
    r"|\bsmb session\b|\bsshd\b|\bssh session\b|\bkerberos\b|\bntlm\b"
    r"|\bsource (?:network )?address\b|\bsource ip\b|\boriginating ip\b"
    r"|\bx-originating-ip\b|\binternetname\b|\bcert(?:ificate)? cn\b"
    r"|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
    re.IGNORECASE,
)


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None

    desc = ctx.description or ""
    if not (_ACCOUNT_RE.search(desc) and _ATTRIB_RE.search(desc)):
        return None

    evidence = lineage_evidence_text(ctx)
    if _SESSION_RE.search(evidence):
        return None

    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding binds an account/identity to a named principal "
            f"but no authentication/session artifact appears in its evidence "
            f"(supporting_evidence or the linked_call_id / input_call_ids "
            f"entries). Attributing an account's actions to a person requires a "
            f"logon-session binding — e.g. Security 4624/4625 with logon type and "
            f"source address (ez.evtxecmd / misc.chainsaw_hunt), an RDP/SMB/SSH "
            f"session, or an identity artifact (SAM InternetName, cert CN). Pull "
            f"that artifact and cite it (pass its _trudi_call_id in "
            f"input_call_ids), or downgrade this finding to SUSPECTED."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "principal_attribution_grounding",
    }
