"""Session binding — is an account/person attribution grounded in an
authentication / session artifact?

The typed path: the finding declares `session_binding_call_ids`, the trace
entries those ids name carry the server-stamped `session_artifact=True` marker
(set by the wrappers that parse logon events: ez.evtxecmd on 4624/4625/4634/
4648/4778/4779, misc.evtx_filter on those ids, net.pcap_identity_timeline /
net.http_session_inventory, live.recent_logins). The agent cannot stamp
that marker from prose.

Fallbacks, weakest last: a cited call whose COMMAND is a logon-enumeration tool
(cmd regex — classifies what ran, not what was written), then the legacy
session-marker regex over the cited evidence TEXT (kept as a validator for
traces that predate the marker).
"""
from __future__ import annotations

import re

from ._match import lineage_evidence_text

SESSION_EVENT_IDS = frozenset({4624, 4625, 4634, 4648, 4778, 4779})

# Logon-enumeration tools, by COMMAND (not prose).
LOGON_TOOL_RE = re.compile(
    r"(?:evtxecmd|chainsaw|evtx_filter|evtx_dump"
    r"|\b4624\b|\b4625\b|\b4778\b|\b4779\b"
    r"|\blast\b|wtmp|utmp|lastlog|\bwho\b"
    r"|pcap_identity_timeline|http_session_inventory|live_recent_logins)",
    re.IGNORECASE,
)

# Authentication / session markers in evidence TEXT (legacy validator).
# ONLY genuine authenticated-session signals belong here. Identity / address
# strings were removed 2026-08-29: a bare IPv4, "source ip", "x-originating-ip",
# an Internet name or a cert CN prove PRESENCE or IDENTITY, not an authenticated
# SESSION — and on a network/PCAP case every finding's evidence text contains an
# IP, so the bare-IPv4 alternation made this fallback bind ANY human attribution
# (observed live: an empty-`session_binding_call_ids` "Amy Smith, CONFIRMED"
# passed principal_attribution_grounding purely because its prose mentioned an
# IP). Binding a named person requires a real logon/session artifact — the
# cited-cid `session_artifact` marker path, the logon-tool cmd path, or one of
# these authentication markers; never merely an address.
SESSION_RE = re.compile(
    r"(?:\blogon\b|\blog-on\b|\b4624\b|\b4625\b|\blogon type\s*\d+"
    r"|\btype\s*(?:3|10)\b|\binteractive session\b|\bremote session\b|\brdp\b"
    r"|\bsmb session\b|\bsshd\b|\bssh session\b|\bkerberos\b|\bntlm\b"
    r"|\bsource network address\b)",
    re.IGNORECASE,
)


def is_session_artifact(entry) -> bool:
    return (isinstance(entry, dict) and entry.get("type") == "tool_call"
            and entry.get("session_artifact") is True and entry.get("success") is not False)


def session_bound(ctx, cids=None) -> tuple[bool, str]:
    """(bound, how). `cids` defaults to claim.session_binding_call_ids."""
    claim = getattr(ctx, "claim", None) or {}
    cids = [int(c) for c in (cids if cids is not None else claim.get("session_binding_call_ids") or []) if c]
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    entries = [by_id.get(c) for c in cids]
    if any(is_session_artifact(e) for e in entries):
        return True, "session_artifact"
    if any(isinstance(e, dict) and LOGON_TOOL_RE.search(str(e.get("cmd") or "")) for e in entries):
        return True, "logon_tool_cmd"
    if SESSION_RE.search(lineage_evidence_text(ctx)):
        return True, "evidence_text"
    return False, ""


def has_logon_enumeration(entries) -> bool:
    """Did any tool call in `entries` enumerate logon sessions (marker or cmd)?"""
    for e in entries or []:
        if not isinstance(e, dict) or e.get("type") != "tool_call":
            continue
        if is_session_artifact(e):
            return True
        if LOGON_TOOL_RE.search(str(e.get("cmd") or "")):
            return True
    return False
