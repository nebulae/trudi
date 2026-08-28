"""Gate: the Triage max-pass cap cannot override OPEN verification challenges.

DAIR's third consecutive Triage/stay lets the agent force-push to Collect. That
override was purely agent-side, and it was used to skip concrete
verification_challenges the backend had asked for (verified: null, with a
named challenge_method). Operator decision: the cap may fire only when no such
challenge is open; otherwise the challenge_method tools must run first.

Two enforcement points:
  (i)  record_self_correction(trigger="dair_max_pass_cap") is refused while the
       latest dair_call carries an open challenge;
  (ii) reason.pre_report_check blocks on any challenge left verified:null that
       was never run, never marked verified by a later dair_call, and never
       settled by a typed tool/challenge disposition.
"""
from __future__ import annotations

import re

from ._evidence_calls import is_evidence_tool_call
from ._dispositions import SOURCE_WAIVER_REASONS_ALL, index_from_entries
from .work_order import _binary_sig, tool_waived

_UNRUNNABLE_NS = ("reason", "dair")   # not evidence tools; cannot be "run"


def _claim_key(c: dict) -> str:
    return re.sub(r"\s+", " ", str(c.get("claim") or "").strip().lower())[:80]


def _challenge_waived(didx, dcid: int, c: dict) -> bool:
    """A typed challenge disposition: target_kind="challenge",
    target_id="<dair_call_id>:<challenge claim>" (claim compared by its
    whitespace-folded key), reason inapplicable|absent_from_evidence|out_of_scope."""
    want = _claim_key(c)
    for (kind, _norm), rows in (getattr(didx, "dispositions", None) or {}).items():
        if kind != "challenge":
            continue
        for d in rows:
            if str(d.get("reason") or "").lower() not in SOURCE_WAIVER_REASONS_ALL:
                continue
            tid = str(d.get("target_id") or "")
            head, _, rest = tid.partition(":")
            if head.strip().isdigit() and int(head) != int(dcid or 0):
                continue
            key = _claim_key({"claim": rest if _ else tid})
            if key and (key == want or want.startswith(key[:40]) or key.startswith(want[:40])):
                return True
    return False


_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\\\-]{3,}")
_TOKEN_STOP = frozenset({
    "with", "from", "this", "that", "into", "onto", "over", "under", "after", "before",
    "host", "file", "files", "user", "users", "account", "created", "create", "contains",
    "shows", "show", "confirm", "confirms", "verify", "exists", "present", "installed",
    "install", "found", "runs", "running", "device", "volume", "registry", "hive", "logs",
    "event", "events", "evidence", "artifact", "artifacts", "windows", "system", "local",
    "remote", "network", "data", "were", "was", "the", "and", "for", "via", "using",
    "large", "small", "multiple", "several", "recent", "successful", "failed",
})


def claim_tokens(claim: str) -> set:
    """Discriminating tokens of a challenge claim (paths, names, ids, words ≥4
    chars minus stop-words), lower-cased. Empty ⇒ the claim carries nothing to
    match on and the binary signature alone decides (legacy behaviour)."""
    out = set()
    for m in _TOKEN_RE.findall(str(claim or "")):
        t = m.lower().strip("._-\\")
        if len(t) >= 4 and t not in _TOKEN_STOP:
            out.add(t)
    return out


# Methods that examine ONE caller-chosen target (a path / pattern): for these
# the cmd says WHAT was examined, so the claim must overlap it. Extractors
# (evtxecmd, recmd, mftecmd, tcpdump …) parse a whole artifact set — any
# successful run is the verification, whatever the claim's wording.
# Registry hive families a claim may name; an extractor run must touch the
# same family to count (matched as path tokens in the cmd).
_HIVE_TOKENS = frozenset({"ntuser", "ntuser.dat", "usrclass", "usrclass.dat", "amcache",
                          "amcache.hve", "software", "security"})

_TARGETED_SIGS = frozenset({
    "stat", "strings", "grep", "ngrep", "hexdump", "xxd", "file", "icat", "istat",
    "read", "exiftool", "floss", "yara", "hash",
})


def run_matches_challenge(entry: dict, sig: str, tokens: set) -> bool:
    """Does this tool_call satisfy the challenge? The binary signature must be
    in the cmd AND — for a TARGETED method with a token-bearing claim — at
    least one claim token must appear in the cmd / output excerpt / stderr /
    output path — a bare `stat` of the evidence image must not verify a claim
    about a specific registry value."""
    cmd = str(entry.get("cmd") or "").lower()
    if sig not in cmd:
        return False
    if not tokens:
        return True
    if sig not in _TARGETED_SIGS:
        # Extractor: a claim naming a specific HIVE must be verified by a run
        # over that hive family ("RDP fDenyTSConnections written" in SYSTEM was
        # 'verified' by a SAM run) — and a token-bearing claim must be
        # TOUCHED by the run: at least one claim token in the cmd, the stored
        # output, or the full-stdout sidecar. Without this, a claim whose term
        # appears in NO collected output can be "verified" by an unrelated
        # parse and silently vanish from the audit trail. Symmetric: running
        # the enumeration and finding nothing is the legitimate resolution —
        # this only stops verification-by-association.
        hives = tokens & _HIVE_TOKENS
        if hives and not any(h in cmd for h in hives):
            return False
        hay = _entry_text_lower(entry)
        return any(t in hay for t in tokens)
    hay = " ".join(str(entry.get(k) or "") for k in
                   ("cmd", "stdout_excerpt", "stderr", "output_path")).lower()
    return any(t in hay for t in tokens)


def _entry_text_lower(entry: dict) -> str:
    """cmd + stored output + bounded sidecar of a tool_call, lower-cased —
    what a verification claim's tokens are matched against."""
    parts = [str(entry.get(k) or "") for k in ("cmd", "stdout_excerpt", "stderr", "output_path")]
    sp = entry.get("stdout_path")
    if sp:
        try:
            with open(sp, "r", errors="replace") as fh:
                parts.append(fh.read(120_000))
        except OSError:
            pass
    return " ".join(parts).lower()


def _latest_dair(entries) -> dict | None:
    for e in reversed(entries or []):
        if isinstance(e, dict) and e.get("type") == "dair_call":
            return e
    return None


def open_challenges(entries, dair_entry: dict) -> list[dict]:
    """Challenges on `dair_entry` with verified:null that nothing since has
    resolved: no later evidence tool_call whose cmd carries the
    challenge_method's binary signature, no later dair_call marking the same
    claim verified, no waiver narration/finding ("<method> inapplicable /
    absent from evidence")."""
    dcid = int(dair_entry.get("call_id") or 0)
    later = [e for e in (entries or []) if isinstance(e, dict)
             and int(e.get("call_id") or 0) > dcid]
    later_runs = [e for e in later if is_evidence_tool_call(e)]
    later_verified = set()
    for e in later:
        if e.get("type") == "dair_call":
            for c in e.get("verification_challenges") or []:
                if isinstance(c, dict) and c.get("verified") is not None:
                    later_verified.add(_claim_key(c))
    didx = index_from_entries(later)
    out = []
    for c in dair_entry.get("verification_challenges") or []:
        if not isinstance(c, dict) or c.get("verified") is not None:
            continue
        # Backends write parametrised methods — `misc.evtx_filter(event_ids="4720",
        # start_time=…)` — the tool name is what runs and what the cmd carries.
        method = str(c.get("challenge_method") or "").strip().split("(", 1)[0].strip()
        if not method or method.split(".")[0].split("_")[0] in _UNRUNNABLE_NS:
            continue
        sig = _binary_sig(method)
        if len(sig) < 3:
            continue                                   # unparseable — cannot enforce
        if _claim_key(c) in later_verified:
            continue
        toks = claim_tokens(c.get("claim"))
        if any(run_matches_challenge(e, sig, toks) for e in later_runs):
            continue
        if tool_waived(didx, method) or _challenge_waived(didx, dcid, c):
            continue
        out.append({"claim": str(c.get("claim") or "")[:160], "challenge_method": method,
                    "dair_call_id": dcid})
    return out


def max_pass_cap_gate(log) -> dict | None:
    """Refusal for record_self_correction(trigger='dair_max_pass_cap') while the
    latest dair_call still has open challenges; None when the cap may fire."""
    entries = getattr(log, "_entries", None) or []
    d = _latest_dair(entries)
    if d is None:
        return None
    oc = open_challenges(entries, d)
    if not oc:
        return None
    listed = "; ".join(f"'{c['claim'][:60]}' via {c['challenge_method']}" for c in oc[:5])
    return {
        "success": False,
        "gate": "max_pass_cap",
        "open_challenges": oc,
        "error": (
            f"Triage max-pass cap refused: the latest dair_assess still carries "
            f"{len(oc)} verification_challenge(s) with verified=null whose "
            f"challenge_method has not run ({listed}). The cap only fires when no "
            f"concrete challenge is open — run each challenge_method (they are in "
            f"priority_tools), or record misc.record_disposition(target_kind=\"tool\", "
            f"target_id=<method>, reason=\"inapplicable\"|\"absent_from_evidence\"), "
            f"then call dair_assess again."
        ),
    }


def open_challenge_issues(entries) -> list[str]:
    """Block-late issue strings: every never-run verification challenge across
    all dair_calls (deduplicated by method + claim)."""
    seen: set = set()
    issues: list[str] = []
    for d in [e for e in (entries or []) if isinstance(e, dict) and e.get("type") == "dair_call"]:
        for c in open_challenges(entries, d):
            key = (_binary_sig(c["challenge_method"]), _claim_key(c))
            if key in seen:
                continue
            seen.add(key)
            issues.append(
                f"DAIR verification challenge never run: '{c['claim'][:80]}' via "
                f"{c['challenge_method']} (dair call {c['dair_call_id']}, verified=null). "
                f"Run it, or record misc.record_disposition(target_kind=\"tool\", "
                f"target_id=\"{c['challenge_method']}\", reason=\"inapplicable\"|"
                f"\"absent_from_evidence\"), before Report."
            )
    return issues
