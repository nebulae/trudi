"""Typed claim v2 — the declared shape of a finding.

The control plane keys on these declared fields, never on the wording of the
description. Every enum lives here once; `FIELD_HELP` is the single source of
the text a refusal uses to teach the agent the missing kwarg.

    kind        positive | negative
    category    exfil | logon_auth | identity | persistence | device_initial_access |
                execution | delivery | destruction | attribution | privilege_escalation | other
    act         presence | execution | timeline | account_creation | persistence_install |
                logon | egress | delivery | possession | c2 | lateral_movement |
                credential_access | privilege_escalation | destruction | attribution | other
    actor_kind  human | account | process | device | system | unknown
    actor       the named actor (person or account) when actor_kind is human/account
    principal   the account/identity the claim binds to an actor
    recipients  who received the data (delivery/possession)
    scope       manifest source ids searched (negatives)
    session_type interactive | remote_interactive | network | service | unknown
    threat_actor G-id / APT / alias
    techniques  ATT&CK ids
    artifacts   concrete values the claim rests on
    session_binding_call_ids / transfer_call_ids / receipt_call_ids
                cids of the artifact entries that ground the binding / transfer / receipt
    rule_outs   [{what, call_ids}] — alternatives excluded with evidence
    resolves    confirmed | refuted (for tested_hypothesis_id)
    answers_case_question  bool
    channel     removable | cloud | email | web | ftp | chat | c2 | other   (egress)
    window      {start, end} ISO dates
"""
from __future__ import annotations

from ._entities import norm_entity

KINDS = ("positive", "negative")
CATEGORIES = ("exfil", "logon_auth", "identity", "persistence", "device_initial_access",
              "execution", "delivery", "destruction", "attribution", "privilege_escalation",
              "other")
ACTS = ("presence", "execution", "timeline", "account_creation", "persistence_install",
        "logon", "egress", "delivery", "possession", "c2", "lateral_movement",
        "credential_access", "privilege_escalation", "destruction", "attribution", "other")
ACTOR_KINDS = ("human", "account", "process", "device", "system", "unknown")
SESSION_TYPES = ("interactive", "remote_interactive", "network", "service", "unknown")
CHANNELS = ("removable", "cloud", "email", "web", "ftp", "chat", "c2", "other")
RESOLVES = ("confirmed", "refuted")
CHANNEL_ALIASES = {"usb": "removable", "removable_media": "removable", "thumbdrive": "removable",
                   "mail": "email", "smtp": "email", "http": "web", "https": "web",
                   "upload": "web", "sftp": "ftp", "messenger": "chat", "im": "chat",
                   "dropbox": "cloud", "onedrive": "cloud", "gdrive": "cloud", "mega": "cloud"}
CORE_ACTS = frozenset({"egress", "delivery", "possession", "execution", "account_creation",
                       "persistence_install", "destruction", "lateral_movement",
                       "credential_access", "privilege_escalation", "c2"})

FIELD_HELP = {
    "claim_kind": "claim_kind='positive'|'negative' — is the finding asserting presence or absence?",
    "category": "category=" + "|".join(f"'{c}'" for c in CATEGORIES),
    "act": "act=" + "|".join(f"'{a}'" for a in ACTS)
           + " — the kind of act the finding asserts (what happened)",
    "actor_kind": "actor_kind=" + "|".join(f"'{a}'" for a in ACTOR_KINDS)
                  + " — what kind of thing did the act",
    "actor": "actor='<name>' — the person/account named as doing the act",
    "principal": "principal='<account or SID>' — the identity the claim binds to an actor",
    "recipients": "recipients=['<address or name>', ...] — who received the data",
    "channel": "channel=" + "|".join(f"'{c}'" for c in CHANNELS) + " — the egress channel",
    "window": "window={'start': 'YYYY-MM-DD', 'end': 'YYYY-MM-DD'} — the period the claim covers",
    "scope": "scope=['<manifest source id>', ...] — the sources searched for a negative",
    "session_type": "session_type=" + "|".join(f"'{s}'" for s in SESSION_TYPES),
    "session_binding_call_ids": "session_binding_call_ids=[<cid>, ...] — the logon/session artifact "
                                "entries (4624/4625 type+source, 4778/4779, RDP/SSH) binding the "
                                "principal to the actor",
    "transfer_call_ids": "transfer_call_ids=[<cid>, ...] — the transfer artifact entries (bytes "
                         "moved: FTP/transfer log, USN write/rename, removable-volume LNK, mail "
                         "attachment, SRUM/netflow)",
    "receipt_call_ids": "receipt_call_ids=[<cid>, ...] — destination-side receipt artifacts",
    "rule_outs": "rule_outs=[{'what': 'injector'|'automation'|'second_principal'|..., "
                 "'call_ids': [<cid>, ...]}] — alternatives excluded with evidence",
    "threat_actor": "threat_actor='<G-id | APT | alias>'",
    "techniques": "techniques=['T1078', ...] — ATT&CK ids the finding asserts",
    "resolves": "resolves='confirmed'|'refuted' — what this finding does to tested_hypothesis_id",
}


def _s(v) -> str:
    return str(v or "").strip().lower()


def _lst(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    return [str(x).strip() for x in v if str(x).strip()]


def _ints(v) -> list[int]:
    out = []
    for x in (v or []):
        try:
            i = int(x)
        except (TypeError, ValueError):
            continue
        if i:
            out.append(i)
    return sorted(set(out))


def normalize_claim(claim_kind="", category="", entities=None, channel="", window=None,
                    act="", actor_kind="", actor="", principal="", recipients=None,
                    scope=None, session_type="", threat_actor="", techniques=None,
                    artifacts=None, session_binding_call_ids=None, transfer_call_ids=None,
                    receipt_call_ids=None, rule_outs=None, resolves="",
                    answers_case_question=False) -> dict:
    """The persisted claim dict. Enum values are lower-cased (validation is
    separate); entity-like fields carry a parallel `*_norm` key produced by the
    shared normalizer so gates compare canonical forms."""
    ch = _s(channel)
    ch = CHANNEL_ALIASES.get(ch, ch)
    ents = _lst(entities)
    recs = _lst(recipients)
    ro = []
    for r in (rule_outs or []):
        if isinstance(r, dict) and _s(r.get("what")):
            ro.append({"what": _s(r.get("what")), "call_ids": _ints(r.get("call_ids"))})
    claim = {
        "claim_version": 2,
        "kind": _s(claim_kind),
        "category": _s(category),
        "act": _s(act),
        "entities": ents,
        "entities_norm": sorted({norm_entity(e) for e in ents if norm_entity(e)}),
        "channel": ch,
        "window": dict(window) if isinstance(window, dict) and window else {},
        "actor_kind": _s(actor_kind),
        "actor": str(actor or "").strip(),
        "actor_norm": norm_entity(actor),
        "principal": str(principal or "").strip(),
        "principal_norm": norm_entity(principal),
        "recipients": recs,
        "recipients_norm": sorted({norm_entity(r) for r in recs if norm_entity(r)}),
        "scope": [_s(x) for x in _lst(scope)],
        "session_type": _s(session_type),
        "threat_actor": str(threat_actor or "").strip(),
        "techniques": [t.upper() for t in _lst(techniques)],
        "artifacts": _lst(artifacts),
        "session_binding_call_ids": _ints(session_binding_call_ids),
        "transfer_call_ids": _ints(transfer_call_ids),
        "receipt_call_ids": _ints(receipt_call_ids),
        "rule_outs": ro,
        "resolves": _s(resolves),
        "answers_case_question": bool(answers_case_question),
    }
    return claim


def declared(claim: dict | None) -> bool:
    """Did the agent declare anything at all (vs. an all-empty v2 dict)?"""
    c = claim or {}
    return any(c.get(k) for k in ("kind", "category", "act", "entities", "channel", "window",
                                  "actor", "principal", "recipients", "scope", "session_type",
                                  "threat_actor", "techniques", "artifacts",
                                  "session_binding_call_ids", "transfer_call_ids",
                                  "receipt_call_ids", "rule_outs", "resolves",
                                  "answers_case_question"))


def enum_errors(claim: dict | None) -> list[str]:
    c = claim or {}
    bad = []
    ch = _s(c.get("channel"))
    ch = CHANNEL_ALIASES.get(ch, ch)     # a raw (un-normalized) dict may carry an alias
    checks = (("claim_kind", c.get("kind"), KINDS), ("category", c.get("category"), CATEGORIES),
              ("act", c.get("act"), ACTS), ("actor_kind", c.get("actor_kind"), ACTOR_KINDS),
              ("session_type", c.get("session_type"), SESSION_TYPES),
              ("channel", ch, CHANNELS), ("resolves", c.get("resolves"), RESOLVES))
    for name, val, allowed in checks:
        if val and val not in allowed:
            bad.append(f"{name}={val!r} (valid: {', '.join(allowed)})")
    return bad


def missing_fields(tier: str, claim: dict | None) -> list[str]:
    """Structural requirement (no wording involved): which fields the tier and
    the declared shape demand but the agent did not pass."""
    c = claim or {}
    t = (tier or "").upper()
    if t not in {"CONFIRMED", "LIKELY", "UNCONFIRMED"}:
        return []
    miss = [n for n, k in (("claim_kind", "kind"), ("category", "category"), ("act", "act"))
            if not c.get(k)]
    if c.get("act") == "egress" and not c.get("channel"):
        miss.append("channel")
    if c.get("act") in ("delivery", "possession") and not c.get("recipients"):
        miss.append("recipients")
    if c.get("kind") == "negative" and c.get("category") in ("logon_auth", "device_initial_access") \
            and not c.get("window"):
        miss.append("window")
    if c.get("actor_kind") == "human" and not c.get("actor"):
        miss.append("actor")
    # An attribution verdict with no actor_kind at all is the bypass shape: the
    # human-binding gates key on actor_kind, so leaving it blank skipped them.
    # Declare who (human/account/…) — or actor_kind="unknown", honestly.
    if c.get("act") == "attribution" and not c.get("actor_kind"):
        miss.append("actor_kind")
    # The created account is the claim's principal; without it the pre-report
    # controller check must guess from `entities`, which can pull in built-in
    # groups and process names.
    if c.get("act") == "account_creation" and not c.get("principal"):
        miss.append("principal")
    return miss


def help_lines(fields) -> str:
    return "; ".join(FIELD_HELP.get(f, f) for f in fields)


def conflicts(claim: dict | None) -> list[str]:
    """Declared fields that contradict each other — reported as a CONFLICT
    with the exact honest alternatives, never as 'missing' (an honest
    account-shaped declaration once refused as 'missing actor_kind' taught
    the agent the gate demanded a human controller)."""
    from ._entities import norm_entity
    c = claim or {}
    out: list[str] = []
    ak = str(c.get("actor_kind") or "")
    pr = str(c.get("principal") or "")
    act = str(c.get("act") or "")
    # The binding rule applies to claims that BIND an account to its operator
    # (attribution / logon). For account_creation the principal is the CREATED
    # account and the actor may well be a device or a process (a keystroke
    # injector creating the account) — no conflict there.
    if act in ("attribution", "logon") and pr and ak and ak not in ("human", "unknown"):
        same = ak == "account" and norm_entity(c.get("actor")) == norm_entity(pr)
        if not same:
            out.append(
                f"actor_kind='{ak}' cannot bind principal='{pr}' — use actor_kind='human' "
                f"(+ actor='<person>' and session_binding_call_ids=[...]) when a person is "
                f"bound to the account, actor_kind='unknown' when the operator is "
                f"unidentified, or actor_kind='account' with actor='{pr}' when only the "
                f"account itself is known to have acted"
            )
    return out
