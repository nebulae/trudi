"""Mail-store correspondent roster — the registry feeder behind read.mail.

Pure parsing (no trace I/O): tools/read_output.read_mail stamps its result
onto the trace; core.execution_log folds the stamps into the correspondent
registry; tools/_readiness and the disposition label gate share
registry_record_engaged() over it.

What it establishes, per address:
  from      — messages the address sent (appears in From)
  to        — messages that listed the address in To/Cc (anyone's mail)
  owner_to  — messages the MAILBOX OWNER sent that listed the address in
              To/Cc. This is the "the subject wrote to them" signal the
              correspondent exhaustion check blocks on; inbound volume and
              third-party To: lists (spam, newsletters, mass mail) never set it.

The mailbox owner is derived from the store itself — the dominant From address
of the Sent/Outbox folders, else Delivered-To/X-Original-To, else an address in
the store path — never assumed.

Only syntactically valid addresses are correspondents: header-field labels
("Address type", "Recipient type", "Email address" from pffexport's
Recipients.txt / OutlookHeaders.txt) and bare display names are rejected.
"""
from __future__ import annotations

import collections
import email
import glob
import mailbox
import os
import re
from email import policy
from email.utils import getaddresses

# RFC 5322 "dot-atom" subset good enough for evidence mail: a local part, one
# '@', a dotted domain with an alphabetic TLD. No whitespace, no labels.
_EMAIL_RE = re.compile(
    r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$")

# pffexport / Outlook header labels that the old parser turned into
# "addresses" (Recipients.txt joined into one To: line). Belt and braces —
# none of these pass _EMAIL_RE anyway.
HEADER_LABELS = frozenset({
    "display name", "email address", "address type", "recipient type",
    "recipients", "recipient", "sender name", "sender email address",
    "sent representing name", "sent representing email address", "to", "cc",
    "bcc", "from", "smtp", "ex",
})

# Chat handles (Skype names, live:ids, WhatsApp JIDs): no whitespace.
_CHAT_HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9._:#@+\-]{1,127}$")

# Messenger service/system accounts — auto-added contacts, not correspondents.
CHAT_SYSTEM_HANDLES = frozenset({
    "echo123", "echo", "concierge", "skype", "skypebot", "live:echo123",
    "28:concierge", "status@broadcast", "0@s.whatsapp.net",
})

_SENT_FOLDER_RE = re.compile(r"(^|[\\/\[\]\s_-])(sent|outbox)([\\/\[\]\s_.-]|$)",
                             re.IGNORECASE)
_PATH_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}", re.IGNORECASE)


def is_valid_email(addr: str) -> bool:
    a = (addr or "").strip().lower()
    return bool(a) and a not in HEADER_LABELS and bool(_EMAIL_RE.match(a))


def is_valid_chat_handle(handle: str) -> bool:
    h = (handle or "").strip().lower()
    return bool(h) and h not in HEADER_LABELS and bool(_CHAT_HANDLE_RE.match(h))


def is_chat_system_handle(handle: str) -> bool:
    return (handle or "").strip().lower() in CHAT_SYSTEM_HANDLES


# Read-receipt tracking services rewrite the recipient as
# "<real address>.<service domain>"; the correspondent is the real address.
_TRACKING_SUFFIXES = (".readnotify.com", ".spypig.com", ".didtheyreadit.com")


def unwrap_tracking(addr: str) -> str:
    a = (addr or "").strip().lower()
    for suf in _TRACKING_SUFFIXES:
        if a.endswith(suf) and is_valid_email(a[: -len(suf)]):
            return a[: -len(suf)]
    return a


def addresses(header_value) -> list[str]:
    """Valid, lower-cased addresses from a From/To/Cc header value."""
    out = []
    try:
        pairs = getaddresses([str(header_value or "")])
    except Exception:
        return out
    for _dn, addr in pairs:
        a = unwrap_tracking((addr or "").strip().strip("<>'\"").lower())
        if is_valid_email(a) and a not in out:
            out.append(a)
    return out


# ── pffexport item trees ────────────────────────────────────────────────────

def _parse_recipients_txt(text: str) -> dict:
    """pffexport Recipients.txt → {"to": [...], "cc": [...], "bcc": [...]}
    of "Display <addr>" strings. The file is blocks of labelled lines:
        Display name:   'S. A. Carlito Edgardo'
        Email address:  sa.ed2@outlook.com
        Address type:   SMTP
        Recipient type: To
    The labels are field NAMES, never correspondents."""
    out = {"to": [], "cc": [], "bcc": []}
    cur: dict = {}

    def _flush():
        addr = (cur.get("email address") or "").strip().strip("'\"<>")
        if is_valid_email(addr):
            kind = (cur.get("recipient type") or "to").strip().lower()
            kind = kind if kind in out else "to"
            dn = (cur.get("display name") or "").strip().strip("'\"").replace('"', "")
            out[kind].append(f'"{dn}" <{addr}>' if dn else addr)
        cur.clear()

    for ln in (text or "").splitlines():
        if not ln.strip():
            if cur:
                _flush()
            continue
        k, sep, v = ln.partition(":")
        if not sep:
            # unlabelled line (older pffexport / hand-built trees): keep any
            # valid addresses on it, never the line itself
            out["to"].extend(addresses(ln))
            continue
        k = k.strip().lower()
        if k == "display name" and "display name" in cur:
            _flush()
        cur[k] = v.strip()
    if cur:
        _flush()
    return out


def pff_item(msg_dir: str):
    """One pffexport item dir (MessageNNNNN/) → an email.message. Primary
    source is InternetHeaders.txt (RFC822); OutlookHeaders.txt + Recipients.txt
    fill From/To/Cc/Subject/Date when internet headers are absent (e.g. some
    OSTs). Body from Message.txt, else de-tagged Message.html."""
    def _read(name):
        p = os.path.join(msg_dir, name)
        try:
            with open(p, "r", errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""
    hdrs = _read("InternetHeaders.txt")
    body = _read("Message.txt")
    if not body:
        html = _read("Message.html")
        if html:
            html = re.sub(r"<style.*?</style>", " ", html, flags=re.S | re.I)
            body = re.sub(r"<[^>]+>", " ", html)
    if not re.search(r"^from:", hdrs, re.IGNORECASE | re.MULTILINE):
        # fall back to the Outlook-side labelled headers
        ok = {}
        for ln in _read("OutlookHeaders.txt").splitlines():
            if ":" in ln:
                k, _, v = ln.partition(":")
                ok[k.strip().lower()] = v.strip()
        rc = _parse_recipients_txt(_read("Recipients.txt"))
        sender = ok.get("sender email address", "")
        if not is_valid_email(sender):
            sender = ""
        hdrs = (f"From: {ok.get('sender name', '')} <{sender}>\n"
                f"To: {', '.join(rc['to'])}\n"
                + (f"Cc: {', '.join(rc['cc'])}\n" if rc["cc"] else "")
                + f"Subject: {ok.get('subject', '')}\n"
                f"Date: {ok.get('client submit time', '')}\n")
    try:
        m = email.message_from_string(hdrs, policy=policy.default)
        m.set_payload(body)
        return m
    except Exception:
        return None


def iter_store(resolved: str, scan_cap: int = 5000):
    """Yield (message, folder_locator) for every message of an extracted
    store: a pffexport item tree, a dir of .eml/.mbox, or one mbox file.
    folder_locator is the item dir / file path — used to tell Sent from
    received mail."""
    n = 0
    if os.path.isdir(resolved):
        item_dirs = sorted(
            d for d in glob.glob(os.path.join(glob.escape(resolved), "**", "Message*"),
                                 recursive=True)
            if os.path.isfile(os.path.join(d, "InternetHeaders.txt")))
        if item_dirs:
            for d in item_dirs:
                if n >= scan_cap:
                    return
                m = pff_item(d)
                if m is not None:
                    yield m, os.path.relpath(d, resolved)
                    n += 1
            return
        for f in sorted(glob.glob(os.path.join(glob.escape(resolved), "**", "*"),
                                  recursive=True)):
            if n >= scan_cap:
                return
            fl = f.lower()
            if fl.endswith(".eml") and os.path.isfile(f):
                try:
                    with open(f, "rb") as fh:
                        yield (email.message_from_binary_file(fh, policy=policy.default),
                               os.path.relpath(f, resolved))
                    n += 1
                except Exception:
                    continue
            elif fl.endswith(".mbox") and os.path.isfile(f):
                try:
                    for m in mailbox.mbox(f):
                        yield m, os.path.relpath(f, resolved)
                        n += 1
                        if n >= scan_cap:
                            return
                except Exception:
                    continue
    else:
        try:
            for m in mailbox.mbox(resolved):
                yield m, os.path.basename(resolved)
                n += 1
                if n >= scan_cap:
                    return
        except Exception:
            return


def is_sent_folder(locator: str) -> bool:
    return bool(_SENT_FOLDER_RE.search(locator or ""))


def is_bulk(m) -> bool:
    try:
        return bool(m.get("List-Unsubscribe") or m.get("List-Id")
                    or re.search(r"\b(bulk|list|junk|auto[- ]?reply)\b",
                                 str(m.get("Precedence", "")), re.IGNORECASE))
    except Exception:
        return False


class RosterBuilder:
    """Accumulates per-message (from, to/cc, folder) and resolves the
    mailbox owner(s) and owner-sent counts at the end."""

    def __init__(self, store_path: str = "", cap: int = 1000):
        self.store_path = store_path or ""
        self.cap = cap
        self.rows: list[tuple] = []     # (froms, rcpts, sent_folder)
        self.bulk: set = set()
        self.delivered: collections.Counter = collections.Counter()
        self.observed: set = set()
        self.capped = False

    def _see(self, a: str) -> bool:
        if a in self.observed:
            return True
        if len(self.observed) < self.cap:
            self.observed.add(a)
            return True
        self.capped = True
        return False

    def add(self, m, locator: str = "") -> None:
        try:
            froms = addresses(m.get("From", ""))
            rcpts = addresses(", ".join(str(m.get(h, "") or "") for h in ("To", "Cc")))
            for h in ("Delivered-To", "X-Original-To"):
                for a in addresses(m.get(h, "")):
                    self.delivered[a] += 1
        except Exception:
            return
        if is_bulk(m):
            self.bulk.update(froms)
        self.rows.append((tuple(froms), tuple(rcpts), is_sent_folder(locator)))

    def owners(self) -> list[str]:
        """Mailbox owner address(es), evidence-derived:
        1. the dominant From of Sent/Outbox-folder messages (plus any other
           address with >= 25% of the top count — an alias used to send);
        2. else the dominant Delivered-To / X-Original-To;
        3. else a valid address embedded in the store path."""
        sent = collections.Counter()
        for froms, _r, is_sent in self.rows:
            if is_sent:
                sent.update(froms)
        if sent:
            top = sent.most_common(1)[0][1]
            return sorted(a for a, c in sent.items() if c >= max(1, top * 0.25))
        if self.delivered:
            top = self.delivered.most_common(1)[0][1]
            return sorted(a for a, c in self.delivered.items() if c >= max(1, top * 0.25))
        return sorted({a.lower() for a in _PATH_EMAIL_RE.findall(self.store_path)
                       if is_valid_email(a)})

    def result(self) -> dict:
        owners = set(self.owners())
        stats: dict = {}
        for froms, rcpts, _s in self.rows:
            owner_sent = any(f in owners for f in froms)
            for a in froms:
                if self._see(a):
                    stats.setdefault(a, {"from": 0, "to": 0, "owner_to": 0})["from"] += 1
            for a in rcpts:
                if self._see(a):
                    s = stats.setdefault(a, {"from": 0, "to": 0, "owner_to": 0})
                    s["to"] += 1
                    # a note-to-self (owner -> the same address) is not a
                    # correspondent; owner -> the owner's OTHER address is.
                    if owner_sent and a not in froms:
                        s["owner_to"] += 1
        observed = sorted(self.observed)
        return {
            "observed": observed,
            "stats": {a: stats[a] for a in observed if a in stats},
            "bulk": sorted(self.bulk & self.observed),
            "owners": sorted(owners),
            "capped": self.capped,
        }


def roster_for_store(resolved: str, scan_cap: int = 5000, cap: int = 1000) -> dict:
    """Whole-store roster (used at pre-report time to re-derive owner-sent
    counts for traces stamped by the legacy parser)."""
    rb = RosterBuilder(resolved, cap=cap)
    n = 0
    for m, loc in iter_store(resolved, scan_cap):
        rb.add(m, loc)
        n += 1
    out = rb.result()
    out["messages_scanned"] = n
    out["partial"] = n >= scan_cap or out["capped"]
    return out


def registry_record_engaged(rec: dict) -> bool:
    """Did the SUBJECT engage this correspondent? One predicate for the
    pre-report exhaustion check and the disposition label gate. `rec` is a
    registry record built by core.execution_log._add_correspondent_stamp:
      - owner_to > 0      the mailbox owner wrote to it (owner-direction stamp)
      - chat_engaged      exchanged messages/files in a chat store
      - legacy_from/_to   pre-owner-direction stamp: conservative two-way
                          fallback (it both sent mail and was a recipient)
    A chat store's own account (store_owner) is the subject, not a
    correspondent. Roster matches are checked by the caller."""
    rec = rec or {}
    if rec.get("store_owner"):
        return False
    if int(rec.get("owner_to") or 0) > 0 or rec.get("chat_engaged"):
        return True
    return int(rec.get("legacy_from") or 0) > 0 and int(rec.get("legacy_to") or 0) > 0
