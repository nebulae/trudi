"""Telegram iOS "Postbox" store reader (account-*/postbox/db/db_sqlite).

The store is plaintext SQLite, but every table is an opaque ``tN (key, value)``
pair whose BLOBs use Telegram's own serialization (Telegram-iOS
``submodules/Postbox``):

* **PostboxEncoder objects** — a run of ``[u8 keyLen][key utf8][u8 type][value]``
  fields, little-endian. Types: 0 int32, 1 int64, 2 bool, 3 double, 4 string
  (i32 len + utf8), 5 object (i32 typeHash, i32 len, fields), 6 int32[],
  7 int64[], 8 object[], 9 object dict, 10 bytes, 11 nil, 12 string[],
  13 bytes[]. Root objects are stored under the key ``"_"``.
* **Peers** (Postbox ``PeerTable``, t2 in current builds): integer key = PeerId,
  value = root object (TelegramUser ``fn``/``ln``/``un``/``p``/``bi``;
  TelegramGroup / TelegramChannel ``t`` title, ``un``, ``i.t`` 0=broadcast).
* **Messages** (``MessageHistoryTable``, t7): 20-byte big-endian key
  ``peerId i64 | namespace i32 | timestamp i32 | id i32``; value is a hand-
  rolled little-endian record (stableId, flags, forward info, author, text,
  attribute objects, embedded media objects, referenced media ids).

PeerId (i64): namespace = bits 32..34 (0 user, 1 group, 2 channel, 3 secret
chat); id = (bits 35.. << 32) | low 32 bits.

Tables are identified by CONTENT (which ``tN`` decodes as peers / messages),
not by number, since numbering can move between app versions. The caller must
pass a connection to a private COPY of the store, never the evidence file.
"""
from __future__ import annotations

import re
import sqlite3
import struct
from collections import Counter
from datetime import datetime, timezone

_BODY_CAP = 4000
_SAMPLE = 64

PEER_NS = {0: "user", 1: "group", 2: "channel", 3: "secret_chat"}
MSG_NS = {0: "cloud", 1: "local", 2: "scheduled_cloud", 3: "scheduled_local"}
INCOMING = 4  # MessageFlags.Incoming

# TelegramMediaActionType raw values (TelegramMediaAction "_rawValue").
ACTIONS = {
    0: "unknown", 1: "group_created", 2: "added_members", 3: "removed_members",
    4: "photo_updated", 5: "title_updated", 6: "pinned_message_updated",
    7: "joined_by_link", 8: "channel_migrated_from_group",
    9: "group_migrated_to_channel", 10: "history_cleared",
    11: "history_screenshot", 12: "autoremove_timeout_updated",
    13: "game_score", 14: "phone_call",
}


class PostboxError(ValueError):
    pass


class _R:
    """Bounded little-endian reader; every overrun is a PostboxError."""
    __slots__ = ("b", "o", "end")

    def __init__(self, b: bytes, o: int = 0, end: int | None = None):
        self.b, self.o = b, o
        self.end = len(b) if end is None else end

    def take(self, n: int) -> bytes:
        if n < 0 or self.o + n > self.end:
            raise PostboxError(f"overrun at {self.o} (+{n} > {self.end})")
        v = self.b[self.o:self.o + n]
        self.o += n
        return v

    def u8(self) -> int:
        return self.take(1)[0]

    def i32(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.take(8))[0]

    def count(self, cap: int = 1_000_000) -> int:
        n = self.i32()
        if n < 0 or n > cap:
            raise PostboxError(f"implausible count {n} at {self.o - 4}")
        return n

    def text(self) -> str:
        return self.take(self.count(self.end)).decode("utf-8", "replace")


def decode_object(b: bytes, off: int = 0, end: int | None = None) -> dict:
    """PostboxEncoder field run → dict. Nested objects carry their type hash
    under ``"@t"``."""
    r = _R(b, off, end)
    out: dict = {}
    while r.o < r.end:
        key = r.take(r.u8()).decode("utf-8", "replace")
        out[key] = _value(r, r.u8())
    return out


def _obj(r: _R) -> dict:
    h = r.u32()
    n = r.count(r.end)
    start = r.o
    r.take(n)
    return {"@t": h, **decode_object(r.b, start, start + n)}


def _value(r: _R, t: int):
    if t == 0:
        return r.i32()
    if t == 1:
        return r.i64()
    if t == 2:
        return r.u8() != 0
    if t == 3:
        return struct.unpack("<d", r.take(8))[0]
    if t == 4:
        return r.text()
    if t == 5:
        return _obj(r)
    if t == 6:
        n = r.count()
        return list(struct.unpack(f"<{n}i", r.take(4 * n)))
    if t == 7:
        n = r.count()
        return list(struct.unpack(f"<{n}q", r.take(8 * n)))
    if t == 8:
        return [_obj(r) for _ in range(r.count())]
    if t == 9:
        return [(_obj(r), _obj(r)) for _ in range(r.count())]
    if t == 10:
        return bytes(r.take(r.count(r.end)))
    if t == 11:
        return None
    if t == 12:
        return [r.text() for _ in range(r.count())]
    if t == 13:
        return [bytes(r.take(r.count(r.end))) for _ in range(r.count())]
    raise PostboxError(f"unknown value type {t} at {r.o - 1}")


def decode_root(blob: bytes) -> dict:
    """Value stored via encodeRootObject → the object under key ``_``."""
    d = decode_object(bytes(blob))
    root = d.get("_")
    if not isinstance(root, dict):
        raise PostboxError("no root object")
    return root


def peer_namespace(pid: int) -> int:
    return (int(pid) >> 32) & 0x7


def peer_raw_id(pid: int) -> int:
    v = int(pid) & 0xFFFFFFFFFFFFFFFF
    return ((v >> 35) << 32) | (v & 0xFFFFFFFF)


def _utc(ts) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


# ── peers ───────────────────────────────────────────────────────────────────

def decode_peer(pid: int, blob: bytes) -> dict:
    o = decode_root(blob)
    if not isinstance(o.get("i"), int) or int(o["i"]) != int(pid):
        raise PostboxError("peer id mismatch")
    ns = peer_namespace(pid)
    kind = PEER_NS.get(ns, f"ns{ns}")
    if kind == "user" and o.get("bi") is not None:
        kind = "bot"
    elif kind == "channel" and o.get("i.t") == 1:
        kind = "supergroup"
    usernames = []
    if isinstance(o.get("un"), str) and o["un"]:
        usernames.append(o["un"])
    for u in o.get("uns") or []:  # TelegramPeerUsername objects
        v = u.get("un") or u.get("u") if isinstance(u, dict) else None
        if isinstance(v, str) and v and v not in usernames:
            usernames.append(v)
    first, last = str(o.get("fn") or ""), str(o.get("ln") or "")
    name = (str(o.get("t") or "") or " ".join(x for x in (first, last) if x)).strip()
    return {
        "peer_id": int(pid), "tg_id": peer_raw_id(pid), "peer_type": kind,
        "display_name": name, "first_name": first, "last_name": last,
        "username": usernames[0] if usernames else "",
        "usernames": usernames, "phone": str(o.get("p") or ""),
        # secret chat → the regular user it is with
        "linked_peer_id": int(o["r"]) if kind == "secret_chat"
        and isinstance(o.get("r"), int) else None,
    }


# ── messages ────────────────────────────────────────────────────────────────

def decode_message_key(key: bytes) -> tuple[int, int, int, int]:
    if len(key) != 20:
        raise PostboxError("message key is not 20 bytes")
    return struct.unpack(">qiii", key)


def decode_message(blob: bytes) -> dict:
    """MessageHistoryTable value → dict (raises PostboxError when the blob is
    not a message record)."""
    r = _R(bytes(blob))
    if r.u8() != 0:
        raise PostboxError("not a message entry")
    m: dict = {"stable_id": r.u32()}
    r.u32()  # stableVersion
    df = r.u8()
    if df & ~0x3F:
        raise PostboxError(f"unknown data flags {df:#x}")
    if df & 0x01:
        m["globally_unique_id"] = r.i64()
    if df & 0x02:
        r.u32()  # global tags
    if df & 0x04:
        m["grouping_key"] = r.i64()
    if df & 0x08:
        r.u32()  # group info
    if df & 0x10:
        r.u32()  # local tags
    if df & 0x20:
        m["thread_id"] = r.i64()
    m["flags"] = r.u32()
    r.u32()  # tags
    ff = r.u8()
    if ff:
        fwd = {"author_id": r.i64(), "date": r.i32()}
        if ff & 0x02:
            fwd["source_id"] = r.i64()
        if ff & 0x04:
            fwd["source_message"] = (r.i64(), r.i32(), r.i32())
        if ff & 0x08:
            fwd["signature"] = r.text()
        if ff & 0x10:
            fwd["psa_type"] = r.text()
        if ff & 0x20:
            r.i32()
        m["forward"] = fwd
    has_author = r.u8()
    if has_author not in (0, 1):
        raise PostboxError("bad author marker")
    m["author_id"] = r.i64() if has_author else None
    m["text"] = r.text()
    m["attributes"] = []
    for _ in range(r.count(4096)):
        n = r.count(r.end)
        start = r.o
        r.take(n)
        m["attributes"].append(decode_object(r.b, start, start + n).get("_") or {})
    m["media"] = []
    for _ in range(r.count(4096)):
        n = r.count(r.end)
        start = r.o
        r.take(n)
        m["media"].append(decode_object(r.b, start, start + n).get("_") or {})
    m["referenced_media"] = [(r.i32(), r.i64()) for _ in range(r.count(4096))]
    # Newer builds append further count-prefixed sections; tolerate an
    # int32-count tail but reject random trailing garbage.
    rest = r.end - r.o
    if rest and (rest < 4 or not 0 <= r.i32() <= 4096):
        raise PostboxError("unexpected trailing bytes")
    return m


def _reply_to(attrs: list) -> str:
    for a in attrs:
        if {"p", "i"} <= set(a) and isinstance(a.get("i"), int) \
                and isinstance(a.get("p"), int) and "entities" not in a:
            return str((a["i"] >> 32) & 0xFFFFFFFF)
    return ""


def _pick_size(*objs) -> str:
    for o in objs:
        if isinstance(o, dict):
            for k in ("s64", "n64", "s", "size"):
                if isinstance(o.get(k), int) and not isinstance(o.get(k), bool):
                    return str(o[k])
    return ""


def describe_media(md: dict) -> dict:
    """Embedded media object → {kind, filename, mime_type, size, detail}."""
    out = {"kind": "media", "filename": "", "mime_type": "", "size": "", "detail": ""}
    if "_rawValue" in md and not ("mt" in md or "at" in md):
        rv = md.get("_rawValue")
        out["kind"] = "action"
        out["detail"] = ACTIONS.get(rv, f"action_{rv}")
        if isinstance(md.get("title"), str):
            out["detail"] += f" title={md['title']}"
        return out
    if "mt" in md or "at" in md:
        out["kind"] = "file"
        out["mime_type"] = str(md.get("mt") or "")
        for a in md.get("at") or []:
            if isinstance(a, dict) and isinstance(a.get("fn"), str):
                out["filename"] = a["fn"]
                break
        res = md.get("r") if isinstance(md.get("r"), dict) else None
        if not out["filename"] and res and isinstance(res.get("fn"), str):
            out["filename"] = res["fn"]
        out["size"] = _pick_size(md, res)
        return out
    reps = md.get("r")
    if isinstance(reps, list) and reps and all(isinstance(x, dict) and "dx" in x for x in reps):
        out["kind"] = "photo"
        best = max(reps, key=lambda x: (x.get("dx") or 0) * (x.get("dy") or 0))
        out["detail"] = f"{best.get('dx')}x{best.get('dy')}"
        out["size"] = _pick_size(best.get("r"))
        return out
    if isinstance(md.get("u"), str):
        out["kind"] = "webpage"
        out["detail"] = md["u"]
    return out


def _action_peers(md: dict) -> list[int]:
    raw = md.get("peerIds")
    if isinstance(raw, list):
        return [int(x) for x in raw if isinstance(x, int)]
    if isinstance(raw, (bytes, bytearray)) and len(raw) >= 4:
        n = struct.unpack_from("<i", raw, 0)[0]
        if 0 <= n and 4 + 8 * n <= len(raw):
            return list(struct.unpack_from(f"<{n}q", raw, 4))
    return []


# ── table discovery ─────────────────────────────────────────────────────────

_TN = re.compile(r"^t\d+$")


def kv_tables(conn) -> list[str]:
    try:
        names = [str(r[0]) for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
    except sqlite3.DatabaseError:
        return []
    return sorted((n for n in names if _TN.match(n)), key=lambda n: int(n[1:]))


def is_postbox(conn) -> bool:
    t = kv_tables(conn)
    if len(t) < 5:
        return False
    try:
        cols = [str(r[1]).lower() for r in conn.execute(f"PRAGMA table_info({t[0]})")]
    except sqlite3.DatabaseError:
        return False
    return cols == ["key", "value"]


def _score(conn, table: str, fn) -> int:
    ok = 0
    try:
        for k, v in conn.execute(f"SELECT key, value FROM {table} LIMIT {_SAMPLE}"):
            try:
                fn(k, v)
                ok += 1
            except (PostboxError, struct.error, TypeError, ValueError, UnicodeError):
                pass
    except sqlite3.DatabaseError:
        return 0
    return ok


def _peer_probe(k, v):
    if not isinstance(k, int) or v is None:
        raise PostboxError("not an integer-keyed peer row")
    decode_peer(k, bytes(v))


def _msg_probe(k, v):
    if not isinstance(k, (bytes, bytearray)) or v is None:
        raise PostboxError("not a blob-keyed row")
    decode_message_key(bytes(k))
    decode_message(bytes(v))


def find_tables(conn) -> dict:
    """{'peers': tN|None, 'messages': tN|None} by decode success rate."""
    best = {"peers": (0, None), "messages": (0, None)}
    for t in kv_tables(conn):
        for role, fn in (("peers", _peer_probe), ("messages", _msg_probe)):
            s = _score(conn, t, fn)
            if s > best[role][0]:
                best[role] = (s, t)
    return {k: v[1] for k, v in best.items()}


# ── top level ───────────────────────────────────────────────────────────────

def _handle(p: dict | None, pid: int) -> str:
    """Stable correspondent identifier: the @username, else tg:<id>."""
    if p and p.get("username"):
        return p["username"]
    return f"tg:{peer_raw_id(pid)}"


def parse_postbox(conn) -> dict:
    """Parse a Postbox store (connection to a private copy)."""
    tables = find_tables(conn)
    partial = False
    errors = Counter()
    peers: dict[int, dict] = {}
    if tables["peers"]:
        for k, v in conn.execute(f"SELECT key, value FROM {tables['peers']}"):
            try:
                peers[int(k)] = decode_peer(int(k), bytes(v))
            except (PostboxError, struct.error, TypeError, ValueError):
                errors["peer"] += 1
    raw_msgs = []
    if tables["messages"]:
        for k, v in conn.execute(f"SELECT key, value FROM {tables['messages']}"):
            try:
                key = decode_message_key(bytes(k))
                raw_msgs.append((key, decode_message(bytes(v))))
            except (PostboxError, struct.error, TypeError, ValueError):
                errors["message"] += 1
    if errors or not tables["messages"] or not tables["peers"]:
        partial = True

    def chat_peer(pid: int) -> dict | None:
        p = peers.get(pid)
        if p and p.get("linked_peer_id"):
            return peers.get(p["linked_peer_id"]) or p
        return p

    # Owner = the author of outgoing messages (falls back to none).
    owner_votes = Counter(m["author_id"] for _, m in raw_msgs
                          if m.get("author_id") and not m["flags"] & INCOMING)
    owner_id = owner_votes.most_common(1)[0][0] if owner_votes else None

    def name(pid) -> str:
        p = peers.get(pid) if pid is not None else None
        return p["display_name"] if p else ""

    def uname(pid) -> str:
        p = peers.get(pid) if pid is not None else None
        return p["username"] if p else ""

    messages, transfers = [], []
    msg_count_by: Counter = Counter()
    engaged_ids: set[int] = set()
    for (pid, ns, ts, mid), m in sorted(raw_msgs, key=lambda x: (x[0][2], x[0][0], x[0][3])):
        cp = chat_peer(pid)
        chat_type = (peers.get(pid) or {}).get("peer_type") or PEER_NS.get(peer_namespace(pid), "")
        author = m.get("author_id")
        incoming = bool(m["flags"] & INCOMING)
        if author is None and not incoming:
            author = owner_id
        media_desc = [describe_media(md) for md in m["media"]]
        media_txt = []
        for md, d in zip(m["media"], media_desc):
            t = d["kind"] if d["kind"] != "action" else d["detail"]
            if d["kind"] == "action":
                added = [_handle(peers.get(x), x) for x in _action_peers(md)]
                if added:
                    t += " " + ",".join(added)
            elif d["filename"]:
                t += f":{d['filename']}"
            media_txt.append(t)
        fwd = m.get("forward") or {}
        row = {
            "ts_utc": _utc(ts),
            "author": _handle(peers.get(author), author) if author is not None else "",
            "author_display": name(author),
            "author_username": uname(author),
            "chat": (cp or {}).get("display_name") or f"tg:{peer_raw_id(pid)}",
            "chat_type": chat_type,
            "partner": _handle(cp, pid) if chat_type in ("user", "bot", "secret_chat") else "",
            "direction": "incoming" if incoming else "outgoing",
            "body": m["text"][:_BODY_CAP],
            "media": "; ".join(media_txt),
            "reply_to_id": _reply_to(m["attributes"]),
            "forward_from": (_handle(peers.get(fwd["author_id"]), fwd["author_id"])
                             if fwd else ""),
            "forward_date_utc": _utc(fwd["date"]) if fwd else "",
            "peer_id": str(pid), "message_id": str(mid),
            "namespace": MSG_NS.get(ns, str(ns)),
        }
        messages.append(row)
        if author is not None:
            msg_count_by[author] += 1
            if author != owner_id:
                engaged_ids.add(author)
        if chat_type in ("user", "bot", "secret_chat") and not incoming:
            engaged_ids.add((cp or {}).get("peer_id", pid))
        for d in media_desc:
            if d["kind"] in ("file", "photo"):
                transfers.append({
                    "start_utc": row["ts_utc"], "chat": row["chat"],
                    "partner": row["partner"], "author": row["author"],
                    "author_display": row["author_display"],
                    "direction": row["direction"], "kind": d["kind"],
                    "filename": d["filename"], "mime_type": d["mime_type"],
                    "filesize": d["size"], "detail": d["detail"],
                    "message_id": row["message_id"],
                })

    from core.mail_roster import is_chat_system_handle
    participant_rows, participants = [], set()
    for pid, p in sorted(peers.items()):
        h = _handle(p, pid)
        participant_rows.append({
            "participant": h, "peer_type": p["peer_type"],
            "display_name": p["display_name"], "username": p["username"],
            "all_usernames": ";".join(p["usernames"]), "phone": p["phone"],
            "tg_id": str(p["tg_id"]), "peer_id": str(pid),
            "is_owner": "yes" if pid == owner_id else "",
            "messages_authored": str(msg_count_by.get(pid, 0)),
        })
        if p["peer_type"] in ("user", "bot") and pid != owner_id:
            participants.add(h)
    # Engaged = PEOPLE/bots the owner exchanged messages with — never a
    # group/channel peer (a channel "authors" its own service messages).
    engaged = sorted(h for h in (_handle(peers.get(i), i) for i in engaged_ids
                                 if peer_namespace(i) in (0, 3))
                     if h and not is_chat_system_handle(h))
    owners = [_handle(peers.get(owner_id), owner_id)] if owner_id is not None else []

    ts = [m["ts_utc"] for m in messages if m["ts_utc"]]
    out = {
        "success": True, "app": "telegram", "partial": partial,
        "messages": messages, "transfers": transfers,
        "participants": sorted(participants), "participant_rows": participant_rows,
        "engaged": engaged, "owners": owners,
        "message_count": len(messages), "transfer_count": len(transfers),
        "peer_count": len(peers),
        "coverage_window": {"start": min(ts), "end": max(ts)} if ts else None,
        "postbox_tables": tables,
        "fields": {
            "messages.csv": ["ts_utc", "chat", "chat_type", "direction", "author",
                             "author_display", "author_username", "partner", "body",
                             "media", "reply_to_id", "forward_from",
                             "forward_date_utc", "peer_id", "message_id", "namespace"],
            "transfers.csv": ["start_utc", "chat", "partner", "author", "author_display",
                              "direction", "kind", "filename", "mime_type", "filesize",
                              "detail", "message_id"],
            "participants.csv": ["participant", "peer_type", "display_name", "username",
                                 "all_usernames", "phone", "tg_id", "peer_id", "is_owner",
                                 "messages_authored"],
        },
    }
    if errors:
        out["decode_errors"] = dict(errors)
    if not tables["messages"]:
        out["warning"] = "Postbox store: no table decoded as the message history"
    return out
