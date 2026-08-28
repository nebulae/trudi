"""Read-only chat/messenger sqlite parsers (Skype main.db, WhatsApp msgstore.db).

First direct-sqlite code in the repo — the access contract matters because the
source db usually lives on a read-only evidence mount:

* Open with ``file:<path>?mode=ro&immutable=1`` (uri=True). Plain ``mode=ro``
  still attempts ``-wal``/``-shm`` sidecar access, which fails (or worse, tries
  to create files) on a read-only mount; ``immutable=1`` promises sqlite the
  file cannot change, so no sidecars are touched and no locks are taken.
* Immutable mode will NOT see frames in an uncheckpointed ``-wal`` sibling. A
  frozen forensic image is normally checkpointed; when a ``-wal`` file exists
  next to the db we surface ``wal_present: True`` + a warning, never a silent
  partial read.
* Column selection is PRAGMA table_info-driven — chat schemas vary by app
  version; missing columns degrade to empty fields with ``partial: True``,
  never a hard failure.

ENUMERATE, DON'T SEARCH: the whole Messages/Transfers tables are exported so a
correspondent or file transfer cannot be missed by grepping the wrong string.
"""
from __future__ import annotations

import os
import re
import sqlite3
from datetime import datetime, timezone
from urllib.request import pathname2url

_TAG_RE = re.compile(r"<[^>]+>")

_BODY_CAP = 4000


def open_ro(db_path: str) -> sqlite3.Connection:
    """Open a sqlite db strictly read-only: no -wal/-shm sidecars, no locks."""
    uri = f"file:{pathname2url(os.path.abspath(db_path))}?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def _utc(ts) -> str:
    """Unix seconds → UTC ISO string; '' on anything unparseable."""
    try:
        return datetime.fromtimestamp(
            int(ts), tz=timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


def _tables(conn) -> set:
    try:
        return {str(r[0]).lower() for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.DatabaseError:
        return set()


def _columns(conn, table: str) -> set:
    try:
        return {str(r[1]).lower() for r in conn.execute(
            f"PRAGMA table_info({table})")}
    except sqlite3.DatabaseError:
        return set()


def detect_schema(conn) -> str:
    """'skype' | 'whatsapp' | '' — table-shape probe, app-version tolerant."""
    t = _tables(conn)
    if "messages" in t and ({"transfers", "chats", "contacts"} & t):
        return "skype"
    if "messages" in t and ({"chat_list", "jid"} & t):
        return "whatsapp"
    return ""


def parse_skype(conn) -> dict:
    partial = False
    msgs: list[dict] = []
    transfers: list[dict] = []
    participants: set[str] = set()

    mcols = _columns(conn, "Messages")
    want_m = [c for c in ("timestamp", "author", "from_dispname", "chatname",
                          "dialog_partner", "body_xml") if c in mcols]
    if mcols and {"timestamp", "author"} - set(want_m):
        partial = True
    if want_m:
        try:
            for row in conn.execute(
                    f"SELECT {', '.join(want_m)} FROM Messages ORDER BY timestamp"):
                r = dict(zip(want_m, row))
                body = _TAG_RE.sub("", str(r.get("body_xml") or "")).strip()
                m = {
                    "ts_utc": _utc(r.get("timestamp")),
                    "author": str(r.get("author") or ""),
                    "author_display": str(r.get("from_dispname") or ""),
                    "chat": str(r.get("chatname") or ""),
                    "partner": str(r.get("dialog_partner") or ""),
                    "body": body[:_BODY_CAP],
                }
                msgs.append(m)
                for who in (m["author"], m["partner"]):
                    if who:
                        participants.add(who)
        except sqlite3.DatabaseError:
            partial = True

    tcols = _columns(conn, "Transfers")
    want_t = [c for c in ("starttime", "finishtime", "partner_handle",
                          "partner_dispname", "filename", "filesize",
                          "status") if c in tcols]
    if want_t:
        try:
            for row in conn.execute(
                    f"SELECT {', '.join(want_t)} FROM Transfers ORDER BY starttime"):
                r = dict(zip(want_t, row))
                t = {
                    "start_utc": _utc(r.get("starttime")),
                    "finish_utc": _utc(r.get("finishtime")),
                    "partner": str(r.get("partner_handle") or ""),
                    "partner_display": str(r.get("partner_dispname") or ""),
                    "filename": str(r.get("filename") or ""),
                    "filesize": str(r.get("filesize") or ""),
                    "status": str(r.get("status") or ""),
                }
                transfers.append(t)
                if t["partner"]:
                    participants.add(t["partner"])
        except sqlite3.DatabaseError:
            partial = True

    # Contacts/Chats widen the participant roster beyond message authors.
    for tbl, col in (("Contacts", "skypename"), ("Chats", "dialog_partner")):
        if col in _columns(conn, tbl):
            try:
                for (v,) in conn.execute(f"SELECT {col} FROM {tbl}"):
                    if v:
                        participants.add(str(v))
            except sqlite3.DatabaseError:
                partial = True

    ts = ([m["ts_utc"] for m in msgs if m["ts_utc"]]
          + [t["start_utc"] for t in transfers if t["start_utc"]])
    cov = {"start": min(ts), "end": max(ts)} if ts else None
    return {"success": True, "app": "skype", "partial": partial,
            "messages": msgs, "transfers": transfers,
            "participants": sorted(participants),
            "message_count": len(msgs), "transfer_count": len(transfers),
            "coverage_window": cov}


def parse_whatsapp(conn) -> dict:
    """Best-effort msgstore.db (schema varies widely across app versions)."""
    partial = False
    msgs: list[dict] = []
    participants: set[str] = set()
    mcols = _columns(conn, "messages")
    want = [c for c in ("key_remote_jid", "key_from_me", "timestamp",
                        "data", "media_name") if c in mcols]
    if mcols and {"key_remote_jid", "timestamp"} - set(want):
        partial = True
    if want:
        try:
            for row in conn.execute(
                    f"SELECT {', '.join(want)} FROM messages ORDER BY timestamp"):
                r = dict(zip(want, row))
                jid = str(r.get("key_remote_jid") or "")
                m = {
                    # WhatsApp timestamps are unix MILLIseconds.
                    "ts_utc": _utc((r.get("timestamp") or 0) // 1000),
                    "author": "me" if r.get("key_from_me") else jid,
                    "author_display": "",
                    "chat": jid,
                    "partner": jid,
                    "body": str(r.get("data") or r.get("media_name") or "")[:_BODY_CAP],
                }
                msgs.append(m)
                if jid:
                    participants.add(jid)
        except sqlite3.DatabaseError:
            partial = True
    ts = [m["ts_utc"] for m in msgs if m["ts_utc"]]
    cov = {"start": min(ts), "end": max(ts)} if ts else None
    return {"success": True, "app": "whatsapp", "partial": partial,
            "messages": msgs, "transfers": [],
            "participants": sorted(participants),
            "message_count": len(msgs), "transfer_count": 0,
            "coverage_window": cov}


def parse_chat_db(db_path: str, chat_app: str = "auto") -> dict:
    """Top-level entry: open read-only, detect schema, parse. Structured error
    (never an exception) on missing/corrupt/unsupported dbs."""
    if not os.path.exists(db_path):
        return {"success": False, "error": f"db not found: {db_path}"}
    wal = os.path.exists(db_path + "-wal")
    try:
        conn = open_ro(db_path)
    except sqlite3.Error as e:
        return {"success": False, "wal_present": wal,
                "error": f"cannot open db read-only: {e}"}
    try:
        app = chat_app if chat_app in ("skype", "whatsapp") else detect_schema(conn)
        if app == "skype":
            out = parse_skype(conn)
        elif app == "whatsapp":
            out = parse_whatsapp(conn)
        else:
            return {"success": False, "wal_present": wal,
                    "error": ("unsupported chat schema — tables found: "
                              + (", ".join(sorted(_tables(conn))) or "none"))}
    except sqlite3.DatabaseError as e:
        return {"success": False, "wal_present": wal,
                "error": f"db parse failed: {e}"}
    finally:
        conn.close()
    out["wal_present"] = wal
    if wal:
        out["warning"] = ("-wal sibling present: immutable read-only mode cannot "
                          "see uncheckpointed WAL frames; the most recent rows "
                          "may be absent from this export")
    return out
