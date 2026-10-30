"""Read-only chat/messenger sqlite parsers (Skype main.db, WhatsApp msgstore.db,
Telegram iOS Postbox db_sqlite — see core/telegram_postbox.py).

The access contract matters because the source db lives on evidence:

* The evidence file is NEVER opened by sqlite. Opening a WAL database in place
  checkpoints the WAL into the main file and deletes the sidecars (this once
  destroyed ~60 evidence DBs). ``parse_chat_db`` copies the db plus its
  ``-wal``/``-shm``/``-journal`` sidecars to a private tempdir, parses the copy
  (so uncheckpointed WAL frames are replayed into the copy only), and checks
  the source sha256 before/after.
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

_TAG_RE = re.compile(r"<[^>]+>")

_BODY_CAP = 4000


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

    # Store owner (the account whose main.db this is) — never a correspondent
    # of itself.
    owners: set[str] = set()
    if "skypename" in _columns(conn, "Accounts"):
        try:
            for (v,) in conn.execute("SELECT skypename FROM Accounts"):
                if v:
                    owners.add(str(v))
        except sqlite3.DatabaseError:
            partial = True
    # Engaged = the owner actually exchanged messages or files with them
    # (message author / dialog partner / transfer partner). Contacts-table-only
    # entries (auto-added service contacts such as echo123, address-book
    # imports) are roster inventory, not engagement.
    from core.mail_roster import is_chat_system_handle
    engaged = {p for p in participants
               if p not in owners and not is_chat_system_handle(p)}

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
            "engaged": sorted(engaged), "owners": sorted(owners),
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
    from core.mail_roster import is_chat_system_handle
    return {"success": True, "app": "whatsapp", "partial": partial,
            "messages": msgs, "transfers": [],
            "participants": sorted(participants),
            # every WhatsApp participant is a conversation partner (jids come
            # from the messages table only)
            "engaged": sorted(p for p in participants if not is_chat_system_handle(p)),
            "owners": [],
            "message_count": len(msgs), "transfer_count": 0,
            "coverage_window": cov}


_SIDECARS = ("-wal", "-shm", "-journal")


def _sha256(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_chat_db(db_path: str, chat_app: str = "auto") -> dict:
    """Top-level entry: copy the store (+ -wal/-shm sidecars) to a private
    tempdir, open ONLY the copy, detect schema, parse. The evidence file is
    never opened by sqlite (opening a WAL db in place checkpoints and deletes
    its sidecars); its sha256 is checked before/after. Structured error (never
    an exception) on missing/corrupt/unsupported dbs."""
    import shutil
    import tempfile
    if not os.path.isfile(db_path):
        return {"success": False, "error": f"db not found: {db_path}"}
    wal = os.path.exists(db_path + "-wal")
    before = _sha256(db_path)
    work = tempfile.mkdtemp(prefix="trudi_chatdb_")
    try:
        copy = os.path.join(work, "store.db")
        shutil.copyfile(db_path, copy)
        for sfx in _SIDECARS:
            if os.path.isfile(db_path + sfx):
                shutil.copyfile(db_path + sfx, copy + sfx)
        out = _parse_copy(copy, chat_app, wal)
    except OSError as e:
        out = {"success": False, "wal_present": wal, "error": f"cannot copy db: {e}"}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    out["source_sha256"] = before
    out["source_unchanged"] = _sha256(db_path) == before
    if not out["source_unchanged"]:
        out["success"] = False
        out["error"] = "source db hash changed during export"
    return out


def _parse_copy(copy: str, chat_app: str, wal: bool) -> dict:
    try:
        # The private copy is opened normally so a copied -wal is replayed.
        conn = sqlite3.connect(copy)
    except sqlite3.Error as e:
        return {"success": False, "wal_present": wal,
                "error": f"cannot open db copy: {e}"}
    try:
        from core import telegram_postbox
        if chat_app in ("skype", "whatsapp", "telegram"):
            app = chat_app
        else:
            app = detect_schema(conn) or ("telegram" if telegram_postbox.is_postbox(conn) else "")
        if app == "skype":
            out = parse_skype(conn)
        elif app == "whatsapp":
            out = parse_whatsapp(conn)
        elif app == "telegram":
            out = telegram_postbox.parse_postbox(conn)
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
        w = ("-wal sibling present: parsed from a private copy with the WAL "
             "replayed (uncheckpointed frames included); the evidence file was "
             "not opened")
        out["warning"] = f"{out['warning']}; {w}" if out.get("warning") else w
    return out
