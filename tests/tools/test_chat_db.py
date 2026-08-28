"""misc.chat_db_export + core.chat_db — read-only chat/messenger extraction.

The chat store is the comms channel the mail extractors don't cover, and a
first-class exfil channel (Transfers = a literal file-transfer trail). The
read-only proof matters most: the source db lives on evidence, and sqlite must
not create -wal/-shm/journal sidecars next to it.
"""
import os
import sqlite3

import pytest

from core import chat_db


def _make_skype_db(path, wal=False):
    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE Messages (id INTEGER PRIMARY KEY, timestamp INTEGER,
            author TEXT, from_dispname TEXT, chatname TEXT, dialog_partner TEXT,
            body_xml TEXT, type INTEGER);
        CREATE TABLE Transfers (id INTEGER PRIMARY KEY, starttime INTEGER,
            finishtime INTEGER, partner_handle TEXT, partner_dispname TEXT,
            filename TEXT, filesize TEXT, status INTEGER, type INTEGER);
        CREATE TABLE Contacts (id INTEGER PRIMARY KEY, skypename TEXT,
            displayname TEXT);
        CREATE TABLE Chats (id INTEGER PRIMARY KEY, name TEXT,
            dialog_partner TEXT);
    """)
    conn.executemany(
        "INSERT INTO Messages (timestamp, author, from_dispname, chatname,"
        " dialog_partner, body_xml, type) VALUES (?,?,?,?,?,?,?)",
        [
            (1466200000, "subject.account", "Subject", "#chat1", "ext.contact.a",
             "its time — send the <b>files</b>", 61),
            (1466286400, "ext.contact.a", "Contact A", "#chat1",
             "subject.account", "received, uploading tonight", 61),
        ])
    conn.execute(
        "INSERT INTO Transfers (starttime, finishtime, partner_handle,"
        " partner_dispname, filename, filesize, status, type)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (1466372800, 1466372900, "ext.contact.a", "Contact A",
         "research_bundle.7z", "35008256", 8, 1))
    conn.execute("INSERT INTO Contacts (skypename, displayname) VALUES (?,?)",
                 ("ext.contact.b", "Contact B"))
    conn.commit()
    conn.close()
    if wal:
        path.parent.joinpath(path.name + "-wal").write_bytes(b"\x00" * 32)
    return path


def _tool(fn):
    return getattr(fn, "fn", fn)  # unwrap @mcp.tool if wrapped


class TestParser:
    def test_parse_counts_window_and_roster(self, tmp_path):
        db = _make_skype_db(tmp_path / "main.db")
        out = chat_db.parse_chat_db(str(db))
        assert out["success"] and out["app"] == "skype"
        assert out["message_count"] == 2 and out["transfer_count"] == 1
        assert "ext.contact.a" in out["participants"]
        assert "ext.contact.b" in out["participants"]   # roster incl. Contacts
        cw = out["coverage_window"]
        assert cw["start"].startswith("2016-06-1") and cw["end"] >= cw["start"]
        assert "<b>" not in out["messages"][0]["body"]  # body_xml tags stripped
        assert "files" in out["messages"][0]["body"]

    def test_transfer_trail_is_first_class(self, tmp_path):
        db = _make_skype_db(tmp_path / "main.db")
        t = chat_db.parse_chat_db(str(db))["transfers"][0]
        assert t["filename"] == "research_bundle.7z"
        assert t["partner"] == "ext.contact.a"
        assert t["start_utc"].startswith("2016-06-19")

    def test_read_only_no_sidecar_files_created(self, tmp_path):
        # The regression that matters on evidence mounts: no -wal/-shm/journal.
        db = _make_skype_db(tmp_path / "main.db")
        os.chmod(db, 0o444)
        before = set(os.listdir(tmp_path))
        out = chat_db.parse_chat_db(str(db))
        assert out["success"]
        assert set(os.listdir(tmp_path)) == before

    def test_wal_sibling_surfaces_warning(self, tmp_path):
        db = _make_skype_db(tmp_path / "main.db", wal=True)
        out = chat_db.parse_chat_db(str(db))
        assert out["success"] and out["wal_present"] is True
        assert "wal" in (out.get("warning") or "").lower()

    def test_missing_db_structured_error(self, tmp_path):
        out = chat_db.parse_chat_db(str(tmp_path / "nope.db"))
        assert out["success"] is False and "not found" in out["error"]

    def test_unsupported_schema_lists_tables(self, tmp_path):
        db = tmp_path / "odd.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE foo (x)")
        conn.commit()
        conn.close()
        out = chat_db.parse_chat_db(str(db))
        assert out["success"] is False and "foo" in out["error"]

    def test_whatsapp_best_effort(self, tmp_path):
        db = tmp_path / "msgstore.db"
        conn = sqlite3.connect(str(db))
        conn.executescript("""
            CREATE TABLE messages (key_remote_jid TEXT, key_from_me INTEGER,
                timestamp INTEGER, data TEXT);
            CREATE TABLE chat_list (key_remote_jid TEXT);
        """)
        conn.execute("INSERT INTO messages VALUES (?,?,?,?)",
                     ("15551234567@s.whatsapp.net", 0, 1466200000000, "hello"))
        conn.commit()
        conn.close()
        out = chat_db.parse_chat_db(str(db))
        assert out["success"] and out["app"] == "whatsapp"
        assert out["message_count"] == 1
        assert out["messages"][0]["ts_utc"].startswith("2016-06-1")  # ms → s


class TestWrapperTool:
    def test_export_writes_csvs_and_is_citable(self, tmp_path):
        from core.execution_log import log
        from tools.misc import chat_db_export
        src = tmp_path / "img" / "Users" / "x" / "AppData" / "Roaming" / "Skype" / "acct"
        src.mkdir(parents=True)
        db = _make_skype_db(src / "main.db")
        out_dir = tmp_path / "exports" / "chat"
        r = _tool(chat_db_export)(str(db), output_dir=str(out_dir))
        assert r["success"] and r["app"] == "skype"
        for name in ("messages.csv", "transfers.csv", "participants.csv"):
            assert (out_dir / name).exists()
        assert "research_bundle.7z" in (out_dir / "transfers.csv").read_text()
        cid = r["_trudi_call_id"]
        assert cid
        entry = log.index().by_call_id[cid]
        # cmd carries the SOURCE DB PATH — the comms/chat manifest regexes key
        # on it, so this one call satisfies them with no gate edits.
        assert entry["cmd"].startswith("misc.chat_db_export ")
        assert "main.db" in entry["cmd"]
        # markers for the correspondent registries (server-stamped, not prose)
        assert entry.get("chat_db_export") is True
        assert "ext.contact.a" in entry.get("observed_correspondents", [])
        assert entry.get("coverage_window")

    def test_evidence_output_dir_refused(self, tmp_path):
        from tools.misc import chat_db_export
        db = _make_skype_db(tmp_path / "main.db")
        with pytest.raises(ValueError):
            _tool(chat_db_export)(str(db), output_dir="/mnt/img/extract")

    def test_failed_export_still_traced(self, tmp_path):
        # The ATTEMPT is part of the audit trail even when the parse fails.
        from core.execution_log import log
        from tools.misc import chat_db_export
        r = _tool(chat_db_export)(str(tmp_path / "no.db"),
                                  output_dir=str(tmp_path / "exports"))
        assert r["success"] is False
        assert r["_trudi_call_id"] in log.index().by_call_id


class TestGateIntegration:
    def test_cmd_satisfies_chat_messenger_manifest(self):
        from tools._gates._manifests import MANIFESTS
        rx = {s: r for s, r, _ in MANIFESTS["EXFIL"]["required"]}["chat_messenger"]
        assert rx.search("misc.chat_db_export /img/Users/x/Skype/main.db")
        assert rx.search("misc.chat_db_export /img/WhatsApp/msgstore.db")

    def test_cmd_satisfies_recipient_comms_re(self):
        from tools._gates.affirmative_coverage import _COMMS_RE
        assert _COMMS_RE.search("misc.chat_db_export /any/where/store.sqlite")
