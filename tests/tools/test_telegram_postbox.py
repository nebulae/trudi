"""core.telegram_postbox + misc.chat_db_export(chat_app=telegram|auto).

The fixture is a synthetic Postbox-shaped store: `tN (key, value)` tables
whose BLOBs are written with a minimal PostboxEncoder (little-endian keyed
fields, type tags) and the MessageHistoryTable record layout. Table numbers
are deliberately NOT the stock t2/t7 so discovery-by-content is exercised.
"""
import csv
import hashlib
import os
import sqlite3
import struct

import pytest

from core import chat_db, telegram_postbox as tp


# ── minimal PostboxEncoder ──────────────────────────────────────────────────

def _k(key: str) -> bytes:
    b = key.encode()
    return bytes([len(b)]) + b


def enc(fields: dict) -> bytes:
    out = b""
    for key, v in fields.items():
        if isinstance(v, bool):
            out += _k(key) + b"\x02" + (b"\x01" if v else b"\x00")
        elif isinstance(v, tuple) and v[0] == "i32":
            out += _k(key) + b"\x00" + struct.pack("<i", v[1])
        elif isinstance(v, int):
            out += _k(key) + b"\x01" + struct.pack("<q", v)
        elif isinstance(v, str):
            b = v.encode()
            out += _k(key) + b"\x04" + struct.pack("<i", len(b)) + b
        elif v is None:
            out += _k(key) + b"\x0b"
        elif isinstance(v, dict):
            body = enc({a: b for a, b in v.items() if a != "@t"})
            out += _k(key) + b"\x05" + struct.pack("<Ii", v.get("@t", 1), len(body)) + body
        elif isinstance(v, list):  # object array
            out += _k(key) + b"\x08" + struct.pack("<i", len(v))
            for o in v:
                body = enc({a: b for a, b in o.items() if a != "@t"})
                out += struct.pack("<Ii", o.get("@t", 1), len(body)) + body
        elif isinstance(v, bytes):
            out += _k(key) + b"\x0a" + struct.pack("<i", len(v)) + v
        else:
            raise TypeError(v)
    return out


def root(obj: dict, h: int = 0x9E68A52B) -> bytes:
    return enc({"_": {"@t": h, **obj}})


def peer_id(ns: int, raw: int) -> int:
    return ((raw >> 32) << 35) | (ns << 32) | (raw & 0xFFFFFFFF)


def msg_key(pid, ts, mid, ns=0) -> bytes:
    return struct.pack(">qiii", pid, ns, ts, mid)


def msg_value(author, text, incoming, stable=1, attrs=(), media=(), fwd=None) -> bytes:
    b = b"\x00" + struct.pack("<II", stable, 0) + b"\x00"
    b += struct.pack("<II", 0x40 | (4 if incoming else 0), 0)
    if fwd:
        b += b"\x01" + struct.pack("<qi", *fwd)
    else:
        b += b"\x00"
    b += (b"\x01" + struct.pack("<q", author)) if author is not None else b"\x00"
    t = text.encode()
    b += struct.pack("<i", len(t)) + t
    for group in (attrs, media):
        b += struct.pack("<i", len(group))
        for o in group:
            body = root(o, o.pop("@t", 7))
            b += struct.pack("<i", len(body)) + body
    b += struct.pack("<i", 0)        # referenced media ids
    b += struct.pack("<i", 0)        # newer-build trailing section count
    return b


OWNER = peer_id(0, 7_100_000_001)
ALICE = peer_id(0, 7_100_000_002)
BOT = peer_id(0, 6_900_000_003)
GROUP = peer_id(1, 4_100_000_004)
TS = 1_712_097_870  # 2024-04-02T22:44:30Z


def make_postbox(path, wal=False):
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE __meta_fulltext_tables (name INTEGER)")
    conn.execute("CREATE TABLE t0 (key INTEGER PRIMARY KEY, value BLOB)")
    conn.execute("CREATE TABLE t1 (key BLOB PRIMARY KEY, value BLOB)")
    conn.execute("CREATE TABLE t5 (key INTEGER PRIMARY KEY, value BLOB)")    # peers
    conn.execute("CREATE TABLE t12 (key BLOB PRIMARY KEY, value BLOB)")      # index noise
    conn.execute("CREATE TABLE t17 (key BLOB PRIMARY KEY, value BLOB)")      # messages
    conn.execute("INSERT INTO t0 VALUES (1, ?)", (struct.pack("<i", 25),))
    conn.execute("INSERT INTO t0 VALUES (2, ?)", (root({"peerId": OWNER}, 5),))
    peers = [
        (OWNER, {"i": OWNER, "fn": "billy", "ln": "owner", "un": "owner_handle",
                 "p": "15550001111", "bi": None, "uns": []}, 0x9E68A52B),
        (ALICE, {"i": ALICE, "fn": "Alice", "un": "alice_x", "bi": None, "uns": []},
         0x9E68A52B),
        (BOT, {"i": BOT, "fn": "Baker Bot", "un": "bakerbot",
               "bi": {"@t": 9, "f": ("i32", 0)}, "uns": []}, 0x9E68A52B),
        (GROUP, {"i": GROUP, "t": "the.crew", "pc": ("i32", 3)}, 0x66A17D51),
    ]
    for pid, obj, h in peers:
        conn.execute("INSERT INTO t5 VALUES (?, ?)", (pid, root(obj, h)))
    conn.execute("INSERT INTO t12 VALUES (?, ?)", (b"\x01\x02\x03", b"\xff\xff"))
    reply = {"@t": 478003709, "i": 1 << 32, "p": GROUP}
    rows = [
        (msg_key(ALICE, TS - 300, 1), msg_value(ALICE, "hi from alice", True, 1)),
        (msg_key(ALICE, TS - 200, 2), msg_value(OWNER, "hello alice", False, 2)),
        (msg_key(GROUP, TS - 100, 1), msg_value(OWNER, "160", False, 3)),
        (msg_key(GROUP, TS, 2), msg_value(BOT, "fresh out the oven", True, 4,
                                         attrs=[reply])),
        (msg_key(ALICE, TS + 60, 3), msg_value(
            ALICE, "", True, 5,
            media=[{"@t": 665733176, "mt": "application/pdf",
                    "at": [{"@t": 1922378215, "fn": "plan.pdf"}],
                    "r": {"@t": 1, "n64": 1234}}])),
        (msg_key(GROUP, TS + 120, 3), msg_value(
            OWNER, "", False, 6,
            media=[{"@t": 3161982849, "_rawValue": ("i32", 2),
                    "peerIds": struct.pack("<iq", 1, ALICE)}])),
        (msg_key(ALICE, TS + 180, 4), msg_value(ALICE, "fwd", True, 7,
                                               fwd=(BOT, TS - 1000))),
    ]
    conn.executemany("INSERT INTO t17 VALUES (?, ?)", rows)
    conn.commit()
    conn.close()
    if wal:
        path.parent.joinpath(path.name + "-wal").write_bytes(b"\x00" * 32)
        path.parent.joinpath(path.name + "-shm").write_bytes(b"\x00" * 32)
    return path


def _sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


# ── decoder ─────────────────────────────────────────────────────────────────

class TestDecoder:
    def test_object_roundtrip_types(self):
        b = enc({"a": ("i32", -5), "b": 2**40, "c": True, "s": "héllo",
                 "o": {"@t": 3, "x": "y"}, "n": None, "d": b"\x00\x01",
                 "arr": [{"@t": 4, "k": 1}]})
        d = tp.decode_object(b)
        assert d["a"] == -5 and d["b"] == 2**40 and d["c"] is True
        assert d["s"] == "héllo" and d["o"]["x"] == "y" and d["o"]["@t"] == 3
        assert d["n"] is None and d["d"] == b"\x00\x01" and d["arr"][0]["k"] == 1

    def test_truncated_blob_raises(self):
        with pytest.raises(tp.PostboxError):
            tp.decode_object(enc({"s": "abcdef"})[:-2])

    def test_peer_id_namespace_and_raw_id(self):
        assert tp.peer_namespace(GROUP) == 1
        assert tp.peer_raw_id(OWNER) == 7_100_000_001
        assert tp.peer_raw_id(777000) == 777000

    def test_message_decode(self):
        m = tp.decode_message(msg_value(ALICE, "yo", True, 9))
        assert m["author_id"] == ALICE and m["text"] == "yo" and m["flags"] & 4

    def test_non_message_rejected(self):
        with pytest.raises((tp.PostboxError, struct.error)):
            tp.decode_message(b"\x00\x01\x02")


# ── parser ──────────────────────────────────────────────────────────────────

class TestParse:
    def test_auto_detects_postbox_and_finds_tables_by_content(self, tmp_path):
        out = chat_db.parse_chat_db(str(make_postbox(tmp_path / "db_sqlite")))
        assert out["success"] and out["app"] == "telegram"
        assert out["postbox_tables"] == {"peers": "t5", "messages": "t17"}
        assert out["message_count"] == 7 and not out["partial"]

    def test_peers_usernames_types(self, tmp_path):
        out = chat_db.parse_chat_db(str(make_postbox(tmp_path / "db_sqlite")))
        rows = {r["username"] or r["display_name"]: r for r in out["participant_rows"]}
        assert rows["alice_x"]["peer_type"] == "user"
        assert rows["bakerbot"]["peer_type"] == "bot"
        assert rows["the.crew"]["peer_type"] == "group"
        assert rows["owner_handle"]["phone"] == "15550001111"
        assert rows["owner_handle"]["is_owner"] == "yes"
        assert out["owners"] == ["owner_handle"]
        assert set(out["participants"]) == {"alice_x", "bakerbot"}
        assert set(out["engaged"]) == {"alice_x", "bakerbot"}

    def test_messages_joined_utc_direction(self, tmp_path):
        out = chat_db.parse_chat_db(str(make_postbox(tmp_path / "db_sqlite")))
        by_body = {m["body"]: m for m in out["messages"]}
        bot = by_body["fresh out the oven"]
        assert bot["ts_utc"] == "2024-04-02T22:44:30+00:00"
        assert bot["author"] == "bakerbot" and bot["author_display"] == "Baker Bot"
        assert bot["chat"] == "the.crew" and bot["chat_type"] == "group"
        assert bot["direction"] == "incoming" and bot["reply_to_id"] == "1"
        mine = by_body["hello alice"]
        assert mine["direction"] == "outgoing" and mine["author"] == "owner_handle"
        assert mine["partner"] == "alice_x" and mine["chat"] == "Alice"
        assert by_body["fwd"]["forward_from"] == "bakerbot"
        acts = [m["media"] for m in out["messages"] if m["media"].startswith("added")]
        assert acts == ["added_members alice_x"]
        assert out["coverage_window"]["end"] == "2024-04-02T22:47:30+00:00"

    def test_file_media_is_a_transfer(self, tmp_path):
        out = chat_db.parse_chat_db(str(make_postbox(tmp_path / "db_sqlite")))
        assert out["transfer_count"] == 1
        t = out["transfers"][0]
        assert (t["filename"], t["mime_type"], t["filesize"], t["author"]) == \
            ("plan.pdf", "application/pdf", "1234", "alice_x")

    def test_explicit_chat_app_telegram(self, tmp_path):
        out = chat_db.parse_chat_db(str(make_postbox(tmp_path / "db_sqlite")),
                                    chat_app="telegram")
        assert out["success"] and out["message_count"] == 7

    def test_evidence_never_modified(self, tmp_path):
        ev = tmp_path / "evidence"
        ev.mkdir()
        db = make_postbox(ev / "db_sqlite", wal=True)
        before = {p.name: _sha(p) for p in ev.iterdir()}
        for p in ev.iterdir():
            os.chmod(p, 0o444)
        os.chmod(ev, 0o555)
        try:
            out = chat_db.parse_chat_db(str(db))
        finally:
            os.chmod(ev, 0o755)
        assert out["success"] and out["source_unchanged"] is True
        assert out["wal_present"] is True and "wal" in out["warning"].lower()
        assert {p.name: _sha(p) for p in ev.iterdir()} == before  # sidecars intact

    def test_garbage_kv_store_not_misparsed(self, tmp_path):
        p = tmp_path / "x.db"
        conn = sqlite3.connect(str(p))
        for i in range(6):
            conn.execute(f"CREATE TABLE t{i} (key BLOB PRIMARY KEY, value BLOB)")
            conn.execute(f"INSERT INTO t{i} VALUES (?, ?)", (b"k" * 20, b"\x07junk"))
        conn.commit()
        conn.close()
        out = chat_db.parse_chat_db(str(p))
        assert out["success"] and out["app"] == "telegram"
        assert out["message_count"] == 0 and out["partial"] and out.get("warning")


# ── tool wrapper ────────────────────────────────────────────────────────────

class TestTool:
    def test_export_csvs_trace_and_parsed_outputs(self, tmp_path):
        from core.execution_log import log
        from tools.misc import chat_db_export
        fn = getattr(chat_db_export, "fn", chat_db_export)
        src = tmp_path / "telegram-data" / "account-1" / "postbox" / "db"
        src.mkdir(parents=True)
        db = make_postbox(src / "db_sqlite")
        out_dir = tmp_path / "exports" / "chat"
        r = fn(str(db), output_dir=str(out_dir))
        assert r["success"] and r["app"] == "telegram" and r["source_unchanged"]
        assert "@alice_x" in r["summary"]
        with open(out_dir / "messages.csv", newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 7 and "author_username" in rows[0]
        with open(out_dir / "participants.csv", newline="", encoding="utf-8") as fh:
            parts = list(csv.DictReader(fh))
        assert {p["username"] for p in parts} >= {"alice_x", "bakerbot", "owner_handle"}
        assert "plan.pdf" in (out_dir / "transfers.csv").read_text()
        entry = log.index().by_call_id[r["_trudi_call_id"]]
        assert "telegram" in entry["cmd"] and entry.get("chat_db_export") is True
        assert "alice_x" in entry.get("chat_engaged", [])
        assert entry.get("chat_owners") == ["owner_handle"]
        stamped = {os.path.basename(f["file"]) for f in entry.get("parsed_outputs") or []}
        assert {"messages.csv", "participants.csv", "transfers.csv"} <= stamped
