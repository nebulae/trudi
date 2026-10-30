"""misc.sqlite_recover — deleted-record recovery (core/sqlite_recover.py).

Databases are built here with secure_delete OFF (the bundled sqlite may default
it on), rows are deleted, and the recovered set is compared with what was
deleted. The source must come through byte-identical with no sidecar files.
"""
import csv
import hashlib
import json
import os
import shutil
import sqlite3

import pytest

from core import sqlite_recover as R


def _tool(fn):
    return getattr(fn, "fn", fn)


def _sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def _rows(out_dir):
    with open(os.path.join(out_dir, "recovered.csv"), encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _msg_db(path):
    con = sqlite3.connect(path)
    con.execute("pragma secure_delete=off")
    con.execute("create table msg(id integer primary key, sender text, body text, ts int)")
    for i in range(300):
        con.execute("insert into msg(sender,body,ts) values(?,?,?)",
                    (f"user{i % 7}", f"hello message number {i} about lunch", 1_700_000_000 + i))
    con.commit()
    con.execute("delete from msg where id in (5,77,150)")
    con.execute("delete from msg where id between 200 and 290")
    con.commit()
    con.close()


def _wal_db(tmp_path):
    """A WAL db whose delete is committed to the -wal but not checkpointed;
    returns a copy (db + -wal) taken while the writer is still open."""
    live = tmp_path / "live"
    live.mkdir()
    db = str(live / "w.db")
    con = sqlite3.connect(db)
    con.execute("pragma secure_delete=off")
    con.execute("pragma journal_mode=wal")
    con.execute("pragma wal_autocheckpoint=0")
    con.execute("create table t(a text, b text)")
    for i in range(50):
        con.execute("insert into t values(?,?)",
                    (f"row{i}", "concert tickets for may" if i == 10 else "x" * 20))
    con.commit()
    con.execute("pragma wal_checkpoint(TRUNCATE)")
    con.execute("delete from t where a='row10'")
    con.commit()
    ev = tmp_path / "ev"
    ev.mkdir()
    shutil.copy(db, ev / "w.db")
    shutil.copy(db + "-wal", ev / "w.db-wal")
    con.close()
    return str(ev / "w.db")


def test_recovers_deleted_rows_from_freeblocks_unallocated_and_freelist(tmp_path):
    db = str(tmp_path / "a.db")
    _msg_db(db)
    out = str(tmp_path / "exports" / "rec")
    r = R.recover(db, out)
    r.pop("_rows")
    assert r["success"] and r["source_unchanged"]
    got = set()
    for row in _rows(out):
        if row["method"] == "strings":
            continue
        v = json.loads(row["values_json"])
        assert row["table"] in ("msg", "") and (row["table"] or row["table_guess"] == "msg")
        got.add(v["ts"] - 1_700_000_000)
    live = {i for i in range(300)} - ({4, 76, 149} | set(range(199, 290)))
    assert not (got & live), "a live row was reported as recovered"
    # rows 199..222 were overwritten by the b-tree rebalance; every deleted row
    # whose bytes survive in the file must come back
    raw = open(db, "rb").read()
    surviving = {i for i in {4, 76, 149} | set(range(199, 290))
                 if f"number {i} about".encode() in raw}
    assert surviving and surviving <= got
    assert r["freelist_pages"] >= 1 and r["recovered_records"] == len(got)


def test_wal_superseded_page_yields_the_deleted_row(tmp_path):
    db = _wal_db(tmp_path)
    out = str(tmp_path / "exports" / "wal")
    r = R.recover(db, out)
    r.pop("_rows")
    assert r["wal"]["present"] and r["wal"]["valid_frames"] >= 1
    rows = [x for x in _rows(out) if "concert tickets" in x["text"]]
    assert rows and rows[0]["source"] == "main_db_superseded_by_wal"
    assert rows[0]["rowid"] == "11" and rows[0]["table"] == "t"
    # live rows are not reported
    assert not any("row11" in x["text"] for x in _rows(out))


def test_source_untouched_and_no_sidecars_created(tmp_path):
    ev = tmp_path / "evidence_like"
    ev.mkdir()
    db = str(ev / "a.db")
    _msg_db(db)
    os.utime(db, (1_600_000_000, 1_600_000_000))
    before = (_sha(db), os.stat(db).st_mtime, sorted(os.listdir(ev)))
    r = R.recover(db, str(tmp_path / "exports" / "x"))
    assert r["success"]
    assert (_sha(db), os.stat(db).st_mtime, sorted(os.listdir(ev))) == before
    wdb = _wal_db(tmp_path)
    wdir = os.path.dirname(wdb)
    wbefore = {f: _sha(os.path.join(wdir, f)) for f in os.listdir(wdir)}
    assert R.recover(wdb, str(tmp_path / "exports" / "y"))["success"]
    assert {f: _sha(os.path.join(wdir, f)) for f in os.listdir(wdir)} == wbefore


def test_not_sqlite_is_an_honest_failure(tmp_path):
    f = tmp_path / "db_sqlite"
    f.write_bytes(os.urandom(8192))
    r = R.recover(str(f), str(tmp_path / "exports" / "z"))
    assert r["success"] is False and "not a plaintext SQLite" in r["error"]
    r = R.recover(str(tmp_path / "missing.db"), str(tmp_path / "exports" / "z"))
    assert r["success"] is False and "not found" in r["error"]


def test_tool_traces_writes_outputs_and_stamps(tmp_path):
    from core.execution_log import log
    from tools.misc import sqlite_recover
    db = str(tmp_path / "a.db")
    _msg_db(db)
    out = tmp_path / "exports" / "sqlrec"
    r = _tool(sqlite_recover)(db, output_dir=str(out))
    assert r["success"] and r["recovered_records"] > 0 and r["source_unchanged"]
    assert os.path.isfile(r["output_paths"]["recovered_csv"])
    assert os.path.isfile(r["output_paths"]["summary_json"])
    entry = log.index().by_call_id[r["_trudi_call_id"]]
    assert entry["cmd"] == f"misc.sqlite_recover {db}"
    assert entry.get("deleted_record_recovery") is True


def test_tool_failure_is_logged_not_raised(tmp_path):
    from core.execution_log import log
    from tools.misc import sqlite_recover
    f = tmp_path / "enc.db"
    f.write_bytes(b"\x01" * 4096)
    r = _tool(sqlite_recover)(str(f), output_dir=str(tmp_path / "exports" / "e"))
    assert r["success"] is False and r["_trudi_call_id"]
    assert log.index().by_call_id[r["_trudi_call_id"]]["success"] is False


@pytest.mark.parametrize("bad", ["/mnt/img/exports/rec", "{tmp}/evidence/exports/rec",
                                 "{tmp}/notes/rec"])
def test_output_dir_safety(tmp_path, bad):
    from tools.misc import sqlite_recover
    db = str(tmp_path / "a.db")
    _msg_db(db)
    with pytest.raises(ValueError):
        _tool(sqlite_recover)(db, output_dir=bad.format(tmp=tmp_path))


def test_recovery_is_a_file_content_tier_class():
    from tools._gates import _tiering as T
    e = {"type": "tool_call", "call_id": 1, "success": True,
         "cmd": "misc.sqlite_recover /c/ios/private/var/mobile/Library/SMS/sms.db"}
    assert "file_content" in T.classify_entry(e)
