"""Deleted-record recovery for SQLite stores (read-only on the evidence).

Deleted rows survive in four places a normal SQL query never reads:

  * freelist pages — a page freed by a DELETE keeps its old cells verbatim
    (unless secure_delete is on); a freed table-leaf page still parses as one;
  * freeblocks — a deleted cell inside a live page; only its first 4 bytes are
    overwritten (next-freeblock pointer + size), the record header and body
    usually survive;
  * unallocated page space — between the cell-pointer array and the cell
    content area; a cell deleted from the content edge is left intact;
  * the write-ahead log — older frames (superseded, uncommitted, stale salts)
    and main-db page versions the WAL has superseded hold pre-delete copies.

Everything is parsed from a private COPY of the db (+ -wal/-shm/-journal):
sqlite can create journal/shm files just by opening a db, so the evidence is
never opened by sqlite at all. A recovered record whose (rowid, values) is
still live in the logical database (main file overlaid by committed WAL frames)
is dropped as a duplicate, so every emitted row is content the live database
no longer returns. The installed sqlite-carver (Mari DeGrazia / digitalsleuth)
is run on the same copy as an independent second pass (unallocated +
freeblock printable dump).
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import tempfile
import time

SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGICS = (0x377F0682, 0x377F0683)
SIDECARS = ("-wal", "-shm", "-journal")
CARVER_CANDIDATES = ("/opt/sqlite-carver/bin/sqlite-carver", "sqlite-carver")

LEAF_TABLE, INTERIOR_TABLE = 0x0D, 0x05
_PRINTABLE = re.compile(rb"(?:[\x20-\x7e]|[\xc2-\xf4][\x80-\xbf]{1,3}){4,}")
_TEXT_CAP = 4000
CSV_FIELDS = ["source", "status", "page", "offset", "table", "table_guess", "rowid",
              "ncols", "method", "text", "values_json"]


def find_carver() -> str | None:
    for c in CARVER_CANDIDATES:
        p = c if os.path.isabs(c) else shutil.which(c)
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


# ── record / cell decoding ─────────────────────────────────────────────────────

def _varint(buf, off: int, end: int):
    v = 0
    for i in range(8):
        if off + i >= end:
            return None, off
        b = buf[off + i]
        v = (v << 7) | (b & 0x7F)
        if b < 0x80:
            return v, off + i + 1
    if off + 8 >= end:
        return None, off
    return (v << 8) | buf[off + 8], off + 9


_FIXED = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}


def _serial_size(t: int):
    if t in _FIXED:
        return _FIXED[t]
    if t < 12:
        return None
    return (t - 12) // 2 if t % 2 == 0 else (t - 13) // 2


def _decode(t: int, raw: bytes, enc: str):
    if t == 0:
        return None
    if t in (8, 9):
        return t - 8
    if 1 <= t <= 6:
        return int.from_bytes(raw, "big", signed=True)
    if t == 7:
        return struct.unpack(">d", raw)[0] if len(raw) == 8 else None
    if t % 2:
        return raw.decode(enc, errors="replace")
    return bytes(raw)


def parse_record(buf, off: int, end: int, enc: str = "utf-8", lenient: bool = False,
                 max_cols: int = 512):
    """(types, values, record_len, truncated) for a record at `off`, or None.
    lenient: a body running past `end` (unfollowed overflow) is decoded as far
    as it goes instead of rejected."""
    hlen, p = _varint(buf, off, end)
    if hlen is None or hlen < 2 or hlen > 4096 or off + hlen > end:
        return None
    hend = off + hlen
    types = []
    while p < hend:
        t, p = _varint(buf, p, hend)
        if t is None or _serial_size(t) is None:
            return None
        types.append(t)
        if len(types) > max_cols:
            return None
    if p != hend or not types:
        return None
    sizes = [_serial_size(t) for t in types]
    body = sum(sizes)
    truncated = hend + body > end
    if truncated and not lenient:
        return None
    vals, q = [], hend
    for t, n in zip(types, sizes):
        raw = bytes(buf[q:min(q + n, end)])
        if len(raw) < n and t < 12:
            vals.append(None)
        else:
            vals.append(_decode(t, raw, enc))
        q += n
    return types, vals, hlen + body, truncated


def _local_size(plen: int, usable: int) -> int:
    x = usable - 35
    if plen <= x:
        return plen
    m = ((usable - 12) * 32 // 255) - 23
    k = m + ((plen - m) % (usable - 4))
    return k if k <= x else m


class _Ctx:
    def __init__(self, pages: dict, page_size: int, usable: int, enc: str, max_cols: int):
        self.pages, self.page_size, self.usable = pages, page_size, usable
        self.enc, self.max_cols = enc, max_cols
        self.table_ncols: set = set()


def _follow_overflow(ctx: _Ctx, first: int, need: int) -> bytes | None:
    out, pg, seen = bytearray(), first, set()
    while need > 0 and pg and pg not in seen and len(seen) < 100_000:
        seen.add(pg)
        data = ctx.pages.get(pg)
        if data is None:
            return None
        chunk = data[4:ctx.usable]
        out += chunk[:need]
        need -= len(chunk[:need])
        pg = struct.unpack(">I", data[:4])[0]
    return bytes(out) if need <= 0 else None


def parse_cell(ctx: _Ctx, buf, off: int, end: int, strict: bool = True):
    """Table-leaf cell at `off`: (rowid, types, values, cell_len, truncated) or None.
    strict: the declared payload length must equal the decoded record length
    (rejects random bytes that merely look like a header)."""
    plen, p = _varint(buf, off, end)
    if plen is None or plen < 2:
        return None
    rowid, p = _varint(buf, p, end)
    if rowid is None:
        return None
    local = _local_size(plen, ctx.usable)
    overflow = local < plen
    cell_len = (p - off) + local + (4 if overflow else 0)
    if off + cell_len > end:
        return None
    payload = bytes(buf[p:p + local])
    truncated = False
    if overflow:
        first = struct.unpack(">I", bytes(buf[p + local:p + local + 4]))[0]
        rest = _follow_overflow(ctx, first, plen - local) if first else None
        if rest is None:
            truncated = True
        else:
            payload += rest
    rec = parse_record(payload, 0, len(payload), ctx.enc, lenient=truncated,
                       max_cols=ctx.max_cols)
    if rec is None:
        return None
    types, vals, rlen, rec_trunc = rec
    if strict and not truncated and rlen != plen:
        return None
    return rowid, types, vals, cell_len, truncated or rec_trunc


def _page_header(data: bytes, pgno: int):
    h = 100 if pgno == 1 else 0
    if len(data) < h + 8:
        return None
    flag = data[h]
    fb, ncells, cstart = struct.unpack(">HHH", data[h + 1:h + 7])
    hdr_len = 12 if flag in (0x02, 0x05) else 8
    return h, flag, fb, ncells, (cstart or 65536), hdr_len


def _leaf_cells(ctx: _Ctx, data: bytes, pgno: int, strict: bool = True):
    hdr = _page_header(data, pgno)
    if not hdr or hdr[1] != LEAF_TABLE:
        return []
    h, _, _, ncells, _, hl = hdr
    out = []
    for i in range(min(ncells, (len(data) - h - hl) // 2)):
        ptr = struct.unpack(">H", data[h + hl + 2 * i:h + hl + 2 * i + 2])[0]
        if not ptr or ptr >= ctx.usable:
            continue
        c = parse_cell(ctx, data, ptr, ctx.usable, strict=strict)
        if c:
            out.append((ptr,) + c)
    return out


def _key(rowid, vals) -> bytes:
    return hashlib.sha1(repr((rowid, vals)).encode("utf-8", "replace")).digest()


def _text_of(vals) -> str:
    parts = []
    for v in vals:
        if isinstance(v, str):
            if v.strip():
                parts.append(v)
        elif isinstance(v, (bytes, bytearray)):
            parts += [m.decode("utf-8", "replace") for m in _PRINTABLE.findall(v)]
    return " | ".join(parts)[:_TEXT_CAP].translate(_CTRL)


_CTRL = {c: " " for c in list(range(0, 9)) + list(range(11, 32)) + [127]}


def _jsonable(v):
    if isinstance(v, (bytes, bytearray)):
        return {"blob_len": len(v), "blob_hex": bytes(v[:64]).hex()}
    if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
        return str(v)
    return v


# ── schema ─────────────────────────────────────────────────────────────────────

def _walk_table_btree(ctx: _Ctx, root: int, limit: int = 1_000_000) -> set:
    leaves, stack, seen = set(), [root], set()
    while stack and len(seen) < limit:
        pg = stack.pop()
        if pg in seen or pg not in ctx.pages:
            continue
        seen.add(pg)
        hdr = _page_header(ctx.pages[pg], pg)
        if not hdr:
            continue
        h, flag, _, ncells, _, hl = hdr
        data = ctx.pages[pg]
        if flag == LEAF_TABLE:
            leaves.add(pg)
        elif flag == INTERIOR_TABLE:
            stack.append(struct.unpack(">I", data[h + 8:h + 12])[0])
            for i in range(min(ncells, (len(data) - h - hl) // 2)):
                ptr = struct.unpack(">H", data[h + hl + 2 * i:h + hl + 2 * i + 2])[0]
                if 0 < ptr <= len(data) - 4:
                    stack.append(struct.unpack(">I", data[ptr:ptr + 4])[0])
    return leaves


def _schema(ctx: _Ctx) -> dict:
    """{table: {"root": n, "columns": [...]}} parsed from the logical page 1
    b-tree (never by opening the db). Column names come from replaying the
    CREATE statement into a throwaway in-memory database."""
    tables = {"sqlite_master": {"root": 1, "sql": "", "columns":
                                ["type", "name", "tbl_name", "rootpage", "sql"]}}
    for pg in _walk_table_btree(ctx, 1):
        for _ptr, _rowid, _t, vals, _l, _tr in _leaf_cells(ctx, ctx.pages[pg], pg):
            if len(vals) >= 5 and vals[0] == "table" and isinstance(vals[3], int):
                tables[str(vals[1])] = {"root": vals[3], "sql": vals[4] or "", "columns": []}
    for name, t in tables.items():
        if not t["sql"]:
            continue
        try:
            con = sqlite3.connect(":memory:")
            con.execute(t["sql"])
            t["columns"] = [r[1] for r in con.execute(f'PRAGMA table_info("{name}")')]
            con.close()
        except Exception:
            pass
    return tables


# ── WAL ────────────────────────────────────────────────────────────────────────

def _wal_frames(wal: bytes, page_size: int):
    """(frames, info). frame = dict(idx, pgno, commit, valid, data, offset)."""
    info = {"present": True, "frames": 0, "valid_frames": 0, "error": None}
    if len(wal) < 32:
        info["error"] = "wal shorter than its header"
        return [], info
    magic, _ver, psz, _ckpt, s1, s2 = struct.unpack(">IIIIII", wal[:24])
    if magic not in WAL_MAGICS:
        info["error"] = f"bad wal magic 0x{magic:08x}"
        return [], info
    psz = psz or page_size
    frames, off, idx = [], 32, 0
    while off + 24 + psz <= len(wal):
        pgno, commit, fs1, fs2 = struct.unpack(">IIII", wal[off:off + 16])
        frames.append({"idx": idx, "pgno": pgno, "commit": commit,
                       "salt_ok": (fs1, fs2) == (s1, s2), "offset": off,
                       "data": wal[off + 24:off + 24 + psz]})
        off += 24 + psz
        idx += 1
    # committed = salt-matching frames up to (and including) the last commit frame
    last_commit = -1
    for f in frames:
        if not f["salt_ok"]:
            break
        if f["commit"]:
            last_commit = f["idx"]
    for f in frames:
        f["valid"] = f["salt_ok"] and f["idx"] <= last_commit
    info["frames"] = len(frames)
    info["valid_frames"] = sum(f["valid"] for f in frames)
    return frames, info


# ── main pass ─────────────────────────────────────────────────────────────────

def _freelist(ctx: _Ctx, header: bytes) -> tuple[set, set]:
    trunks, leaves = set(), set()
    pg = struct.unpack(">I", header[32:36])[0]
    while pg and pg in ctx.pages and pg not in trunks and len(trunks) < 1_000_000:
        trunks.add(pg)
        d = ctx.pages[pg]
        n = struct.unpack(">I", d[4:8])[0]
        for i in range(min(n, (ctx.usable - 8) // 4)):
            leaves.add(struct.unpack(">I", d[8 + 4 * i:12 + 4 * i])[0])
        pg = struct.unpack(">I", d[:4])[0]
    return trunks, leaves


def _regions(ctx: _Ctx, data: bytes, pgno: int):
    """(unallocated span, [freeblock spans]) of a table-leaf page."""
    hdr = _page_header(data, pgno)
    if not hdr or hdr[1] != LEAF_TABLE:
        return None, []
    h, _, fb, ncells, cstart, hl = hdr
    ua = (h + hl + 2 * ncells, min(cstart, ctx.usable))
    fbs, seen = [], set()
    while fb and fb not in seen and fb + 4 <= ctx.usable and len(seen) < 4096:
        seen.add(fb)
        nxt, size = struct.unpack(">HH", data[fb:fb + 4])
        if size < 4 or fb + size > ctx.usable:
            break
        fbs.append((fb, fb + size))
        fb = nxt
    return (ua if ua[1] > ua[0] else None), fbs


def _plausible(ctx: _Ctx, vals, types) -> bool:
    if len(vals) > ctx.max_cols:
        return False
    if len(vals) == 1 and not (types[0] >= 12 and _serial_size(types[0]) > 0):
        return False
    return any(t != 0 for t in types)


def _types_at(buf, p: int, end: int, n: int):
    types = []
    for _ in range(n):
        t, p = _varint(buf, p, end)
        if t is None or _serial_size(t) is None:
            return None, p
        types.append(t)
    return types, p


def _body(buf, types, p: int, end: int, enc: str):
    sizes = [_serial_size(t) for t in types]
    if p + sum(sizes) > end:
        return None, p
    vals = []
    for t, n in zip(types, sizes):
        vals.append(_decode(t, bytes(buf[p:p + n]), enc))
        p += n
    return vals, p


def _guess_value(raw: bytes, enc: str):
    """A column whose serial type was overwritten: typed from its bytes."""
    if not raw:
        return None
    try:
        t = raw.decode(enc)
        if t.isprintable():
            return t
    except UnicodeDecodeError:
        pass
    if len(raw) in (1, 2, 3, 4, 6, 8):
        return int.from_bytes(raw, "big", signed=True)
    return bytes(raw)


def _damaged_at(ctx: _Ctx, data: bytes, o: int, re_: int, ncols=None):
    """Best reading of a deleted cell at `o` whose first 4 bytes were overwritten
    by a freeblock header (next ptr + size). That wiped the payload-length and
    rowid varints and, for small cells, the header-length byte and the first
    serial type too. Readings (N = a schema table's column count):
      A  intact record header at o+4.. (long payload / rowid varints);
      B  header byte lost, all N serial types intact from o+4;
      C  header byte + first serial type (1 byte) lost, N-1 types from o+4; the
         lost column's size is what closes the cell exactly, its type is
         inferred from its bytes (NULL when it closes at size 0).
    Anchors: a freed cell's header declares the distance to the end of its
    (merged) freeblock, so the true cell ends either there or where the next
    freed cell's header declares the SAME block end. A reading that lands on an
    anchor wins; otherwise the one ending closest to the declared end."""
    size = struct.unpack(">H", data[o + 2:o + 4])[0]
    declared = o + size
    block_end = min(declared, re_) if size >= 4 else re_
    # region end always anchors (cells absorbed into unallocated space keep a
    # stale size); a chained header declaring the same block end anchors too
    anchors = {block_end, re_}
    for q in range(o + 5, re_ - 3):
        if declared == q + struct.unpack(">H", data[q + 2:q + 4])[0] and \
                _fb_header_like(ctx, data, q, ctx.usable):
            anchors.add(q)
    ncols = sorted(ncols or ctx.table_ncols)
    readings = []                      # (anchored, rank, s, types, vals, end, method)
    for s in range(o + 4, min(re_ - 1, o + 4 + 18)):
        r = parse_record(data, s, re_, ctx.enc, max_cols=ctx.max_cols)
        if r and _plausible(ctx, r[1], r[0]) and (not ncols or len(r[0]) in ncols):
            readings.append((s + r[2], 0, s, r[0], r[1], "freeblock_header"))
    for n in ncols:
        types, p = _types_at(data, o + 4, re_, n)
        if types:
            vals, end = _body(data, types, p, re_, ctx.enc)
            if vals is not None and _plausible(ctx, vals, types):
                readings.append((end, 1, o + 4, types, vals, "freeblock_header_lost_len"))
        if n < 2:
            continue
        types, p = _types_at(data, o + 4, re_, n - 1)
        if not types:
            continue
        rest = sum(_serial_size(t) for t in types)
        for e in sorted(anchors) + [None]:
            lost = 0 if e is None else e - p - rest
            if lost < 0:
                continue
            vals, end = _body(data, types, p + lost, re_, ctx.enc)
            if vals is None or not _plausible(ctx, vals, types):
                continue
            lv = _guess_value(bytes(data[p:p + lost]), ctx.enc)
            if isinstance(lv, bytes):     # an inferred blob is too weak to claim
                continue
            readings.append((end, 2, o + 4, [0 if lv is None else -1] + types, [lv] + vals,
                             "freeblock_header_lost_col1"))
            if e is not None:
                break
    if not readings:
        return None
    anchored = [r for r in readings if r[0] in anchors]
    if anchored:
        e, _, s, types, vals, method = min(anchored, key=lambda r: (r[0], r[1]))
    else:
        e, _, s, types, vals, method = min(readings, key=lambda r: (abs(block_end - r[0]), r[1]))
        method += "_unanchored"
    return 0, 0, s, types, vals, e, method


def _fb_header_like(ctx: _Ctx, data: bytes, o: int, end: int) -> bool:
    """A freed cell's header: size >= 4 ending inside the slack region, next
    pointer 0 or forward."""
    nxt, size = struct.unpack(">HH", data[o:o + 4])
    return size >= 4 and o + size <= end and (nxt == 0 or o < nxt < ctx.usable)


def _scan_slack(ctx: _Ctx, data: bytes, start: int, end: int, is_freeblock: bool = False,
                ncols=None):
    """Deleted cells in a slack region (unallocated space, a freeblock, a freed
    trunk page). Intact cells parse strictly (declared payload length == record
    length); a cell whose first 4 bytes are a freeblock header (every freed cell
    gets one, and it survives after the block is merged or absorbed into
    unallocated space) is read by _damaged_at. Adjacent deleted cells chain."""
    out, o = [], start
    while o < end - 3:
        if not any(data[o:o + 4]):
            o += 1
            continue
        c = parse_cell(ctx, data, o, end, strict=True)
        if c and _plausible(ctx, c[2], c[1]):
            out.append((o,) + c + ("intact_cell",))
            o += c[3]
            continue
        if (is_freeblock and o == start) or _fb_header_like(ctx, data, o, ctx.usable):
            d = _damaged_at(ctx, data, o, end, ncols)
            # off a known block start only an anchored reading counts: stale
            # cell-pointer bytes in unallocated space often look header-like
            if d and (not d[6].endswith("_unanchored") or (is_freeblock and o == start)):
                # a header-like position a few bytes on that closes the SAME
                # cell is the real start (the earlier one straddles its header)
                for o2 in range(o + 1, o + 4):
                    if _fb_header_like(ctx, data, o2, ctx.usable):
                        d2 = _damaged_at(ctx, data, o2, end, ncols)
                        if d2 and d2[5] == d[5] and not d2[6].endswith("_unanchored"):
                            d = d2
                _, _, s, types, vals, e, method = d
                out.append((s, None, types, vals, e - s, False, method))
                o = e
                continue
        o += 1
    return out


def recover(db_path: str, output_dir: str, carver: str | None = "auto",
            max_seconds: int = 600, max_rows: int = 200_000) -> dict:
    t0 = time.time()
    res = {"success": False, "db_path": db_path, "output_dir": output_dir}
    if not os.path.isfile(db_path):
        res["error"] = f"db not found: {db_path}"
        return res
    with open(db_path, "rb") as fh:
        if fh.read(16) != SQLITE_MAGIC:
            res["error"] = ("not a plaintext SQLite 3 database (bad header — "
                            "encrypted/SQLCipher stores need their key first)")
            return res
    before = sha256_file(db_path)
    work = tempfile.mkdtemp(prefix="trudi_sqlrec_")
    try:
        copy = os.path.join(work, "db.sqlite")
        shutil.copyfile(db_path, copy)
        copied = {"db": db_path}
        for sfx in SIDECARS:
            if os.path.isfile(db_path + sfx):
                shutil.copyfile(db_path + sfx, copy + sfx)
                copied[sfx.lstrip("-")] = db_path + sfx
        os.makedirs(output_dir, exist_ok=True)
        res.update(_recover_copy(copy, output_dir, max_seconds, max_rows, t0))
        res["sidecars_copied"] = sorted(k for k in copied if k != "db")
        # independent second pass: sqlite-carver on the same copy
        cbin = find_carver() if carver == "auto" else carver
        res["carver"] = _run_carver(cbin, copy, output_dir) if cbin else \
            {"ran": False, "note": "sqlite-carver not installed (in-process pass only)"}
    except Exception as e:  # noqa: BLE001 — surfaced, never swallowed
        res["success"] = False
        res["error"] = f"{type(e).__name__}: {e}"
    finally:
        shutil.rmtree(work, ignore_errors=True)
    after = sha256_file(db_path)
    res["source_sha256"] = before
    res["source_unchanged"] = before == after
    if before != after:
        res["success"] = False
        res["error"] = "source hash changed during recovery"
    res["elapsed_seconds"] = round(time.time() - t0, 2)
    return res


def _run_carver(cbin: str, copy: str, output_dir: str) -> dict:
    out = os.path.join(output_dir, "carver.tsv")
    try:
        p = subprocess.run([cbin, "-f", copy, "-o", out], capture_output=True,
                           text=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ran": True, "success": False, "error": str(e), "binary": cbin}
    rows = 0
    if os.path.isfile(out):
        with open(out, encoding="utf-8", errors="replace") as fh:
            rows = max(0, sum(1 for _ in fh) - 1)
    ok = p.returncode == 0 and os.path.isfile(out) and "does not appear" not in p.stdout
    return {"ran": True, "success": ok, "binary": cbin, "exit_code": p.returncode,
            "rows": rows, "output_path": out if os.path.isfile(out) else None,
            "stderr": (p.stderr or p.stdout)[-600:] if not ok else ""}


def _recover_copy(copy: str, output_dir: str, max_seconds: int, max_rows: int, t0: float) -> dict:
    with open(copy, "rb") as fh:
        main = fh.read()
    page_size = struct.unpack(">H", main[16:18])[0]
    page_size = 65536 if page_size == 1 else page_size
    if page_size < 512 or page_size & (page_size - 1):
        return {"success": False, "error": f"implausible page size {page_size}"}
    reserved = main[20]
    enc = {1: "utf-8", 2: "utf-16-le", 3: "utf-16-be"}.get(
        struct.unpack(">I", main[56:60])[0], "utf-8")
    usable = page_size - reserved
    main_pages = {i // page_size + 1: main[i:i + page_size]
                  for i in range(0, len(main) - page_size + 1, page_size)}

    wal_info = {"present": False}
    frames = []
    if os.path.isfile(copy + "-wal"):
        with open(copy + "-wal", "rb") as fh:
            frames, wal_info = _wal_frames(fh.read(), page_size)
    current = {}                              # pgno -> latest committed frame
    for f in frames:
        if f["valid"]:
            current[f["pgno"]] = f
    logical = dict(main_pages)
    for pg, f in current.items():
        logical[pg] = f["data"]

    ctx = _Ctx(logical, page_size, usable, enc, max_cols=512)
    tables = _schema(ctx)
    if tables:
        ctx.max_cols = max((len(t["columns"]) for t in tables.values()), default=0) or 512
        ctx.table_ncols = {len(t["columns"]) for t in tables.values() if t["columns"]}
    page_table = {}
    for name, t in tables.items():
        for pg in _walk_table_btree(ctx, t["root"]):
            page_table[pg] = name
    by_ncols = {}
    for name, t in tables.items():
        if t["columns"]:
            by_ncols.setdefault(len(t["columns"]), []).append(name)

    header = logical.get(1, main[:100])
    trunks, free_leaves = _freelist(ctx, header)
    freelist = trunks | free_leaves

    # live logical records
    live, live_vals = set(), set()   # a freeblock record lost its rowid: match on values
    for pg, d in logical.items():
        if pg not in freelist:
            for c in _leaf_cells(ctx, d, pg):
                live.add(_key(c[1], c[3]))
                live_vals.add(_key_any_rowid(c[3]))

    rows, stats = [], {"dup_of_live": 0, "timed_out": False}
    seen = set()

    def emit(source, pg, off, rowid, types, vals, method, truncated=False, table=""):
        k = _key(rowid, vals) if rowid is not None else None
        if (k and k in live) or (rowid is None and _key_any_rowid(vals) in live_vals):
            stats["dup_of_live"] += 1
            return
        dk = (rowid, repr(vals))
        if dk in seen:
            return
        seen.add(dk)
        cands = [] if table else by_ncols.get(len(vals), [])
        guess = ",".join(cands) if len(cands) <= 4 else f"ambiguous ({len(cands)} tables)"
        cols = tables.get(table or (cands[0] if len(cands) == 1 else ""), {}).get("columns", [])
        if cols and len(cols) >= len(vals):
            vj = {cols[i]: _jsonable(v) for i, v in enumerate(vals)}
        else:
            vj = [_jsonable(v) for v in vals]
        rows.append({"source": source, "status": "not_live" + (" (truncated)" if truncated else ""),
                     "page": pg, "offset": off, "table": table, "table_guess": guess,
                     "rowid": "" if rowid is None else rowid, "ncols": len(vals),
                     "method": method, "text": _text_of(vals),
                     "values_json": json.dumps(vj, ensure_ascii=False, default=str)[:20000],
                     "_vals": repr(vals)})

    def strings_row(source, pg, off, blob, table=""):
        runs = [m.decode("utf-8", "replace") for m in _PRINTABLE.findall(blob)]
        if not runs:
            return
        rows.append({"source": source, "status": "residual", "page": pg, "offset": off,
                     "table": table, "table_guess": "", "rowid": "", "ncols": "",
                     "method": "strings", "text": " | ".join(runs)[:_TEXT_CAP].translate(_CTRL),
                     "values_json": ""})

    def page_pass(source, pg, data, table, whole_page_deleted):
        if time.time() - t0 > max_seconds or len(rows) >= max_rows:
            stats["timed_out"] = True
            return
        hdr = _page_header(data, pg)
        is_leaf = bool(hdr and hdr[1] == LEAF_TABLE)
        if whole_page_deleted:
            if is_leaf:
                cells = _leaf_cells(ctx, data, pg, strict=False)
                for ptr, rowid, types, vals, _l, tr in cells:
                    emit(source, pg, ptr, rowid, types, vals, "freed_page_cell", tr, table)
                if not cells:
                    strings_row(source, pg, 0, data[:usable], table)
            else:
                strings_row(source, pg, 0, data[:usable], table)
                return
        if not is_leaf:
            return
        ua, fbs = _regions(ctx, data, pg)
        # a page of a known table only holds that table's rows
        ncols = {len(tables[table]["columns"])} if tables.get(table, {}).get("columns") else None
        if ua:
            found = _scan_slack(ctx, data, ua[0], ua[1], ncols=ncols)
            for o, rowid, types, vals, _l, tr, method in found:
                emit(source + ":unallocated", pg, o, rowid, types, vals, method, tr, table)
            if not found:
                strings_row(source + ":unallocated", pg, ua[0], data[ua[0]:ua[1]], table)
        for fs, fe in fbs:
            recs = _scan_slack(ctx, data, fs, fe, is_freeblock=True, ncols=ncols)
            for o, rowid, types, vals, _l, tr, method in recs:
                emit(source + ":freeblock", pg, o, rowid, types, vals, method, tr, table)
            if not recs:
                strings_row(source + ":freeblock", pg, fs, data[fs + 4:fe], table)

    # 1. logical pages: freelist pages (whole page deleted) + live leaf slack
    for pg in sorted(logical):
        if pg in trunks:
            # a trunk was a leaf once: its bytes past the pointer array are intact
            d = logical[pg]
            start = 8 + 4 * min(struct.unpack(">I", d[4:8])[0], (usable - 8) // 4)
            found = _scan_slack(ctx, d, start, usable)
            for o, rowid, types, vals, _l, tr, method in found:
                emit("freelist_trunk", pg, o, rowid, types, vals, method, tr)
            if not found:
                strings_row("freelist_trunk", pg, start, d[start:usable])
        elif pg in free_leaves:
            page_pass("freelist_page", pg, logical[pg], page_table.get(pg, ""), True)
        else:
            page_pass("live_page_slack", pg, logical[pg], page_table.get(pg, ""), False)
    # 2. main-file page versions the WAL superseded
    for pg in sorted(current):
        if pg in main_pages and main_pages[pg] != current[pg]["data"]:
            page_pass("main_db_superseded_by_wal", pg, main_pages[pg], page_table.get(pg, ""), True)
    # 3. WAL frames that are not the current version of their page
    cur_idx = {f["idx"] for f in current.values()}
    for f in frames:
        if f["idx"] not in cur_idx:
            state = "wal_frame_stale" if not f["valid"] else "wal_frame_superseded"
            page_pass(state, f["pgno"], f["data"], page_table.get(f["pgno"], ""), True)

    # a damaged copy (rowid lost) of a record also recovered intact is redundant
    with_rowid = {r["_vals"] for r in rows if r.get("_vals") and r["rowid"] != ""}
    before = len(rows)
    rows = [r for r in rows if not (r.get("_vals") and r["rowid"] == "" and r["_vals"] in with_rowid)]
    stats["dup_damaged_copies"] = before - len(rows)
    for r in rows:
        r.pop("_vals", None)
    out_csv = os.path.join(output_dir, "recovered.csv")
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)
    records = [r for r in rows if r["method"] != "strings"]
    by_source, by_table = {}, {}
    for r in records:
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
        t = r["table"] or r["table_guess"] or "?"
        by_table[t] = by_table.get(t, 0) + 1
    summary = {
        "success": True, "page_size": page_size, "page_count": len(main_pages),
        "text_encoding": enc, "tables": len(tables) - 1,
        "freelist_pages": len(freelist), "freelist_trunks": len(trunks),
        "wal": {k: v for k, v in wal_info.items()},
        "wal_current_pages": len(current),
        "recovered_records": len(records),
        "residual_string_regions": len(rows) - len(records),
        "records_by_source": by_source, "records_by_table": by_table,
        "dropped_as_live_duplicates": stats["dup_of_live"],
        "dropped_as_damaged_copies": stats["dup_damaged_copies"],
        "timed_out": stats["timed_out"], "row_cap_hit": len(rows) >= max_rows,
        "output_csv": out_csv,
    }
    with open(os.path.join(output_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, default=str)
    summary["output_json"] = os.path.join(output_dir, "summary.json")
    summary["_rows"] = rows
    return summary


def _key_any_rowid(vals) -> bytes:
    return hashlib.sha1(repr(vals).encode("utf-8", "replace")).digest()
