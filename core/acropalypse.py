"""Acropalypse detection and recovery (CVE-2023-21036 Pixel Markup,
CVE-2023-28303 Windows Snipping Tool / Snip & Sketch).

The vulnerable editors overwrote a screenshot in place with the cropped PNG
without truncating the file, so everything past the cropped image's IEND is
the TAIL of the original, larger PNG: the rest of its zlib-compressed IDAT
stream (split into IDAT chunks) and its own IEND.

Recovery (after David Buchanan's method): collect the trailing IDAT data, find
a bit offset where a non-final dynamic-Huffman deflate block starts, and
inflate from there behind a 32 KiB stored block of placeholder bytes, which
stands in for the lost sliding window (back-references into it come out as
placeholder bytes). The inflated bytes are the END of the original image's
filtered scanlines, so the original width is the one whose row stride
(width*bpp + 1 filter byte), stepped back from the end, lands on filter bytes
(0..4) almost every time. Those bottom rows are written out as a new PNG; the
top of the original (overwritten by the crop) is unrecoverable and filled.

JPEG: detection only — bytes after the EOI that closes the image.
"""
from __future__ import annotations

import os
import re
import struct
import time
import zlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"
PLACEHOLDER = 0x58               # 'X' — a byte recovered from the lost window
WINDOW = 0x8000
_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
_FILTER_BYTES = bytes(range(5))
_PLACEHOLDER_B = bytes([PLACEHOLDER])
MAX_WIDTH = 8192
IMAGE_EXT = (".png", ".jpg", ".jpeg")


def _chunk(ctype: bytes, body: bytes) -> bytes:
    return (struct.pack(">I", len(body)) + ctype + body
            + struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF))


def parse_png(data: bytes) -> dict:
    """Walk the chunks up to the first IEND. {ok, ihdr, iend_end, chunks}"""
    if not data.startswith(PNG_SIG):
        return {"ok": False, "error": "not a PNG"}
    off, ihdr, chunks = 8, None, []
    while off + 12 <= len(data):
        ln = struct.unpack(">I", data[off:off + 4])[0]
        ctype = data[off + 4:off + 8]
        if off + 12 + ln > len(data):
            return {"ok": False, "error": f"chunk {ctype!r} runs past EOF", "ihdr": ihdr}
        body = data[off + 8:off + 8 + ln]
        chunks.append((ctype, body))
        if ctype == b"IHDR" and ln >= 13:
            w, h, bd, ct, _cm, _fm, il = struct.unpack(">IIBBBBB", body[:13])
            ihdr = {"width": w, "height": h, "bit_depth": bd, "color_type": ct, "interlace": il}
        off += 12 + ln
        if ctype == b"IEND":
            return {"ok": True, "ihdr": ihdr, "iend_end": off, "chunks": chunks}
    return {"ok": False, "error": "no IEND chunk", "ihdr": ihdr}


def jpeg_end(data: bytes) -> int | None:
    """Offset just past the EOI that closes the image (marker walk: segments,
    then entropy-coded data after each SOS), or None when unparseable."""
    if not data.startswith(b"\xff\xd8"):
        return None
    off, n = 2, len(data)
    while off + 4 <= n:
        if data[off] != 0xFF:
            return None
        m = data[off + 1]
        if m == 0xFF:
            off += 1
            continue
        if m == 0xD9:
            return off + 2
        if m == 0x01 or 0xD0 <= m <= 0xD7:
            off += 2
            continue
        seg = struct.unpack(">H", data[off + 2:off + 4])[0]
        off += 2 + seg
        if m == 0xDA:                  # entropy-coded scan: next non-stuffed, non-RST marker
            while True:
                i = data.find(b"\xff", off)
                if i < 0 or i + 1 >= n:
                    return None
                nb = data[i + 1]
                if nb == 0x00 or 0xD0 <= nb <= 0xD7 or nb == 0xFF:
                    off = i + (1 if nb == 0xFF else 2)
                    continue
                off = i
                break
    return None


def trailing_idat(trailer: bytes) -> tuple[bytes, int]:
    """(deflate bytes, intact IDAT chunks) from the tail. The bytes before the
    first intact chunk are the rest of the chunk the crop cut through, minus
    its 4-byte CRC; with no intact chunk the whole tail (minus a closing IEND
    chunk and that CRC) is used."""
    first = None
    for m in re.finditer(b"IDAT", trailer):
        i = m.start()
        if i < 4:
            continue
        ln = struct.unpack(">I", trailer[i - 4:i])[0]
        if i + 8 + ln > len(trailer):
            continue
        if zlib.crc32(trailer[i:i + 4 + ln]) & 0xFFFFFFFF == struct.unpack(
                ">I", trailer[i + 4 + ln:i + 8 + ln])[0]:
            first = i - 4
            break
    if first is None:
        body = trailer
        if body[-8:-4] == b"IEND":
            body = body[:-12]
        return body[:-4] if len(body) > 4 else body, 0
    out, off, n = bytearray(trailer[:max(0, first - 4)]), first, 0
    while off + 12 <= len(trailer):
        ln = struct.unpack(">I", trailer[off:off + 4])[0]
        if trailer[off + 4:off + 8] != b"IDAT" or off + 12 + ln > len(trailer):
            break
        out += trailer[off + 8:off + 8 + ln]
        off += 12 + ln
        n += 1
    return bytes(out), n


def inflate_tail(idat: bytes, max_seconds: float = 60.0) -> dict:
    """Find the first bit offset where a non-final dynamic block inflates to the
    end of the stream behind a placeholder window."""
    if len(idat) < 16:
        return {"ok": False, "error": "too little trailing IDAT data"}
    big = int.from_bytes(idat, "little")
    shifted = [(big >> k).to_bytes(len(idat), "little") for k in range(8)]
    prefix = (b"\x00" + WINDOW.to_bytes(2, "little") + (WINDOW ^ 0xFFFF).to_bytes(2, "little")
              + bytes([PLACEHOLDER]) * WINDOW)
    t0 = time.time()
    for bit in range(len(idat) * 8 - 64):
        cand = shifted[bit % 8]
        start = bit // 8
        if cand[start] & 7 != 0b100:           # BFINAL=0, BTYPE=10 (dynamic)
            continue
        if time.time() - t0 > max_seconds:
            return {"ok": False, "error": f"no deflate block start found in {max_seconds}s",
                    "timed_out": True}
        d = zlib.decompressobj(-15)
        try:
            d.decompress(prefix + cand[start:start + 4096], WINDOW + 65536)
        except zlib.error:
            continue
        d = zlib.decompressobj(-15)
        try:
            out = d.decompress(prefix + cand[start:]) + d.flush()
        except zlib.error:
            continue
        if d.eof and len(d.unused_data) <= 16 and len(out) > WINDOW:
            return {"ok": True, "bit_offset": bit, "raw": out[WINDOW:],
                    "placeholder_bytes": out[WINDOW:WINDOW * 2].count(PLACEHOLDER)}
    return {"ok": False, "error": "no deflate block start inflates to the end of the stream"}


def infer_width(raw: bytes, bpp: int, min_width: int = 1, max_width: int = MAX_WIDTH) -> dict:
    """Width whose row stride lands on filter bytes (0..4) from the end back.
    Any multiple-row stride would score as well, so the smallest high scorer
    wins."""
    scores = []
    for w in range(max(1, min_width), max_width + 1):
        stride = w * bpp + 1
        rows = len(raw) // stride
        if rows < 4:
            break
        # placeholder bytes (copied out of the lost window) say nothing
        starts = raw[len(raw) - stride::-stride][:4096].translate(None, _PLACEHOLDER_B)
        if len(starts) < 4:
            continue
        hits = len(starts) - len(starts.translate(None, _FILTER_BYTES))
        scores.append((hits / len(starts), w, len(starts)))
    if not scores:
        return {"ok": False, "error": "too little data for any width"}
    # rank by the Wilson lower bound: a width that fits a handful of rows by
    # chance, or a multiple-row stride (fewer samples), loses to the true one
    def lower(s):
        p, n, z = s[0], s[2], 2.0
        return (p + z * z / (2 * n) - z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5) / (1 + z * z / n)
    score, w, n = max(scores, key=lambda s: (lower(s), -s[1]))
    if score < 0.9 or n < 8:
        return {"ok": False, "error": f"no width fits the scanline filter bytes "
                                      f"(best {score:.2f} at width {w} over {n} rows)",
                "best_score": round(score, 3)}
    return {"ok": True, "width": w, "score": round(score, 3), "rows_sampled": n}


def build_png(raw: bytes, width: int, ihdr: dict, extra_chunks: list) -> tuple[bytes, int]:
    """PNG of the recovered bottom rows; the partial first row is filled."""
    bpp = _CHANNELS[ihdr["color_type"]] * ihdr["bit_depth"] // 8
    stride = width * bpp + 1
    height = -(-len(raw) // stride)
    fill = bytes([0x00]) + (b"\xff\x00\xff\xff"[:bpp] if ihdr["color_type"] in (2, 6)
                            and ihdr["bit_depth"] == 8 else b"\x00" * bpp) * width
    buf = bytearray(fill[:height * stride - len(raw)]) + raw   # pad < one row
    for r in range(height):                   # a placeholder filter byte -> None
        if buf[r * stride] > 4:
            buf[r * stride] = 0
    hdr = struct.pack(">IIBBBBB", width, height, ihdr["bit_depth"], ihdr["color_type"], 0, 0, 0)
    png = (PNG_SIG + _chunk(b"IHDR", hdr)
           + b"".join(_chunk(t, b) for t, b in extra_chunks)
           + _chunk(b"IDAT", zlib.compress(bytes(buf), 9)) + _chunk(b"IEND", b""))
    return png, height


def analyze_file(path: str, output_dir: str | None, max_seconds: float = 60.0) -> dict:
    rec = {"path": path, "format": "", "size": 0, "trailing_bytes": 0, "detected": False,
           "recovered": False, "recovered_width": "", "recovered_height": "",
           "cropped_width": "", "cropped_height": "", "output_path": "", "note": ""}
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        rec["note"] = f"unreadable: {e}"
        return rec
    rec["size"] = len(data)
    if data.startswith(PNG_SIG):
        rec["format"] = "png"
        p = parse_png(data)
        if not p.get("ok"):
            rec["note"] = p.get("error", "unparseable PNG")
            return rec
        ihdr = p["ihdr"] or {}
        rec["cropped_width"], rec["cropped_height"] = ihdr.get("width", ""), ihdr.get("height", "")
        trailer = data[p["iend_end"]:]
        rec["trailing_bytes"] = len(trailer)
        if not trailer:
            return rec
        has_idat = b"IDAT" in trailer
        rec["detected"] = has_idat or trailer.endswith(b"IEND\xaeB`\x82")
        if not rec["detected"]:
            rec["note"] = "trailing data after IEND, but no PNG stream remnant in it"
            return rec
        if ihdr.get("bit_depth") not in (8, 16) or ihdr.get("color_type") not in _CHANNELS \
                or ihdr.get("interlace"):
            rec["note"] = "detection only: recovery supports 8/16-bit non-interlaced PNGs"
            return rec
        _recover_png(rec, data, p, trailer, output_dir, max_seconds)
        return rec
    if data.startswith(b"\xff\xd8"):
        rec["format"] = "jpeg"
        end = jpeg_end(data)
        if end is None:
            rec["note"] = "unparseable JPEG marker stream"
            return rec
        tail = data[end:]
        rec["trailing_bytes"] = len(tail)
        if tail.strip(b"\x00"):
            has_jpeg = b"\xff\xd8\xff" in tail
            rec["detected"] = True
            rec["note"] = ("detection only (JPEG). Trailing data "
                           + ("holds another JPEG — may be a benign MPF/depth/preview "
                              "image or the uncropped original" if has_jpeg
                              else "after EOI — possible uncropped remainder"))
        return rec
    rec["note"] = "not a PNG/JPEG"
    return rec


def _recover_png(rec: dict, data: bytes, p: dict, trailer: bytes, output_dir, max_seconds):
    ihdr = p["ihdr"]
    bpp = _CHANNELS[ihdr["color_type"]] * ihdr["bit_depth"] // 8
    idat, nchunks = trailing_idat(trailer)
    inf = inflate_tail(idat, max_seconds)
    if not inf.get("ok"):
        rec["note"] = f"detected; recovery failed: {inf.get('error')}"
        return
    raw = inf["raw"]
    fit = infer_width(raw, bpp)
    if not fit.get("ok"):
        rec["note"] = (f"detected; inflated {len(raw)} bytes but "
                       f"width inference failed: {fit.get('error')}")
        return
    extra = [(t, b) for t, b in p["chunks"] if t in (b"PLTE", b"tRNS", b"gAMA", b"sRGB")]
    png, height = build_png(raw, fit["width"], ihdr, extra)
    rec.update(recovered=True, recovered_width=fit["width"], recovered_height=height)
    rec["note"] = (f"inflated {len(raw)} bytes from bit {inf['bit_offset']} of "
                   f"{len(idat)} trailing IDAT bytes ({nchunks} intact chunk(s)); width "
                   f"fit {fit['score']} over {fit['rows_sampled']} rows; bottom {height} "
                   "rows of the original (top is overwritten by the crop)")
    if output_dir:
        import hashlib
        base = os.path.splitext(os.path.basename(rec["path"]))[0]
        tag = hashlib.sha1(rec["path"].encode("utf-8", "replace")).hexdigest()[:8]
        out = os.path.join(output_dir, f"{base}_{tag}.recovered.png")
        os.makedirs(output_dir, exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(png)
        rec["output_path"] = out
        try:                                  # decode check: Pillow must render it
            from PIL import Image
            with Image.open(out) as im:
                im.load()
        except Exception as e:  # noqa: BLE001
            rec["note"] += f"; WARNING recovered PNG failed to decode: {e}"


def scan(path: str, output_dir: str | None, max_files: int = 5000,
         max_seconds: float = 900.0, per_file_seconds: float = 60.0,
         max_file_mb: int = 200) -> dict:
    t0 = time.time()
    if os.path.isdir(path):
        files = []
        for root, dirs, names in os.walk(path):
            dirs.sort()
            for n in sorted(names):
                if n.lower().endswith(IMAGE_EXT):
                    files.append(os.path.join(root, n))
    elif os.path.isfile(path):
        files = [path]
    else:
        return {"success": False, "error": f"not found: {path}"}
    results, skipped, truncated = [], 0, False
    for f in files:
        if len(results) >= max_files or time.time() - t0 > max_seconds:
            truncated = True
            break
        try:
            if os.path.getsize(f) > max_file_mb * 1024 * 1024:
                skipped += 1
                continue
        except OSError:
            skipped += 1
            continue
        results.append(analyze_file(f, output_dir, per_file_seconds))
    return {"success": True, "files_total": len(files), "files_scanned": len(results),
            "skipped_large_or_unreadable": skipped, "truncated": truncated,
            "detected": sum(r["detected"] for r in results),
            "recovered": sum(r["recovered"] for r in results),
            "results": results, "elapsed_seconds": round(time.time() - t0, 2)}
