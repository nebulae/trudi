"""Cobalt Strike beacon configuration extractor (pure Python, no third-party parser).

The beacon's settings table is a sequence of TLV entries embedded in the beacon
DLL's .data section:

    id (u16 BE) | type (u16 BE: 1=short, 2=int, 3=blob) | length (u16 BE) | value

terminated by an all-zero entry, and XOR-encoded with a single byte (0x69 in CS
3.x, 0x2e in CS 4.x). The first three entries are always BeaconType (short),
Port (short), SleepTime (int), so the encoded table starts with a fixed shape:

    k, 1^k, k, 1^k, k, 2^k, v, v, k, 2^k, k, 1^k, k, 2^k, v, v, k, 3^k, k, 2^k, k, 4^k

That shape is key-independent up to the XOR, so one regex pre-filter
(`b0 b1 b0 b1 b0`) plus an arithmetic check finds the table under ANY single-byte
key; the known keys fall out of the same scan. A big input (a raw memory image)
is read in chunks with an overlap larger than the table, bounded by wall clock.
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
import time

KNOWN_KEYS = {0x2E: "4.x", 0x69: "3.x", 0x00: "unencoded"}

CHUNK_SIZE = 64 * 1024 * 1024
MAX_CONFIG = 8192          # CS 3.x tables are 4 KiB, 4.x 6 KiB; overlap covers both
MAX_MATCHES = 50

# Pre-filter: b0 b1 b0 b1 b0 with b1 != b0 (zero runs never match), 6th byte
# neither b0 nor b1 (it is b0^2). The XOR relations are checked in Python.
_PREFILTER = re.compile(rb"(?=(.)(?!\1)(.)\1\2\1(?!\1|\2))", re.S)

T_SHORT, T_INT, T_BLOB = 1, 2, 3

SETTINGS = {
    1: "BeaconType", 2: "Port", 3: "SleepTime", 4: "MaxGetSize", 5: "Jitter",
    6: "MaxDNS", 7: "PublicKey", 8: "C2Server", 9: "UserAgent", 10: "HttpPostUri",
    11: "Malleable_C2_Instructions", 12: "HttpGet_Metadata", 13: "HttpPost_Metadata",
    14: "SpawnTo", 15: "PipeName", 19: "DNS_Idle", 20: "DNS_Sleep",
    21: "SSH_Host", 22: "SSH_Port", 23: "SSH_Username", 24: "SSH_Password_Plaintext",
    25: "SSH_Password_Pubkey", 26: "HttpGet_Verb", 27: "HttpPost_Verb",
    28: "HttpPostChunk", 29: "Spawnto_x86", 30: "Spawnto_x64", 31: "CryptoScheme",
    32: "Proxy_Config", 33: "Proxy_User", 34: "Proxy_Password", 35: "Proxy_Behavior",
    36: "Watermark_Hash", 37: "Watermark", 38: "bStageCleanup", 39: "bCFGCaution",
    40: "KillDate", 41: "TextSectionEnd", 42: "ObfuscateSectionsInfo",
    43: "ProcInject_StartRWX", 44: "ProcInject_UseRWX", 45: "ProcInject_MinAllocSize",
    46: "ProcInject_PrependAppend_x86", 47: "ProcInject_PrependAppend_x64",
    49: "BindHost", 50: "bUsesCookies", 51: "ProcInject_Execute",
    52: "ProcInject_AllocationMethod", 53: "ProcInject_Stub", 54: "HostHeader",
    55: "ExitFunk", 56: "SSH_Banner", 57: "SMB_FrameHeader", 58: "TCP_FrameHeader",
    59: "Headers_Remove", 60: "DNS_Beacon_Beacon", 61: "DNS_Beacon_Get_A",
    62: "DNS_Beacon_Get_AAAA", 63: "DNS_Beacon_Get_TXT", 64: "DNS_Beacon_Put_Metadata",
    65: "DNS_Beacon_Put_Output", 66: "DNS_Resolver", 67: "DNS_Strategy",
    68: "DNS_Strategy_Rotate_Seconds", 69: "DNS_Strategy_Fail_X",
    70: "DNS_Strategy_Fail_Seconds", 71: "Retry_Max_Attempts",
    72: "Retry_Increase_Attempts", 73: "Retry_Duration",
}

BEACON_TYPES = {0: "HTTP", 1: "Hybrid HTTP DNS", 2: "SMB", 4: "TCP", 8: "HTTPS",
                16: "Bind TCP"}
PROXY_BEHAVIOR = {1: "direct connection", 2: "IE settings", 4: "proxy server"}
ALLOC_METHOD = {0: "VirtualAllocEx", 1: "NtMapViewOfSection"}
CRYPTO_SCHEME = {0: "default (AES/RSA)", 1: "no encryption (trial)"}
EXIT_FUNK = {0: "ExitProcess", 1: "ExitThread"}
BOOL_IDS = {38, 39, 43, 44, 50}

_STRING_IDS = {8, 9, 10, 15, 21, 23, 24, 25, 26, 27, 29, 30, 32, 33, 34, 49, 54,
               56, 60, 61, 62, 63, 64, 65, 66}

# HttpGet/HttpPost metadata transform steps; ops with a length-prefixed string arg.
_TSTEPS = {1: "append", 2: "prepend", 3: "base64", 4: "print", 5: "parameter",
           6: "header", 7: "build", 8: "netbios", 9: "const_parameter",
           10: "const_header", 11: "netbiosu", 12: "uri_append", 13: "base64url",
           14: "strrep", 15: "mask", 16: "const_host_header"}
_TSTEP_STR_ARG = {1, 2, 5, 6, 9, 10, 16}
# Malleable_C2_Instructions (response recovery): ops 1/2 carry an int arg.
_RECOVER = {1: "remove {} bytes from end", 2: "remove {} bytes from beginning",
            3: "base64 decode", 4: "print (end)", 8: "netbios decode 'a'", 11: "netbios decode 'A'",
            13: "base64url decode", 15: "xor mask w/ random key"}
_EXECUTE = {1: "CreateThread", 2: "SetThreadContext", 3: "CreateRemoteThread",
            4: "RtlCreateUserThread", 5: "NtQueueApcThread", 6: "CreateThread (module+func)",
            7: "NtQueueApcThread-s", 8: "CreateRemoteThread (module+func)"}


def _hexrest(blob: bytes, i: int) -> str:
    return blob[i:].rstrip(b"\x00").hex()


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _key_ok(buf, o: int) -> int | None:
    """XOR key if the 22-byte table head at `o` has the BeaconType/Port/SleepTime
    shape under a single-byte key, else None."""
    if o + 22 > len(buf):
        return None
    k = buf[o]
    want = ((0, 0), (1, 1), (2, 0), (3, 1), (4, 0), (5, 2),
            (8, 0), (9, 2), (10, 0), (11, 1), (12, 0), (13, 2),
            (16, 0), (17, 3), (18, 0), (19, 2), (20, 0), (21, 4))
    for pos, v in want:
        if buf[o + pos] != (v ^ k):
            return None
    return k


def _parse_table(buf, o: int, k: int) -> list[tuple[int, int, bytes]] | None:
    """Decode TLV entries from offset o with key k. None if not a valid table."""
    raw = bytes(b ^ k for b in buf[o:o + MAX_CONFIG])
    entries, i = [], 0
    while i + 6 <= len(raw):
        sid, typ, ln = struct.unpack_from(">HHH", raw, i)
        if sid == 0:
            break
        if not (1 <= sid <= 128) or typ not in (1, 2, 3):
            break
        if (typ == T_SHORT and ln != 2) or (typ == T_INT and ln != 4):
            break
        if i + 6 + ln > len(raw):
            break
        entries.append((sid, typ, raw[i + 6:i + 6 + ln]))
        i += 6 + ln
    if len(entries) < 3 or [e[0] for e in entries[:3]] != [1, 2, 3]:
        return None
    return entries


def _transform(blob: bytes) -> list[str]:
    out, i = [], 0
    try:
        while i + 4 <= len(blob):
            op = struct.unpack_from(">I", blob, i)[0]
            i += 4
            if op == 0:
                break
            name = _TSTEPS.get(op)
            if name is None:
                out.append(f"<unknown op {op}; rest hex {_hexrest(blob, i - 4)}>")
                break
            if op in _TSTEP_STR_ARG:
                ln = struct.unpack_from(">I", blob, i)[0]
                i += 4
                if ln > len(blob) - i:
                    out.append(f"{name} <bad length {ln}>")
                    break
                out.append(f'{name} "{blob[i:i + ln].decode("utf-8", "replace")}"')
                i += ln
            elif op == 7:
                arg = struct.unpack_from(">I", blob, i)[0]
                i += 4
                out.append(f"build {({0: 'metadata/sessionid', 1: 'output'}).get(arg, arg)}")
            else:
                out.append(name)
    except struct.error:
        out.append("<truncated>")
    return out


def _recover(blob: bytes) -> list[str]:
    out, i = [], 0
    try:
        while i + 4 <= len(blob):
            op = struct.unpack_from(">I", blob, i)[0]
            i += 4
            if op == 0:
                break
            tmpl = _RECOVER.get(op)
            if tmpl is None:
                out.append(f"<unknown op {op}; rest hex {_hexrest(blob, i - 4)}>")
                break
            if "{}" in tmpl:
                out.append(tmpl.format(struct.unpack_from(">I", blob, i)[0]))
                i += 4
            else:
                out.append(tmpl)
    except struct.error:
        out.append("<truncated>")
    return out


def _execute(blob: bytes) -> list[str]:
    out = []
    for n, b in enumerate(blob):
        if b == 0:
            break
        out.append(_EXECUTE.get(b, f"op {b}"))
        if b in (6, 8):      # module/function args follow — stop decoding, keep hex
            out.append(f"<args hex {_hexrest(blob, n + 1)}>")
            break
    return out


def _pubkey(blob: bytes) -> dict:
    der = blob
    # DER SEQUENCE 30 81 LL / 30 82 LLLL — trim the zero padding by its own length.
    if len(blob) > 3 and blob[0] == 0x30:
        if blob[1] == 0x81:
            der = blob[:3 + blob[2]]
        elif blob[1] == 0x82 and len(blob) > 4:
            der = blob[:4 + struct.unpack_from(">H", blob, 2)[0]]
        elif blob[1] < 0x80:
            der = blob[:2 + blob[1]]
    return {"der_length": len(der), "blob_length": len(blob),
            "sha256": hashlib.sha256(der).hexdigest(),
            "der_hex_prefix": der[:32].hex()}


def decode_value(sid: int, typ: int, val: bytes):
    if typ == T_SHORT:
        n = struct.unpack(">H", val)[0]
        if sid == 1:
            return {"value": n, "meaning": BEACON_TYPES.get(n, f"unknown ({n})")}
        if sid == 35:
            return {"value": n, "meaning": PROXY_BEHAVIOR.get(n, f"unknown ({n})")}
        if sid == 52:
            return {"value": n, "meaning": ALLOC_METHOD.get(n, f"unknown ({n})")}
        if sid == 31:
            return {"value": n, "meaning": CRYPTO_SCHEME.get(n, f"unknown ({n})")}
        if sid == 55:
            return {"value": n, "meaning": EXIT_FUNK.get(n, f"unknown ({n})")}
        if sid in BOOL_IDS:
            return bool(n)
        return n
    if typ == T_INT:
        n = struct.unpack(">I", val)[0]
        if sid == 19:
            return ".".join(str(b) for b in val)
        if sid == 1:
            return {"value": n, "meaning": BEACON_TYPES.get(n, f"unknown ({n})")}
        if sid in BOOL_IDS:
            return bool(n)
        return n
    # blob
    if sid == 7:
        return _pubkey(val)
    if sid == 11:
        return _recover(val)
    if sid in (12, 13):
        return _transform(val)
    if sid == 51:
        return _execute(val)
    if sid in _STRING_IDS:
        return _cstr(val)
    if sid in (46, 47):
        # length-prefixed prepend (u32 len + bytes) then append (u32 len + bytes)
        try:
            ln = struct.unpack_from(">I", val, 0)[0]
            pre = val[4:4 + ln]
            ln2 = struct.unpack_from(">I", val, 4 + ln)[0]
            app = val[8 + ln:8 + ln + ln2]
            return {"prepend_hex": pre.hex(), "append_hex": app.hex()}
        except struct.error:
            pass
    stripped = val.rstrip(b"\x00")
    if not stripped:
        return ""
    return {"hex": stripped[:512].hex(), "length": len(val)}


def decode_config(entries) -> dict:
    settings = {}
    for sid, typ, val in entries:
        name = SETTINGS.get(sid, f"unknown_{sid}")
        try:
            settings[name] = decode_value(sid, typ, val)
        except Exception:     # a malformed value never loses the table
            settings[name] = {"hex": val[:512].hex(), "length": len(val)}
        if name.startswith("unknown_"):
            settings[name] = {"id": sid, "type": typ, "value": settings[name]}
    return settings


def _version_guess(key: int, entries) -> str:
    ids = {e[0] for e in entries}
    if key == 0x2E:
        return "4.x"
    if key == 0x69:
        return "3.x"
    if ids & set(range(38, 74)):
        return "4.x (settings ids >= 38 present)"
    return "unknown"


def summarize(settings: dict) -> dict:
    """The fields an analyst asks for first."""
    def g(name):
        v = settings.get(name)
        return v.get("meaning") if isinstance(v, dict) and "meaning" in v else v
    pk = settings.get("PublicKey")
    return {
        "beacon_type": g("BeaconType"), "port": g("Port"),
        "sleep_ms": g("SleepTime"), "jitter_pct": g("Jitter"),
        "c2_server": g("C2Server"), "user_agent": g("UserAgent"),
        "http_post_uri": g("HttpPostUri"), "http_get_verb": g("HttpGet_Verb"),
        "http_post_verb": g("HttpPost_Verb"), "watermark": g("Watermark"),
        "spawnto_x86": g("Spawnto_x86"), "spawnto_x64": g("Spawnto_x64"),
        "pipe_name": g("PipeName"), "host_header": g("HostHeader"),
        "kill_date": g("KillDate"), "crypto_scheme": g("CryptoScheme"),
        "public_key_sha256": pk.get("sha256") if isinstance(pk, dict) else None,
    }




# ── Runtime (decoded) settings table ─────────────────────────────────────────
# Once running, a beacon parses the TLV block into a heap array indexed by
# setting id: {u16 type, pad, value} — 16 bytes on x64, 8 on x86, little-endian;
# shorts/ints are inline, blobs/strings are POINTERS into the process heap. The
# encoded block is usually gone from a live beacon's memory, so this array is
# what a process dump or raw image actually holds.
_RT64 = re.compile(rb"\x01\x00{7}..\x00{6}\x01\x00{7}..\x00{6}\x02\x00{7}....\x00{4}", re.S)
_RT86 = re.compile(rb"\x01\x00\x00\x00..\x00\x00\x01\x00\x00\x00..\x00\x00\x02\x00\x00\x00....", re.S)
_RT_MAX_ID = 128
_READ_LEN = {7: 256, 11: 4096, 12: 4096, 13: 4096, 14: 16, 46: 512, 47: 512, 51: 256}


def _parse_runtime(buf, o: int, arch: str) -> list[tuple[int, int, int]] | None:
    """Entries (id, type, raw value) of a runtime table whose entry 1 is at o."""
    size = 16 if arch == "x64" else 8
    ptr_max = (1 << 47) if arch == "x64" else (1 << 31)
    entries = []
    for sid in range(1, _RT_MAX_ID + 1):
        off = o + (sid - 1) * size
        if off + size > len(buf):
            break
        typ = struct.unpack_from("<H", buf, off)[0]
        pad = buf[off + 2:off + (8 if arch == "x64" else 4)]
        if any(pad) or typ > 3:
            break
        val = struct.unpack_from("<Q" if arch == "x64" else "<I", buf,
                                 off + (8 if arch == "x64" else 4))[0]
        if typ == 0:
            continue
        if (typ == T_SHORT and val > 0xFFFF) or (typ == T_INT and val > 0xFFFFFFFF) \
                or (typ == T_BLOB and not 0x10000 <= val < ptr_max):
            break
        entries.append((sid, typ, val))
    ids = {e[0]: e[1] for e in entries}
    if [e[0] for e in entries[:3]] != [1, 2, 3] or ids.get(7) != T_BLOB or len(entries) < 8:
        return None
    return entries


class _Resolver:
    """Virtual address -> bytes, over (va_start, va_end, file, file_offset) segments."""

    def __init__(self, segs):
        self.segs = sorted(segs)
        self.starts = [s[0] for s in self.segs]

    def read(self, va: int, n: int) -> bytes | None:
        import bisect
        out = b""
        while n > 0:
            i = bisect.bisect_right(self.starts, va) - 1
            if i < 0 or va >= self.segs[i][1]:
                break
            start, end, path, foff = self.segs[i]
            k = min(n, end - va)
            try:
                with open(path, "rb") as fh:
                    fh.seek(foff + (va - start))
                    chunk = fh.read(k)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            va += len(chunk)
            n -= len(chunk)
            if len(chunk) < k:
                break
        return out or None


_VAD_NAME = re.compile(r"pid\.(\d+)\.vad\.0x([0-9a-fA-F]+)-0x([0-9a-fA-F]+)\.dmp$")
_MM_FIELD = {k: re.compile(r'"' + k + r'"\s*:\s*(\d+)')
             for k in ("Offset in File", "Physical", "Size", "Virtual")}
_MM_FILE = re.compile(r'"File output"\s*:\s*"([^"]*)"')


def load_memmap_listing(path: str) -> list[tuple[int, int, int, int, str]]:
    """(virtual, size, physical, offset_in_file, file_output) rows from a
    Volatility 3 windows.memmap `-r json` listing. Lenient: a truncated listing
    (e.g. a capped stdout sidecar) yields every complete row it holds."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    rows = []
    for m in re.finditer(r"\{[^{}]*\}", text):
        b = m.group()
        f = {k: rx.search(b) for k, rx in _MM_FIELD.items()}
        if not all(f.values()):
            continue
        fo = _MM_FILE.search(b)
        rows.append((int(f["Virtual"].group(1)), int(f["Size"].group(1)),
                     int(f["Physical"].group(1)), int(f["Offset in File"].group(1)),
                     fo.group(1) if fo else ""))
    return rows


def _resolver_for(path: str, memmap_rows) -> tuple[_Resolver | None, callable, str]:
    """Resolver for pointers of a table found in `path`, plus a function mapping
    a file offset to the table's virtual address (None when unknown)."""
    m = _VAD_NAME.search(os.path.basename(path))
    if m:
        pid, base = m.group(1), int(m.group(2), 16)
        d = os.path.dirname(path) or "."
        segs = []
        for n in os.listdir(d):
            mm = _VAD_NAME.search(n)
            if mm and mm.group(1) == pid:
                segs.append((int(mm.group(2), 16), int(mm.group(3), 16) + 1,
                             os.path.join(d, n), 0))
        return _Resolver(segs), (lambda off: base + off), f"sibling VAD dumps of pid {pid}"
    if memmap_rows:
        name = os.path.basename(path)
        by_file = any(r[4] == name for r in memmap_rows)
        rows = [r for r in memmap_rows if r[4] == name] if by_file else memmap_rows
        segs = [(v, v + s, path, fo if by_file else ph) for v, s, ph, fo, _f in rows]
        keyed = sorted((fo if by_file else ph, v, s) for v, s, ph, fo, _f in rows)
        keys = [k[0] for k in keyed]

        def to_va(off):
            import bisect
            i = bisect.bisect_right(keys, off) - 1
            if i >= 0 and off < keyed[i][0] + keyed[i][2]:
                return keyed[i][1] + (off - keyed[i][0])
            return None
        mode = "memmap listing (offset in file)" if by_file else "memmap listing (physical)"
        return _Resolver(segs), to_va, mode
    return None, (lambda off: None), "none"


def _decode_runtime(entries, resolver, table_va) -> tuple[dict, int, int]:
    settings, ok, bad = {}, 0, 0
    for sid, typ, val in entries:
        name = SETTINGS.get(sid, f"unknown_{sid}")
        if typ == T_SHORT:
            v = decode_value(sid, typ, struct.pack(">H", val))
        elif typ == T_INT:
            v = decode_value(sid, typ, struct.pack(">I", val))
        else:
            data = resolver.read(val, _READ_LEN.get(sid, 4096 if sid in _STRING_IDS else 64)) \
                if (resolver and table_va is not None) else None
            if data is None:
                bad += 1
                v = {"pointer": f"0x{val:x}", "resolved": False}
            else:
                ok += 1
                try:
                    v = decode_value(sid, typ, data)
                except Exception:
                    v = {"hex": data[:512].hex()}
                if sid not in _STRING_IDS and sid not in _READ_LEN and isinstance(v, dict):
                    v["note"] = "runtime blob length unknown; first 64 bytes"
                if isinstance(v, dict):
                    v.setdefault("pointer", f"0x{val:x}")
        if name.startswith("unknown_"):
            v = {"id": sid, "type": typ, "value": v}
        settings[name] = v
    return settings, ok, bad


def _scan_buffer(buf, base: int, limit: int, found: list):
    """Find tables starting before `limit` in buf; append match dicts."""
    for m in _PREFILTER.finditer(buf):
        o = m.start()
        if o >= limit or len(found) >= MAX_MATCHES:
            break
        k = _key_ok(buf, o)
        if k is None:
            continue
        entries = _parse_table(buf, o, k)
        if entries is None:
            continue
        found.append({"form": "encoded_tlv", "offset": base + o, "xor_key": f"0x{k:02x}",
                      "entries": entries, "version_guess": _version_guess(k, entries)})
    for arch, rx in (("x64", _RT64), ("x86", _RT86)):
        for m in rx.finditer(buf):
            o = m.start()
            if o >= limit or len(found) >= MAX_MATCHES:
                break
            entries = _parse_runtime(buf, o, arch)
            if entries is None:
                continue
            size = 16 if arch == "x64" else 8
            found.append({"form": f"runtime_table_{arch}", "offset": base + o - size,
                          "entry1_offset": base + o, "xor_key": None, "entries": entries,
                          "version_guess": _version_guess(-1, entries)})


def scan_file(path: str, *, chunk_size: int = CHUNK_SIZE, deadline: float | None = None,
              ) -> dict:
    """Scan one file in overlapping chunks. Returns matches + bytes scanned."""
    found: list = []
    size = os.path.getsize(path)
    scanned = 0
    timed_out = False
    overlap = MAX_CONFIG
    with open(path, "rb") as fh:
        pos = 0
        while pos < size:
            if deadline is not None and time.monotonic() > deadline:
                timed_out = True
                break
            fh.seek(pos)
            buf = fh.read(chunk_size + overlap)
            if not buf:
                break
            last = pos + chunk_size >= size
            _scan_buffer(buf, pos, len(buf) if last else chunk_size, found)
            scanned = min(size, pos + chunk_size)
            if len(found) >= MAX_MATCHES:
                break
            pos += chunk_size
    for f in found:
        f["file"] = path
    return {"matches": found, "bytes_scanned": scanned, "size": size,
            "timed_out": timed_out}


def _list_files(path: str) -> list[str]:
    files = []
    for root, _d, names in os.walk(path):
        for n in names:
            p = os.path.join(root, n)
            if os.path.isfile(p) and not os.path.islink(p):
                files.append(p)
    return sorted(files)


def extract(path: str, *, memmap_listing: str = "", chunk_size: int = CHUNK_SIZE,
            max_seconds: int = 600) -> dict:
    """Scan a file or a directory tree for beacon configs (encoded TLV block
    under any single-byte XOR key, and the runtime settings table). Identical
    configs are grouped so N copies in memory do not read as N beacons."""
    import json
    t0 = time.monotonic()
    deadline = t0 + max(1, int(max_seconds))
    if os.path.isdir(path):
        files = _list_files(path)
    elif os.path.isfile(path):
        files = [path]
    else:
        return {"success": False, "error": f"not a file or directory: {path}"}
    memmap_rows = []
    if memmap_listing:
        try:
            memmap_rows = load_memmap_listing(memmap_listing)
        except OSError as e:
            return {"success": False, "error": f"memmap_listing unreadable: {e}"}

    matches, scanned_files, total_bytes, timed_out, errors = [], [], 0, False, []
    for p in files:
        if time.monotonic() > deadline:
            timed_out = True
            break
        try:
            r = scan_file(p, chunk_size=chunk_size, deadline=deadline)
        except OSError as e:
            errors.append(f"{p}: {e}")
            continue
        scanned_files.append(p)
        total_bytes += r["bytes_scanned"]
        matches.extend(r["matches"])
        if r["timed_out"]:
            timed_out = True
            break
        if len(matches) >= MAX_MATCHES:
            break

    decoded, configs, resolvers = [], {}, {}
    for m in matches[:MAX_MATCHES]:
        rec = {"file": m["file"], "form": m["form"], "offset": m["offset"],
               "offset_hex": f"0x{m['offset']:x}", "xor_key": m["xor_key"],
               "version_guess": m["version_guess"], "setting_count": len(m["entries"])}
        if m["form"] == "encoded_tlv":
            settings = decode_config(m["entries"])
        else:
            if m["file"] not in resolvers:
                resolvers[m["file"]] = _resolver_for(m["file"], memmap_rows)
            res, to_va, mode = resolvers[m["file"]]
            table_va = to_va(m["offset"])
            settings, ok, bad = _decode_runtime(m["entries"], res, table_va)
            rec.update({"table_va": f"0x{table_va:x}" if table_va is not None else None,
                        "pointer_resolution": mode if table_va is not None else
                        ("table not inside the listed process" if res else "none"),
                        "pointers_resolved": ok, "pointers_unresolved": bad})
            if bad and table_va is None:
                rec["hint"] = ("blob/string settings are heap pointers: pass the vol "
                               "windows.memmap -r json listing of the owning process "
                               "(memmap_listing=) or scan its vadinfo --dump files")
        digest = hashlib.sha256(json.dumps(settings, sort_keys=True, default=str)
                                .encode()).hexdigest()[:16]
        rec.update({"config_id": digest, "summary": summarize(settings), "settings": settings})
        decoded.append(rec)
        configs.setdefault(digest, []).append(f"{m['file']}@0x{m['offset']:x}")
    return {
        "success": True, "found": bool(decoded), "matches": decoded,
        "distinct_configs": len(configs), "config_locations": configs,
        "files_scanned": len(scanned_files), "files_total": len(files),
        "bytes_scanned": total_bytes, "timed_out": timed_out,
        "match_cap_hit": len(matches) >= MAX_MATCHES,
        "searched_for": ("encoded TLV block under all 256 single-byte XOR keys "
                         "(0x2e=CS4, 0x69=CS3, 0x00=plain); runtime settings table "
                         "(x64 16-byte / x86 8-byte entries)"),
        "memmap_rows": len(memmap_rows),
        "elapsed_seconds": round(time.monotonic() - t0, 2),
        "errors": errors,
        "scanned_file_list": scanned_files[:500],
    }
