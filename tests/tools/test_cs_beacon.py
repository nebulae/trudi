"""misc.cs_beacon_config — Cobalt Strike beacon config extraction (core/cs_beacon.py).

Configs are synthesised here: the documented TLV settings block (u16 id, u16
type, u16 length, value; XOR single byte) and the runtime settings table a live
beacon keeps on its heap (x64 16-byte entries, blob settings as pointers).
"""
import json
import random
import struct

import pytest

from core import cs_beacon as cs

UA = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0)"
PUBKEY = bytes.fromhex("30819f300d06092a864886f70d010101050003818d00308189028181") + bytes(range(134))


def _tlv(sid, typ, val: bytes) -> bytes:
    return struct.pack(">HHH", sid, typ, len(val)) + val


def _blob(s: str, n: int) -> bytes:
    b = s.encode()
    return b + b"\x00" * (n - len(b))


def _config(key: int) -> bytes:
    get_meta = (struct.pack(">I", 7) + struct.pack(">I", 0) + struct.pack(">I", 3)
                + struct.pack(">I", 6) + struct.pack(">I", 6) + b"Cookie" + b"\x00" * 4)
    raw = b"".join([
        _tlv(1, 1, struct.pack(">H", 0)),
        _tlv(2, 1, struct.pack(">H", 80)),
        _tlv(3, 2, struct.pack(">I", 60000)),
        _tlv(4, 2, struct.pack(">I", 1048576)),
        _tlv(5, 1, struct.pack(">H", 20)),
        _tlv(7, 3, PUBKEY + b"\x00" * (256 - len(PUBKEY))),
        _tlv(8, 3, _blob("192.0.2.57,/pixel.gif", 256)),
        _tlv(9, 3, _blob(UA, 128)),
        _tlv(10, 3, _blob("/submit.php", 64)),
        _tlv(12, 3, get_meta),
        _tlv(26, 3, _blob("GET", 16)),
        _tlv(29, 3, _blob("%windir%\\syswow64\\rundll32.exe", 64)),
        _tlv(30, 3, _blob("%windir%\\sysnative\\rundll32.exe", 64)),
        _tlv(37, 2, struct.pack(">I", 305419896)),
        _tlv(99, 1, struct.pack(">H", 7)),
        b"\x00" * 6,
    ])
    return bytes(b ^ key for b in raw)


def _noise(n, seed=1):
    return random.Random(seed).randbytes(n)


def _tool(fn):
    return getattr(fn, "fn", fn)


@pytest.mark.parametrize("key,ver", [(0x2E, "4.x"), (0x69, "3.x"), (0x5A, "unknown")])
def test_decodes_known_and_fallback_keys(tmp_path, key, ver):
    f = tmp_path / "carved.bin"
    f.write_bytes(_noise(5000) + _config(key) + _noise(3000, 2))
    r = cs.extract(str(f))
    assert r["success"] and r["found"] and len(r["matches"]) == 1
    m = r["matches"][0]
    assert m["form"] == "encoded_tlv" and m["xor_key"] == f"0x{key:02x}" and m["offset"] == 5000
    assert m["version_guess"] == ver
    s = m["summary"]
    assert (s["beacon_type"], s["port"], s["sleep_ms"], s["jitter_pct"]) == ("HTTP", 80, 60000, 20)
    assert s["c2_server"] == "192.0.2.57,/pixel.gif" and s["user_agent"] == UA
    assert s["http_post_uri"] == "/submit.php" and s["watermark"] == 305419896
    assert s["spawnto_x64"] == "%windir%\\sysnative\\rundll32.exe"
    import hashlib
    assert s["public_key_sha256"] == hashlib.sha256(PUBKEY[:162]).hexdigest()
    assert m["settings"]["HttpGet_Metadata"] == ["build metadata/sessionid", "base64", 'header "Cookie"']
    assert m["settings"]["unknown_99"] == {"id": 99, "type": 1, "value": 7}


def test_directory_input_and_grouping(tmp_path):
    d = tmp_path / "malfind"
    (d / "sub").mkdir(parents=True)
    (d / "pid.1.vad.0x1000-0x1fff.dmp").write_bytes(_noise(4096))
    (d / "pid.2.vad.0x1000-0x2fff.dmp").write_bytes(_noise(100) + _config(0x2E) + _noise(100, 3))
    (d / "sub" / "copy.bin").write_bytes(_config(0x2E))
    r = cs.extract(str(d))
    assert r["found"] and r["files_scanned"] == 3 and len(r["matches"]) == 2
    assert r["distinct_configs"] == 1          # two copies of ONE beacon config


def test_config_straddling_a_chunk_edge(tmp_path):
    f = tmp_path / "image.raw"
    chunk = 4096
    f.write_bytes(_noise(chunk - 40) + _config(0x2E) + _noise(3 * chunk, 4))
    r = cs.extract(str(f), chunk_size=chunk)
    assert r["found"] and len(r["matches"]) == 1          # not lost, not duplicated
    assert r["matches"][0]["offset"] == chunk - 40
    assert r["matches"][0]["summary"]["c2_server"] == "192.0.2.57,/pixel.gif"
    assert r["bytes_scanned"] == f.stat().st_size


def test_no_match_is_a_clean_negative(tmp_path):
    f = tmp_path / "clean.dmp"
    f.write_bytes(_noise(200_000) + b"\x00" * 50_000)
    r = cs.extract(str(f))
    assert r["success"] is True and r["found"] is False and r["matches"] == []
    assert r["files_scanned"] == 1 and r["bytes_scanned"] == 250_000
    assert "256" in r["searched_for"] and "runtime" in r["searched_for"]


def test_missing_input_fails(tmp_path):
    assert cs.extract(str(tmp_path / "nope"))["success"] is False


# ── runtime (heap) settings table ────────────────────────────────────────────

def _rt_entry(typ, val):
    return struct.pack("<HxxxxxxQ", typ, val)


def _runtime_table(ptrs):
    ents = {1: (1, 8), 2: (1, 443), 3: (2, 5000), 4: (2, 1048576), 5: (1, 10),
            7: (3, ptrs["key"]), 8: (3, ptrs["c2"]), 9: (3, ptrs["ua"]), 37: (2, 1234)}
    table = b"\x00" * 16
    for sid in range(1, 129):
        typ, val = ents.get(sid, (0, 0))
        table += _rt_entry(typ, val)
    return table


def test_runtime_table_resolved_from_sibling_vad_dumps(tmp_path):
    heap = bytearray(0x1000)
    heap[0:17] = b"evil.example,/cm\x00"
    heap[0x100:0x100 + len(UA) + 1] = UA.encode() + b"\x00"
    heap[0x200:0x200 + len(PUBKEY)] = PUBKEY
    (tmp_path / "pid.42.vad.0x20000000-0x20000fff.dmp").write_bytes(bytes(heap))
    table = _runtime_table({"c2": 0x20000000, "ua": 0x20000100, "key": 0x20000200})
    region = b"\x00" * 0x100 + table
    region += b"\x00" * (0x1000 - len(region))
    (tmp_path / "pid.42.vad.0x10000000-0x10000fff.dmp").write_bytes(region)
    r = cs.extract(str(tmp_path / "pid.42.vad.0x10000000-0x10000fff.dmp"))
    m = r["matches"][0]
    assert m["form"] == "runtime_table_x64" and m["table_va"] == "0x10000100"
    assert m["pointers_resolved"] == 3 and m["pointers_unresolved"] == 0
    s = m["summary"]
    assert (s["beacon_type"], s["port"], s["sleep_ms"], s["watermark"]) == ("HTTPS", 443, 5000, 1234)
    assert s["c2_server"] == "evil.example,/cm" and s["user_agent"] == UA
    assert s["public_key_sha256"]


def test_runtime_table_in_raw_image_via_memmap_listing(tmp_path):
    img = bytearray(0x4000)
    table = _runtime_table({"c2": 0x7000_0010, "ua": 0x7000_0100, "key": 0x7000_0200})
    img[0x1000:0x1000 + len(table)] = table                # VA page 0x6000_0000
    img[0x3010:0x3010 + 12] = b"c2.test,/a\x00\x00"        # VA page 0x7000_0000
    img[0x3100:0x3100 + len(UA)] = UA.encode()
    img[0x3200:0x3200 + len(PUBKEY)] = PUBKEY
    (tmp_path / "mem.raw").write_bytes(bytes(img))
    rows = [{"File output": "pid.9.dmp", "Offset in File": 0, "Physical": 0x1000,
             "Size": 0x1000, "Virtual": 0x6000_0000, "__children": []},
            {"File output": "pid.9.dmp", "Offset in File": 0x1000, "Physical": 0x3000,
             "Size": 0x1000, "Virtual": 0x7000_0000, "__children": []}]
    listing = tmp_path / "memmap.json"
    listing.write_text(json.dumps(rows, indent=2))
    unresolved = cs.extract(str(tmp_path / "mem.raw"))["matches"][0]
    assert unresolved["pointers_unresolved"] == 3 and "hint" in unresolved
    r = cs.extract(str(tmp_path / "mem.raw"), memmap_listing=str(listing))
    m = r["matches"][0]
    assert m["pointer_resolution"] == "memmap listing (physical)"
    assert m["summary"]["c2_server"] == "c2.test,/a" and m["summary"]["user_agent"] == UA


def test_truncated_memmap_listing_is_read_leniently(tmp_path):
    p = tmp_path / "792.txt"
    p.write_text('[\n {"File output": "pid.1.dmp", "Offset in File": 0, "Physical": 4096, '
                 '"Size": 4096, "Virtual": 8192, "__children": []},\n {"File output": "pid.1.dmp", '
                 '"Offset in File": 4096, "Phys')
    assert cs.load_memmap_listing(str(p)) == [(8192, 4096, 4096, 0, "pid.1.dmp")]


# ── MCP wrapper: tracing, output safety, tier class ─────────────────────────

def test_tool_writes_json_traces_and_stamps_marker(tmp_path):
    from core.execution_log import log
    from tools.misc import cs_beacon_config
    f = tmp_path / "pid.7.vad.0x1000-0x2fff.dmp"
    f.write_bytes(_noise(64) + _config(0x2E))
    out = tmp_path / "exports" / "cs" / "cfg.json"
    r = _tool(cs_beacon_config)(str(f), output_path=str(out))
    assert r["success"] and r["found"] and r["matches"][0]["summary"]["port"] == 80
    assert json.loads(out.read_text())["matches"][0]["xor_key"] == "0x2e"
    entry = log.index().by_call_id[r["_trudi_call_id"]]
    assert entry["cmd"].startswith("misc.cs_beacon_config ") and str(f) in entry["cmd"]
    assert entry.get("implant_config") is True
    assert "192.0.2.57,/pixel.gif" in entry.get("beacon_c2", [])


def test_tool_negative_is_success_without_marker(tmp_path):
    from core.execution_log import log
    from tools.misc import cs_beacon_config
    f = tmp_path / "clean.dmp"
    f.write_bytes(_noise(10_000))
    r = _tool(cs_beacon_config)(str(f))
    assert r["success"] is True and r["found"] is False
    assert "NO beacon config found" in r["summary"] and "10000 bytes" in r["summary"]
    entry = log.index().by_call_id[r["_trudi_call_id"]]
    assert not entry.get("implant_config")


@pytest.mark.parametrize("bad", ["/mnt/img/exports/cfg.json", "{tmp}/evidence/exports/cfg.json",
                                 "{tmp}/notes/cfg.json"])
def test_output_path_safety(tmp_path, bad):
    from tools.misc import cs_beacon_config
    f = tmp_path / "x.dmp"
    f.write_bytes(_config(0x2E))
    with pytest.raises(ValueError):
        _tool(cs_beacon_config)(str(f), output_path=bad.format(tmp=tmp_path))


def test_decoded_config_is_a_tier_class_only_when_found():
    from tools._gates import _tiering as T
    hit = {"type": "tool_call", "call_id": 1, "success": True,
           "cmd": "misc.cs_beacon_config /c/exports/memmap_7300/pid.7300.dmp", "implant_config": True}
    miss = dict(hit, implant_config=None)
    assert "implant_config" in T.classify_entry(hit)
    assert "implant_config" not in T.classify_entry(miss)
    groups = T.load_contract()["groups"]
    assert "implant_config" in groups["presence_primary"] and "implant_config" in groups["c2_weak"]
