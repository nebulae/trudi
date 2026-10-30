"""strings.png_acropalypse — Acropalypse detection/recovery (core/acropalypse.py).

The vulnerable write is reproduced exactly: the cropped PNG overwrites the
start of the original PNG file, which is not truncated.
"""
import hashlib
import io
import os
import random
import zlib

import pytest
from PIL import Image

from core import acropalypse as A


def _tool(fn):
    return getattr(fn, "fn", fn)


def _png(img) -> bytes:
    b = io.BytesIO()
    img.save(b, "PNG")
    return b.getvalue()


def _screenshot(w=640, h=400, mode="RGBA", seed=7):
    """A screenshot-like image: flat panels, text-ish noise, gradients."""
    rnd = random.Random(seed)
    img = Image.new(mode, (w, h), (240, 240, 240, 255)[:len(mode)])
    px = img.load()
    for y in range(h):
        for x in range(w):
            if (x // 40 + y // 25) % 3 == 0:
                v = (x * 3 + y * 5 + rnd.randrange(60)) % 256
                px[x, y] = (v, (v * 7) % 256, 255 - v, 255)[:len(mode)]
    return img


def _stream(png: bytes) -> bytes:
    p = A.parse_png(png)
    return zlib.decompress(b"".join(b for t, b in p["chunks"] if t == b"IDAT"))


def _acropalypsed(tmp_path, mode="RGBA", name="Capture.PNG"):
    orig_img = _screenshot(mode=mode)
    orig = _png(orig_img)
    cropped = _png(orig_img.crop((10, 10, 110, 60)))
    assert len(cropped) < len(orig)
    f = tmp_path / name
    f.write_bytes(cropped + orig[len(cropped):])
    return f, orig_img, orig


@pytest.mark.parametrize("mode", ["RGBA", "RGB"])
def test_detects_and_recovers_original_bottom_rows(tmp_path, mode):
    f, orig_img, orig = _acropalypsed(tmp_path, mode)
    out = tmp_path / "exports" / "acro"
    r = A.analyze_file(str(f), str(out))
    assert r["detected"] and r["recovered"], r["note"]
    assert r["trailing_bytes"] == len(orig) - len(_png(orig_img.crop((10, 10, 110, 60))))
    assert (r["cropped_width"], r["cropped_height"]) == (100, 50)
    assert r["recovered_width"] == orig_img.width
    assert 0 < r["recovered_height"] <= orig_img.height
    # the recovered scanlines are the tail of the original's filtered stream
    tail = _stream(orig)
    inf = A.inflate_tail(A.trailing_idat(open(f, "rb").read()[A.parse_png(open(f, "rb").read())["iend_end"]:])[0])
    assert inf["ok"] and tail.endswith(inf["raw"][-20000:])
    with Image.open(r["output_path"]) as im:
        im.load()
        assert im.size == (orig_img.width, r["recovered_height"])
        # bottom row pixels equal the original's bottom row
        assert im.crop((0, im.height - 1, im.width, im.height)).tobytes() == \
            orig_img.crop((0, orig_img.height - 1, orig_img.width, orig_img.height)).tobytes()


def test_clean_png_is_not_detected(tmp_path):
    f = tmp_path / "clean.png"
    f.write_bytes(_png(_screenshot(200, 100)))
    r = A.analyze_file(str(f), str(tmp_path / "exports"))
    assert r["format"] == "png" and not r["detected"] and r["trailing_bytes"] == 0


def test_detection_survives_failed_recovery(tmp_path):
    png = _png(_screenshot(120, 60))
    f = tmp_path / "junk.png"
    # trailing remnant with an IEND but no inflatable stream
    f.write_bytes(png + os.urandom(64) + b"\x00\x00\x00\x00IEND\xaeB`\x82")
    r = A.analyze_file(str(f), str(tmp_path / "exports"))
    assert r["detected"] and not r["recovered"] and "recovery failed" in r["note"]
    assert r["trailing_bytes"] == 64 + 12


def test_jpeg_trailing_data_is_detection_only(tmp_path):
    b = io.BytesIO()
    _screenshot(160, 90, mode="RGB").save(b, "JPEG")
    f = tmp_path / "shot.jpg"
    f.write_bytes(b.getvalue() + b"\x12\x34" * 500)
    r = A.analyze_file(str(f), str(tmp_path / "exports"))
    assert r["format"] == "jpeg" and r["detected"] and r["trailing_bytes"] == 1000
    assert not r["recovered"] and "detection only" in r["note"]
    g = tmp_path / "clean.jpg"
    g.write_bytes(b.getvalue())
    assert not A.analyze_file(str(g), None)["detected"]


def test_tool_scans_directory_traces_and_leaves_input_untouched(tmp_path):
    from core.execution_log import log
    from tools.strings_tools import png_acropalypse
    shots = tmp_path / "Pictures"
    shots.mkdir()
    f, orig_img, _ = _acropalypsed(shots)
    (shots / "clean.png").write_bytes(_png(_screenshot(80, 40)))
    os.utime(f, (1_600_000_000, 1_600_000_000))
    before = {p: (hashlib.sha256(open(shots / p, "rb").read()).hexdigest(),
                  os.stat(shots / p).st_mtime) for p in os.listdir(shots)}
    out = tmp_path / "exports" / "acro"
    r = _tool(png_acropalypse)(str(shots), output_dir=str(out))
    assert r["success"] and r["files_scanned"] == 2
    assert r["detected"] == 1 and r["recovered"] == 1
    hit = r["findings"][0]
    assert hit["recovered_width"] == orig_img.width and os.path.isfile(hit["output_path"])
    assert str(out) in hit["output_path"] and os.path.isfile(r["output_csv"])
    after = {p: (hashlib.sha256(open(shots / p, "rb").read()).hexdigest(),
                 os.stat(shots / p).st_mtime) for p in os.listdir(shots)}
    assert after == before
    entry = log.index().by_call_id[r["_trudi_call_id"]]
    assert entry["cmd"] == f"strings.png_acropalypse {shots}"
    assert "RECOVERED" in entry.get("stdout_excerpt", "") + str(entry.get("stdout", ""))


@pytest.mark.parametrize("bad", ["/mnt/img/exports/acro", "{tmp}/evidence/exports/acro",
                                 "{tmp}/notes/acro"])
def test_output_dir_safety(tmp_path, bad):
    from tools.strings_tools import png_acropalypse
    f = tmp_path / "x.png"
    f.write_bytes(_png(_screenshot(50, 50)))
    with pytest.raises(ValueError):
        _tool(png_acropalypse)(str(f), output_dir=bad.format(tmp=tmp_path))


def test_missing_input_is_an_honest_failure(tmp_path):
    from tools.strings_tools import png_acropalypse
    r = _tool(png_acropalypse)(str(tmp_path / "nope"), output_dir=str(tmp_path / "exports"))
    assert r["success"] is False and "not found" in r["error"]
