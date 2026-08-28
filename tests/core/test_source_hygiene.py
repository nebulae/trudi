"""Source hygiene: control characters must never reach shipped source.

A regex written as \\b inside an ordinary (non-raw) string during a patch
turned into a literal backspace byte (\\x08) — the pattern silently never
matched. Any control byte in source is a latent corruption of this class."""
import pathlib


def test_no_control_bytes_in_shipped_source():
    root = pathlib.Path(__file__).resolve().parents[2]
    bad = []
    for sub in ("tools", "core", "claude", "data"):
        for f in (root / sub).rglob("*"):
            if f.suffix not in (".py", ".yaml", ".md", ".json") or not f.is_file():
                continue
            data = f.read_bytes()
            for byte in (b"\x08", b"\x0b", b"\x0c", b"\x00"):
                if byte in data:
                    bad.append(f"{f}: {byte!r}")
    assert bad == [], bad
