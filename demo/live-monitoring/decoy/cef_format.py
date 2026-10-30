"""Vendored CEF formatter for the decoy container (no access to the
repo `monitoring` package). Keep in sync with monitoring/cef.py.
Source of truth: monitoring/cef.py — these three functions only."""
from __future__ import annotations
from typing import Any


def _esc_header(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|")


def _esc_ext(v: Any) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def format_cef(*, vendor: str, product: str, version: str, event_class_id: str,
               name: str, severity: int, extension: list[tuple[str, Any]],
               quote_values: bool = True) -> str:
    """Render a CEF record. `extension` is an ordered list of (key, value) so
    csNLabel/csN pairs stay adjacent like the vendor's output; values with
    spaces are double-quoted when `quote_values` (the ShadowPlex style)."""
    header = "|".join(_esc_header(x) for x in (
        "CEF:0", vendor, product, version, event_class_id, name, severity))
    ext = []
    for k, v in extension:
        if v is None:
            continue
        s = _esc_ext(v)
        if quote_values and (" " in s or s == ""):
            s = '"' + s.replace('"', '\\"') + '"'
        ext.append(f"{k}={s}")
    return header + "|" + " ".join(ext)
