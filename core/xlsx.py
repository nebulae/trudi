"""Read an Office Open XML workbook (.xlsx / .xlsm) into rows per sheet.

Standard library only: a workbook is a zip of XML parts. Shared strings,
inline strings, booleans and formula results are resolved; numeric cells whose
style is a date/time format are rendered as ISO timestamps (the Excel 1900 date
system, or 1904 when the workbook says so). Formulas are not evaluated: the
cached value Excel stored is what is returned.
"""
from __future__ import annotations

import datetime as _dt
import re
import zipfile
import xml.etree.ElementTree as ET

_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
       "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
       "rel": "http://schemas.openxmlformats.org/package/2006/relationships"}
_RID = "{%s}id" % _NS["r"]

# Built-in number formats that are dates/times (ECMA-376 18.8.30).
_BUILTIN_DATE_FMTS = set(range(14, 23)) | {45, 46, 47}
_DATE_TOKENS = re.compile(r"[dmyhs]", re.IGNORECASE)
_CELL_REF = re.compile(r"([A-Z]+)(\d+)")


def _col_index(letters: str) -> int:
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _text(el) -> str:
    """Concatenated <t> text of a string item (plain or rich-text runs)."""
    return "".join(t.text or "" for t in el.iter("{%s}t" % _NS["m"]))


def _shared_strings(z: zipfile.ZipFile) -> list[str]:
    try:
        root = ET.fromstring(z.read("xl/sharedStrings.xml"))
    except KeyError:
        return []
    return [_text(si) for si in root.findall("m:si", _NS)]


def _date_styles(z: zipfile.ZipFile) -> set[int]:
    """Indexes into cellXfs whose number format is a date/time."""
    try:
        root = ET.fromstring(z.read("xl/styles.xml"))
    except KeyError:
        return set()
    custom = {}
    for nf in root.findall("m:numFmts/m:numFmt", _NS):
        code = re.sub(r'"[^"]*"|\[[^\]]*\]|\\.', "", nf.get("formatCode") or "")
        custom[int(nf.get("numFmtId"))] = bool(_DATE_TOKENS.search(code))
    out = set()
    for i, xf in enumerate(root.findall("m:cellXfs/m:xf", _NS)):
        fid = int(xf.get("numFmtId") or 0)
        if fid in _BUILTIN_DATE_FMTS or custom.get(fid):
            out.add(i)
    return out


def _serial_to_iso(value: str, date1904: bool) -> str:
    try:
        f = float(value)
    except ValueError:
        return value
    base = _dt.datetime(1904, 1, 1) if date1904 else _dt.datetime(1899, 12, 30)
    ts = base + _dt.timedelta(days=f)
    if ts.hour == ts.minute == ts.second == 0 and f == int(f):
        return ts.strftime("%Y-%m-%d")
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def _sheets(z: zipfile.ZipFile) -> tuple[list[tuple[str, str]], bool]:
    """([(sheet name, part path)], date1904) in workbook order."""
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    pr = wb.find("m:workbookPr", _NS)
    date1904 = pr is not None and pr.get("date1904") in ("1", "true")
    rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
    target = {r.get("Id"): r.get("Target") for r in rels.findall("rel:Relationship", _NS)}
    out = []
    for s in wb.findall("m:sheets/m:sheet", _NS):
        t = target.get(s.get(_RID), "")
        part = t.lstrip("/") if t.startswith("/") else "xl/" + t
        out.append((s.get("name") or part, part))
    return out, date1904


def read_workbook(path: str) -> dict:
    """{"success", "sheets": [{"name", "rows": [[cell, ...], ...]}], "error"}."""
    try:
        z = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        return {"success": False, "error": f"not a readable xlsx workbook: {exc}"}
    with z:
        try:
            sheets, date1904 = _sheets(z)
            strings = _shared_strings(z)
            dates = _date_styles(z)
        except (KeyError, ET.ParseError) as exc:
            return {"success": False, "error": f"workbook structure unreadable: {exc}"}
        out = []
        for name, part in sheets:
            try:
                root = ET.fromstring(z.read(part))
            except (KeyError, ET.ParseError) as exc:
                out.append({"name": name, "rows": [], "error": str(exc)})
                continue
            rows: list[list[str]] = []
            for row in root.iter("{%s}row" % _NS["m"]):
                cells: dict[int, str] = {}
                for c in row.findall("m:c", _NS):
                    m = _CELL_REF.match(c.get("r") or "")
                    col = _col_index(m.group(1)) if m else len(cells)
                    t = c.get("t") or "n"
                    v = c.find("m:v", _NS)
                    raw = v.text if v is not None and v.text is not None else ""
                    if t == "s" and raw:
                        val = strings[int(raw)] if int(raw) < len(strings) else raw
                    elif t == "inlineStr":
                        is_ = c.find("m:is", _NS)
                        val = _text(is_) if is_ is not None else ""
                    elif t == "b":
                        val = "TRUE" if raw == "1" else "FALSE"
                    elif t == "n" and raw and int(c.get("s") or 0) in dates:
                        val = _serial_to_iso(raw, date1904)
                    else:
                        val = raw
                    cells[col] = val
                if cells:
                    r_idx = int(row.get("r") or len(rows) + 1) - 1
                    while len(rows) < r_idx:
                        rows.append([])
                    rows.append([cells.get(i, "") for i in range(max(cells) + 1)])
            out.append({"name": name, "rows": rows})
    return {"success": True, "sheets": out}
