"""core.xlsx workbook reader and misc.xlsx_export."""
import csv
import zipfile
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog
from core.xlsx import read_workbook

_WB = """<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Spend" sheetId="1" r:id="rId1"/><sheet name="Notes 2" sheetId="2" r:id="rId2"/></sheets>
</workbook>"""
_RELS = """<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="ws" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="ws" Target="/xl/worksheets/sheet2.xml"/>
</Relationships>"""
_SST = """<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<si><t>When</t></si><si><t>What</t></si><si><r><t>Rolex </t></r><r><t>Submariner</t></r></si>
</sst>"""
# cellXfs[1] = built-in date (14); cellXfs[2] = custom yyyy-mm-dd hh:mm
_STYLES = """<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<numFmts><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm"/></numFmts>
<cellXfs><xf numFmtId="0"/><xf numFmtId="14"/><xf numFmtId="164"/></cellXfs>
</styleSheet>"""
_S1 = """<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="D1" t="inlineStr"><is><t>Paid</t></is></c></row>
<row r="3"><c r="A3" s="1"><v>45368</v></c><c r="B3" t="s"><v>2</v></c><c r="C3"><v>30500</v></c><c r="D3" t="b"><v>1</v></c></row>
<row r="4"><c r="A4" s="2"><v>45368.75</v></c><c r="C4" t="str"><f>C3*2</f><v>61000</v></c></row>
</sheetData></worksheet>"""
_S2 = """<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>"""


def _book(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("xl/workbook.xml", _WB)
        z.writestr("xl/_rels/workbook.xml.rels", _RELS)
        z.writestr("xl/sharedStrings.xml", _SST)
        z.writestr("xl/styles.xml", _STYLES)
        z.writestr("xl/worksheets/sheet1.xml", _S1)
        z.writestr("xl/worksheets/sheet2.xml", _S2)
    return str(path)


def test_cells_strings_dates_gaps_and_cached_formulas(tmp_path):
    wb = read_workbook(_book(tmp_path / "spending.xlsx"))
    assert wb["success"] and [s["name"] for s in wb["sheets"]] == ["Spend", "Notes 2"]
    rows = wb["sheets"][0]["rows"]
    assert rows[0] == ["When", "What", "", "Paid"]           # gap column C kept empty
    assert rows[1] == []                                      # missing row 2 kept
    assert rows[2] == ["2024-03-17", "Rolex Submariner", "30500", "TRUE"]
    assert rows[3] == ["2024-03-17 18:00:00", "", "61000"]    # cached formula value
    assert wb["sheets"][1]["rows"] == []


def test_not_a_workbook(tmp_path):
    p = tmp_path / "x.xlsx"
    p.write_bytes(b"not a zip")
    assert read_workbook(str(p))["success"] is False


@pytest.fixture
def live_log(tmp_path):
    lg = ExecutionLog()
    (tmp_path / "analysis").mkdir(exist_ok=True)
    lg.configure("XLSX-TEST", str(tmp_path / "analysis" / "trace.json"), save_session=False)
    lg.record_dair_call("Collect", "", False, "", "", "stay", "")
    with patch("core.execution_log.log", lg):
        yield lg


def test_export_writes_one_csv_per_sheet_and_traces(live_log, tmp_path):
    from tools.misc import xlsx_export
    (tmp_path / "evidence").mkdir()
    src = _book(tmp_path / "evidence" / "spending.xlsx")
    out = tmp_path / "exports" / "xlsx"
    r = getattr(xlsx_export, "fn", xlsx_export)(src, str(out))
    assert r["success"] and len(r["sheets"]) == 2
    rows = list(csv.reader(open(r["sheets"][0]["csv"])))
    assert rows[0] == ["When", "What", "", "Paid"] and rows[2][1] == "Rolex Submariner"
    assert r["sheets"][1]["csv"].endswith("spending__Notes_2.csv")
    e = live_log.index().by_call_id[r["_trudi_call_id"]]
    assert e["success"] is True and e["cmd"].startswith("misc.xlsx_export ")


def test_export_refuses_output_into_evidence(live_log, tmp_path):
    from tools.misc import xlsx_export
    (tmp_path / "evidence").mkdir()
    src = _book(tmp_path / "evidence" / "spending.xlsx")
    with pytest.raises(ValueError):
        getattr(xlsx_export, "fn", xlsx_export)(src, str(tmp_path / "evidence" / "out"))
