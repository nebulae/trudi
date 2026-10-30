"""Parsed output a run produced but never read (tools/_parsed_outputs.py)."""
import json
import os
import time

from tools import _parsed_outputs as P


def _tables(root):
    os.makedirs(root / "Export", exist_ok=True)
    (root / "Wifi.csv").write_text("SSID,BSSID\nUCPLPublicWireless,36:56:ee:50:83:97\n")
    (root / "empty.csv").write_text("SSID,BSSID\n")
    (root / "shortcuts.json").write_text(json.dumps([{"shortcut_name": "SecuEncrypt"}]))
    (root / "info.json").write_text(json.dumps({"mvt_version": "2"}))      # not a table
    (root / "Export" / "raw.csv").write_text("a\n1\n")
    (root / "log.txt").write_text("x")


def test_collect_tables_with_records_only(tmp_path):
    _tables(tmp_path)
    got = {os.path.basename(f["file"]): f["rows"]
           for f in P.collect(str(tmp_path), skip_dirs=("Export",))}
    assert got == {"Wifi.csv": 1, "shortcuts.json": 1}


def test_collect_ignores_files_older_than_the_run(tmp_path):
    _tables(tmp_path)
    old = time.time() - 3600
    os.utime(tmp_path / "Wifi.csv", (old, old))
    names = {os.path.basename(f["file"]) for f in P.collect(str(tmp_path), since=time.time())}
    assert "Wifi.csv" not in names


def _trace(tmp_path):
    _tables(tmp_path)
    files = P.collect(str(tmp_path), skip_dirs=("Export",))
    return [{"type": "tool_call", "call_id": 537, "mcp_tool": "mobile_ios_apt",
             "cmd": "ios_apt.py -i x", "success": True, "parsed_outputs": files}]


def test_unread_until_read_output_names_the_file(tmp_path):
    entries = _trace(tmp_path)
    assert {os.path.basename(f["file"]) for f in P.unread(entries)} == {"Wifi.csv", "shortcuts.json"}
    entries.append({"type": "tool_call", "call_id": 600, "mcp_tool": "read_output",
                    "cmd": f"read.output --output {tmp_path}/Wifi.csv query=UCPL"})
    left = P.unread(entries)
    assert [os.path.basename(f["file"]) for f in left] == ["shortcuts.json"]
    assert left[0]["call_id"] == 537 and left[0]["rows"] == 1


def test_source_disposition_settles_a_file_or_its_directory(tmp_path):
    entries = _trace(tmp_path)
    entries.append({"type": "disposition", "target_kind": "source",
                    "target_id": str(tmp_path / "shortcuts.json"), "reason": "inapplicable"})
    assert [os.path.basename(f["file"]) for f in P.unread(entries)] == ["Wifi.csv"]
    entries.append({"type": "disposition", "target_kind": "source",
                    "target_id": str(tmp_path), "reason": "out_of_scope"})
    assert P.unread(entries) == []


def test_dair_block_from_collect_on(tmp_path):
    entries = _trace(tmp_path)
    assert P.dair_block(entries, "Triage") == ""
    block = P.dair_block(entries, "Analyze")
    assert "UNREAD PARSER OUTPUT (2 table(s)" in block and "Wifi.csv (1 records" in block


def test_stamp_annotates_the_tool_call(tmp_path, monkeypatch):
    _tables(tmp_path)
    seen = {}

    class _Log:
        def annotate_tool_call(self, cid, **kw):
            seen[cid] = kw

    monkeypatch.setattr("core.execution_log.log", _Log())
    P.stamp({"success": True, "_trudi_call_id": 9}, str(tmp_path), skip_dirs=("Export",))
    assert {os.path.basename(f["file"]) for f in seen[9]["parsed_outputs"]} == \
        {"Wifi.csv", "shortcuts.json"}
    seen.clear()
    P.stamp({"success": False, "_trudi_call_id": 10}, str(tmp_path))
    assert seen == {}
