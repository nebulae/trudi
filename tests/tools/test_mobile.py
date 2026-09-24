"""Tests for tools/mobile.py — iOS parsers (MVT, mac_apt ios_apt).

No real binaries run: core.executor.subprocess.run is replaced by a fake that
records argv/env and writes whatever output the scenario needs into the -o /
-d directory, so the wrappers' success detection, summaries, trace entries
and redaction are exercised end to end through core.run.
"""
import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.execution_log import ExecutionLog


def _tool(fn):
    return getattr(fn, "fn", fn)


@pytest.fixture
def live_log(tmp_path):
    lg = ExecutionLog()
    (tmp_path / "analysis").mkdir(exist_ok=True)
    lg.configure("MOBILE-TEST", str(tmp_path / "analysis" / "trace.json"), save_session=False)
    lg.record_dair_call("Collect", "", False, "", "", "stay", "")
    with patch("core.execution_log.log", lg):
        yield lg


@pytest.fixture(autouse=True)
def installed(monkeypatch):
    monkeypatch.setattr("tools.mobile._which", lambda p: p)


@pytest.fixture
def ios_tree(tmp_path):
    root = tmp_path / "evidence" / "ios_filesystem"
    (root / "private" / "var" / "mobile" / "Library").mkdir(parents=True)
    (root / "Library").mkdir()
    return root


class FakeProc:
    """subprocess.run stand-in; `writer(argv, env)` produces the tool's output."""

    def __init__(self, writer=None, rc=0, stdout=b"", stderr=b""):
        self.writer, self.rc, self.stdout, self.stderr = writer, rc, stdout, stderr
        self.calls = []

    def __call__(self, cmd, capture_output=True, timeout=None, env=None, cwd=None):
        self.calls.append(SimpleNamespace(cmd=list(cmd), env=env))
        if self.writer:
            self.writer(list(cmd), env)
        return SimpleNamespace(returncode=self.rc, stdout=self.stdout, stderr=self.stderr)


def _flag(cmd, flag):
    return cmd[cmd.index(flag) + 1]


def _mvt_writer(records=None, log=""):
    records = {"sms": [{"text": "hi"}], "safari_history": [{"url": "https://x"}],
               "calls": []} if records is None else records

    def w(cmd, env):
        out = _flag(cmd, "-o")
        os.makedirs(out, exist_ok=True)
        for name, recs in records.items():
            with open(os.path.join(out, f"{name}.json"), "w") as fh:
                json.dump(recs, fh, indent=4)
        with open(os.path.join(out, "info.json"), "w") as fh:
            json.dump({"mvt_version": "2.7.0"}, fh)
        with open(os.path.join(out, "command.log"), "w") as fh:
            fh.write(log or (
                "2026-01-01 00:00:00,000 - mvt.ios.modules.mixed.sms - INFO - Running module SMS...\n"
                "2026-01-01 00:00:00,000 - mvt.ios.modules.fs.analytics - INFO - Running module Analytics...\n"
                "2026-01-01 00:00:00,000 - mvt.ios.modules.fs.analytics - ERROR - Error in running "
                "extraction from module Analytics: no such table: soft_failures\n"))
    return w


def _apt_writer(csvs=None):
    csvs = {"Wifi.csv": "SSID,BSSID\nNet1,aa:bb\nNet2,cc:dd\n",
            "Safari.csv": "Type,Name,URL\nHISTORY,Bank,https://bank\n"} if csvs is None else csvs

    def w(cmd, env):
        out = _flag(cmd, "-o")
        os.makedirs(os.path.join(out, "Export", "WIFI"), exist_ok=True)
        for name, body in csvs.items():
            with open(os.path.join(out, name), "w") as fh:
                fh.write(body)
        with open(os.path.join(out, "Export", "WIFI", "known.plist"), "w") as fh:
            fh.write("<plist/>")
        with open(os.path.join(out, "Log.20260101-000000.txt"), "w") as fh:
            fh.write("MAIN-INFO-Running plugin WIFI\nMAIN-INFO-Running plugin DOCUMENTREVISIONS\n"
                     "MAIN-ERROR-An exception occurred while running plugin - DOCUMENTREVISIONS\n")
    return w


def _entry(lg, cid):
    return lg.index().by_call_id[cid]


# ── argv ──────────────────────────────────────────────────────────────────────

class TestArgv:
    def test_check_fs_offline_output_and_input(self, live_log, ios_tree, tmp_path):
        from tools.mobile import mvt_ios_check_fs
        out = str(tmp_path / "analysis" / "mvt")
        fake = FakeProc(_mvt_writer())
        with patch("core.executor.subprocess.run", fake):
            r = _tool(mvt_ios_check_fs)(str(ios_tree), out)
        cmd = fake.calls[0].cmd
        assert cmd[0].endswith("mvt-ios")
        assert cmd[1:3] == ["--disable-update-check", "--disable-indicator-update-check"]
        assert cmd[3] == "check-fs" and _flag(cmd, "-o") == out and cmd[-1] == str(ios_tree)
        assert "-m" not in cmd
        assert r["success"] is True and r["_trudi_call_id"]

    def test_check_fs_one_run_per_module(self, live_log, ios_tree, tmp_path):
        from tools.mobile import mvt_ios_check_fs
        fake = FakeProc(_mvt_writer())
        with patch("core.executor.subprocess.run", fake):
            r = _tool(mvt_ios_check_fs)(str(ios_tree), str(tmp_path / "analysis" / "m"),
                                        modules="SMS, SafariHistory")
        assert [_flag(c.cmd, "-m") for c in fake.calls] == ["SMS", "SafariHistory"]
        assert len(r["call_ids"]) == 2 and r["success"] is True

    def test_check_fs_rejects_bad_module_name(self, live_log, ios_tree, tmp_path):
        from tools.mobile import mvt_ios_check_fs
        fake = FakeProc()
        with patch("core.executor.subprocess.run", fake):
            r = _tool(mvt_ios_check_fs)(str(ios_tree), str(tmp_path / "analysis" / "m"),
                                        modules="SMS;rm -rf /")
        assert r["success"] is False and not fake.calls

    def test_check_backup_argv(self, live_log, tmp_path):
        from tools.mobile import mvt_ios_check_backup
        backup = tmp_path / "backup"; backup.mkdir()
        out = str(tmp_path / "analysis" / "bk")
        fake = FakeProc(_mvt_writer())
        with patch("core.executor.subprocess.run", fake):
            _tool(mvt_ios_check_backup)(str(backup), out)
        cmd = fake.calls[0].cmd
        assert "check-backup" in cmd and _flag(cmd, "-o") == out and cmd[-1] == str(backup)
        assert "--disable-update-check" in cmd

    def test_ios_apt_argv_plugins_uppercased(self, live_log, ios_tree, tmp_path):
        from tools.mobile import ios_apt, IOS_APT, IOS_APT_PYTHON
        (ios_tree / "System" / "Library" / "CoreServices").mkdir(parents=True)
        (ios_tree / "System" / "Library" / "CoreServices" / "SystemVersion.plist").write_text("x")
        out = str(tmp_path / "analysis" / "apt")
        fake = FakeProc(_apt_writer())
        with patch("core.executor.subprocess.run", fake):
            r = _tool(ios_apt)(str(ios_tree), out, plugins="wifi, safari")
        cmd = fake.calls[0].cmd
        assert cmd[:2] == [IOS_APT_PYTHON, IOS_APT]
        assert _flag(cmd, "-i") == str(ios_tree) and _flag(cmd, "-o") == out
        assert cmd[cmd.index("-c") + 1:] == ["WIFI", "SAFARI"]
        assert r["success"] is True and "version_source" not in r

    def test_ios_apt_unknown_plugin_refused(self, live_log, ios_tree, tmp_path):
        from tools.mobile import ios_apt
        fake = FakeProc()
        with patch("core.executor.subprocess.run", fake):
            r = _tool(ios_apt)(str(ios_tree), str(tmp_path / "analysis" / "a"), plugins="WIFI,BOGUS")
        assert r["success"] is False and "BOGUS" in r["error"] and not fake.calls

    def test_input_must_be_a_directory(self, live_log, tmp_path):
        from tools.mobile import mvt_ios_check_fs, ios_apt
        fake = FakeProc()
        with patch("core.executor.subprocess.run", fake):
            for fn in (mvt_ios_check_fs, ios_apt):
                r = _tool(fn)(str(tmp_path / "nope"), str(tmp_path / "analysis" / "o"))
                assert r["success"] is False and "not a directory" in r["error"]
        assert not fake.calls


# ── password redaction ────────────────────────────────────────────────────────

class TestDecryptBackup:
    SECRET = "hunter2-S3cret!"

    def _writer(self, cmd, env):
        os.makedirs(_flag(cmd, "-d"), exist_ok=True)
        open(os.path.join(_flag(cmd, "-d"), "Manifest.db"), "w").close()

    def test_password_via_env_never_argv_or_trace(self, live_log, tmp_path):
        from tools.mobile import mvt_ios_decrypt_backup
        backup = tmp_path / "backup"; backup.mkdir()
        out = str(tmp_path / "analysis" / "decrypted")
        fake = FakeProc(self._writer, stdout=f"using password {self.SECRET}".encode(),
                        stderr=f"echo {self.SECRET}".encode())
        with patch("core.executor.subprocess.run", fake):
            r = _tool(mvt_ios_decrypt_backup)(str(backup), out, password=self.SECRET)
        call = fake.calls[0]
        assert self.SECRET not in " ".join(call.cmd) and "-p" not in call.cmd
        assert call.env["MVT_IOS_BACKUP_PASSWORD"] == self.SECRET
        assert "decrypt-backup" in call.cmd and _flag(call.cmd, "-d") == out
        assert r["success"] is True and r["manifest_db"] is True
        assert self.SECRET not in json.dumps(r)
        with open(live_log._path) as fh:
            trace_text = fh.read()
        assert self.SECRET not in trace_text
        sidecar = _entry(live_log, r["_trudi_call_id"]).get("stdout_path")
        if sidecar and os.path.exists(sidecar):
            assert self.SECRET not in open(sidecar).read()

    def test_key_file_uses_dash_k(self, live_log, tmp_path):
        from tools.mobile import mvt_ios_decrypt_backup
        backup = tmp_path / "backup"; backup.mkdir()
        fake = FakeProc(self._writer)
        with patch("core.executor.subprocess.run", fake):
            _tool(mvt_ios_decrypt_backup)(str(backup), str(tmp_path / "analysis" / "d"),
                                          key_file="/keys/k.bin")
        assert _flag(fake.calls[0].cmd, "-k") == "/keys/k.bin" and fake.calls[0].env is None

    def test_exactly_one_secret(self, live_log, tmp_path):
        from tools.mobile import mvt_ios_decrypt_backup
        backup = tmp_path / "backup"; backup.mkdir()
        for kw in ({}, {"password": "a", "key_file": "/k"}):
            r = _tool(mvt_ios_decrypt_backup)(str(backup), str(tmp_path / "analysis" / "d"), **kw)
            assert r["success"] is False

    def test_wrong_password_is_a_failure(self, live_log, tmp_path):
        from tools.mobile import mvt_ios_decrypt_backup
        backup = tmp_path / "backup"; backup.mkdir()
        fake = FakeProc(None)                      # exit 0, no Manifest.db written
        with patch("core.executor.subprocess.run", fake):
            r = _tool(mvt_ios_decrypt_backup)(str(backup), str(tmp_path / "analysis" / "d"),
                                              password="nope")
        assert r["success"] is False and "Manifest.db" in r["error"]
        assert _entry(live_log, r["_trudi_call_id"])["success"] is False


# ── output safety ─────────────────────────────────────────────────────────────

class TestOutputSafety:
    @pytest.mark.parametrize("bad", ["/cases/x/evidence/mvt", "/mnt/phone/out", "/media/usb/out"])
    def test_evidence_output_refused(self, live_log, ios_tree, bad):
        from tools.mobile import mvt_ios_check_fs, mvt_ios_check_backup, mvt_ios_decrypt_backup, ios_apt
        fake = FakeProc()
        with patch("core.executor.subprocess.run", fake):
            for fn, kw in ((mvt_ios_check_fs, {}), (mvt_ios_check_backup, {}),
                           (ios_apt, {}), (mvt_ios_decrypt_backup, {"password": "p"})):
                with pytest.raises(ValueError):
                    _tool(fn)(str(ios_tree), bad, **kw)
        assert not fake.calls


# ── success / failure detection ───────────────────────────────────────────────

class TestSuccessDetection:
    def test_mvt_summary_records_and_module_errors(self, live_log, ios_tree, tmp_path):
        from tools.mobile import mvt_ios_check_fs
        out = str(tmp_path / "analysis" / "mvt")
        with patch("core.executor.subprocess.run", FakeProc(_mvt_writer())):
            r = _tool(mvt_ios_check_fs)(str(ios_tree), out)
        assert r["records_by_module"] == {"sms": 1, "safari_history": 1, "calls": 0}
        assert r["modules_with_records"] == ["safari_history", "sms"]
        assert r["module_errors"] == {"Analytics": "no such table: soft_failures"}
        assert r["modules_run"] == ["SMS", "Analytics"]
        e = _entry(live_log, r["_trudi_call_id"])
        assert e["success"] is True
        assert e["stdout_excerpt"].startswith("MVT output summary")
        assert "sms.json: 1 records" in e["stdout_excerpt"]
        # families stamped only for files with records (calls.json is empty)
        assert e.get("mobile_messaging") and e.get("mobile_browser")
        assert r["artifact_families"] == ["mobile_browser", "mobile_messaging"]

    def test_mvt_exit0_without_output_is_failure(self, live_log, ios_tree, tmp_path):
        from tools.mobile import mvt_ios_check_fs
        with patch("core.executor.subprocess.run", FakeProc(None)):
            r = _tool(mvt_ios_check_fs)(str(ios_tree), str(tmp_path / "analysis" / "mvt"))
        assert r["success"] is False and "no module JSON" in r["error"]
        assert _entry(live_log, r["_trudi_call_id"])["success"] is False

    def test_mvt_stale_output_does_not_count(self, live_log, ios_tree, tmp_path):
        from tools.mobile import mvt_ios_check_fs
        out = tmp_path / "analysis" / "mvt"; out.mkdir(parents=True)
        (out / "sms.json").write_text("[1]")
        old = os.path.getmtime(out / "sms.json") - 3600
        os.utime(out / "sms.json", (old, old))
        with patch("core.executor.subprocess.run", FakeProc(None)):
            r = _tool(mvt_ios_check_fs)(str(ios_tree), str(out))
        assert r["success"] is False

    def test_mvt_nonzero_exit_is_failure(self, live_log, ios_tree, tmp_path):
        from tools.mobile import mvt_ios_check_fs
        with patch("core.executor.subprocess.run", FakeProc(_mvt_writer(), rc=1, stderr=b"boom")):
            r = _tool(mvt_ios_check_fs)(str(ios_tree), str(tmp_path / "analysis" / "mvt"))
        assert r["success"] is False and r["exit_code"] == 1 and "boom" in r["stderr"]

    def test_ios_apt_rows_plugins_and_export_skipped(self, live_log, ios_tree, tmp_path):
        from tools.mobile import ios_apt
        out = str(tmp_path / "analysis" / "apt")
        with patch("core.executor.subprocess.run", FakeProc(_apt_writer())):
            r = _tool(ios_apt)(str(ios_tree), out)
        assert r["success"] is True
        assert r["rows_by_csv"] == {"Safari.csv": 1, "Wifi.csv": 2}
        assert r["plugins_failed"] == ["DOCUMENTREVISIONS"]
        assert not any(f["file"].startswith("Export") for f in r["output_files"])
        assert r["output_file_count"] >= 4
        assert r["artifact_families"] == ["mobile_browser", "mobile_location"]

    def test_ios_apt_no_ios_installation_is_failure(self, live_log, ios_tree, tmp_path):
        from tools.mobile import ios_apt
        fake = FakeProc(None, rc=0, stdout=b":( Could not find an iOS installation on path provided.")
        with patch("core.executor.subprocess.run", fake):
            r = _tool(ios_apt)(str(ios_tree), str(tmp_path / "analysis" / "apt"))
        assert r["success"] is False and "no iOS installation" in r["error"]
        assert _entry(live_log, r["_trudi_call_id"])["success"] is False

    def test_ios_apt_version_overlay(self, live_log, ios_tree, tmp_path):
        """No readable SystemVersion.plist but a LastBuildInfo.plist: ios_apt runs
        on a symlink overlay; the traced cmd names the evidence root; the overlay
        is removed and the evidence tree is untouched."""
        from tools.mobile import ios_apt, _LAST_BUILD_INFO
        lbi = ios_tree / _LAST_BUILD_INFO
        lbi.parent.mkdir(parents=True)
        lbi.write_text("<plist>16.3</plist>")
        before = sorted(str(p) for p in ios_tree.rglob("*"))
        seen = {}

        def writer(cmd, env):
            root = _flag(cmd, "-i")
            seen["root"] = root
            sv = os.path.join(root, "System/Library/CoreServices/SystemVersion.plist")
            seen["version"] = open(sv).read()
            seen["private"] = os.path.realpath(os.path.join(root, "private"))
            _apt_writer()(cmd, env)

        with patch("core.executor.subprocess.run", FakeProc(writer)):
            r = _tool(ios_apt)(str(ios_tree), str(tmp_path / "analysis" / "apt"))
        assert r["success"] is True
        assert seen["root"] != str(ios_tree) and seen["version"] == "<plist>16.3</plist>"
        assert seen["private"] == os.path.realpath(ios_tree / "private")
        assert not os.path.exists(seen["root"])                    # overlay removed
        assert sorted(str(p) for p in ios_tree.rglob("*")) == before   # evidence untouched
        e = _entry(live_log, r["_trudi_call_id"])
        assert seen["root"] not in e["cmd"] and str(ios_tree) in e["cmd"]
        assert "LastBuildInfo" in e.get("version_overlay", "")
        assert "LastBuildInfo" in r["version_source"]

    def test_unreadable_dirs_reported(self, live_log, ios_tree, tmp_path):
        from tools.mobile import mvt_ios_check_fs
        locked = ios_tree / "private" / "var" / "containers" / "Library"
        locked.mkdir(parents=True)
        os.chmod(locked, 0)
        try:
            if os.access(locked, os.R_OK):
                pytest.skip("running as root: mode 000 is readable")
            with patch("core.executor.subprocess.run", FakeProc(_mvt_writer())):
                r = _tool(mvt_ios_check_fs)(str(ios_tree), str(tmp_path / "analysis" / "mvt"))
            assert r["unreadable_dirs"]["count"] == 1
            assert "NOT parsed" in r["coverage_warning"]
        finally:
            os.chmod(locked, 0o755)

    def test_binary_missing_is_typed_unavailable(self, live_log, ios_tree, tmp_path, monkeypatch):
        from tools.mobile import mvt_ios_check_fs, ios_apt
        monkeypatch.setattr("tools.mobile._which", lambda p: None)
        fake = FakeProc()
        with patch("core.executor.subprocess.run", fake):
            for fn in (mvt_ios_check_fs, ios_apt):
                r = _tool(fn)(str(ios_tree), str(tmp_path / "analysis" / "o"))
                assert r["status"] == "tool_unavailable"
        assert not fake.calls


# ── registration, evidence kinds, jobs ────────────────────────────────────────

class TestRegistration:
    def test_tools_mounted_under_mobile(self):
        import asyncio
        import server
        names = {t.name for t in asyncio.run(server.mcp.list_tools())}
        assert {"mobile_mvt_ios_check_fs", "mobile_mvt_ios_check_backup",
                "mobile_mvt_ios_decrypt_backup", "mobile_ios_apt"} <= names

    def test_long_tools_are_background_jobs(self):
        from core.jobs import background_mode
        for t in ("mobile_mvt_ios_check_fs", "mobile_ios_apt", "mobile_mvt_ios_check_backup",
                  "mobile_mvt_ios_decrypt_backup"):
            assert background_mode(t) == "if_slow"

    def test_mobile_tools_hidden_without_mobile_evidence(self, monkeypatch):
        import tools.tool_capabilities as tc
        monkeypatch.setattr(tc.shutil, "which", lambda n: f"/usr/bin/{n}")
        for t in ("mobile.mvt_ios_check_fs", "mobile.ios_apt"):
            assert tc.tool_evidence_needs(t) == frozenset({"mobile"})
            assert not tc.tool_fits_evidence(t, {"disk_image", "memory"})
            assert tc.tool_fits_evidence(t, {"mobile"})
            assert tc.tool_fits_evidence(t, set())             # undetermined: fail-open
            assert t not in tc.allowed_tool_names({"disk_image"})
            assert t in tc.allowed_tool_names({"mobile"})
            assert tc.capability_for_tool(t) == "mobile_device"
        assert "mobile.ios_apt" not in tc.format_tool_manifest_for_prompt(evidence_kinds={"pcap"})
        assert "mobile.ios_apt" in tc.format_tool_manifest_for_prompt(evidence_kinds={"mobile"})

    def test_mobile_tools_dropped_when_binaries_missing(self, monkeypatch):
        import tools.tool_capabilities as tc
        monkeypatch.setattr(tc.shutil, "which", lambda n: None)
        assert "mobile.mvt_ios_check_fs" in tc.unavailable_tools()
        assert "mobile.ios_apt" not in tc.allowed_tool_names({"mobile"})

    def test_successful_mobile_call_marks_mobile_kind(self):
        from core.evidence_kinds import _trace_kinds
        kinds = _trace_kinds([{"type": "tool_call", "success": True,
                               "mcp_tool": "mobile_ios_apt", "cmd": "ios_apt.py -i /x"}])
        assert "mobile" in kinds


# ── tier classes ──────────────────────────────────────────────────────────────

class TestTierClasses:
    def test_markers_and_cmd_classify(self):
        from tools._gates._tiering import classify_entry
        e = {"type": "tool_call", "success": True, "call_id": 9,
             "cmd": "/usr/local/bin/mvt-ios --disable-update-check check-fs -o /c/analysis/m /c/evidence/ios",
             "mobile_messaging": True, "mobile_accounts": True}
        got = classify_entry(e)
        assert {"mobile_artifact", "mobile_messaging", "mobile_accounts"} <= got
        assert "mobile_browser" not in got

    def test_decrypt_is_not_an_artifact_parse(self):
        from tools._gates._tiering import classify_entry
        e = {"type": "tool_call", "success": True, "call_id": 9,
             "cmd": "/usr/local/bin/mvt-ios decrypt-backup -d /c/analysis/d /c/evidence/bk"}
        assert "mobile_artifact" not in classify_entry(e)

    def test_attribution_documentary_binding(self):
        from tools._gates._tiering import tier_for
        res = tier_for({"act": "attribution"}, {"mobile_accounts", "mobile_messaging"})
        assert res.tier == "LIKELY"
        res = tier_for({"act": "attribution"}, {"mobile_artifact"})
        assert res.tier not in ("LIKELY", "CONFIRMED")


# ── read.output over MVT JSON ─────────────────────────────────────────────────

class TestReadJsonRecords:
    def test_json_array_read_one_record_per_row(self, live_log, tmp_path):
        from tools.read_output import read_output
        d = tmp_path / "analysis" / "mvt"; d.mkdir(parents=True)
        f = d / "safari_browser_state.json"
        f.write_text(json.dumps([
            {"tab_title": "News", "tab_url": "https://news", "last_viewed_timestamp": "2024-01-01"},
            {"tab_title": "Crooked River Bank", "tab_url": "https://crbk.org",
             "last_viewed_timestamp": "2024-02-06 02:24:17"},
        ], indent=4))
        r = _tool(read_output)(str(f), query="crooked")
        body = r["body"]
        assert "Crooked River Bank" in body and "2024-02-06 02:24:17" in body
        assert "crbk.org" in body and "News" not in body
        assert len(body.strip().splitlines()) == 1

    def test_json_object_keeps_line_scan(self, tmp_path):
        from tools._output_reader import read_relevant, _file_inventory
        f = tmp_path / "info.json"
        f.write_text(json.dumps({"a": 1, "mvt_version": "2.7.0"}, indent=2))
        assert '"mvt_version": "2.7.0"' in read_relevant(str(f), ["mvt_version"], 2000)
        arr = tmp_path / "arr.json"
        arr.write_text(json.dumps([{"x": 1}, {"x": 2}, {"x": 3}], indent=4))
        assert _file_inventory(str(arr))["total_rows"] == 3
