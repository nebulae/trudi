"""Windows victim support — the real Windows RDP victim build.

Covers the OS-aware pieces so a Windows client is baselined and watched with the
Windows detector set (Custom.TRUDI.Win.*), never the Linux one, and the sidecar
dedups/summarises Windows alerts via the shared leaf logic. Runtime behaviour of
the VQL itself (pslist()/watch_evtx against a live Windows client) is validated
on first boot of victim-win, not here — these tests pin the orchestration.
"""
import importlib.util
import json
from pathlib import Path

import pytest

from monitoring import render
from tools import monitor as monitor_mod

SIDECAR = Path(__file__).resolve().parents[2] / "bin" / "trudi-velo-watcher.py"


class TestDetectorOsSplit:
    def test_linux_set_excludes_windows(self):
        lin = render.list_detector_templates("linux")
        assert "Custom.TRUDI.NewProcess" in lin
        assert not any(".Win." in n for n in lin)

    def test_windows_set_is_only_win(self):
        win = render.list_detector_templates("windows")
        assert set(win) == {"Custom.TRUDI.Win.NewProcess",
                            "Custom.TRUDI.Win.NewLogon",
                            "Custom.TRUDI.Win.NewPersistence"}

    def test_default_is_linux(self):
        assert render.list_detector_templates() == render.list_detector_templates("linux")

    def test_windows_templates_substitute_baseline(self):
        bl = {"image_paths": ["C:\\Windows\\System32\\cmd.exe"], "process_names": ["cmd.exe"],
              "logon_sources": ["10.0.0.9"], "autoruns": ["HKLM/Run/TrudiMarker|cmd"]}
        np = render.render_template("Custom.TRUDI.Win.NewProcess", bl)
        assert "${" not in np and "pslist()" in np and "cmd.exe" in np
        lg = render.render_template("Custom.TRUDI.Win.NewLogon", bl)
        assert "${" not in lg and "watch_evtx" in lg and "10.0.0.9" in lg
        pe = render.render_template("Custom.TRUDI.Win.NewPersistence", bl)
        # autoruns allowlist is injected as a JSON array literal (the distinctive
        # token survives; backslashes in real identities are JSON-escaped).
        assert "${" not in pe and "registry" in pe and "TrudiMarker" in pe


class TestClientOsFamily:
    def test_windows_detected(self, monkeypatch):
        import tools.velo as velo
        monkeypatch.setattr(velo, "query", lambda vql: {"rows": [{"system": "windows"}]})
        assert monitor_mod._client_os_family("C.abc") == "windows"

    def test_linux_default(self, monkeypatch):
        import tools.velo as velo
        monkeypatch.setattr(velo, "query", lambda vql: {"rows": [{"system": "linux"}]})
        assert monitor_mod._client_os_family("C.abc") == "linux"

    def test_unresolved_defaults_linux(self, monkeypatch):
        import tools.velo as velo
        monkeypatch.setattr(velo, "query", lambda vql: {"rows": []})
        assert monitor_mod._client_os_family("C.abc") == "linux"


class TestWindowsBaseline:
    def _fake_velo(self, monkeypatch, ps_rows, snap_rows):
        import tools.velo as velo
        monkeypatch.setattr(velo, "collect_artifact",
                            lambda c, a, parameters=None, **k: {"success": True, "flow_id": f"F.{a}"})
        monkeypatch.setattr(velo, "wait_for_flow",
                            lambda *a, **k: {"success": True, "final_state": "FINISHED"})

        def results(c, fid, artifact, *, full_output=False):
            assert full_output
            if artifact == "Windows.System.Pslist":
                return {"rows": ps_rows}
            if artifact == "Custom.TRUDI.Win.PersistenceSnapshot":
                return {"rows": snap_rows}
            return {"rows": []}
        monkeypatch.setattr(velo, "get_collection_results", results)
        monkeypatch.setattr(velo, "upload_artifact_yaml", lambda y: {"success": True})

    def test_captures_windows_baseline(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        monkeypatch.setattr(monitor_mod, "_client_os_family", lambda c: "windows")
        self._fake_velo(
            monkeypatch,
            ps_rows=[{"Name": "System", "Exe": ""},
                     {"Name": "cmd.exe", "Exe": "C:\\Windows\\System32\\cmd.exe", "Username": "SYSTEM"}],
            snap_rows=[{"path": "HKLM\\...\\Run\\OneDrive", "identity": "HKLM\\...\\Run\\OneDrive|C:\\OneDrive.exe"},
                       {"path": "C:/Windows/System32/Tasks/MsCtfMonitor", "identity": "C:/Windows/System32/Tasks/MsCtfMonitor"}])
        r = monitor_mod.baseline_capture("C.winbox", "WINRDP-TEST")
        assert r["success"] is True and r["os_family"] == "windows"
        bl = json.loads((tmp_path / "WINRDP-TEST" / "monitoring" / "baselines" / "C.winbox.json").read_text())
        assert bl["os_family"] == "windows"
        assert "C:\\Windows\\System32\\cmd.exe" in bl["image_paths"]
        assert "cmd.exe" in bl["process_names"]
        assert "HKLM\\...\\Run\\OneDrive|C:\\OneDrive.exe" in bl["autoruns"]
        assert "C:/Windows/System32/Tasks/MsCtfMonitor" in bl["autoruns"]
        assert bl["logon_sources"] == []          # fresh host, first RDP is the signal
        assert bl["benign_signatures"] == [] and bl["extensions"] == []

    def test_dispatch_from_baseline_capture(self, tmp_path, monkeypatch):
        """baseline_capture routes a Windows client to the Windows path."""
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        monkeypatch.setattr(monitor_mod, "_client_os_family", lambda c: "windows")
        called = {}

        def _stub(c, case, t):
            called["win"] = (c, case)
            return {"success": True}
        monkeypatch.setattr(monitor_mod, "_baseline_capture_windows", _stub)
        r = monitor_mod.baseline_capture("C.winbox", "WINRDP-TEST")
        assert r["success"] is True and called["win"] == ("C.winbox", "WINRDP-TEST")


class TestStartWatcherOsSelection:
    def test_windows_baseline_gets_windows_detectors(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        case_id, cid = "WINRDP-TEST", "C.winbox"
        bdir = tmp_path / case_id / "monitoring" / "baselines"
        bdir.mkdir(parents=True)
        (bdir / f"{cid}.json").write_text(json.dumps({"os_family": "windows", "image_paths": [],
                                                       "process_names": [], "autoruns": [], "logon_sources": []}))
        import tools.velo as velo
        pushed = []
        monkeypatch.setattr(velo, "upload_artifact_yaml",
                            lambda y: (pushed.append(y.splitlines()[0].split("name: ")[1]), {"success": True})[1])
        monkeypatch.setattr(velo, "update_client_event_table", lambda c, a, parameters=None: {"success": True})

        class _Proc:
            pid = 5555
        monkeypatch.setattr(monitor_mod.subprocess, "Popen", lambda *a, **k: _Proc())

        r = monitor_mod.start_watcher(cid, case_id)
        assert r["success"] is True
        assert set(r["artifacts"]) == set(render.list_detector_templates("windows"))
        assert all(".Win." in n for n in pushed)
        # The Windows set is NewProcess + NewLogon + NewPersistence; NewProcess is
        # paired with... there is no Win NewPersistence/NewProcess split warning,
        # but the coverage check keys on the LINUX names, so no warning here.
        assert r["warnings"] == []


class TestSidecarWindowsLeaf:
    def _w(self):
        spec = importlib.util.spec_from_file_location("w_win", str(SIDECAR))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def test_leaf_normalisation(self):
        w = self._w()
        assert w._detector_leaf("Custom.TRUDI.Win.NewProcess") == "NewProcess"
        assert w._detector_leaf("Custom.TRUDI.NewProcess") == "NewProcess"

    def test_windows_process_signature_and_dedup(self):
        w = self._w()
        row = {"image_path": "C:\\tmp\\evil.exe", "pid": "4242", "started_utc": "t"}
        det = "Custom.TRUDI.Win.NewProcess"
        assert w._row_signature(det, row)
        assert w._should_emit(det, row) is True
        assert w._should_emit(det, row) is False

    def test_windows_logon_signature(self):
        w = self._w()
        det = "Custom.TRUDI.Win.NewLogon"
        row = {"source_ip": "10.73.0.3", "account": "rdpadmin", "logon_type": 10}
        sig = w._row_signature(det, row)
        assert sig == ""  # no event identity: do not suppress later sessions

    def test_windows_persistence_signature_uses_identity(self):
        w = self._w()
        det = "Custom.TRUDI.Win.NewPersistence"
        row = {"path": "HKCU\\...\\Run", "identity": "HKCU\\...\\Run\\TrudiImplant|cmd.exe /c echo"}
        assert w._row_signature(det, row) == "HKCU\\...\\Run\\TrudiImplant|cmd.exe /c echo"

    def test_windows_summaries_and_severity(self):
        w = self._w()
        assert "Windows process" in w._summarize_row("Custom.TRUDI.Win.NewProcess",
                                                     {"image_path": "x", "pid": 1})
        assert "logon type 10" in w._summarize_row("Custom.TRUDI.Win.NewLogon",
                                                   {"logon_type": 10, "account": "rdpadmin", "source_ip": "10.73.0.3"})
        assert w._severity("Custom.TRUDI.Win.NewLogon") == "high"

    def test_windows_process_merge(self, tmp_path):
        w = self._w()
        alerts = tmp_path / "monitoring" / "alerts"
        alerts.mkdir(parents=True)
        p1 = w._write_alert(alerts, "WINRDP", "C.win", "Custom.TRUDI.Win.NewProcess",
                            {"pid": "900", "image_path": "C:\\x.exe", "started_utc": "t1"})
        # A YaraProcess row on the same pid folds in (both are process-leaf).
        merged = w._try_merge(alerts, "C.win", "Custom.TRUDI.YaraProcess",
                              {"pid": "900", "image_path": "C:\\x.exe", "started_utc": "t1"})
        # another detector, same process incarnation → grouped
        assert merged == p1
        assert len(list(alerts.glob("*_*.json"))) == 1
