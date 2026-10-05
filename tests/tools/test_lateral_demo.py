"""Tests for the two-host lateral-movement demo additions:

- the NewLogon / PrivilegeEscalation detector templates render with their
  baseline allowlists substituted,
- baseline_capture records logon_sources + root_image_paths,
- monitor.verify_clean recomputes per-detector residuals from a fresh snapshot.
"""
import json

import pytest

from monitoring import render
from tools import monitor as monitor_mod


class TestLateralDetectorRender:
    def test_newlogon_renders_with_sources(self):
        y = render.render_template(
            "Custom.TRUDI.NewLogon", {"logon_sources": ["172.18.0.1", "172.19.0.1"]})
        assert "${baseline_logon_sources}" not in y
        assert "172.18.0.1" in y and "172.19.0.1" in y
        assert "NetstatEnriched" in y

    def test_privesc_renders_with_root_images(self):
        y = render.render_template(
            "Custom.TRUDI.PrivilegeEscalation",
            {"root_image_paths": ["/usr/sbin/sshd", "/sbin/init"]})
        assert "${baseline_root_image_paths}" not in y
        assert "/usr/sbin/sshd" in y
        assert 'Username = "root"' in y

    def test_empty_baseline_still_valid(self):
        # No allowlist keys → renders a valid "allow nothing" filter, no leftover
        # placeholders.
        for d in ("Custom.TRUDI.NewLogon", "Custom.TRUDI.PrivilegeEscalation"):
            y = render.render_template(d, {})
            assert "${" not in y

    def test_both_detectors_discovered(self):
        dets = render.list_detector_templates()
        assert "Custom.TRUDI.NewLogon" in dets
        assert "Custom.TRUDI.PrivilegeEscalation" in dets


def _fake_velo(monkeypatch, pslist, netstat, persist):
    def fake_collect(client_id, artifact, parameters=None, **kw):
        return {"success": True, "flow_id": f"F.{artifact}"}

    def fake_wait(client_id, fid, timeout_seconds=300):
        return {"success": True, "final_state": "FINISHED"}

    def fake_results(client_id, fid, artifact):
        if artifact == "Linux.Sys.Pslist":
            return {"rows": pslist}
        if artifact in ("Linux.Network.Netstat", "Linux.Network.NetstatEnriched"):
            return {"rows": netstat}
        if artifact == monitor_mod.PERSISTENCE_SNAPSHOT_ARTIFACT:
            return {"rows": persist}
        return {"rows": []}

    import tools.velo as velo
    monkeypatch.setattr(velo, "collect_artifact", fake_collect)
    monkeypatch.setattr(velo, "wait_for_flow", fake_wait)
    monkeypatch.setattr(velo, "get_collection_results", fake_results)
    monkeypatch.setattr(velo, "upload_artifact_yaml", lambda y: {"success": True})


class TestBaselineLateralFields:
    def test_baseline_records_root_images_and_logon_sources(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        pslist = [
            {"Name": "sshd", "Exe": "/usr/sbin/sshd", "Username": "root"},
            {"Name": "bash", "Exe": "/bin/bash", "Username": "victim"},
        ]
        netstat = [
            {"Laddr": {"Port": 22}, "Raddr": {"IP": "172.18.0.1", "Port": 5000},
             "Status": "ESTABLISHED"},
        ]
        _fake_velo(monkeypatch, pslist, netstat, [{"path": "/etc/cron.d/e2scrub_all"}])
        r = monitor_mod.baseline_capture("C.abc", "LAT-TEST")
        assert r["success"] is True
        bl = json.loads((tmp_path / "LAT-TEST" / "monitoring" / "baselines" / "C.abc.json").read_text())
        assert bl["root_image_paths"] == ["/usr/sbin/sshd"]
        assert bl["logon_sources"] == ["172.18.0.1"]


class TestVerifyClean:
    def _write_baseline(self, tmp_path, client="C.abc", case="LAT-TEST"):
        d = tmp_path / case / "monitoring" / "baselines"
        d.mkdir(parents=True)
        (d / f"{client}.json").write_text(json.dumps({
            "image_paths": ["/usr/sbin/sshd", "/bin/bash"],
            "process_names": ["sshd", "bash"],
            "root_image_paths": ["/usr/sbin/sshd"],
            "persistence_paths": ["/etc/cron.d/e2scrub_all"],
            "logon_sources": ["172.18.0.1"],
            "endpoints": [],
        }))

    def test_clean_when_matches_baseline(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        self._write_baseline(tmp_path)
        _fake_velo(monkeypatch,
                   pslist=[{"Name": "sshd", "Exe": "/usr/sbin/sshd", "Username": "root"}],
                   netstat=[{"Laddr": {"Port": 22}, "Raddr": {"IP": "172.18.0.1", "Port": 5000},
                             "Status": "ESTABLISHED"}],
                   persist=[{"path": "/etc/cron.d/e2scrub_all"}])
        r = monitor_mod.verify_clean("C.abc", "LAT-TEST")
        assert r["success"] is True
        assert r["clean"] is True
        assert all(c == 0 for c in r["residual_counts"].values())

    def test_detects_residual_intrusion(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        self._write_baseline(tmp_path)
        _fake_velo(monkeypatch,
                   pslist=[
                       {"Name": "sshd", "Exe": "/usr/sbin/sshd", "Username": "root"},
                       {"Name": ".trudi-rootsvc", "Exe": "/usr/local/sbin/.trudi-rootsvc",
                        "Username": "root", "Pid": 106},
                       {"Name": ".systemd-private", "Exe": "/tmp/.systemd-private",
                        "Username": "devops", "Pid": 98},
                   ],
                   netstat=[{"Laddr": {"Port": 22}, "Raddr": {"IP": "10.73.0.3", "Port": 44130},
                             "Status": "ESTABLISHED", "Pid": 200}],
                   persist=[{"path": "/etc/cron.d/e2scrub_all"},
                            {"path": "/etc/cron.d/trudi-pivot"}])
        r = monitor_mod.verify_clean("C.abc", "LAT-TEST")
        assert r["clean"] is False
        rc = r["residual_counts"]
        assert rc["Custom.TRUDI.PrivilegeEscalation"] == 1   # the root binary
        assert rc["Custom.TRUDI.NewPersistence"] == 1        # the pivot cron
        assert rc["Custom.TRUDI.NewLogon"] == 1              # held session from 10.73.0.3
        assert rc["Custom.TRUDI.NewProcess"] >= 1            # dropped tool

    def test_gateway_and_zombie_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        self._write_baseline(tmp_path)
        _fake_velo(monkeypatch,
                   pslist=[{"Name": ".trudi-rootsvc", "Exe": "/usr/local/sbin/.trudi-rootsvc",
                            "Username": "root", "Status": "zombie", "Pid": 106}],
                   netstat=[{"Laddr": {"Port": 22}, "Raddr": {"IP": "172.18.0.1", "Port": 5000},
                             "Status": "ESTABLISHED"}],   # gateway .1, management plane
                   persist=[{"path": "/etc/cron.d/e2scrub_all"}])
        r = monitor_mod.verify_clean("C.abc", "LAT-TEST")
        # zombie root proc skipped; .1 gateway logon skipped → clean
        assert r["clean"] is True

    def test_ephemeral_tooling_not_flagged(self, tmp_path, monkeypatch):
        # The collection's own transient processes (ps/dash/sleep in standard bin
        # dirs) must NOT read as residual intrusion; a novel-path implant must.
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        self._write_baseline(tmp_path)
        _fake_velo(monkeypatch,
                   pslist=[
                       {"Name": "ps", "Exe": "/usr/bin/ps", "Username": "root", "Pid": 900},
                       {"Name": "dash", "Exe": "/usr/bin/dash", "Username": "root", "Pid": 901},
                       {"Name": "sleep", "Exe": "/usr/bin/sleep", "Username": "devops", "Pid": 902},
                       {"Name": "evil", "Exe": "/tmp/evil", "Username": "root", "Pid": 903},
                   ],
                   netstat=[], persist=[{"path": "/etc/cron.d/e2scrub_all"}])
        r = monitor_mod.verify_clean("C.abc", "LAT-TEST")
        assert r["clean"] is False
        # only the /tmp implant remains; ps/dash/sleep filtered as ephemeral
        assert r["residual_counts"]["Custom.TRUDI.PrivilegeEscalation"] == 1
        paths = [x["image_path"] for x in r["residuals"]["Custom.TRUDI.PrivilegeEscalation"]]
        assert paths == ["/tmp/evil"]
        assert r["residual_counts"]["Custom.TRUDI.NewProcess"] == 1

    def test_no_baseline_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        r = monitor_mod.verify_clean("C.none", "LAT-TEST")
        assert r["success"] is False and "baseline" in r["error"]
