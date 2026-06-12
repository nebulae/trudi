"""Baseline persistence-allowlist tests.

Regression cover for the empty-allowlist false-positive bug: the baseline must
enumerate the SAME persistence surface the NewPersistence detector globs (via
Custom.TRUDI.PersistenceSnapshot), not Linux.Sys.Crontab (cron schedules, empty
on a stock box).
"""
import json

import pytest

from monitoring import render
from tools import monitor as monitor_mod


class TestRenderWatchDirs:
    def test_detector_gets_watch_dirs_and_allowlist(self):
        y = render.render_template(
            "Custom.TRUDI.NewPersistence",
            {"persistence_paths": ["/etc/cron.d/e2scrub_all",
                                   "/etc/systemd/system/sshd.service"]})
        assert "${watch_dirs}" not in y          # substituted
        assert "/etc/cron.d/*" in y               # canonical glob present
        assert "/etc/cron.d/e2scrub_all" in y     # baseline allowlist present

    def test_watch_globs_are_the_canonical_constant(self):
        y = render.render_template("Custom.TRUDI.NewPersistence", {})
        for g in render.PERSISTENCE_WATCH_GLOBS:
            assert g in y


class TestBaselinePersistenceSnapshot:
    def test_persistence_comes_from_snapshot_not_crontab(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)

        # Crontab is no longer a baseline source.
        assert "Linux.Sys.Crontab" not in monitor_mod.BASELINE_ARTIFACTS

        snap_paths = ["/etc/cron.d/e2scrub_all", "/etc/cron.daily/apt-compat",
                      "/etc/systemd/system/sshd.service"]

        def fake_collect(client_id, artifact, parameters=None, **kw):
            # The snapshot must be collected with the canonical WatchDirs.
            if artifact == monitor_mod.PERSISTENCE_SNAPSHOT_ARTIFACT:
                assert parameters and json.loads(parameters["WatchDirs"]) == \
                    render.PERSISTENCE_WATCH_GLOBS
            return {"success": True, "flow_id": f"F.{artifact}"}

        def fake_wait(client_id, fid, timeout_seconds=300):
            return {"success": True, "final_state": "FINISHED"}

        def fake_results(client_id, fid, artifact):
            if artifact == "Linux.Sys.Pslist":
                return {"rows": [{"Name": "sshd", "Exe": "/usr/sbin/sshd"}]}
            if artifact == monitor_mod.PERSISTENCE_SNAPSHOT_ARTIFACT:
                return {"rows": [{"path": p} for p in snap_paths]}
            return {"rows": []}

        import tools.velo as velo
        monkeypatch.setattr(velo, "collect_artifact", fake_collect)
        monkeypatch.setattr(velo, "wait_for_flow", fake_wait)
        monkeypatch.setattr(velo, "get_collection_results", fake_results)
        monkeypatch.setattr(velo, "upload_artifact_yaml", lambda y: {"success": True})

        r = monitor_mod.baseline_capture("C.deadbeef", "DEMO-TEST")
        assert r["success"] is True
        baseline = json.loads(
            (tmp_path / "DEMO-TEST" / "monitoring" / "baselines" / "C.deadbeef.json").read_text())
        assert sorted(baseline["persistence_paths"]) == sorted(snap_paths)

    def test_snapshot_upload_failure_fails_baseline(self, tmp_path, monkeypatch):
        # If the snapshot can't be collected we must NOT silently produce an
        # empty allowlist (the bug) — fail loudly instead.
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        import tools.velo as velo
        monkeypatch.setattr(velo, "collect_artifact",
                            lambda *a, **k: {"success": True, "flow_id": "F.x"})
        monkeypatch.setattr(velo, "wait_for_flow",
                            lambda *a, **k: {"success": True, "final_state": "FINISHED"})
        monkeypatch.setattr(velo, "get_collection_results", lambda *a, **k: {"rows": []})
        monkeypatch.setattr(velo, "upload_artifact_yaml",
                            lambda y: {"success": False, "error": "boom"})
        r = monitor_mod.baseline_capture("C.deadbeef", "DEMO-TEST")
        assert r["success"] is False
        assert monitor_mod.PERSISTENCE_SNAPSHOT_ARTIFACT in r["error"]
