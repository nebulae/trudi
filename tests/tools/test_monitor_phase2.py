"""Phase 2 — stop the daily false-positive investigations.

Covers: ancestry-aware detector templates, crontab-aware baseline, the
benign-verdict feedback tool (`baseline_extend`), `check_alerts`'s
known-benign stamping, `verify_clean` mirroring the new rules, and the
sidecar's cross-detector merge. Regression for DECOY-DEMO INV-002 / INV-003,
where the stock Ubuntu cron.daily chain at 06:25 UTC opened a full
investigation two mornings running.
"""
import importlib.util
import json
from pathlib import Path

import pytest

from monitoring import render
from tools import monitor as monitor_mod

HERE = Path(__file__).resolve()
SIDECAR = HERE.parents[2] / "bin" / "trudi-velo-watcher.py"

# The DECOY-DEMO process table on 2026-10-09 06:27 UTC (cron.daily running),
# plus a user-shell → sudo → root implant chain and a cron job dropping to /tmp.
SYNTHETIC_PS = [
    {"Pid": "1", "Ppid": "0", "Exe": "/usr/sbin/docker-init", "Username": "root", "Name": "docker-init", "CommandLine": "/sbin/docker-init"},
    {"Pid": "31", "Ppid": "1", "Exe": "/usr/sbin/cron", "Username": "root", "Name": "cron", "CommandLine": "/usr/sbin/cron -P"},
    {"Pid": "745", "Ppid": "31", "Exe": "/usr/sbin/cron", "Username": "root", "Name": "cron", "CommandLine": "/usr/sbin/CRON -P"},
    {"Pid": "746", "Ppid": "745", "Exe": "/usr/bin/dash", "Username": "root", "Name": "sh", "CommandLine": "/bin/sh -c test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )"},
    {"Pid": "747", "Ppid": "746", "Exe": "/usr/bin/run-parts", "Username": "root", "Name": "run-parts", "CommandLine": "run-parts --report /etc/cron.daily"},
    {"Pid": "748", "Ppid": "747", "Exe": "/usr/bin/dash", "Username": "root", "Name": "apt-compat", "CommandLine": "/bin/sh /etc/cron.daily/apt-compat"},
    {"Pid": "755", "Ppid": "748", "Exe": "/usr/bin/sleep", "Username": "root", "Name": "sleep", "CommandLine": "sleep 1140"},
    {"Pid": "760", "Ppid": "745", "Exe": "/usr/bin/python3", "Username": "root", "Name": "python3", "CommandLine": "/usr/bin/python3 /tmp/evil.py"},
    {"Pid": "32", "Ppid": "1", "Exe": "/usr/sbin/sshd", "Username": "root", "Name": "sshd", "CommandLine": "sshd -D"},
    {"Pid": "400", "Ppid": "32", "Exe": "/usr/sbin/sshd", "Username": "victim", "Name": "sshd", "CommandLine": "sshd: victim@pts/0"},
    {"Pid": "401", "Ppid": "400", "Exe": "/usr/bin/bash", "Username": "victim", "Name": "bash", "CommandLine": "-bash"},
    {"Pid": "402", "Ppid": "401", "Exe": "/usr/bin/sudo", "Username": "root", "Name": "sudo", "CommandLine": "sudo /tmp/.implant"},
    {"Pid": "403", "Ppid": "402", "Exe": "/tmp/.implant", "Username": "root", "Name": ".implant", "CommandLine": "/tmp/.implant"},
    {"Pid": "120", "Ppid": "1", "Exe": "/usr/bin/bash", "Username": "root", "Name": ".rdp-probe", "CommandLine": "/bin/bash /tmp/.rdp-probe decoy 3389 linda 3600"},
]

STOCK_CRON_DUMP = """## /etc/crontab
# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly
25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
## /etc/cron.d/e2scrub_all
30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r
## /var/spool/cron/crontabs/victim
@reboot /home/victim/bin/sync.sh
## /etc/cron.daily/
.placeholder
apt-compat
dpkg
"""


def _baseline():
    return {"process_names": ["cron", "docker-init", "sshd", "velociraptor"],
            "image_paths": ["/usr/local/bin/velociraptor", "/usr/sbin/cron",
                            "/usr/sbin/docker-init", "/usr/sbin/sshd"],
            "root_image_paths": ["/usr/local/bin/velociraptor", "/usr/sbin/cron",
                                 "/usr/sbin/docker-init", "/usr/sbin/sshd"],
            "cron_daemon_images": ["/usr/sbin/cron"],
            "persistence_paths": ["/etc/crontab"], "persistence_fingerprints": ["/etc/crontab|abc"],
            "endpoints": [], "logon_sources": []}


# ── Templates ───────────────────────────────────────────────────────────────

class TestAncestryTemplates:
    def test_newprocess_template_has_scheduled_work_exemption(self):
        y = render.render_template("Custom.TRUDI.NewProcess", _baseline())
        assert "${" not in y
        assert '["/usr/sbin/cron"]' in y                      # CronDaemonImages from baseline
        assert "scheduled_work" in y and "DropPathRegex" in y
        assert "parent_exe" in y and "ancestry" in y
        # The exemption regexes are injected from render's canonical patterns
        # (JSON-encoded), so /usr/local + /opt are trusted and /home + /root are
        # not treated as staging dirs.
        assert render.TRUSTED_BIN_REGEX in y and "/opt/" in y
        assert "home|root" not in y

    def test_newprocess_template_defaults_cron_images(self):
        b = _baseline(); b.pop("cron_daemon_images")
        y = render.render_template("Custom.TRUDI.NewProcess", b)
        for img in render.DEFAULT_CRON_DAEMON_IMAGES:
            assert img in y

    def test_privesc_template_requires_uid_boundary(self):
        y = render.render_template("Custom.TRUDI.PrivilegeEscalation", _baseline())
        assert "${" not in y
        assert "nonroot_hops" in y and "EscalationBrokers" in y
        assert "/usr/bin/sudo" in y
        assert "Status" not in y          # not a Linux.Sys.Pslist column in 0.76


# ── Baseline: crontab parsing + capture fields ──────────────────────────────

class TestCrontabParse:
    def test_stock_ubuntu_dump(self):
        jobs = monitor_mod._parse_crontab_dump(STOCK_CRON_DUMP)
        by_src = {}
        for j in jobs:
            by_src.setdefault(j["source"], []).append(j)
        daily = next(j for j in by_src["/etc/crontab"] if j["schedule"] == "25 6 * * *")
        assert daily["user"] == "root" and daily["command"].startswith("test -x /usr/sbin/anacron")
        assert len(by_src["/etc/crontab"]) == 4                       # comments / VAR= skipped
        assert len(by_src["/etc/cron.d/e2scrub_all"]) == 2
        user_job = by_src["/var/spool/cron/crontabs/victim"][0]
        assert user_job["schedule"] == "@reboot" and user_job["user"] == "victim"
        assert user_job["command"] == "/home/victim/bin/sync.sh"
        scripts = [j["command"] for j in by_src["/etc/cron.daily"]]
        assert scripts == ["/etc/cron.daily/apt-compat", "/etc/cron.daily/dpkg"]  # .placeholder dropped

    def test_empty_and_garbage(self):
        assert monitor_mod._parse_crontab_dump("") == []
        assert monitor_mod._parse_crontab_dump("no section header\n1 2 3") == []


class TestBaselineCaptureScheduledWork:
    def test_records_cron_images_and_jobs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        import tools.velo as velo
        commands = []

        def fake_collect(client_id, artifact, parameters=None, **kw):
            if artifact == "Linux.Sys.BashShell":
                commands.append(parameters["Command"])
            return {"success": True, "flow_id": f"F.{artifact}"}

        def fake_results(client_id, fid, artifact, **kwargs):
            if artifact == "Linux.Sys.Pslist":
                return {"rows": [{"Name": "cron", "Exe": "/usr/sbin/cron", "Username": "root"},
                                 {"Name": "sshd", "Exe": "/usr/sbin/sshd", "Username": "root"}]}
            if artifact == "Linux.Sys.BashShell":
                return {"rows": [{"Stdout": STOCK_CRON_DUMP}]}
            return {"rows": []}

        monkeypatch.setattr(velo, "collect_artifact", fake_collect)
        monkeypatch.setattr(velo, "wait_for_flow", lambda *a, **k: {"success": True, "final_state": "FINISHED"})
        monkeypatch.setattr(velo, "get_collection_results", fake_results)
        monkeypatch.setattr(velo, "upload_artifact_yaml", lambda y: {"success": True})

        r = monitor_mod.baseline_capture("C.deadbeef", "DEMO-TEST")
        assert r["success"] is True
        assert commands and "/etc/crontab" in commands[0]
        b = json.loads((tmp_path / "DEMO-TEST" / "monitoring" / "baselines" / "C.deadbeef.json").read_text())
        assert b["cron_daemon_images"] == ["/usr/sbin/cron"]
        assert any(j["schedule"] == "25 6 * * *" for j in b["scheduled_jobs"])
        assert b["benign_signatures"] == [] and b["extensions"] == []
        assert r["summary"]["scheduled_jobs"] == len(b["scheduled_jobs"])

    def test_bashshell_failure_is_not_fatal(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        import tools.velo as velo

        def fake_collect(client_id, artifact, parameters=None, **kw):
            if artifact == "Linux.Sys.BashShell":
                return {"success": False, "error": "no shell"}
            return {"success": True, "flow_id": f"F.{artifact}"}

        monkeypatch.setattr(velo, "collect_artifact", fake_collect)
        monkeypatch.setattr(velo, "wait_for_flow", lambda *a, **k: {"success": True, "final_state": "FINISHED"})
        monkeypatch.setattr(velo, "get_collection_results", lambda *a, **k: {"rows": []})
        monkeypatch.setattr(velo, "upload_artifact_yaml", lambda y: {"success": True})
        r = monitor_mod.baseline_capture("C.deadbeef", "DEMO-TEST")
        assert r["success"] is True
        assert "no shell" in r["summary"]["scheduled_jobs_note"]
        b = json.loads((tmp_path / "DEMO-TEST" / "monitoring" / "baselines" / "C.deadbeef.json").read_text())
        assert b["scheduled_jobs"] == []
        assert b["cron_daemon_images"] == render.DEFAULT_CRON_DAEMON_IMAGES   # fallback


# ── Ancestry rules (verify_clean mirror of the detectors) ───────────────────

class TestAncestryRules:
    def test_flags(self):
        f = monitor_mod._ancestry_flags(SYNTHETIC_PS, {"/usr/sbin/cron"})
        assert f["755"]["cron_descendant"] and not f["755"]["nonroot_ancestor"]
        assert f["755"]["parent_exe"] == "/usr/bin/dash"
        assert f["403"]["nonroot_ancestor"] and not f["403"]["cron_descendant"]
        assert f["402"]["nonroot_ancestor"]                     # sudo: parent is the user shell
        assert not f["120"]["nonroot_ancestor"]                 # root → root (decoy probe)
        assert f["1"] == {"nonroot_ancestor": False, "cron_descendant": False, "parent_exe": None}

    def test_scheduled_work_exemption(self):
        f = monitor_mod._ancestry_flags(SYNTHETIC_PS, {"/usr/sbin/cron"})
        row = {r["Pid"]: r for r in SYNTHETIC_PS}
        assert monitor_mod._is_scheduled_work(row["755"]["Exe"], row["755"]["CommandLine"], f["755"], schedule_intact=True)
        assert monitor_mod._is_scheduled_work(row["747"]["Exe"], row["747"]["CommandLine"], f["747"], schedule_intact=True)
        # cron job dropping to /tmp: interpreter is standard, command line is not
        assert not monitor_mod._is_scheduled_work(row["760"]["Exe"], row["760"]["CommandLine"], f["760"], schedule_intact=True)
        # implant: not cron-descended, not a standard bin
        assert not monitor_mod._is_scheduled_work(row["403"]["Exe"], row["403"]["CommandLine"], f["403"], schedule_intact=True)

    def test_production_path_semantics(self):
        """The trusted-bin and drop-path sets must reflect real hosts, not the
        demo's /tmp-only view: /usr/local and /opt scheduled jobs are exempt,
        legitimate user/root crontabs under /home and /root are NOT voided, and
        the world-writable staging dirs still void the exemption."""
        cron = {"cron_descendant": True}
        notcron = {"cron_descendant": False}
        # /usr/local and /opt binaries a cron job may legitimately run:
        assert monitor_mod._is_scheduled_work("/usr/local/bin/backup", "/usr/local/bin/backup --full", cron, schedule_intact=True)
        assert monitor_mod._is_scheduled_work("/usr/local/sbin/logrotate", "/usr/local/sbin/logrotate", cron, schedule_intact=True)
        assert monitor_mod._is_scheduled_work("/opt/app/bin/report", "/opt/app/bin/report", cron, schedule_intact=True)
        # user and root crontab commands referencing their own dirs are NOT a
        # staging location — exemption holds (regression: /home,/root removed):
        assert monitor_mod._is_scheduled_work("/usr/bin/bash", "/usr/bin/bash /home/alice/bin/sync.sh", cron, schedule_intact=True)
        assert monitor_mod._is_scheduled_work("/usr/bin/bash", "/usr/bin/bash /root/maint.sh", cron, schedule_intact=True)
        # world-writable staging dirs still void it:
        for drop in ("/tmp/x", "/var/tmp/x", "/dev/shm/x"):
            assert not monitor_mod._is_scheduled_work("/usr/bin/python3", f"/usr/bin/python3 {drop}", cron, schedule_intact=True)
        # a trusted-bin path is exempt ONLY in combination with cron descent — a
        # non-cron process in /usr/local/sbin (the lateral implant) still alerts:
        assert not monitor_mod._is_scheduled_work("/usr/local/sbin/.rootsvc", "/usr/local/sbin/.rootsvc", notcron, schedule_intact=True)

    def test_python_mirror_tracks_render(self):
        # One source of truth: verify_clean's regexes ARE render's patterns.
        assert monitor_mod.SCHEDULED_WORK_BIN_RE.pattern == render.TRUSTED_BIN_REGEX
        assert monitor_mod.DROP_PATH_RE.pattern == render.DROP_PATH_REGEX


class TestDetectorCoverageDependency:
    """The NewProcess scheduled-work exemption is only safe with NewPersistence
    running (a new attacker cron file is caught file-side). start_watcher must
    surface that blind spot when the pair is split — never silently."""

    def test_split_pair_warns(self):
        w = monitor_mod._detector_coverage_warnings(["Custom.TRUDI.NewProcess"])
        assert len(w) == 1
        assert "NewPersistence" in w[0] and "blind spot" in w[0]

    def test_pair_together_no_warning(self):
        assert monitor_mod._detector_coverage_warnings(
            ["Custom.TRUDI.NewProcess", "Custom.TRUDI.NewPersistence"]) == []

    def test_persistence_only_no_warning(self):
        assert monitor_mod._detector_coverage_warnings(["Custom.TRUDI.NewPersistence"]) == []

    def test_full_default_set_no_warning(self):
        assert monitor_mod._detector_coverage_warnings(render.list_detector_templates()) == []

    def test_start_watcher_surfaces_warning(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        case_id, cid = "DEMO-TEST", "C.deadbeef"
        bdir = tmp_path / case_id / "monitoring" / "baselines"
        bdir.mkdir(parents=True)
        (bdir / f"{cid}.json").write_text(json.dumps(_baseline()))
        import tools.velo as velo
        monkeypatch.setattr(velo, "upload_artifact_yaml", lambda y: {"success": True})
        monkeypatch.setattr(velo, "update_client_event_table", lambda c, a, parameters=None: {"success": True})

        class _Proc:
            pid = 4321
        monkeypatch.setattr(monitor_mod.subprocess, "Popen", lambda *a, **k: _Proc())

        r = monitor_mod.start_watcher(cid, case_id, detectors=["Custom.TRUDI.NewProcess"])
        assert r["success"] is True
        assert r["warnings"] and "NewPersistence" in r["warnings"][0]
        log = (tmp_path / case_id / "monitoring" / "watchers" / f"{cid}.log").read_text()
        assert "[watcher][WARNING]" in log and "blind spot" in log

    def test_verify_clean_mirrors_rules(self, tmp_path, monkeypatch):
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        case_id, cid = "DEMO-TEST", "C.deadbeef"
        bdir = tmp_path / case_id / "monitoring" / "baselines"
        bdir.mkdir(parents=True)
        (bdir / f"{cid}.json").write_text(json.dumps(_baseline()))
        import tools.velo as velo
        monkeypatch.setattr(velo, "collect_artifact", lambda *a, **k: {"success": True, "flow_id": "F.x"})
        monkeypatch.setattr(velo, "wait_for_flow", lambda *a, **k: {"success": True, "final_state": "FINISHED"})

        def fake_results(client_id, fid, artifact, **kwargs):
            if artifact == "Linux.Sys.Pslist":
                return {"rows": SYNTHETIC_PS}
            if artifact == "Custom.TRUDI.PersistenceSnapshot":
                return {"rows": [{"path": "/etc/crontab", "sha256": "abc"}]}
            return {"rows": []}
        monkeypatch.setattr(velo, "get_collection_results", fake_results)
        monkeypatch.setattr(velo, "upload_artifact_yaml", lambda y: {"success": True})

        r = monitor_mod.verify_clean(cid, case_id)
        assert r["success"] is True and r["clean"] is False
        proc_imgs = {x["image_path"] for x in r["residuals"]["Custom.TRUDI.NewProcess"]}
        privesc_imgs = {x["image_path"] for x in r["residuals"]["Custom.TRUDI.PrivilegeEscalation"]}
        # The cron chain is NOT a residual; the implant and the /tmp-dropping cron job are.
        assert "/usr/bin/run-parts" not in proc_imgs and "/usr/bin/sleep" not in proc_imgs
        assert "/tmp/.implant" in proc_imgs
        # python3 is an ephemeral std tool by name, but the /tmp drop path voids the
        # exemption — and the ephemeral filter runs first, so it is excluded there.
        assert "/tmp/.implant" in privesc_imgs
        assert "/usr/bin/sudo" not in privesc_imgs            # broker
        assert "/usr/bin/dash" not in privesc_imgs            # all-root cron chain


# ── Signatures, feedback, recurrence ────────────────────────────────────────

def _alert(seq, detector, pid, image, cmd, parent="/usr/bin/dash", client="C.deadbeef"):
    return {"alert_id": f"a-{seq}", "seq": seq, "case_id": "DEMO-TEST", "client_id": client,
            "detector": detector, "detectors": [detector], "severity": "high",
            "summary": f"{detector} {image} pid={pid}",
            "evidence": {"pid": str(pid), "image_path": image, "commandline": cmd,
                         "parent_exe": parent, "username": "root"},
            "consumed": False}


def _write_alerts(root, case_id, alerts):
    d = root / case_id / "monitoring" / "alerts"
    d.mkdir(parents=True, exist_ok=True)
    for a in alerts:
        (d / f"{a['seq']:08d}_{a['detector'].rsplit('.', 1)[-1]}.json").write_text(json.dumps(a))
    return d


class TestSignatures:
    def test_digits_and_whitespace_normalised(self):
        a = _alert(1, "Custom.TRUDI.NewProcess", 755, "/usr/bin/sleep", "sleep 1140")
        b = _alert(2, "Custom.TRUDI.PrivilegeEscalation", 1150, "/usr/bin/sleep", "sleep  1784")
        assert monitor_mod._alert_signature(a) == monitor_mod._alert_signature(b)
        assert monitor_mod._alert_signature(a) == "/usr/bin/sleep|sleep #|/usr/bin/dash"

    def test_parent_distinguishes(self):
        a = _alert(1, "Custom.TRUDI.NewProcess", 1, "/usr/bin/sleep", "sleep 5", parent="/usr/bin/dash")
        b = _alert(2, "Custom.TRUDI.NewProcess", 2, "/usr/bin/sleep", "sleep 5", parent="/tmp/.implant")
        assert monitor_mod._alert_signature(a) != monitor_mod._alert_signature(b)

    def test_empty_evidence_has_no_signature(self):
        assert monitor_mod._alert_signature({"evidence": {}}) == ""


class TestBaselineExtendAndRecurrence:
    @pytest.fixture
    def case(self, tmp_path, monkeypatch):
        import response.gates as G
        monkeypatch.setattr(monitor_mod, "CASES_ROOT", tmp_path)
        monkeypatch.setattr(G, "CASES_ROOT", tmp_path, raising=False)
        case_id, cid = "DEMO-TEST", "C.deadbeef"
        bdir = tmp_path / case_id / "monitoring" / "baselines"
        bdir.mkdir(parents=True)
        (bdir / f"{cid}.json").write_text(json.dumps(_baseline()))
        (tmp_path / case_id / "monitoring" / "_open_investigation.json").write_text(json.dumps(
            {"investigation_id": "INV-002", "alert_ids": ["a-4", "a-8"]}))
        alerts = [
            _alert(4, "Custom.TRUDI.NewProcess", 746, "/usr/bin/dash",
                   "/bin/sh -c test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )",
                   parent="/usr/sbin/cron"),
            _alert(8, "Custom.TRUDI.PrivilegeEscalation", 755, "/usr/bin/sleep", "sleep 1140"),
        ]
        _write_alerts(tmp_path, case_id, alerts)
        uploads, tables = [], []
        import tools.velo as velo
        monkeypatch.setattr(velo, "upload_artifact_yaml",
                            lambda y: (uploads.append(y.splitlines()[0]), {"success": True})[1])
        monkeypatch.setattr(velo, "update_client_event_table",
                            lambda c, arts, parameters=None: (tables.append(list(arts)), {"success": True})[1])
        return case_id, cid, tmp_path, uploads, tables

    def test_requires_reason(self, case):
        case_id, cid, *_ = case
        r = monitor_mod.baseline_extend(case_id, cid, image_paths=["/usr/bin/sleep"], reason="")
        assert r["success"] is False and "reason" in r["error"]

    def test_extends_records_and_repushes(self, case):
        case_id, cid, root, uploads, tables = case
        r = monitor_mod.baseline_extend(
            case_id, cid, image_paths=["/usr/bin/sleep", "/usr/bin/run-parts"],
            benign_alert_ids=["a-4", "a-8"], reason="stock cron.daily chain (F-1241)",
            finding_id="F-1241", evidence_call_ids=[1211, 1212])
        assert r["success"] is True
        assert r["investigation_id"] == "INV-002"
        assert sorted(r["added"]["image_paths"]) == ["/usr/bin/run-parts", "/usr/bin/sleep"]
        assert len(r["added"]["benign_signatures"]) == 2
        b = json.loads((root / case_id / "monitoring" / "baselines" / f"{cid}.json").read_text())
        assert "/usr/bin/sleep" in b["image_paths"]
        assert b["extensions"][0]["reason"].startswith("stock cron.daily")
        assert b["extensions"][0]["evidence_call_ids"] == [1211, 1212]
        assert b["benign_signatures"][0]["finding_id"] == "F-1241"
        # Every detector template re-rendered + uploaded, event table re-pushed.
        assert sorted(u.split("name: ")[1] for u in uploads) == sorted(render.list_detector_templates() + ["Custom.TRUDI.PersistenceSnapshot"])
        assert tables and set(render.list_detector_templates()) <= set(tables[0])
        # The re-rendered NewProcess carries the new allowlist entry.
        rendered = (root / case_id / "monitoring" / "artifacts" / cid / "Custom.TRUDI.NewProcess.yaml").read_text()
        assert "/usr/bin/sleep" in rendered

    def test_noop_when_nothing_new(self, case):
        case_id, cid, *_ = case
        monitor_mod.baseline_extend(case_id, cid, image_paths=["/usr/bin/sleep"], reason="x", repush=False)
        r = monitor_mod.baseline_extend(case_id, cid, image_paths=["/usr/bin/sleep"], reason="x", repush=False)
        assert r.get("noop") is True

    def test_check_alerts_marks_recurrence(self, case):
        case_id, cid, root, *_ = case
        monitor_mod.baseline_extend(case_id, cid, benign_alert_ids=["a-4", "a-8"],
                                    reason="stock cron.daily chain", finding_id="F-1241", repush=False)
        # Next morning: same chain, new pids, different random sleep.
        tomorrow = [
            _alert(12, "Custom.TRUDI.PrivilegeEscalation", 1150, "/usr/bin/sleep", "sleep 1784"),
            _alert(16, "Custom.TRUDI.NewProcess", 1141, "/usr/bin/dash",
                   "/bin/sh -c test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )",
                   parent="/usr/sbin/cron"),
        ]
        _write_alerts(root, case_id, tomorrow)
        r = monitor_mod.check_alerts(case_id, since_seq=8)
        assert r["count"] == 2 and r["all_known_benign"] is True
        for a in r["alerts"]:
            assert a["known_benign"]["finding_id"] == "F-1241"
            assert a["known_benign"]["investigation_id"] == "INV-002"
        # An unknown process in the batch breaks the fast path.
        _write_alerts(root, case_id, [_alert(17, "Custom.TRUDI.NewProcess", 2000, "/tmp/.x", "/tmp/.x", parent="/usr/bin/bash")])
        r2 = monitor_mod.check_alerts(case_id, since_seq=8)
        assert r2["count"] == 3 and r2["all_known_benign"] is False and r2["known_benign_count"] == 2


# ── Sidecar: cross-detector merge ───────────────────────────────────────────

class TestWatcherMerge:
    def _w(self):
        spec = importlib.util.spec_from_file_location("w_merge", str(SIDECAR))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m

    def test_second_detector_folds_into_first_alert(self, tmp_path):
        w = self._w()
        alerts = tmp_path / "monitoring" / "alerts"
        alerts.mkdir(parents=True)
        row_np = {"pid": "746", "image_path": "/usr/bin/dash", "started_utc": "2026-10-15T12:00:00Z", "commandline": "/bin/sh -c x"}
        row_pe = {"pid": "746", "image_path": "/usr/bin/dash", "started_utc": "2026-10-15T12:00:00Z", "commandline": "/bin/sh -c x", "parent_user": "root"}
        p1 = w._write_alert(alerts, "DEMO", "C.x", "Custom.TRUDI.NewProcess", row_np)
        assert w._try_merge(alerts, "C.x", "Custom.TRUDI.PrivilegeEscalation", row_pe) == p1
        merged = json.loads(p1.read_text())
        assert merged["detectors"] == ["Custom.TRUDI.NewProcess", "Custom.TRUDI.PrivilegeEscalation"]
        assert merged["detector"] == "Custom.TRUDI.NewProcess"
        assert merged["evidence_by_detector"]["Custom.TRUDI.PrivilegeEscalation"]["parent_user"] == "root"
        assert merged["summary"].endswith("[+PrivilegeEscalation]")
        assert merged["severity"] == "high"
        assert len(list(alerts.glob("*_*.json"))) == 1
        assert (alerts / "_seq.txt").read_text().strip() == "1"

    def test_other_pid_or_window_or_open_investigation_gets_own_alert(self, tmp_path):
        w = self._w()
        alerts = tmp_path / "monitoring" / "alerts"
        alerts.mkdir(parents=True)
        p1 = w._write_alert(alerts, "DEMO", "C.x", "Custom.TRUDI.NewProcess",
                            {"pid": "746", "image_path": "/usr/bin/dash", "started_utc": "2026-10-15T12:00:00Z"})
        # different pid → no merge
        assert w._try_merge(alerts, "C.x", "Custom.TRUDI.PrivilegeEscalation",
                            {"pid": "747", "image_path": "/usr/bin/run-parts"}) is None
        # non-process detector → no merge
        assert w._try_merge(alerts, "C.x", "Custom.TRUDI.NewNetwork", {"pid": "746"}) is None
        # outside the window → no merge
        late = w.time.monotonic() + w._MERGE_WINDOW_SECONDS + 1
        assert w._try_merge(alerts, "C.x", "Custom.TRUDI.PrivilegeEscalation",
                            {"pid": "746", "image_path": "/usr/bin/dash", "started_utc": "2026-10-15T12:00:00Z"}, now_mono=late) is None
        # re-register and put the alert inside an open investigation → no merge
        w._remember_process_alert("C.x", "Custom.TRUDI.NewProcess", {"pid": "746", "image_path": "/usr/bin/dash", "started_utc": "2026-10-15T12:00:00Z"}, p1)
        aid = json.loads(p1.read_text())["alert_id"]
        (tmp_path / "monitoring" / "_open_investigation.json").write_text(json.dumps(
            {"investigation_id": "INV-001", "alert_ids": [aid]}))
        assert w._try_merge(alerts, "C.x", "Custom.TRUDI.PrivilegeEscalation",
                            {"pid": "746", "image_path": "/usr/bin/dash", "started_utc": "2026-10-15T12:00:00Z"}) is None
        assert json.loads(p1.read_text())["detectors"] == ["Custom.TRUDI.NewProcess"]
