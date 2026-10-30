"""Regressions for trust, client isolation, event identity, and response ownership."""
import copy
import importlib.util
import json
from pathlib import Path
import time

import pytest

from monitoring import cef, cef_auth, client_config, response_store
from tools import monitor, respond, velo
from response import gates, policy

REPO = Path(__file__).resolve().parents[2]


def load_sidecar(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), REPO / "bin" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fused(incident="incident-1", source="10.73.0.3", remote="10.73.0.50", port=3389):
    return cef.format_cef(vendor="Acalvio", product="ShadowPlex", version="1",
        event_class_id="DETECT_AND_RESPOND", name="ENDPOINT_COMPROMISE", severity=9,
        extension=[("cs2Label", "incidentID"), ("cs2", incident),
                   ("cs15Label", "srcIP"), ("cs15", source),
                   ("cs25Label", "dstIP"), ("cs25", remote),
                   ("cs35Label", "dstPort"), ("cs35", port)])


def test_collection_reads_can_retain_all_rows_for_baselines(tmp_path, monkeypatch):
    import subprocess
    api = tmp_path / "api.yaml"
    api.touch()
    monkeypatch.setenv("TRUDI_VELO_API_CONFIG", str(api))
    rows = [{"path": f"task-{i}", "data": "x" * 512} for i in range(1000)]
    output = "\n".join(json.dumps(row) for row in rows).encode()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k:
                        subprocess.CompletedProcess(a[0], 0, stdout=output, stderr=b""))
    monkeypatch.setattr(velo, "_log_velo_tool", lambda result: None)
    limited = velo.get_collection_results("C.test", "F.test", "Custom.TRUDI.PersistenceSnapshot")
    assert limited["truncated"] and len(limited["rows"]) < len(rows)
    complete = velo.get_collection_results("C.test", "F.test", "Custom.TRUDI.PersistenceSnapshot",
                                           full_output=True)
    assert not complete["truncated"] and complete["rows"] == rows


def test_monitoring_update_retries_with_a_fresh_configuration(monkeypatch):
    initial = {"version": 1, "artifacts": {"artifacts": ["Generic.Client.Stats"]}}
    other = {"label": "operator", "artifacts": {"artifacts": ["Operator.Detector"]}}
    concurrent = {**initial, "version": 2, "label_events": [other]}
    desired = {"label": "TRUDI-client-C.test", "artifacts": {
        "artifacts": ["Custom.TRUDI.NewLogon"],
        "specs": [{"artifact": "Custom.TRUDI.NewLogon", "parameters": {"env": []}}]}}
    final = {**concurrent, "version": 3, "label_events": [other, desired]}
    reads = iter([initial, concurrent, final])
    attempts = []

    def query(vql, **kwargs):
        if vql.startswith("LET current"):
            attempts.append(vql)
            if len(attempts) == 1:
                result = {"state": None}
            else:
                assert "(current.version || 0) = 2" in vql
                assert "/label_events/-" in vql
                result = {"state": final}
        elif "get_client_monitoring" in vql:
            result = {"state": next(reads)}
        else:
            result = {"r": True}
        return {"success": True, "stdout": json.dumps(result)}

    monkeypatch.setattr(velo, "_velo_query", query)
    result = velo.update_client_event_table("C.test", ["Custom.TRUDI.NewLogon"])
    assert result["success"] and len(attempts) == 2


@pytest.fixture
def signed_case(tmp_path, monkeypatch):
    case, cid = "REVIEW", "C.source"
    directory = tmp_path / case
    (directory / "monitoring" / "baselines").mkdir(parents=True)
    (directory / "monitoring" / "baselines" / f"{cid}.json").write_text("{}")
    key = tmp_path / "sensor.key"
    key.write_text("a" * 64)
    sender = {"key_file": str(key), "source_clients": {"10.73.0.3": cid},
              "decoy_endpoints": ["10.73.0.50:3389"]}
    (directory / "monitoring" / "config.json").write_text(json.dumps({
        "host": "test-host", "auto_protect": {"enabled": True},
        "cef_ingest": {"senders": {"sensor-1": sender}}}))
    for module in (monitor, respond, gates, policy):
        monkeypatch.setattr(module, "CASES_ROOT", tmp_path)
    calls = []
    def write(*args, **kwargs):
        calls.append(args)
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": "", "cmd": "stub"}
    monkeypatch.setattr(respond.ssh_exec, "ssh_run_write", write)
    monkeypatch.setattr(respond, "_log_narration", lambda *a, **k: 0)
    return case, cid, directory, key.read_bytes(), calls


def buffer(directory, case, *, auto=True, replay=False):
    module = load_sidecar("trudi-cef-ingest")
    resolver = module.ClientResolver(None, "velociraptor", {"10.73.0.3": "C.source"}, enabled=False)
    return module.IncidentBuffer(directory / "monitoring" / "alerts", case, resolver,
                                 merge_window=0, auto_contain=auto, replay=replay)


@pytest.mark.parametrize("value", [r"DOMAIN\linda", r"C:\new\run.exe", "space  space", 'quote " inside', "pipe|equals=x", "line\nbreak", r"literal\n"])
def test_cef_roundtrip_preserves_extension(value):
    line = cef.format_cef(vendor="A|B", product="ShadowPlex", version="1",
        event_class_id="TEST", name="TEST", severity=1, extension=[("cs1", value)])
    parsed = cef.parse_cef(line)
    assert parsed["header"]["device_vendor"] == "A|B"
    assert parsed["fields"]["cs1"] == value


def test_cef_json_fingerprint_roundtrip():
    data = {"user_name": r"DOMAIN\linda", "service_details": {"client_host_name": 'PC "One"'}}
    line = cef.format_cef(vendor="Acalvio", product="ShadowPlex", version="1",
        event_class_id="DETECT_AND_RESPOND", name="SERVICE_INTERACTION", severity=9,
        extension=[("cs78Label", "event_data"), ("cs78", json.dumps(data))], quote_values=False)
    fp = cef.service_interaction_to_fingerprint(cef.parse_cef(line))
    assert fp["user_name"] == data["user_name"]
    assert fp["client_host_name"] == data["service_details"]["client_host_name"]


def test_unsigned_incident_cannot_contain_through_ingest_or_agent(signed_case):
    case, cid, directory, key, calls = signed_case
    buf = buffer(directory, case)
    buf.ingest_line(fused()); buf.flush_all()
    alert = json.loads(next((directory / "monitoring" / "alerts").glob("*_*.json")).read_text())
    assert not alert["response_eligible"] and not calls
    sug = respond.suggest_containment(case, detector=cef.DETECTOR,
        evidence=alert["evidence"], client_id=cid)
    block = next(s for s in sug["suggestions"] if s["action_template"] == "block_egress_to_endpoint")
    result = respond.execute_action(case, block["action_id"], mode="auto")
    assert result["gate"] == "approval_required" and not calls


def test_authenticated_incident_contains_once_and_report_adopts_it(signed_case):
    case, cid, directory, key, calls = signed_case
    buf = buffer(directory, case)
    buf.ingest_line(cef_auth.sign(fused(), "sensor-1", key)); buf.flush_all()
    assert len(calls) == 1
    alert = json.loads(next((directory / "monitoring" / "alerts").glob("*_*.json")).read_text())
    before = monitor._load_executions(case)
    assert before[0]["investigation_id"] is None
    assert before[0]["alert_ids"] == [alert["alert_id"]]
    opened = monitor.start_investigation(case, "INV-001", [alert["alert_id"]])
    assert opened["success"]
    sug = respond.suggest_containment(case, detector=cef.DETECTOR, evidence=alert["evidence"], client_id=cid)
    block = next(s for s in sug["suggestions"] if s["action_template"] == "block_egress_to_endpoint")
    assert block["action_id"] == before[0]["action_id"]
    assert respond.execute_action(case, block["action_id"], mode="auto")["already_executed"]
    assert len(calls) == 1
    finished = monitor.end_investigation(case, "INV-001")
    report = json.loads(Path(finished["report_json_path"]).read_text())
    assert len(report["autonomous_response_actions"]) == 1
    assert report["autonomous_response_actions"][0]["rollback_command"]


@pytest.mark.parametrize("change", ["tamper", "sender", "stale", "replay"])
def test_invalid_signed_envelopes_never_contain(signed_case, change):
    case, cid, directory, key, calls = signed_case
    envelope = json.loads(cef_auth.sign(fused(), "sensor-1", key))
    if change == "tamper":
        envelope["cef"] = fused(remote="198.51.100.20")
    elif change == "sender":
        envelope["sender"] = "unknown"
    elif change == "stale":
        envelope = json.loads(cef_auth.sign(fused(), "sensor-1", key, timestamp=int(time.time()) - 1000))
    elif change == "replay":
        cef_auth.claim_nonce(envelope, directory)
    buf = buffer(directory, case)
    buf.ingest_line(json.dumps(envelope)); buf.flush_all()
    assert not calls
    assert not list((directory / "monitoring" / "alerts").glob("*_*.json"))


@pytest.mark.parametrize("line", [fused(source="10.73.0.99"), fused(remote="198.51.100.20"),
    fused().replace("Acalvio", "OtherVendor"), fused().replace("ENDPOINT_COMPROMISE", "HEALTHY")])
def test_signed_but_unbound_or_unrelated_event_cannot_contain(signed_case, line):
    case, cid, directory, key, calls = signed_case
    buf = buffer(directory, case)
    buf.ingest_line(cef_auth.sign(line, "sensor-1", key)); buf.flush_all()
    assert not calls


def test_replay_mode_cannot_authorize_later_auto_response(signed_case):
    case, cid, directory, key, calls = signed_case
    buf = buffer(directory, case, replay=True)
    buf.ingest_line(cef_auth.sign(fused(), "sensor-1", key)); buf.flush_all()
    alert = json.loads(next((directory / "monitoring" / "alerts").glob("*_*.json")).read_text())
    assert not cef_auth.authorize_alert(directory, alert, alert["evidence"], cid)
    assert not calls


def apply_patch_to_state(state, ops):
    import shutil
    import subprocess
    binary = shutil.which("velociraptor")
    if not binary:
        pytest.skip("Velociraptor runtime needed for JSON Patch integration")
    query = f"SELECT patch(item=parse_json(data={json.dumps(json.dumps(state))}), patch=parse_json_array(data={json.dumps(json.dumps(ops))})) AS state FROM scope()"
    result = subprocess.run([binary, "query", "--format=jsonl", query], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["state"]


def test_monitoring_tables_and_parameters_are_isolated():
    state = {"artifacts": {"artifacts": ["Generic.Client.Stats", "Operator.Custom"],
                           "specs": [{"artifact": "Operator.Custom", "parameters": {"env": [{"key": "x", "value": "keep"}]}}]},
             "label_events": [{"label": "Other", "artifacts": {"artifacts": ["Other.Detector"]}}]}
    untouched = copy.deepcopy(state)
    for cid, detector, value in [("C.lin1", "Custom.TRUDI.NewProcess", "one"),
                                 ("C.win", "Custom.TRUDI.Win.NewProcess", "windows"),
                                 ("C.lin2", "Custom.TRUDI.NewProcess", "two")]:
        state = apply_patch_to_state(state, client_config.table_patch(state, cid, [detector], {detector: {"BaselineImagePaths": value}}))
    assert state["artifacts"] == untouched["artifacts"]
    assert state["label_events"][0] == untouched["label_events"][0]
    assert [e["artifacts"]["specs"][0]["parameters"]["env"][0]["value"] for e in state["label_events"][1:]] == ["one", "windows", "two"]
    state = apply_patch_to_state(state, client_config.table_patch(state, "C.win", []))
    assert [e["label"] for e in state["label_events"]] == ["Other", "TRUDI-client-C.lin1", "TRUDI-client-C.lin2"]


def test_windows_baseline_refresh_preserves_selected_detectors(signed_case, monkeypatch):
    case, cid, directory, key, calls = signed_case
    bpath = directory / "monitoring" / "baselines" / f"{cid}.json"
    bpath.write_text(json.dumps({"os_family": "windows"}))
    config = directory / "monitoring" / "watchers" / f"{cid}.json"
    config.parent.mkdir()
    config.write_text(json.dumps({"os_family": "windows", "detectors": ["Custom.TRUDI.Win.NewLogon"]}))
    uploads, updates = [], []
    monkeypatch.setattr(velo, "upload_artifact_yaml", lambda text: uploads.append(text) or {"success": True})
    monkeypatch.setattr(velo, "update_client_event_table", lambda c, a, parameters=None: updates.append((c, a, parameters)) or {"success": True})
    result = monitor.baseline_extend(case, cid, image_paths=[r"C:\trusted.exe"], reason="verified benign")
    assert result["success"]
    assert updates[0][1] == ["Custom.TRUDI.Win.NewLogon"]
    assert all(r"trusted.exe" not in text for text in uploads)


def test_failed_repush_can_be_retried_without_new_baseline_entries(signed_case, monkeypatch):
    case, cid, directory, *_ = signed_case
    monkeypatch.setattr(velo, "upload_artifact_yaml", lambda text: {"success": True})
    monkeypatch.setattr(velo, "update_client_event_table", lambda *a, **k: {"success": False, "error": "offline"})
    args = dict(image_paths=["/usr/local/bin/benign"], reason="verified benign")
    assert not monitor.baseline_extend(case, cid, **args)["success"]
    monkeypatch.setattr(velo, "update_client_event_table", lambda *a, **k: {"success": True})
    result = monitor.baseline_extend(case, cid, **args)
    assert result["success"] and result["repushed_detectors"]


def test_windows_logon_events_remain_distinct():
    w = load_sidecar("trudi-velo-watcher")
    row = {"source_ip": "10.73.0.3", "account": "linda", "logon_type": 10,
           "event_id": 4625, "event_record_id": 1, "channel": "Security", "computer": "PC", "timestamp_utc": "t1"}
    assert w._should_emit("Custom.TRUDI.Win.NewLogon", row)
    assert not w._should_emit("Custom.TRUDI.Win.NewLogon", row)
    assert w._should_emit("Custom.TRUDI.Win.NewLogon", dict(row, event_id=4624, event_record_id=2))
    assert w._should_emit("Custom.TRUDI.Win.NewLogon", dict(row, event_id=4624, event_record_id=3))


def test_process_merge_preserves_yara_rules_and_pid_reuse(tmp_path):
    w = load_sidecar("trudi-velo-watcher")
    row = {"pid": 123, "image_path": "/tmp/evil", "started_utc": "t1", "rule": "one"}
    first = w._write_alert(tmp_path, "CASE", "C.src", "Custom.TRUDI.YaraProcess", row)
    second = dict(row, rule="two")
    assert w._should_emit("Custom.TRUDI.YaraProcess", row)
    assert w._should_emit("Custom.TRUDI.YaraProcess", second)
    assert w._try_merge(tmp_path, "C.src", "Custom.TRUDI.YaraProcess", second) is None
    assert w._try_merge(tmp_path, "C.src", "Custom.TRUDI.NewProcess", dict(row, started_utc="t2")) is None
    assert w._try_merge(tmp_path, "C.src", "Custom.TRUDI.NewProcess", row) == first
    assert w._process_key("C.src", "Custom.TRUDI.NewProcess", {"pid": 123, "image_path": "/tmp/evil"}) == ""


@pytest.mark.parametrize("current,known,expected", [
    ("good", True, False), ("changed", True, True), ("good", False, True),
    (None, True, True),
])
def test_vql_cron_exemption_requires_intact_fingerprints(current, known, expected):
    import shutil
    import subprocess
    import yaml
    from monitoring import render
    binary = shutil.which("velociraptor")
    if not binary:
        pytest.skip("Velociraptor needed for detector runtime test")
    rows = [dict(Pid=1, Ppid=0, Exe="/sbin/init", Username="root", Name="init", CommandLine="init", CreatedTime=1),
            dict(Pid=31, Ppid=1, Exe="/usr/sbin/cron", Username="root", Name="cron", CommandLine="cron", CreatedTime=1),
            dict(Pid=99, Ppid=31, Exe="/opt/evil", Username="root", Name="evil", CommandLine="/opt/evil", CreatedTime=2)]
    baseline = dict(image_paths=["/sbin/init", "/usr/sbin/cron"], process_names=["init", "cron"],
                    persistence_fingerprints=["/etc/crontab|good"] if known else [])
    doc = yaml.safe_load(render.render_template("Custom.TRUDI.NewProcess", baseline))
    query = doc["sources"][0]["query"].replace(
        "LET tick = SELECT * FROM clock(period=PollSeconds)", "LET tick = SELECT 1 AS tick FROM scope()")
    start, end = query.index("LET snapshot ="), query.index("-- Index")
    query = query[:start] + f"LET snapshot = SELECT * FROM foreach(row=parse_json_array(data={json.dumps(json.dumps(rows))}))\n" + query[end:]
    persistence = [{"path": "/etc/crontab", "sha256": current, "identity": f"/etc/crontab|{current}"}] if current else []
    query = query.replace("SELECT * FROM Artifact.Custom.TRUDI.PersistenceSnapshot(WatchDirs=WatchDirs)",
        f"SELECT * FROM foreach(row=parse_json_array(data={json.dumps(json.dumps(persistence))}))")
    params = "\n".join("LET " + p["name"] + " = " + json.dumps(
        True if p["name"] == "ScheduledWorkEnabled" else p["default"]) for p in doc["parameters"]) + "\n"
    result = subprocess.run([binary, "query", "--format=jsonl", "--timeout=5", params + query],
                             capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert bool(result.stdout.strip()) == expected


def test_persistence_snapshot_detects_changed_content_even_with_same_metadata(tmp_path):
    import hashlib
    import os
    import shutil
    import subprocess
    binary = shutil.which("velociraptor")
    if not binary:
        pytest.skip("Velociraptor needed for snapshot runtime test")
    crontab = tmp_path / "crontab"
    crontab.write_text("trusted job")
    before = crontab.stat()
    crontab.write_text("changed job")
    os.utime(crontab, ns=(before.st_atime_ns, before.st_mtime_ns))
    globs = json.dumps(json.dumps([str(crontab)]))
    query = f"SELECT * FROM Artifact.Custom.TRUDI.PersistenceSnapshot(WatchDirs={globs})"
    result = subprocess.run([binary, "--definitions", str(REPO / "monitoring" / "artifacts"),
        "query", "--format=jsonl", query], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    row = json.loads(result.stdout)
    assert row["sha256"] == hashlib.sha256(b"changed job").hexdigest()
    assert row["identity"] == f"{crontab}|{row['sha256']}"


@pytest.mark.parametrize("sha,expected_clean", [("good", True), ("changed", False), (None, False)])
def test_verify_clean_rechecks_existing_schedule_content(signed_case, monkeypatch, sha, expected_clean):
    case, cid, directory, *_ = signed_case
    baseline = {"image_paths": ["/sbin/init", "/usr/sbin/cron"], "process_names": ["init", "cron"],
                "root_image_paths": ["/sbin/init", "/usr/sbin/cron"],
                "persistence_fingerprints": ["/etc/crontab|good"]}
    (directory / "monitoring" / "baselines" / f"{cid}.json").write_text(json.dumps(baseline))
    monkeypatch.setattr(velo, "collect_artifact", lambda *a, **k: {"success": True, "flow_id": "F.test"})
    monkeypatch.setattr(velo, "wait_for_flow", lambda *a, **k: {"success": True, "final_state": "FINISHED"})
    monkeypatch.setattr(velo, "upload_artifact_yaml", lambda *a, **k: {"success": True})
    def results(c, f, artifact, **kwargs):
        if artifact == "Linux.Sys.Pslist":
            return {"rows": [dict(Pid=1, Ppid=0, Exe="/sbin/init", Name="init", Username="root"),
                dict(Pid=31, Ppid=1, Exe="/usr/sbin/cron", Name="cron", Username="root"),
                dict(Pid=99, Ppid=31, Exe="/opt/evil", Name="evil", Username="root", CommandLine="/opt/evil")]}
        if artifact == "Custom.TRUDI.PersistenceSnapshot":
            return {"rows": [{"path": "/etc/crontab", "sha256": sha}]}
        return {"rows": []}
    monkeypatch.setattr(velo, "get_collection_results", results)
    result = monitor.verify_clean(cid, case)
    assert result["clean"] == expected_clean
    if not expected_clean:
        assert result["residual_counts"]["Custom.TRUDI.NewPersistence"] > 0
        assert result["residual_counts"]["Custom.TRUDI.NewProcess"] > 0


def test_powershell_sensor_signature_is_verified_by_python(signed_case):
    import os
    import shutil
    import subprocess
    binary = shutil.which("pwsh")
    if not binary:
        pytest.skip("PowerShell required for cross-runtime signing test")
    case, cid, directory, key, _ = signed_case
    script = REPO / "demo" / "live-monitoring" / "windecoy" / "sensor.ps1"
    command = r'''
    $tokens=$null; $errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseFile($env:TRUDI_TEST_SENSOR,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
    $function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Protect-Cef'},$true)
    Invoke-Expression $function.Extent.Text
    $cfg=@{key_file=$env:TRUDI_TEST_KEY; sender='sensor-1'}
    Protect-Cef $env:TRUDI_TEST_LINE
    '''
    env = dict(os.environ, TRUDI_TEST_SENSOR=str(script), TRUDI_TEST_KEY=str(directory.parent / "sensor.key"), TRUDI_TEST_LINE=fused())
    result = subprocess.run([binary, "-NoProfile", "-NonInteractive", "-Command", command],
                             env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    envelope = json.loads(result.stdout)
    sender = cef_auth.verify(envelope, directory)
    assert cef_auth.bound_client(cef.parse_cef(envelope["cef"]), sender) == cid


def test_containment_does_not_attach_to_an_unrelated_open_investigation(signed_case):
    case, cid, directory, key, calls = signed_case
    monitor.start_investigation(case, "INV-OTHER", ["unrelated-alert"])
    buf = buffer(directory, case)
    buf.ingest_line(cef_auth.sign(fused(), "sensor-1", key)); buf.flush_all()
    alert = json.loads(next((directory / "monitoring" / "alerts").glob("*_*.json")).read_text())
    assert len(calls) == 1
    assert monitor._load_executions(case)[0]["investigation_id"] is None
    assert monitor.get_response_state(case)["auto_executed"] == []
    monitor.extend_investigation(case, "INV-OTHER", [alert["alert_id"]])
    assert monitor.get_response_state(case)["auto_executed"]


def test_concurrent_response_workers_execute_one_block(signed_case):
    from concurrent.futures import ThreadPoolExecutor
    case, cid, directory, key, calls = signed_case
    buf = buffer(directory, case, auto=False)
    buf.ingest_line(cef_auth.sign(fused(), "sensor-1", key)); buf.flush_all()
    alert = json.loads(next((directory / "monitoring" / "alerts").glob("*_*.json")).read_text())
    def contain(_):
        return respond.auto_contain(case, cef.DETECTOR, alert["evidence"], cid, alert_id=alert["alert_id"])
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(contain, range(2)))
    assert all(r["ran"] for r in results)
    assert len(calls) == 1


def test_saved_signature_does_not_authorize_a_different_target(signed_case):
    case, cid, directory, key, calls = signed_case
    buf = buffer(directory, case, auto=False)
    buf.ingest_line(cef_auth.sign(fused(), "sensor-1", key)); buf.flush_all()
    alert = json.loads(next((directory / "monitoring" / "alerts").glob("*_*.json")).read_text())
    evidence = dict(alert["evidence"], remote_ip="198.51.100.20", authenticated=True)
    assert not cef_auth.authorize_alert(directory, alert, evidence, cid)
    out = respond.auto_contain(case, cef.DETECTOR, evidence, cid, alert_id=alert["alert_id"])
    assert not out["ran"] and not calls
