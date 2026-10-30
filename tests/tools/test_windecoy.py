"""WINDECOY-DEMO: the real-Windows deception-decoy path.

Covers the pieces that make the ShadowPlex-trigger + real-Windows-investigation
scenario work end to end, offline:

  * the on-decoy sensor's CEF output (sampled in
    demo/live-monitoring/windecoy/sample-sensor-incident.cef) parses through
    monitoring/cef.py to the expected DecoyTouch evidence;
  * the touching host resolves from the CEF srcIP / client hostname;
  * the lan-net relay forwards CEF datagrams verbatim;
  * replaying the sample through bin/trudi-cef-ingest.py writes a
    Custom.TRUDI.DecoyTouch alert with honey_credential=linda.

The sensor itself is PowerShell (runs only on the Windows decoy), so it is
validated here by its emitted format, not by execution.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from monitoring import cef  # noqa: E402

SAMPLE = REPO / "demo" / "live-monitoring" / "windecoy" / "sample-sensor-incident.cef"
RELAY = REPO / "demo" / "live-monitoring" / "windecoy" / "relay.py"
INGEST = REPO / "bin" / "trudi-cef-ingest.py"


def _sample_lines() -> list[str]:
    return [l for l in SAMPLE.read_text().splitlines()
            if l.strip() and not l.lstrip().startswith("#")]


# ── sensor CEF format ────────────────────────────────────────────────────────

def test_sample_exists_two_records():
    lines = _sample_lines()
    assert len(lines) == 2, "expected a fused + a service-interaction record"


def test_fused_incident_evidence():
    fused = cef.parse_cef(_sample_lines()[0])
    assert not cef.is_service_interaction(fused)
    ev = cef.shadowplex_to_evidence(fused)
    assert ev["honey_credential"] == "linda"
    assert ev["source_ip"] == "10.73.0.3"       # the beachhead (touching host)
    assert ev["remote_ip"] == "10.73.0.60"       # the decoy (remote from source)
    assert ev["remote_port"] == 3389
    assert ev["decoy_name"] == "WIN-DECOY01"
    assert "T1021.001" in ev["attack_technique_ids"]
    assert ev["category"] == "Endpoint Compromise"


def test_service_interaction_fingerprint():
    svc = cef.parse_cef(_sample_lines()[1])
    assert cef.is_service_interaction(svc)
    fp = cef.service_interaction_to_fingerprint(svc)
    assert fp["user_name"] == "linda"
    assert fp["client_host_name"] == "VICTIM-A"
    assert fp["service_name"] == "MS-WBT-SERVER"
    assert fp["service_port"] == 3389


def test_fingerprint_merge_keeps_source_orientation():
    fused = cef.shadowplex_to_evidence(cef.parse_cef(_sample_lines()[0]))
    fp = cef.service_interaction_to_fingerprint(cef.parse_cef(_sample_lines()[1]))
    merged = cef.merge_fingerprint(fused, fp)
    # The source stays the beachhead; the decoy stays the remote endpoint.
    assert merged["source_ip"] == "10.73.0.3"
    assert merged["remote_ip"] == "10.73.0.60"
    assert merged["client_fingerprint"]["client_host_name"] == "VICTIM-A"


# ── touching-host resolution ─────────────────────────────────────────────────

def test_resolve_touching_host_by_hostname():
    # Cross-network topology: the beachhead reaches the server on a different
    # network than the one it touched the decoy from, so its `last_ip` does NOT
    # match the CEF srcIP — resolution falls back to the hostname.
    clients = [
        {"client_id": "C.decoywin", "hostname": "WIN-DECOY01", "last_ip": "10.73.0.60",
         "last_seen_at": 200},
        {"client_id": "C.beachhead", "hostname": "victim-a", "last_ip": "192.168.50.9",
         "last_seen_at": 100},
    ]
    res = cef.resolve_client(clients, source_ip="10.73.0.3", client_host_name="VICTIM-A")
    assert res["matched"] is True
    assert res["client_id"] == "C.beachhead"   # the SOURCE host, not the decoy
    assert res["method"] == "hostname"


def test_resolve_touching_host_by_last_ip():
    clients = [{"client_id": "C.beachhead", "hostname": "victim-a", "last_ip": "10.73.0.3",
                "last_seen_at": 100}]
    res = cef.resolve_client(clients, source_ip="10.73.0.3", client_host_name=None)
    assert res["client_id"] == "C.beachhead"


def test_resolve_prefers_srcip_over_decoy_hostname():
    # Regression: a deception decoy's sensor stamps client_host_name with the
    # DECOY's OWN hostname (the 4624 only knows what the RDP client claimed), so
    # a hostname-first resolver matched the decoy's client and "contained" the
    # decoy. The reliable signal is the CEF srcIP → the beachhead's last_ip.
    clients = [
        {"client_id": "C.decoywin", "hostname": "LABADMI-RVNNP7I", "last_ip": "10.73.0.60",
         "last_seen_at": 200},
        {"client_id": "C.beachhead", "hostname": "victim-a", "last_ip": "10.73.0.4",
         "last_seen_at": 100},
    ]
    res = cef.resolve_client(clients, source_ip="10.73.0.4", client_host_name="LABADMI-RVNNP7I")
    assert res["client_id"] == "C.beachhead"   # NOT C.decoywin
    assert res["method"] == "last_ip"


def test_resolve_skips_empty_source_map_value():
    # An empty-string source_map value must NOT resolve to an empty client_id;
    # it is ignored so real resolution (last_ip) proceeds.
    clients = [{"client_id": "C.beachhead", "hostname": "victim-a", "last_ip": "10.73.0.4",
                "last_seen_at": 100}]
    res = cef.resolve_client(clients, source_ip="10.73.0.4", client_host_name=None,
                             source_map={"10.73.0.4": ""})
    assert res["client_id"] == "C.beachhead"
    assert res["method"] == "last_ip"


# ── relay forwarding ─────────────────────────────────────────────────────────

def test_relay_forwards_datagram_verbatim():
    # A socket standing in for the SIFT-host ingest (the relay's forward target).
    fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fwd.bind(("127.0.0.1", 0))
    fwd.settimeout(5.0)
    fwd_port = fwd.getsockname()[1]

    # Reserve a listen port for the relay, then free it for the relay to bind.
    tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp.bind(("127.0.0.1", 0))
    listen_port = tmp.getsockname()[1]
    tmp.close()

    env = dict(os.environ,
               RELAY_LISTEN=f"127.0.0.1:{listen_port}",
               RELAY_FORWARD=f"127.0.0.1:{fwd_port}")
    proc = subprocess.Popen([sys.executable, str(RELAY)], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        payload = _sample_lines()[0].encode("utf-8")
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        got = None
        # The relay needs a moment to bind; retry the send a few times.
        for _ in range(50):
            tx.sendto(payload, ("127.0.0.1", listen_port))
            try:
                data, _peer = fwd.recvfrom(65535)
                got = data
                break
            except socket.timeout:
                continue
            except OSError:
                time.sleep(0.1)
        assert got == payload, "relay did not forward the datagram verbatim"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        fwd.close()


# ── end-to-end ingest replay ─────────────────────────────────────────────────

def test_ingest_replay_writes_decoytouch_alert(tmp_path):
    alerts = tmp_path / "alerts"
    alerts.mkdir()
    proc = subprocess.run(
        [sys.executable, str(INGEST), "--case-id", "WINDECOY-DEMO",
         "--alerts-dir", str(alerts), "--no-resolve", "--replay", str(SAMPLE)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    files = sorted(alerts.glob("*.json"))
    assert len(files) == 1, f"expected one merged alert, got {[f.name for f in files]}"
    alert = json.loads(files[0].read_text())
    assert alert["detector"] == "Custom.TRUDI.DecoyTouch"
    assert alert["severity"] == "high"
    assert alert["evidence"]["honey_credential"] == "linda"
    assert alert["evidence"]["source_ip"] == "10.73.0.3"
    assert alert["evidence"]["remote_ip"] == "10.73.0.60"
    assert alert["client_id"] is None            # --no-resolve
    assert alert["evidence"]["client_fingerprint"]["client_host_name"] == "VICTIM-A"


# ── server-side auto-contain (the ingest fires reversible containment itself) ─

def _mk_case(tmp_path, auto_protect=True):
    """A minimal live-monitoring case dir under a throwaway cases root."""
    case = tmp_path / "WINDECOY-DEMO"
    (case / "monitoring" / "baselines").mkdir(parents=True)
    # live_monitoring_scope requires a baseline to exist.
    (case / "monitoring" / "baselines" / "C.beachhead.json").write_text(
        json.dumps({"client_id": "C.beachhead", "process_names": [], "image_paths": []}))
    cfg = {
        "host": "trudi-victim-a",
        "auto_protect": {"enabled": auto_protect},
        "demo_response": {"enabled": True, "respond_to_synthetic": True},
        "client_map": {"C.beachhead": "trudi-victim-a"},
    }
    from monitoring import cef_auth
    key = case / "sensor.key"
    key.write_text("a" * 64)
    cfg["cef_ingest"] = {"senders": {"windows-decoy": {
        "key_file": str(key), "source_clients": {DECOY_EV["source_ip"]: "C.beachhead"},
        "decoy_endpoints": ["10.73.0.60:3389"]}}}
    (case / "monitoring" / "config.json").write_text(json.dumps(cfg))
    line = cef.format_cef(vendor="Acalvio", product="ShadowPlex", version="1",
        event_class_id="DETECT_AND_RESPOND", name="ENDPOINT_COMPROMISE", severity=9,
        extension=[("cs2Label", "incidentID"), ("cs2", DECOY_EV["incident_id"]),
                   ("cs15Label", "srcIP"), ("cs15", DECOY_EV["source_ip"]),
                   ("cs25Label", "dstIP"), ("cs25", DECOY_EV["remote_ip"]),
                   ("cs35Label", "dstPort"), ("cs35", DECOY_EV["remote_port"])])
    alert = cef.build_alert(DECOY_EV, case_id="WINDECOY-DEMO", seq=1,
        client_id="C.beachhead", raw_lines=[line], alert_id="decoy-alert")
    alert["ingress_envelope"] = json.loads(cef_auth.sign(line, "windows-decoy", key.read_bytes()))
    alerts = case / "monitoring" / "alerts"
    alerts.mkdir()
    (alerts / "00000001_DecoyTouch.json").write_text(json.dumps(alert))
    return case


def _load_respond(tmp_path, monkeypatch):
    from tools import respond as _r
    from response import gates, policy
    for module in (_r, gates, policy):
        monkeypatch.setattr(module, "CASES_ROOT", tmp_path)
    return _r


DECOY_EV = {"source_ip": "10.73.0.4", "remote_ip": "10.73.0.60", "remote_port": 3389,
            "honey_credential": "linda", "incident_id": "demo-incident"}


def test_auto_contain_executes_reversible_block(tmp_path, monkeypatch):
    _mk_case(tmp_path, auto_protect=True)
    respond = _load_respond(tmp_path, monkeypatch)
    # Stand in for the write-SSH path so no endpoint is touched.
    calls = []
    def fake_write(case_id, host, template, evidence):
        calls.append((template, host, dict(evidence)))
        return {"success": True, "stdout": "", "stderr": "", "exit_code": 0, "_trudi_call_id": 1}
    monkeypatch.setattr(respond.ssh_exec, "ssh_run_write", fake_write)

    out = respond.auto_contain("WINDECOY-DEMO", "Custom.TRUDI.DecoyTouch",
                               DECOY_EV, client_id="C.beachhead", alert_id="decoy-alert")
    assert out["ran"] is True
    # The reversible block ran…
    blocks = [c for c in out["contained"] if c["template"] == "block_egress_to_endpoint"]
    assert len(blocks) == 1 and blocks[0]["success"] is True
    assert any(t == "block_egress_to_endpoint" for t, _h, _e in calls)
    # …and the destructive kill was DEFERRED, never executed server-side.
    assert any(d["template"] == "kill_owning_pid" for d in out["deferred"])
    assert not any(t.startswith("kill") for t, _h, _e in calls)


def test_auto_contain_skips_when_auto_protect_off(tmp_path, monkeypatch):
    _mk_case(tmp_path, auto_protect=False)
    respond = _load_respond(tmp_path, monkeypatch)
    monkeypatch.setattr(respond.ssh_exec, "ssh_run_write",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not execute")))
    out = respond.auto_contain("WINDECOY-DEMO", "Custom.TRUDI.DecoyTouch", DECOY_EV, "C.beachhead", alert_id="decoy-alert")
    assert out["ran"] is False and "auto_protect disabled" in out["skipped"]


def test_auto_contain_skips_non_confirmed_positive_detector(tmp_path, monkeypatch):
    _mk_case(tmp_path, auto_protect=True)
    respond = _load_respond(tmp_path, monkeypatch)
    monkeypatch.setattr(respond.ssh_exec, "ssh_run_write",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not execute")))
    out = respond.auto_contain("WINDECOY-DEMO", "Custom.TRUDI.NewProcess",
                               {"pid": 783, "image_path": "/usr/bin/xfreerdp"}, "C.beachhead")
    assert out["ran"] is False and "confirmed-positive" in out["skipped"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
