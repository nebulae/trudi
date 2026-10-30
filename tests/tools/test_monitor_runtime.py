"""Installed Velociraptor server integration, isolated from the operator's lab.

Uses only temporary certificates, datastore, and loopback ports. Requires local
sockets; run outside a network-restricted sandbox.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import threading

import pytest
import yaml

from monitoring import client_config, render
from tools import velo
from tests.tools.test_monitor_review_fixes import signed_case, fused, buffer


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_scoped_monitoring_against_real_server(tmp_path, monkeypatch):
    binary = shutil.which("velociraptor")
    if not binary:
        pytest.skip("installed Velociraptor required")
    api_port, gui_port, frontend_port = port(), port(), port()
    data = tmp_path / "data"
    data.mkdir()
    merge = {"Client": {"server_urls": [f"https://127.0.0.1:{frontend_port}/"],
                        "use_self_signed_ssl": True},
             "API": {"bind_address": "127.0.0.1", "bind_port": api_port, "hostname": "127.0.0.1"},
             "GUI": {"bind_address": "127.0.0.1", "bind_port": gui_port},
             "Frontend": {"bind_address": "127.0.0.1", "bind_port": frontend_port},
             "Datastore": {"implementation": "FileBaseDataStore", "location": str(data),
                           "filestore_directory": str(data / "filestore")},
             "Logging": {"output_directory": str(tmp_path / "logs")}}
    config = tmp_path / "server.yaml"
    generated = subprocess.run([binary, "config", "generate", "--merge", json.dumps(merge)],
                                capture_output=True, text=True, timeout=20, check=True)
    config.write_text(generated.stdout)
    config.chmod(0o600)
    api = tmp_path / "api.yaml"
    subprocess.run([binary, "--config", str(config), "config", "api_client", "--name", "review-test",
                    "--role", "administrator", str(api)], capture_output=True, text=True, timeout=20, check=True)
    monkeypatch.setenv("TRUDI_VELO_API_CONFIG", str(api))
    log_path = tmp_path / "frontend.log"
    with log_path.open("w") as log:
        server = subprocess.Popen([binary, "--config", str(config), "frontend"], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 20
            while True:
                assert server.poll() is None, log_path.read_text()[-4000:]
                result = velo._velo_query("SELECT get_client_monitoring() AS state FROM scope()", timeout=2)
                rows = velo._parse_jsonl(result.get("stdout", ""))
                if result.get("success") and rows and rows[0].get("state"):
                    break
                assert time.monotonic() < deadline, result.get("stderr")
                time.sleep(0.2)
            original = rows[0]["state"]
            lin, win = "Custom.TRUDI.NewLogon", "Custom.TRUDI.Win.NewLogon"
            for name in (lin, win):
                assert velo.upload_artifact_yaml(render.render_template(name, {}))["success"]
            for cid, name, ip in (("C.1111111111111111", lin, "10.0.0.1"),
                                  ("C.2222222222222222", win, "10.0.0.2"),
                                  ("C.3333333333333333", lin, "10.0.0.3")):
                params = {name: render.detector_parameters(name, {"logon_sources": [ip]})}
                if name == win:
                    # A real Windows baseline plus the server's compiled queries
                    # can exceed the normal tool-output cap. Exercise both the
                    # subsequent client's update and the large table read-back.
                    params[name]["BaselineLogonSources"] = json.dumps([
                        f"10.20.{i // 256}.{i % 256}" for i in range(6000)])
                changed = velo.update_client_event_table(cid, [name], params)
                assert changed["success"], changed
            assert velo._velo_query("SELECT get_client_monitoring() AS state FROM scope()")["truncated"]
            result = velo._velo_query("SELECT get_client_monitoring() AS state FROM scope()", full_output=True)
            state = velo._parse_jsonl(result["stdout"])[0]["state"]
            assert state["artifacts"] == original["artifacts"]
            assert len(state["label_events"]) == len(original.get("label_events") or []) + 3
            assert velo.update_client_event_table("C.2222222222222222", [win],
                {win: render.detector_parameters(win, {"logon_sources": ["10.0.0.20"]})})["success"]
            assert velo.update_client_event_table("C.2222222222222222", [])["success"]
            state = velo._parse_jsonl(velo._velo_query("SELECT get_client_monitoring() AS state FROM scope()")["stdout"])[0]["state"]
            assert {e["label"] for e in state["label_events"]} == {
                client_config.client_label("C.1111111111111111"), client_config.client_label("C.3333333333333333"),
                *(e["label"] for e in original.get("label_events") or [])}
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


def test_signed_alert_through_udp_relay_containment_and_report(signed_case):
    from monitoring import cef_auth
    from tools import monitor
    case, cid, directory, key, calls = signed_case
    buf = buffer(directory, case)
    # The sidecar module is loaded by file path, so obtain its function globals
    # from the bound method rather than installing it in sys.modules.
    namespace = buf.ingest_line.__func__.__globals__
    stop = namespace["_stop"]
    ingest_port, relay_port = port(), port()
    ingest_thread = threading.Thread(target=namespace["_serve_udp"], args=(buf, "127.0.0.1", ingest_port))
    ingest_thread.start()
    relay_script = Path(__file__).resolve().parents[2] / "demo" / "live-monitoring" / "windecoy" / "relay.py"
    relay = subprocess.Popen([shutil.which("python3"), str(relay_script)],
        env=dict(os.environ, RELAY_LISTEN=f"127.0.0.1:{relay_port}", RELAY_FORWARD=f"127.0.0.1:{ingest_port}"),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        envelope = cef_auth.sign(fused(), "sensor-1", key).encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            deadline = time.monotonic() + 5
            while not calls and time.monotonic() < deadline:
                sender.sendto(envelope, ("127.0.0.1", relay_port))
                time.sleep(0.1)
        assert len(calls) == 1
        stop.set()
        ingest_thread.join(timeout=5)
        assert not ingest_thread.is_alive()
        alert = json.loads(next((directory / "monitoring" / "alerts").glob("*_*.json")).read_text())
        monitor.start_investigation(case, "INV-UDP", [alert["alert_id"]])
        report = monitor.end_investigation(case, "INV-UDP")
        data = json.loads(Path(report["report_json_path"]).read_text())
        assert len(data["autonomous_response_actions"]) == 1
        assert data["autonomous_response_actions"][0]["rollback_command"]
    finally:
        stop.set()
        ingest_thread.join(timeout=5)
        relay.terminate()
        relay.wait(timeout=5)
