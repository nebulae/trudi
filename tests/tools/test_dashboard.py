"""Tests for the TRUDI dashboard discovery + standalone server.

The dashboard runs as a separate long-lived process (`trudi-dashboard`,
i.e. `python -m dashboard.serve`). MCP-side code never spawns a server;
it discovers the running one via ~/.cache/trudi/dashboard.url and returns
a deep-link URL pre-loaded with the case's trace.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import threading
import time
from unittest.mock import patch

import pytest


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


@pytest.fixture
def standalone_server(tmp_path):
    """Spin up dashboard.serve in a thread, isolated under tmp_path."""
    from dashboard import serve as dash_serve

    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    port = _free_port()

    discovery = tmp_path / "discovery.json"
    with patch.object(dash_serve, "DISCOVERY_FILE", str(discovery)):
        httpd, chosen = dash_serve._bind(str(cases_root), port)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        dash_serve._write_discovery(
            f"http://127.0.0.1:{chosen}/_dashboard/dashboard.html",
            chosen, str(cases_root),
        )
        try:
            time.sleep(0.05)
            yield {
                "cases_root": cases_root,
                "port": chosen,
                "discovery": discovery,
                "url": f"http://127.0.0.1:{chosen}/_dashboard/dashboard.html",
            }
        finally:
            httpd.shutdown()
            dash_serve._clear_discovery()


def _seed_case(cases_root, case_dir_name, case_id, trace_name=None):
    case = cases_root / case_dir_name
    case.mkdir()
    (case / "CLAUDE.md").write_text(f"**Case ID**: {case_id}\n")
    (case / "analysis").mkdir()
    if trace_name:
        (case / "analysis" / trace_name).write_text(
            json.dumps({"case_id": case_id, "entries": []})
        )
    return case


class TestStandaloneServer:
    def test_redirect_to_dashboard(self, standalone_server):
        port = standalone_server["port"]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/")
        resp = conn.getresponse()
        assert resp.status == 302
        assert resp.getheader("Location") == "/_dashboard/dashboard.html"

    def test_serves_dashboard_html(self, standalone_server):
        port = standalone_server["port"]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/_dashboard/dashboard.html")
        resp = conn.getresponse()
        body = resp.read().decode()
        assert resp.status == 200
        assert "TRUDI Trace" in body
        # The case + trace dropdowns are the centrepiece of the redesign
        assert 'id="case-select"' in body
        assert 'id="trace-select"' in body

    def test_serves_chain_view(self, standalone_server):
        port = standalone_server["port"]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/_dashboard/chain_view.html")
        resp = conn.getresponse()
        assert resp.status == 200
        assert b"dagre" in resp.read()

    def test_serves_vendor_dagre(self, standalone_server):
        port = standalone_server["port"]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/_dashboard/vendor/dagre.min.js")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.getheader("Content-Type").startswith("application/javascript")

    def test_dashboard_asset_rejects_traversal(self, standalone_server):
        port = standalone_server["port"]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/_dashboard/../tools/misc.py")
        resp = conn.getresponse()
        # SimpleHTTPRequestHandler normalizes the path before do_GET sees it,
        # so traversal under the dashboard prefix never reaches the source dir.
        assert resp.status in (403, 404)

    def test_api_cases_lists_seeded_cases(self, standalone_server):
        cases_root = standalone_server["cases_root"]
        _seed_case(cases_root, "alpha-case", "ALPHA",
                   trace_name="ALPHA_trace.json")
        _seed_case(cases_root, "beta-case", "BETA",
                   trace_name="BETA_trace.json")
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2,
        )
        conn.request("GET", "/_dashboard/api/cases")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        ids = {c["case_id"] for c in data["cases"]}
        assert {"ALPHA", "BETA"} <= ids
        alpha = next(c for c in data["cases"] if c["case_id"] == "ALPHA")
        assert alpha["traces"][0]["path"] == "/alpha-case/analysis/ALPHA_trace.json"

    def test_api_cases_picks_up_new_trace_without_restart(self, standalone_server):
        cases_root = standalone_server["cases_root"]
        case = _seed_case(cases_root, "live-case", "LIVE")
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2,
        )
        conn.request("GET", "/_dashboard/api/cases")
        before = json.loads(conn.getresponse().read())
        live = next(c for c in before["cases"] if c["case_id"] == "LIVE")
        assert live["traces"] == []
        # Drop a trace while the server is running.
        (case / "analysis" / "LIVE_trace.json").write_text(
            '{"case_id":"LIVE","entries":[]}'
        )
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2,
        )
        conn.request("GET", "/_dashboard/api/cases")
        after = json.loads(conn.getresponse().read())
        live2 = next(c for c in after["cases"] if c["case_id"] == "LIVE")
        assert len(live2["traces"]) == 1

    def test_serves_trace_json_from_case(self, standalone_server):
        cases_root = standalone_server["cases_root"]
        _seed_case(cases_root, "ts-case", "TS",
                   trace_name="TS_trace.json")
        conn = http.client.HTTPConnection(
            "127.0.0.1", standalone_server["port"], timeout=2,
        )
        conn.request("GET", "/ts-case/analysis/TS_trace.json")
        resp = conn.getresponse()
        assert resp.status == 200
        assert b'"case_id": "TS"' in resp.read()


class TestServeDashboardDiscovery:
    """The MCP `serve_dashboard` tool just builds a deep-link URL into the
    running standalone dashboard."""

    def test_no_dashboard_returns_hint(self, tmp_path, monkeypatch):
        from tools import misc
        case = tmp_path / "fallback-case"
        case.mkdir()
        (case / "CLAUDE.md").write_text("**Case ID**: FALLBACK\n")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(tmp_path / "missing.url"),
        )
        r = misc.launch_dashboard(str(case))
        assert r["success"] is False
        assert "trudi-dashboard" in r["error"]
        # The hint URL still uses the case's expected trace path so the
        # operator can open it as soon as the dashboard is running.
        assert "?trace=/fallback-case/analysis/FALLBACK_trace.json" in r["hint_url"]

    def test_invalid_case_dir(self, tmp_path):
        from tools import misc
        r = misc.launch_dashboard(str(tmp_path / "nope"))
        assert r["success"] is False
        assert "not a directory" in r["error"]

    def test_live_dashboard_returns_deep_link(self, standalone_server, monkeypatch):
        from tools import misc

        cases_root = standalone_server["cases_root"]
        case = _seed_case(cases_root, "deep-case", "DEEP")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(standalone_server["discovery"]),
        )
        r = misc.launch_dashboard(str(case))
        assert r["success"] is True
        assert r["url"].startswith(standalone_server["url"])
        assert "?trace=/deep-case/analysis/DEEP_trace.json" in r["url"]
        assert r["case_id"] == "DEEP"

    def test_case_outside_cases_root_refuses(
        self, standalone_server, tmp_path, monkeypatch,
    ):
        from tools import misc

        outsider = tmp_path / "outside-case"
        outsider.mkdir()
        (outsider / "CLAUDE.md").write_text("**Case ID**: OUT\n")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(standalone_server["discovery"]),
        )
        r = misc.launch_dashboard(str(outsider))
        assert r["success"] is False
        assert "outside the dashboard's cases_root" in r["error"]

    def test_stale_discovery_file_is_ignored(self, tmp_path, monkeypatch):
        """A discovery file with a dead PID must not look like a live dashboard."""
        from tools import misc

        case = tmp_path / "stale-case"
        case.mkdir()
        (case / "CLAUDE.md").write_text("**Case ID**: STALE\n")
        discovery = tmp_path / "stale.json"
        # PID 1 is init — exists, but won't match a Python dashboard.
        # Use a definitely-dead PID instead by picking a very large one.
        discovery.write_text(json.dumps({
            "url": "http://127.0.0.1:65535/_dashboard/dashboard.html",
            "port": 65535,
            "cases_root": str(tmp_path),
            "pid": 999999,
        }))
        monkeypatch.setattr(misc, "_DASHBOARD_DISCOVERY_FILE", str(discovery))
        r = misc.launch_dashboard(str(case))
        assert r["success"] is False
        assert "no standalone dashboard reachable" in r["error"]


class TestStartExecutionLogIntegratesDashboard:
    def test_url_written_when_dashboard_live(
        self, standalone_server, tmp_path, monkeypatch,
    ):
        from tools import misc
        from tools.misc import start_execution_log
        from core.execution_log import log as global_log

        cases_root = standalone_server["cases_root"]
        case = _seed_case(cases_root, "EL-CASE", "EL-CASE")
        log_path = str(case / "analysis" / "EL-CASE_trace.json")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(standalone_server["discovery"]),
        )
        with patch("core.execution_log._SESSION_FILE", str(tmp_path / "sess.json")):
            r = start_execution_log("EL-CASE", log_path)
        assert r["success"] is True
        assert r.get("dashboard_url"), r
        assert "?trace=/EL-CASE/analysis/EL-CASE_trace.json" in r["dashboard_url"]
        # Also persisted next to the trace so the operator can grab it from
        # the analysis dir.
        url_file = case / "analysis" / "dashboard.url"
        assert url_file.exists()
        assert r["dashboard_url"] in url_file.read_text()
        # Happy path: the only system_error allowed is the trace_initialized
        # sentinel that start_execution_log writes to verify the trace path.
        # Anything else means a silent failure slipped through.
        bad = [e for e in global_log._entries
               if e.get("type") == "system_error"
               and e.get("category") != "trace_initialized"]
        assert not bad, f"unexpected system_error entries on happy path: {bad}"

    def test_no_dashboard_surfaces_hint(
        self, tmp_path, monkeypatch,
    ):
        from tools import misc
        from tools.misc import start_execution_log

        case = tmp_path / "OFFLINE-CASE"
        case.mkdir()
        (case / "CLAUDE.md").write_text("**Case ID**: OFFLINE-CASE\n")
        (case / "analysis").mkdir()
        log_path = str(case / "analysis" / "OFFLINE-CASE_trace.json")
        monkeypatch.setattr(
            misc, "_DASHBOARD_DISCOVERY_FILE", str(tmp_path / "missing.url"),
        )
        with patch("core.execution_log._SESSION_FILE", str(tmp_path / "sess.json")):
            r = start_execution_log("OFFLINE-CASE", log_path)
        assert r["success"] is True
        assert "dashboard_url" not in r
        assert r.get("dashboard_error")
        assert r.get("dashboard_hint_url")

    def test_launch_dashboard_false_skips_discovery(self, tmp_path):
        from tools.misc import start_execution_log
        case = tmp_path / "SKIP-CASE"
        case.mkdir()
        (case / "CLAUDE.md").write_text("**Case ID**: SKIP-CASE\n")
        (case / "analysis").mkdir()
        log_path = str(case / "analysis" / "SKIP-CASE_trace.json")
        with patch("core.execution_log._SESSION_FILE", str(tmp_path / "sess.json")):
            r = start_execution_log(
                "SKIP-CASE", log_path, launch_dashboard=False,
            )
        assert r["success"] is True
        assert "dashboard_url" not in r
        assert "dashboard_error" not in r
        assert not (case / "analysis" / "dashboard.url").exists()
