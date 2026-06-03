"""Tests for the Investigation Chain blueprint view (chain_view.html).

The cytoscape DAG (graph_view.html) was deprecated when user feedback flagged
it as adding no signal over the list view. The chain view replaces it with a
display-only blueprint: rich HTML cards, dagre auto-layout, SVG wires.
"""
import os
import pytest


DASHBOARD_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "dashboard",
)


def test_chain_view_html_present():
    p = os.path.join(DASHBOARD_DIR, "chain_view.html")
    assert os.path.exists(p), f"chain_view.html missing at {p}"
    body = open(p).read()
    # CSS tokens for each block kind
    for token in [
        "kind-reason_plan", "kind-dair_call", "kind-tool_batch",
        "kind-reason_hypothesize", "kind-finding", "kind-self_correction",
    ]:
        assert token in body, f"block class {token} missing"
    # Wire kinds
    for kind in ["edge-supports", "edge-tests", "edge-consumes", "edge-instigates",
                 "edge-evaluates", "edge-directs"]:
        assert kind in body, f"wire colour token {kind} missing"
    # Vendored dagre
    assert 'src="vendor/dagre.min.js"' in body


def test_dagre_vendored():
    p = os.path.join(DASHBOARD_DIR, "vendor", "dagre.min.js")
    assert os.path.exists(p), f"vendored dagre missing at {p}"
    assert os.path.getsize(p) > 50_000, "dagre file looks truncated"


def test_trace_viewer_links_to_chain():
    p = os.path.join(DASHBOARD_DIR, "trace_viewer.html")
    body = open(p).read()
    assert "chain_view.html" in body
    assert "Chain ↗" in body
    assert "updateGraphLink" in body  # kept the function name; just retargeted
    # IR velocity pills still present
    for metric_id in ["metric-ttf", "metric-tta", "metric-tts", "metric-wall"]:
        assert metric_id in body, f"metric {metric_id} missing from trace_viewer"


def test_chain_view_served_under_dashboard_prefix(tmp_path, monkeypatch):
    """The standalone server exposes chain_view.html and dagre under
    /_dashboard/, alongside dashboard.html — no per-case copy needed."""
    import http.client
    import threading
    import time
    from dashboard import serve as dash_serve

    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    monkeypatch.setattr(dash_serve, "DISCOVERY_FILE", str(tmp_path / "d.url"))
    httpd, port = dash_serve._bind(str(cases_root), 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        time.sleep(0.05)
        for path, needle in [
            ("/_dashboard/dashboard.html", b"TRUDI Trace"),
            ("/_dashboard/chain_view.html", b"dagre"),
            ("/_dashboard/vendor/dagre.min.js", b"dagre"),
        ]:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request("GET", path)
            resp = conn.getresponse()
            assert resp.status == 200, f"{path} -> {resp.status}"
            assert needle in resp.read(), f"{path} missing marker"
    finally:
        httpd.shutdown()


def test_chain_view_blueprint_features():
    """Spot-check the key blueprint features that distinguish this from the
    deprecated graph view."""
    p = os.path.join(DASHBOARD_DIR, "chain_view.html")
    body = open(p).read()
    # Block types should be richer than just node/edge
    assert "buildBlocks" in body, "block grouping function missing"
    assert "tool_batch" in body, "tool-batch grouping missing"
    # Dagre is used for layout
    assert "dagre.graphlib.Graph" in body
    assert "rankdir: 'LR'" in body
    # SVG wires + bezier paths
    assert "wirePath" in body
    assert "marker-end" in body  # arrow markers
    # Pan/zoom on the canvas
    assert "setupCanvasInteraction" in body
    assert "applyTransform" in body
    # Detail pane shows inputs/outputs/connections explicitly
    assert "Connections" in body
    assert "Inputs" in body
    assert "Output / Conclusion" in body
