#!/usr/bin/env python3
"""Persistent multi-case TRUDI dashboard server.

Serves a cases root directory (default ~/cases) as the document root.
The dashboard HTML and vendor assets are served from the trudi/dashboard/
source dir under the ``/_dashboard/`` URL prefix, so the dashboard is
available even when no investigation is running and a freshly written
trace.json shows up in the dropdown without restarting the server.

Usage:
    trudi-dashboard [--cases-root DIR] [--port N]
    python -m dashboard.serve [--cases-root DIR] [--port N]

Environment overrides:
    TRUDI_CASES_ROOT       default for --cases-root (fallback: ~/cases)
    TRUDI_DASHBOARD_PORT   default for --port      (fallback: 8765)

Binds 127.0.0.1 only. On startup writes ~/.cache/trudi/dashboard.url so
other TRUDI components (start_execution_log, MCP tools) can discover the
running dashboard without taking a port for themselves.
"""
from __future__ import annotations

import argparse
import atexit
import http.server
import json
import os
import re
import signal
import socketserver
import sys
from urllib.parse import urlparse


DEFAULT_PORT = int(os.environ.get("TRUDI_DASHBOARD_PORT", "8765"))
DEFAULT_CASES_ROOT = os.environ.get(
    "TRUDI_CASES_ROOT",
    os.path.expanduser("~/cases"),
)
DASHBOARD_SRC = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_PREFIX = "/_dashboard/"
API_PREFIX = "/_dashboard/api/"
TRACE_RE = re.compile(r".*_trace\.json$", re.IGNORECASE)
DISCOVERY_FILE = os.path.expanduser("~/.cache/trudi/dashboard.url")


def _detect_case_id(case_dir: str) -> str | None:
    md = os.path.join(case_dir, "CLAUDE.md")
    if not os.path.exists(md):
        return None
    try:
        with open(md) as f:
            text = f.read(8192)
    except OSError:
        return None
    m = re.search(r"\*\*Case ID\*\*[:\s|]+([A-Za-z0-9_\-]+)", text)
    if m:
        return m.group(1)
    m = re.search(r"case[_\s]id[:\s|]+([A-Za-z0-9_\-]+)", text, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def list_cases(cases_root: str) -> list[dict]:
    """One-level scan under cases_root for case dirs and their trace files."""
    out: list[dict] = []
    try:
        entries = sorted(os.listdir(cases_root))
    except OSError:
        return out
    for name in entries:
        if name.startswith(".") or name == "_dashboard":
            continue
        case_dir = os.path.join(cases_root, name)
        if not os.path.isdir(case_dir):
            continue
        analysis = os.path.join(case_dir, "analysis")
        traces: list[dict] = []
        if os.path.isdir(analysis):
            try:
                for fn in sorted(os.listdir(analysis)):
                    if not TRACE_RE.match(fn):
                        continue
                    p = os.path.join(analysis, fn)
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    traces.append({
                        "name": fn,
                        "path": f"/{name}/analysis/{fn}",
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                    })
            except OSError:
                pass
        traces.sort(key=lambda t: t["mtime"], reverse=True)
        out.append({
            "case_id": _detect_case_id(case_dir) or name,
            "case_dir": name,
            "traces": traces,
        })
    return out


def _build_handler(cases_root: str) -> type:
    class TrudiDashboardHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=cases_root, **kwargs)

        def log_message(self, fmt, *args):
            sys.stderr.write(
                f"[{self.log_date_time_string()}] {self.address_string()} "
                f"{fmt % args}\n"
            )

        def do_GET(self):
            path = urlparse(self.path).path
            if path in ("", "/"):
                self.send_response(302)
                self.send_header("Location", f"{DASHBOARD_PREFIX}dashboard.html")
                self.end_headers()
                return
            if path.startswith(API_PREFIX):
                return self._handle_api(path[len(API_PREFIX):])
            if path.startswith(DASHBOARD_PREFIX):
                return self._serve_dashboard_asset(path[len(DASHBOARD_PREFIX):])
            return super().do_GET()

        def do_HEAD(self):
            path = urlparse(self.path).path
            if path.startswith(DASHBOARD_PREFIX) or path.startswith(API_PREFIX):
                self.send_response(200)
                self.end_headers()
                return
            return super().do_HEAD()

        def _handle_api(self, endpoint: str):
            if endpoint == "cases":
                payload = {
                    "cases_root": cases_root,
                    "cases": list_cases(cases_root),
                }
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_error(404, f"unknown API endpoint: {endpoint}")

        def _serve_dashboard_asset(self, rel: str):
            if rel in ("", "/"):
                rel = "dashboard.html"
            if ".." in rel.split("/") or rel.startswith("/"):
                self.send_error(403, "forbidden")
                return
            # `dashboard.html` is the public URL — on disk the file is named
            # trace_viewer.html for historical reasons.
            on_disk = "trace_viewer.html" if rel == "dashboard.html" else rel
            full = os.path.join(DASHBOARD_SRC, on_disk)
            if not os.path.isfile(full):
                self.send_error(404, f"not found: {rel}")
                return
            try:
                with open(full, "rb") as f:
                    body = f.read()
            except OSError as e:
                self.send_error(500, f"read failed: {e}")
                return
            self.send_response(200)
            self.send_header("Content-Type", _guess_content_type(rel))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return TrudiDashboardHandler


def _guess_content_type(rel: str) -> str:
    if rel.endswith(".html"):
        return "text/html; charset=utf-8"
    if rel.endswith(".js"):
        return "application/javascript; charset=utf-8"
    if rel.endswith(".css"):
        return "text/css; charset=utf-8"
    if rel.endswith(".json"):
        return "application/json; charset=utf-8"
    if rel.endswith(".svg"):
        return "image/svg+xml"
    return "application/octet-stream"


def _bind(cases_root: str, port: int) -> tuple[socketserver.ThreadingTCPServer, int]:
    handler = _build_handler(cases_root)
    last_err = ""
    # port=0 → kernel picks a free port; one attempt is enough. Otherwise
    # fall through up to +19 on collision.
    candidates = [0] if port == 0 else range(port, port + 20)
    for candidate in candidates:
        try:
            httpd = socketserver.ThreadingTCPServer(("127.0.0.1", candidate), handler)
            httpd.daemon_threads = True
            httpd.allow_reuse_address = True
            return httpd, httpd.server_address[1]
        except OSError as e:
            last_err = str(e)
    raise OSError(f"no free port in {port}..{port + 19}: {last_err}")


def _write_discovery(url: str, port: int, cases_root: str) -> None:
    try:
        os.makedirs(os.path.dirname(DISCOVERY_FILE), exist_ok=True)
        with open(DISCOVERY_FILE, "w") as f:
            f.write(json.dumps({
                "url": url,
                "port": port,
                "cases_root": cases_root,
                "pid": os.getpid(),
            }) + "\n")
    except OSError as e:
        print(f"warn: could not write discovery file {DISCOVERY_FILE}: {e}",
              file=sys.stderr)


def _clear_discovery() -> None:
    try:
        os.remove(DISCOVERY_FILE)
    except OSError:
        pass


def serve(cases_root: str, port: int = DEFAULT_PORT) -> int:
    cases_root = os.path.abspath(os.path.expanduser(cases_root))
    if not os.path.isdir(cases_root):
        sys.exit(f"cases_root not a directory: {cases_root}")
    httpd, chosen = _bind(cases_root, port)
    url = f"http://127.0.0.1:{chosen}{DASHBOARD_PREFIX}dashboard.html"
    _write_discovery(url, chosen, cases_root)
    discovered = list_cases(cases_root)
    print(f"\nTRUDI dashboard")
    print(f"  cases_root: {cases_root}")
    print(f"  URL: {url}")
    if discovered:
        names = ", ".join(c["case_id"] for c in discovered)
        print(f"  cases: {len(discovered)} ({names})")
    else:
        print("  cases: 0 — drop a case dir under cases_root and it will appear "
              "in the dropdown")
    print("Press Ctrl-C to stop.\n", flush=True)
    # SIGTERM → SystemExit on the main thread so serve_forever() unwinds and
    # the atexit cleanup fires. Calling httpd.shutdown() directly from the
    # handler deadlocks because shutdown() waits on serve_forever() which is
    # itself the interrupted thread.
    atexit.register(_clear_discovery)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        httpd.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        print("\nShutting down.", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="trudi-dashboard",
        description="Persistent TRUDI trace dashboard (multi-case).",
    )
    parser.add_argument(
        "--cases-root",
        default=DEFAULT_CASES_ROOT,
        help=(f"root dir containing case subdirectories "
              f"(default: {DEFAULT_CASES_ROOT}; env TRUDI_CASES_ROOT)"),
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=(f"starting port; falls through up to +19 on collision "
              f"(default: {DEFAULT_PORT}; env TRUDI_DASHBOARD_PORT)"),
    )
    args = parser.parse_args(argv)
    return serve(args.cases_root, port=args.port)


if __name__ == "__main__":
    raise SystemExit(main())
