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
from urllib.parse import parse_qs, unquote, urlparse


DEFAULT_PORT = int(os.environ.get("TRUDI_DASHBOARD_PORT", "8765"))
DEFAULT_CASES_ROOT = os.environ.get(
    "TRUDI_CASES_ROOT",
    os.path.expanduser("~/cases"),
)
DASHBOARD_SRC = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_PREFIX = "/_dashboard/"
API_PREFIX = "/_dashboard/api/"
TRACE_RE = re.compile(r".*_trace\.json$", re.IGNORECASE)
# /_dashboard/api/output serves produced output ONLY from these case subdirs.
OUTPUT_ROOTS = (os.path.join("analysis", ".tool_output"), "exports")
OUTPUT_DEFAULT_BYTES = 2 * 1024 * 1024
OUTPUT_MAX_BYTES = 16 * 1024 * 1024
# Mirrors core.paths.trudi_cache_dir() (this script runs standalone).
DISCOVERY_FILE = os.path.join(
    os.path.expanduser(os.environ.get("TRUDI_CACHE_DIR") or "~/.cache/trudi"),
    "dashboard.url")


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
                return self._handle_api(path[len(API_PREFIX):],
                                        parse_qs(urlparse(self.path).query))
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

        def _handle_api(self, endpoint: str, qs: dict | None = None):
            if endpoint == "output":
                return self._serve_output(qs or {})
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

        def _serve_output(self, qs: dict):
            """Read-only view of one produced-output file (a tool's stdout
            sidecar, an evidence-fetch result, an exported CSV) for the trace
            viewer. Only files under the trace's case analysis/.tool_output/
            or exports/ are served; see resolve_output_file."""
            trace = (qs.get("trace") or [""])[0]
            want = (qs.get("path") or [""])[0]
            try:
                limit = int((qs.get("max") or [OUTPUT_DEFAULT_BYTES])[0])
            except ValueError:
                limit = OUTPUT_DEFAULT_BYTES
            limit = max(1, min(limit, OUTPUT_MAX_BYTES))
            full, err = resolve_output_file(cases_root, trace, want)
            if not full:
                self.send_error(403 if err != "not found" else 404, err)
                return
            try:
                size = os.path.getsize(full)
                with open(full, "rb") as f:
                    body = f.read(limit)
            except OSError as e:
                self.send_error(500, f"read failed: {e}")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Trudi-Size", str(size))
            self.send_header("X-Trudi-Truncated", "1" if size > len(body) else "0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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


def _within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def resolve_output_file(cases_root: str, trace: str, want: str) -> tuple[str | None, str]:
    """Map (trace URL path, requested file) to a real file the output endpoint
    may serve, or (None, reason).

    The trace must be a *_trace.json under cases_root/<case>/analysis/. The
    file may be named absolutely (as the trace records it — stdout_path,
    result_path, a read.output file) or relative to the case dir. It is
    served only when its real path (symlinks resolved) lies under that case's
    analysis/.tool_output/ or exports/. A recorded absolute path from where
    the case used to live is re-rooted by its analysis/.tool_output/… or
    exports/… tail, so a copied or moved case still resolves."""
    root = os.path.realpath(cases_root)
    tpath = unquote(urlparse(trace or "").path or "").lstrip("/")
    if not tpath or not TRACE_RE.match(tpath) or ".." in tpath.split("/"):
        return None, "bad trace"
    tfull = os.path.realpath(os.path.join(root, tpath))
    if not _within(tfull, root) or not os.path.isfile(tfull):
        return None, "bad trace"
    analysis = os.path.dirname(tfull)
    if os.path.basename(analysis) != "analysis":
        return None, "trace is not under a case analysis/ dir"
    case_dir = os.path.dirname(analysis)
    allowed = [os.path.realpath(os.path.join(case_dir, r)) for r in OUTPUT_ROOTS]
    want = (want or "").strip()
    if not want or "\x00" in want:
        return None, "bad path"
    candidates = []
    if os.path.isabs(want):
        candidates.append(want)
        norm = want.replace("\\", "/")
        for rel in OUTPUT_ROOTS:
            marker = "/" + rel.replace(os.sep, "/") + "/"
            i = norm.rfind(marker)
            if i >= 0:
                candidates.append(os.path.join(case_dir, rel, norm[i + len(marker):]))
    else:
        candidates.append(os.path.join(case_dir, want))
    for c in candidates:
        real = os.path.realpath(c)
        if any(_within(real, a) and real != a for a in allowed):
            if os.path.isfile(real):
                return real, ""
    if any(any(_within(os.path.realpath(c), a) for a in allowed) for c in candidates):
        return None, "not found"
    return None, "path outside the case's analysis/.tool_output/ and exports/"


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

    class _Server(socketserver.ThreadingTCPServer):
        # Must be set before bind: set on the instance it came too late, so a
        # restart while the old socket sat in TIME_WAIT moved to the next port.
        allow_reuse_address = True
        daemon_threads = True

    for candidate in candidates:
        try:
            httpd = _Server(("127.0.0.1", candidate), handler)
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
