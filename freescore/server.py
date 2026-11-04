"""
PILA Suite — Community (Host) server
========================================

Serves the single PILA Suite product: one page (Scan -> Score -> Fix ->
Coverage) plus the JSON endpoints it calls. Host-scope only; Network and Fleet are
reported as locked and there is no code path that would scan them — the Community
build genuinely cannot reach beyond this machine.

Pure standard library only (http.server) — no third-party runtime dependencies,
so the packaged product embeds only this code plus CPython. Run standalone:

    python -m freescore            # opens the GUI in your browser
    python -m freescore --no-browser --port 8090

Standalone, it scores the machine it runs on (real collector) and uses the
sample Prove path from engine_hooks until wired into pila-suite at home.
"""

from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, TIER, SCOPE, LOCKED_SCOPES
from . import collector, engine_hooks
from .scoring import compute

_TEMPLATE = Path(__file__).parent / "templates" / "index.html"


def _run_scan() -> dict:
    """Full Scan -> Score -> Fix -> Prove for this host."""
    signals = collector.collect()
    signals = engine_hooks.enrich(signals)   # Prove (+ AESP if wired)
    result = compute(signals)
    # Surface the log sources actually found, for the Scan panel.
    result["sources"] = signals.present_log_sources or signals.expected_log_sources
    result["meta"] = {
        "tier": TIER,
        "scope": SCOPE,
        "locked_scopes": LOCKED_SCOPES,
        "edition": "Community",
        "version": __version__,
    }
    return result


def _meta() -> dict:
    return {
        "tier": TIER, "scope": SCOPE, "locked_scopes": LOCKED_SCOPES,
        "edition": "Community", "version": __version__,
    }


class _Handler(BaseHTTPRequestHandler):
    server_version = f"PILASuiteCommunity/{__version__}"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: dict, status: int = 200) -> None:
        self._send(status, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def _html(self, markup: str, status: int = 200) -> None:
        self._send(status, markup.encode("utf-8"), "text/html; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        route = self.path.split("?", 1)[0].rstrip("/") or "/"
        if route == "/":
            try:
                self._html(_TEMPLATE.read_text(encoding="utf-8"))
            except FileNotFoundError:
                self._html("<h1>PILA Suite</h1><p>UI template missing.</p>", status=500)
        elif route in ("/api/score", "/api/scan"):
            self._json(_run_scan())
        elif route == "/api/meta":
            self._json(_meta())
        elif route == "/health":
            self._json({"ok": True, "edition": "Community", "scope": SCOPE})
        else:
            self._json({"error": "not found", "path": self.path}, status=404)

    def log_message(self, *args) -> None:  # keep the console quiet
        pass


def serve(host: str = "127.0.0.1", port: int = 0, open_browser: bool = True) -> None:
    """Start the local server. port=0 picks a free port (best for a desktop app)."""
    httpd = ThreadingHTTPServer((host, port), _Handler)
    actual_port = httpd.server_address[1]
    url = f"http://{host}:{actual_port}/"
    print(f"PILA Suite — Community (Host) {__version__}")
    print(f"Serving on {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
        httpd.shutdown()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="PILA Suite — Community (Host)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0, help="0 = pick a free port")
    p.add_argument("--no-browser", action="store_true", help="don't open a browser")
    args = p.parse_args(argv)
    serve(args.host, args.port, open_browser=not args.no_browser)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
