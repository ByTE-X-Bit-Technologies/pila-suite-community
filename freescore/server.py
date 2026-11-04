"""
PILA Suite — Community (Host) server
========================================

Serves the single PILA Suite product: one page (Scan -> Score -> Fix ->
Coverage) plus the JSON endpoints it calls. Host-scope only; Network and Fleet are
reported as locked and there is no code path that would scan them — the Community
build genuinely cannot reach beyond this machine.

Run standalone:
    pip install -r requirements.txt
    uvicorn freescore.server:app --host 127.0.0.1 --port 8090
    open http://127.0.0.1:8090/

Standalone, it scores the machine it runs on (real collector) and uses the
sample Prove path from engine_hooks until wired into pila-suite at home.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from . import __version__, TIER, SCOPE, LOCKED_SCOPES
from . import collector, engine_hooks
from .scoring import compute

app = FastAPI(title="PILA Suite — Community (Host)", version=__version__)

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


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    try:
        return HTMLResponse(_TEMPLATE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return HTMLResponse("<h1>PILA Suite</h1><p>UI template missing.</p>", status_code=500)


@app.get("/api/score")
@app.get("/api/scan")
def api_score() -> JSONResponse:
    """Run (or re-run) the scan and return the full score payload."""
    return JSONResponse(_run_scan())


@app.get("/api/meta")
def api_meta() -> JSONResponse:
    return JSONResponse({
        "tier": TIER, "scope": SCOPE, "locked_scopes": LOCKED_SCOPES,
        "edition": "Community", "version": __version__,
    })


@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"ok": True, "edition": "Community", "scope": SCOPE})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="info")
