"""Local server for the analysis workstation.

Binds to 127.0.0.1 by default: the tool handles evidence artefacts and API
keys, and has no business being exposed on the network.
"""

from __future__ import annotations

import asyncio
import html
import json
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .bus import EventBus
from . import report as report_module
from .config import APP_DIR, Settings
from .pipeline import Case

WEB_DIR = APP_DIR / "web"

bus = EventBus()
settings = Settings.load()
case = Case(settings, bus)


def _attach_logfile() -> None:
    """One log file per case, under output/."""
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in settings.case_name)
    bus.attach_file(settings.output_dir / f"{safe}-console.log")


_attach_logfile()

app = FastAPI(title="Kage DFIR Toolkit", docs_url=None, redoc_url=None)


class RunRequest(BaseModel):
    steps: list[str] = Field(default_factory=list)


class SettingsRequest(BaseModel):
    workspace: str | None = None
    case_name: str | None = None
    analyst: str | None = None
    demo_mode: bool | None = None
    virustotal_key: str | None = None
    abuseipdb_key: str | None = None
    anthropic_key: str | None = None
    ai_provider: str | None = None
    ai_base_url: str | None = None
    ai_model: str | None = None
    logs_source: str | None = None
    cylr_args: str | None = None
    thor_args: str | None = None
    thor_timeout_min: int | None = None
    yara_path: str | None = None
    logs_path: str | None = None
    ai_max_chars: int | None = None
    enrich_limit: int | None = None
    auto_enrich: bool | None = None


ROUTES = ("/", "/summary", "/alerts", "/indicators", "/system", "/yara",
          "/attack", "/log", "/settings")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/{page}")
async def page(page: str) -> FileResponse:
    """Views are rendered in the browser; the server returns the same page.

    Switching views never loses the analysis: it is held server-side and
    reloaded from /api/state on every mount.
    """
    if f"/{page}" not in ROUTES:
        raise HTTPException(status_code=404, detail="Unknown page.")
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/providers")
async def providers() -> JSONResponse:
    from .ai import provider_catalog

    return JSONResponse({"providers": provider_catalog()})


@app.get("/api/state")
async def state() -> JSONResponse:
    return JSONResponse(case.snapshot())


@app.get("/api/backlog")
async def backlog() -> JSONResponse:
    return JSONResponse({"events": bus.backlog()})


@app.post("/api/settings")
async def update_settings(payload: SettingsRequest) -> JSONResponse:
    changes = payload.model_dump(exclude_none=True)
    for key, value in changes.items():
        setattr(settings, key, value)
    settings.save()
    if {"case_name", "workspace"} & changes.keys():
        _attach_logfile()
    bus.log("Configuration saved.", level="ok")
    bus.emit("settings", settings=settings.public())
    return JSONResponse(settings.public())


@app.post("/api/run")
async def run(payload: RunRequest) -> JSONResponse:
    if case.running:
        raise HTTPException(status_code=409, detail="A run is already in progress.")
    steps = payload.steps or case.order
    unknown = [s for s in steps if s not in case.steps]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown steps: {', '.join(unknown)}")
    case.start(steps)
    return JSONResponse({"started": steps})


@app.post("/api/cancel")
async def cancel() -> JSONResponse:
    return JSONResponse({"cancelled": case.cancel()})


@app.post("/api/reset")
async def reset() -> JSONResponse:
    if case.running:
        raise HTTPException(status_code=409, detail="Stop the run before resetting.")
    case.reset()
    bus.emit("run", state="reset", snapshot=case.snapshot())
    return JSONResponse(case.snapshot())


@app.get("/api/console.log")
async def console_log() -> Response:
    path = bus.logfile
    if path is None or not path.exists():
        raise HTTPException(status_code=404, detail="No log recorded.")
    return Response(
        content=path.read_text(encoding="utf-8", errors="replace"),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
    )


@app.get("/api/report.json")
async def report_json() -> Response:
    if not case.report:
        raise HTTPException(status_code=404, detail="No report available.")
    body = json.dumps(
        {
            "case": settings.case_name,
            "analyst": settings.analyst,
            "generated": datetime.now(timezone.utc).isoformat(),
            "steps": [case.steps[s].public() for s in case.order],
            "timeline": case.report,
            "thor": case.thor,
            "ai": case.ai,
        },
        ensure_ascii=False, indent=2,
    )
    filename = f"{settings.case_name}-report.json"
    return Response(
        content=body, media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/report.html")
async def report_html() -> HTMLResponse:
    if not case.report:
        raise HTTPException(status_code=404, detail="No report available.")
    return HTMLResponse(report_module.render(settings, case))


@app.websocket("/ws")
async def websocket(ws: WebSocket) -> None:
    await ws.accept()
    queue = bus.subscribe()
    try:
        await ws.send_json({"kind": "hello", "snapshot": case.snapshot(),
                            "backlog": bus.backlog()})
        while True:
            event = await queue.get()
            await ws.send_json(event)
    except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
        pass  # a closed tab is not an error
    finally:
        bus.unsubscribe(queue)
        # The client may already be gone; any exception here would only fill
        # the console with a useless traceback.
        with suppress(Exception):
            await ws.close()


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


def main() -> None:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(
        description="Kage DFIR Toolkit — triage CyLR / Hayabusa / THOR Lite")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--demo", action="store_true", help="Force demonstration mode")
    args = parser.parse_args()

    if args.demo:
        settings.demo_mode = True
    from . import APP_FULL_NAME, __version__

    print(f"{APP_FULL_NAME} {__version__}")
    print(f"  code      {APP_DIR}")
    print(f"  workspace {settings.workspace}")
    print(f"  open      http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
