"""Local server for the analysis workstation.

Binds to 127.0.0.1 by default: the tool handles evidence artefacts and API
keys, and has no business being exposed on the network.
"""

from __future__ import annotations

import asyncio
import html
import json
import os
from contextlib import suppress
import sys
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .bus import EventBus
from . import APP_FULL_NAME, __version__
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
    image_path: str | None = None
    image_files_mb: int | None = None
    remote_host: str | None = None
    remote_user: str | None = None
    remote_password: str | None = None
    remote_ssl: bool | None = None
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


LOG_SOURCES = ("collector", "remote", "image", "live", "custom")


@app.post("/api/settings")
async def update_settings(payload: SettingsRequest) -> JSONResponse:
    changes = payload.model_dump(exclude_none=True)
    source = changes.get("logs_source")
    if source is not None and source not in LOG_SOURCES:
        raise HTTPException(status_code=400,
                            detail=f"Unknown log source '{source}'. Expected one of: "
                                   + ", ".join(LOG_SOURCES))
    for numeric in ("enrich_limit", "thor_timeout_min", "ai_max_chars", "image_files_mb"):
        if numeric in changes and changes[numeric] < 0:
            raise HTTPException(status_code=400, detail=f"{numeric} cannot be negative.")
    # An empty password field means "keep the one already set", not "erase it".
    if not changes.get("remote_password"):
        changes.pop("remote_password", None)
    if "remote_host" in changes:
        changes["remote_host"] = changes["remote_host"].strip().strip("\\/")
    for key, value in changes.items():
        setattr(settings, key, value)
    settings.save()
    # Step descriptions follow the evidence source; push them so the chain
    # on the left changes as soon as the source does.
    case._refresh_step_hints()
    for step_id in ("tools", "collect", "system"):
        bus.emit("step", step=case.steps[step_id].public())
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


@app.post("/api/remote/test")
async def remote_test() -> JSONResponse:
    """Open a session with the saved remote settings and say who answered."""
    from . import remote as remote_module

    try:
        transport = remote_module.open_transport(
            settings.remote_host, settings.remote_user, settings.remote_password,
            settings.remote_ssl)
        try:
            code, text = await asyncio.to_thread(
                transport.run, ["powershell", "-NoProfile", "-Command", remote_module.HELLO], 60)
            hello = json.loads(text.strip().splitlines()[-1])
        finally:
            transport.close()
    except remote_module.RemoteError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (ValueError, IndexError):
        raise HTTPException(status_code=400, detail="The host answered but not as expected.")
    hello["transport"] = transport.label
    bus.log(f"Remote host {hello.get('hostname')} reachable over {transport.label}"
            f"{', as administrator' if hello.get('admin') else ', WITHOUT administrator rights'}.",
            level="ok" if hello.get("admin") else "warn")
    return JSONResponse(hello)


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
    # The Log buttons are always on screen: before the first line is written
    # they download a one-line note instead of opening a raw 404 page.
    if path is None or not path.exists():
        name = path.name if path is not None else "console.log"
        return Response(content="No log line recorded yet for this case.\n",
                        media_type="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})
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
            "tool": f"{APP_FULL_NAME} {__version__}",
            "case": settings.case_name,
            "analyst": settings.analyst,
            "generated": datetime.now(timezone.utc).isoformat(),
            "evidence": {
                "source": "demo" if settings.demo_mode else settings.logs_source,
                "image": case.image,
                "remote": case.remote,
                "logs_dir": str(case.logs_dir) if case.logs_dir else None,
            },
            "steps": [case.steps[s].public() for s in case.order],
            "timeline": case.report,
            "system": case.system,
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


def _hello() -> dict:
    """Snapshot, recent backlog and the sequence number they cover: the client
    drops queued events it has already seen through them."""
    return {"kind": "hello", "seq": bus.seq, "snapshot": case.snapshot(),
            "backlog": bus.backlog()}


@app.websocket("/ws")
async def websocket(ws: WebSocket) -> None:
    await ws.accept()
    queue = bus.subscribe()
    try:
        await ws.send_json(_hello())
        while True:
            event = await queue.get()
            # A client too slow to keep up gets the whole picture again
            # instead of an endless gap.
            await ws.send_json(_hello() if event["kind"] == "resync" else event)
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


def serve(args) -> None:
    """Start the console. `args` comes from dfirconsole.cli."""
    import socket
    import threading
    import webbrowser

    import uvicorn

    from . import APP_FULL_NAME, __version__
    from .config import FROZEN, PROJECT_DIR

    if args.demo:
        settings.demo_mode = True
    if args.image:
        settings.logs_source = "image"
        settings.image_path = str(Path(args.image).expanduser().resolve())
        settings.demo_mode = False
    if getattr(args, "remote", None):
        settings.logs_source = "remote"
        settings.remote_host = args.remote
        settings.remote_user = args.remote_user or ""
        settings.remote_password = os.environ.get("KAGE_REMOTE_PASSWORD", "")
        settings.demo_mode = False
        case._refresh_step_hints()

    # A second instance on the same port would fail with an opaque socket
    # error after the banner; say it plainly instead.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        if probe.connect_ex((args.host if args.host != "0.0.0.0" else "127.0.0.1",
                             args.port)) == 0:
            print(f"Port {args.port} is already in use — Kage may already be running: "
                  f"http://{args.host}:{args.port}\nUse --port to start another instance.")
            raise SystemExit(2)

    url = f"http://{args.host}:{args.port}"
    print(f"{APP_FULL_NAME} {__version__}")
    print(f"  {'executable' if FROZEN else 'code      '} "
          f"{Path(sys.executable).resolve() if FROZEN else APP_DIR}")
    print(f"  workspace  {settings.workspace}")
    print(f"  config     {PROJECT_DIR / 'config.json'}")
    if settings.logs_source == "image" and settings.image_path:
        print(f"  image      {settings.image_path}")
    if settings.logs_source == "remote" and settings.remote_host:
        print(f"  remote     {settings.remote_host} over WinRM"
              f" as {settings.remote_user or 'the current Windows session'}")
    print(f"  open       {url}")
    print("  Close this window or press Ctrl+C to stop Kage.")

    # Double-clicking an executable should land in the console, not in a
    # terminal waiting for someone to copy a URL. From the sources it stays
    # opt-in: launch.bat already opens the page.
    if args.browser if args.browser is not None else FROZEN:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    except KeyboardInterrupt:
        pass


def main(argv: list[str] | None = None) -> None:
    from .cli import main as cli_main

    cli_main(argv)


if __name__ == "__main__":
    main()
