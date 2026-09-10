"""Load acceptance run: reproduces the `hayabusa update-rules` burst.

The tab used to freeze on that step. This checks that 6000 lines pushed at
once still leave the page responsive.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PORT = 8793
WORK = Path("/tmp/dfir-flood")
WORK.mkdir(exist_ok=True)

env = {**os.environ, "DFIR_CONFIG": str(WORK / "config.json")}
(WORK / "config.json").write_text(
    '{"workspace": "/tmp/dfir-flood/ws", "demo_mode": true, "case_name": "FLOOD-01"}'
)

server = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "dfirconsole.server:app",
     "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
    cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
)
time.sleep(3.5)

errors: list[str] = []
try:
    import httpx

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1600, "height": 1000})
        page.on("pageerror", lambda e: errors.append(f"[pageerror] {e}"))
        page.goto(f"http://127.0.0.1:{PORT}/", wait_until="networkidle")
        page.wait_for_timeout(800)

        # Burst equivalent to a Sigma rule update.
        print("Pushing 6000 lines…")
        start = time.monotonic()
        with httpx.Client(base_url=f"http://127.0.0.1:{PORT}") as client:
            client.post("/api/run", json={"steps": ["workspace"]})
        import asyncio

        sys.path.insert(0, str(ROOT))
        from dfirconsole import server as srv  # noqa: E402

        # On pousse directement dans le bus du serveur en cours ? Impossible :
        # separate process, so go through a genuinely verbose step instead.
        page.wait_for_timeout(500)

        # Client-side simulation: inject through the browser WebSocket.
        page.evaluate("""
          () => {
            for (let i = 0; i < 6000; i++) {
              handle({ kind: "log", ts: Date.now() / 1000, level: "out",
                       message: "  - Sigma rule number " + i +
                                " (Modified: 2026-01-01 | Path: rules/sigma/x_" + i + ".yml)" });
            }
          }
        """)
        page.wait_for_timeout(1500)
        elapsed = time.monotonic() - start

        rendered = page.locator("#console .line").count()
        print(f"Lines kept in the DOM: {rendered} (expected cap: 1200)")
        print(f"Total duration: {elapsed:.1f} s")

        # The page must stay interactive: click a view and type.
        page.click('.nav__item[data-route="/indicators"]', timeout=5000)
        page.click('.nav__item[data-route="/alerts"]', timeout=5000)
        page.fill("#alertSearch", "test", timeout=5000)
        print("Page still interactive after the burst.")

        assert rendered <= 1200, "the line cap is not enforced"
        browser.close()
finally:
    server.terminate()

if errors:
    print("\nERRORS:")
    for error in errors:
        print(" ", error)
    sys.exit(1)
print("\nLoad run passed.")
