"""Visual acceptance run: drives the dashboard in a real browser."""

import os
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PORT = 8791
WORK = Path("/tmp/dfir-ui")
WORK.mkdir(exist_ok=True)

env = {**os.environ, "DFIR_CONFIG": str(WORK / "config.json")}
(WORK / "config.json").write_text(
    '{"workspace": "/tmp/dfir-ui/ws", "demo_mode": true, '
    '"case_name": "INC-2026-0418", "analyst": "N. Delaunay"}'
)

server = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "dfirconsole.server:app",
     "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
    cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
)
time.sleep(3.5)

errors: list[str] = []
try:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1680, "height": 1050},
                                device_scale_factor=2)
        page.on("console", lambda m: errors.append(f"[console.{m.type}] {m.text}")
                if m.type == "error" and "403" not in m.text else None)
        page.on("pageerror", lambda e: errors.append(f"[pageerror] {e}"))

        page.goto(f"http://127.0.0.1:{PORT}/", wait_until="networkidle")
        page.wait_for_timeout(1200)
        assert page.locator(".tag").count() == 11, "all 11 custody tags must render"
        page.screenshot(path=str(WORK / "01-repos.png"), full_page=False)

        # Run the whole chain
        page.click("#btnRun")
        page.wait_for_function("() => document.querySelector('#btnRun').disabled",
                               timeout=15000)
        page.wait_for_timeout(2500)
        page.screenshot(path=str(WORK / "02-encours.png"))

        page.wait_for_function("() => !document.querySelector('#btnRun').disabled",
                               timeout=90000)
        page.wait_for_timeout(900)
        page.screenshot(path=str(WORK / "03-alertes.png"))

        score = page.inner_text("#scoreValue")
        verdict = page.inner_text("#verdictLine")
        alerts = page.inner_text("#nAlerts")
        iocs = page.inner_text("#nIocs")
        rows = page.locator("#alertTable tbody tr").count()
        seals = page.locator(".tag__seal").count()
        print(f"score={score} verdict={verdict!r} alerts={alerts} iocs={iocs} "
              f"rows={rows} seals={seals}")

        page.click('.nav__item[data-route="/indicators"]')
        page.wait_for_timeout(400)
        page.screenshot(path=str(WORK / "04-iocs.png"))
        print("ioc rows:", page.locator("#iocTable tbody tr").count())

        page.click('.nav__item[data-route="/attack"]')
        page.wait_for_timeout(300)
        page.screenshot(path=str(WORK / "05-attack.png"))
        print("tactics:", page.locator(".tacrow").count())

        page.click('.nav__item[data-route="/summary"]')
        page.wait_for_timeout(300)
        page.screenshot(path=str(WORK / "06-synthese.png"))
        print("summary sections:", page.locator("#aiReport h3").count())

        # Filters
        page.click('.nav__item[data-route="/alerts"]')
        page.fill("#alertSearch", "lsass")
        page.wait_for_timeout(300)
        print("after the lsass filter:", page.locator("#alertTable tbody tr").count())
        page.fill("#alertSearch", "")

        # Reading pane for one alert
        page.click('.nav__item[data-route="/alerts"]')
        page.wait_for_timeout(300)
        page.click("#alertTable tbody tr:first-child")
        page.wait_for_selector("#reader:not([hidden])", timeout=4000)
        page.wait_for_timeout(400)
        print("pane opened:", page.inner_text("#readerTitle")[:60])
        print("position:", page.inner_text("#readerPos"))
        print("fields shown:", page.locator(".rfield").count())
        page.screenshot(path=str(WORK / "10-lecteur.png"))

        page.click("#readerNext")
        page.wait_for_timeout(250)
        print("after next:", page.inner_text("#readerPos"))
        page.keyboard.press("ArrowLeft")
        page.wait_for_timeout(250)
        print("after left arrow:", page.inner_text("#readerPos"))
        page.keyboard.press("Escape")
        page.wait_for_timeout(250)
        assert page.locator("#reader").is_hidden(), "Esc must close the pane"
        print("Esc closes the pane.")

        # Settings drawer
        page.click("#btnSettings")
        page.wait_for_timeout(400)
        page.screenshot(path=str(WORK / "07-reglages.png"))
        page.click("#btnSettings")

        # Mobile rendering
        page.set_viewport_size({"width": 430, "height": 900})
        page.wait_for_timeout(500)
        page.screenshot(path=str(WORK / "08-mobile.png"))

        # Printable report
        report = browser.new_context().new_page()
        report.goto(f"http://127.0.0.1:{PORT}/api/report.html")
        report.wait_for_timeout(400)
        report.screenshot(path=str(WORK / "09-rapport.png"), full_page=True)

        browser.close()
finally:
    server.terminate()

if errors:
    print("\nBROWSER ERRORS:")
    for error in errors:
        print(" ", error)
    sys.exit(1)
print("\nNo console error. Screenshots in", WORK)
