"""Navigation acceptance run.

Checks the three promises of the layout: every view has its own URL, moving
between views loses nothing, and a full browser reload restores the analysis
from the server.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PORT = 8799
WORK = Path("/tmp/dfir-nav")
WORK.mkdir(exist_ok=True)

env = {**os.environ, "DFIR_CONFIG": str(WORK / "config.json")}
(WORK / "config.json").write_text(
    '{"workspace": "/tmp/dfir-nav/ws", "demo_mode": true, '
    '"case_name": "NAV-001", "analyst": "Recette"}'
)

# The YARA view can only be checked if a scanner exists, so the run installs
# its own stand-in rather than depending on whatever happens to be on disk.
# It emits THOR's real output shape: a start-up banner that must be dropped,
# then verdicts at every level, so the filters have something to filter.
import stat

thor_dir = WORK / "ws" / "tools" / "thor"
thor_dir.mkdir(parents=True, exist_ok=True)
fake_thor = thor_dir / "thor64-lite.exe"
fake_thor.write_text('''#!/usr/bin/env python3
import sys, random
args = sys.argv[1:]
log = args[args.index("--logfile") + 1]
lines = [
    "Info: MODULE: Startup MESSAGE: Thor Version: 10.7.29",
    "Info: MODULE: Startup MESSAGE: Run on system: NAV-HOST",
]
for level, name, message, score in [
    ("Alert", "Rubeus.exe", "YARA rule HKTL_Rubeus", 100),
    ("Alert", "AmsiTrigger.exe", "YARA rule HKTL_AmsiTrigger", 95),
    ("Warning", "svchost32.exe", "Suspicious filename in user directory", None),
    ("Notice", "chrome.exe", "File checked - signed", None),
    ("Info", "notepad.exe", "Clean", None),
]:
    digest = "".join(random.choice("0123456789abcdef") for _ in range(64))
    line = ("Aug 07 09:12:%02d HOST THOR: %s: MODULE: Filescan MESSAGE: %s "
            "FILE: C:\\\\AD\\\\Tools\\\\%s SHA256: %s"
            % (random.randint(10, 59), level, message, name, digest))
    if score:
        line += " SCORE: %d" % score
    lines.append(line)
for line in lines:
    print(line)
open(log, "w").write("\\n".join(lines) + "\\n")
''')
fake_thor.chmod(fake_thor.stat().st_mode | stat.S_IEXEC)

server = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "dfirconsole.server:app",
     "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
    cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
)
time.sleep(3.5)

errors: list[str] = []
failures: list[str] = []


def check(condition: bool, message: str) -> None:
    print(("  ok    " if condition else "  FAIL  ") + message)
    if not condition:
        failures.append(message)


try:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1680, "height": 1050},
                                device_scale_factor=2)
        page.on("pageerror", lambda e: errors.append(f"[pageerror] {e}"))
        page.on("console", lambda m: errors.append(f"[console] {m.text}")
                if m.type == "error" and "403" not in m.text else None)

        page.goto(f"http://127.0.0.1:{PORT}/", wait_until="networkidle")
        page.wait_for_timeout(1000)

        print("\n— Full chain —")
        # The YARA scan is unticked by default: tick it for this run.
        page.locator('.tag:has-text("YARA scan") .tag__check').check()
        page.click("#btnRun")
        # Wait for the run to actually start before watching for its end,
        # otherwise we observe "finished" before anything began.
        page.wait_for_function("() => document.querySelector('#btnRun').disabled",
                               timeout=15000)
        page.wait_for_function("() => !document.querySelector('#btnRun').disabled",
                               timeout=180000)
        page.wait_for_timeout(1500)
        check(page.inner_text("#scoreValue") != "—", "risk score computed")
        check(int(page.inner_text("#nSystem")) > 0, "system findings surfaced")

        print("\n— Navigation —")
        for route, marqueur in [("/alerts", "#alertTable"), ("/indicators", "#iocTable"),
                                ("/system", "#sysgrid"), ("/yara", "#yaraTable"),
                                ("/attack", "#attack"), ("/summary", "#aiReport"),
                                ("/log", "#console2")]:
            page.click(f'.nav__item[data-route="{route}"]')
            page.wait_for_timeout(350)
            visible = page.locator(f'.view[data-view="{route}"]').is_visible()
            check(visible and page.url.endswith(route), f"{route} shown and reflected in the URL")

        print("\n— Navigation loses nothing —")
        page.click('.nav__item[data-route="/alerts"]')
        page.wait_for_timeout(300)
        before = page.locator("#alertTable tbody tr").count()
        page.click('.nav__item[data-route="/system"]')
        page.wait_for_timeout(250)
        page.click('.nav__item[data-route="/alerts"]')
        page.wait_for_timeout(300)
        check(page.locator("#alertTable tbody tr").count() == before,
                 f"the {before} alerts survive a round trip")

        print("\n— Full browser reload —")
        page.goto(f"http://127.0.0.1:{PORT}/system", wait_until="networkidle")
        page.wait_for_timeout(1400)
        check(page.locator('.view[data-view="/system"]').is_visible(),
                 "direct open on /system")
        check(page.locator(".syscard").count() >= 3,
                 "system cards restored after reload")
        check(page.inner_text("#scoreValue") != "—",
                 "the score is restored from the server")
        page.screenshot(path=str(WORK / "systeme.png"))

        print("\n— Browser history —")
        page.go_back()
        page.wait_for_timeout(500)
        check(not page.url.endswith("/system"), "the Back button changes view")

        print("\n— Family filters —")
        page.goto(f"http://127.0.0.1:{PORT}/alerts", wait_until="networkidle")
        page.wait_for_timeout(1200)
        total = page.locator("#alertTable tbody tr").count()
        families = page.locator("#catChips .chip--cat").count()
        check(families == 6, f"{families} families offered")

        # Keep only the evasion family
        for chip in page.locator("#catChips .chip--cat").all():
            if chip.get_attribute("data-cat") != "evasion":
                chip.click()
                page.wait_for_timeout(60)
        page.wait_for_timeout(350)
        filtered = page.locator("#alertTable tbody tr").count()
        check(0 < filtered < total, f"evasion filter: {filtered} of {total}")
        # The CSS uppercases labels, so compare case-insensitively.
        shown_families = {c.inner_text().strip().lower() for c in
                              page.locator("#alertTable tbody tr td:nth-child(3)").all()}
        check(shown_families <= {"evasion"},
                 f"a single family displayed: {shown_families}")
        page.screenshot(path=str(WORK / "alerts.png"))

        print("\n— YARA page: every verdict, not just alerts —")
        page.goto(f"http://127.0.0.1:{PORT}/yara", wait_until="networkidle")
        page.wait_for_timeout(800)
        total_yara = page.locator("#yaraTable tbody tr").count()
        check(total_yara > 0, f"{total_yara} verdict(s) displayed")
        levels = {c.inner_text().strip().lower() for c in
                   page.locator("#yaraTable tbody tr td:nth-child(1)").all()}
        check(len(levels) > 1, f"several distinct verdicts: {levels}")
        hashes = page.locator("#yaraTable tbody tr td:nth-child(5)").count()
        check(hashes == total_yara, "hash column populated")

        # Keep only the alerts
        for chip in page.locator("#yaraChips .chip").all():
            if chip.get_attribute("data-level") != "critical":
                chip.click()
                page.wait_for_timeout(60)
        page.wait_for_timeout(300)
        alerts = page.locator("#yaraTable tbody tr").count()
        check(0 < alerts < total_yara, f"alert filter: {alerts} of {total_yara}")
        page.fill("#yaraSearch", "rubeus")
        page.wait_for_timeout(300)
        check(page.locator("#yaraTable tbody tr").count() == 1,
                 "search for rubeus: one row")
        page.screenshot(path=str(WORK / "yara.png"))

        print("\n— Logging coverage —")
        page.goto(f"http://127.0.0.1:{PORT}/system", wait_until="networkidle")
        page.wait_for_timeout(1200)
        cards = page.locator(".syscard").count()
        check(cards >= 5, f"{cards} system cards")
        header = " ".join(c.inner_text() for c in page.locator(".syscard .eyebrow").all())
        check("LOGGING" in header.upper(), "logging & audit card present")
        check(page.locator(".covgap").count() == 1, "blind spots flagged")
        page.screenshot(path=str(WORK / "systeme.png"), full_page=True)

        print("\n— Elapsed timer stops with the chain —")
        first = page.inner_text("#clockLabel")
        page.wait_for_timeout(2500)
        check(page.inner_text("#clockLabel") == first,
              f"clock frozen at {first} after the run ended")

        print("\n— Score is published with its breakdown —")
        page.goto(f"http://127.0.0.1:{PORT}/", wait_until="networkidle")
        page.wait_for_timeout(900)
        comps = [c.inner_text().replace("\n", " ") for c in page.locator(".scomp").all()]
        check(len(comps) == 4, f"4 score components: {comps}")
        check(page.locator(".conf").count() == 1,
              f"confidence shown: {page.locator('.conf').first.inner_text()}")

        print("\n— Family counts match the table —")
        page.goto(f"http://127.0.0.1:{PORT}/alerts", wait_until="networkidle")
        page.wait_for_timeout(1000)
        badges = {c.get_attribute("data-cat"): int(c.inner_text().split()[-1])
                  for c in page.locator("#catChips .chip--cat").all()}
        total_badges = sum(badges.values())
        rows_all = page.locator("#alertTable tbody tr").count()
        check(total_badges == rows_all,
              f"families sum to {total_badges}, table shows {rows_all}")

        for family, count in badges.items():
            if not count:
                continue
            for chip in page.locator("#catChips .chip--cat").all():
                on = "is-on" in (chip.get_attribute("class") or "")
                if (chip.get_attribute("data-cat") == family) != on:
                    chip.click()
                    page.wait_for_timeout(40)
            page.wait_for_timeout(250)
            shown = page.locator("#alertTable tbody tr").count()
            check(shown == count, f"{family}: badge {count}, table {shown}")

        print("\n— Histogram follows the selected family —")
        # Only the evasion family is selected at this point: the histogram must
        # be drawn in that family's colour, not the neutral one.
        colours = {r.get_attribute("fill") for r in page.locator("#spark rect").all()}
        selected = page.evaluate("() => [...state.cats]")
        check("#B36BC4" in colours,
              f"histogram uses the evasion colour (selection={selected}, fills={colours})")

        print("\n— Reading pane from the System view —")
        page.goto(f"http://127.0.0.1:{PORT}/system", wait_until="networkidle")
        page.wait_for_timeout(1200)
        page.locator(".syscard .grid tbody tr").first.click()
        page.wait_for_selector("#reader:not([hidden])", timeout=4000)
        page.wait_for_timeout(300)
        check(page.locator(".rfield").count() >= 3,
                 f"pane opened with {page.locator('.rfield').count()} fields")
        print("      kind:", page.inner_text("#readerKind"))
        page.keyboard.press("Escape")

        browser.close()
finally:
    server.terminate()

print()
if errors:
    print("BROWSER ERRORS:")
    for error in errors:
        print("  ", error)
if failures:
    print(f"{len(failures)} check(s) failed.")
    sys.exit(1)
if errors:
    sys.exit(1)
print(f"Navigation run passed. Screenshots in {WORK}")
