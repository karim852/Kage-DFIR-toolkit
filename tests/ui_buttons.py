"""Every control of the console, clicked once.

    python tests/ui_buttons.py

Toolbar, settings drawer, step tags, navigation and counters, filters and
searches, the reading pane from every table, the exports, browser history,
Reset, and a disk-image run driven from the interface. Any browser console
error fails the run.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "kage-fixture.E01"
PORT = 8797
WORK = Path("/tmp/dfir-buttons")
shutil.rmtree(WORK, ignore_errors=True)
WORK.mkdir()
BASE = f"http://127.0.0.1:{PORT}"

# A simulated Windows host for the remote section, carrying the fixture
# disk's own event logs (see tests/fixtures/simulated_host.py).
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))
import simulated_host  # noqa: E402
from dfirconsole import image as image_module  # noqa: E402

image_module.extract(image_module.open_image(FIXTURE), WORK / "fixture-logs")
PROFILE = simulated_host.build_profile(WORK / "remote-host", WORK / "fixture-logs" / "Logs")
(WORK / "ws" / "tools" / "cylr").mkdir(parents=True)
(WORK / "ws" / "tools" / "cylr" / "CyLR.exe").write_bytes(b"MZ simulated CyLR")

env = {**os.environ, "DFIR_CONFIG": str(WORK / "config.json"),
       "KAGE_REMOTE_SIMULATION": str(PROFILE)}
(WORK / "config.json").write_text(json.dumps({
    "workspace": str(WORK / "ws"), "demo_mode": True, "case_name": "BTN-001",
    "analyst": "Recette", "ai_provider": "none"}))

# Same stand-in scanner as ui_nav: THOR's real output shape, every verdict level.
thor_dir = WORK / "ws" / "tools" / "thor"
thor_dir.mkdir(parents=True, exist_ok=True)
fake_thor = thor_dir / "thor64-lite.exe"
SLOW = WORK / "slow-scan"
fake_thor.write_text(f'''#!/usr/bin/env python3
import os, sys, time
SLOW = {str(SLOW)!r}
args = sys.argv[1:]
log = args[args.index("--logfile") + 1]
lines = ["Info: MODULE: Startup MESSAGE: Thor Version: 10.7.29"]
if os.path.exists(SLOW):           # the Stop test needs a scan that lasts
    print(lines[0], flush=True)
    time.sleep(60)
for i, (level, name, message, score) in enumerate([
    ("Alert", "Rubeus.exe", "YARA rule HKTL_Rubeus", 100),
    ("Alert", "AmsiTrigger.exe", "YARA rule HKTL_AmsiTrigger", 95),
    ("Warning", "svchost32.exe", "Suspicious filename in user directory", None),
    ("Notice", "chrome.exe", "File checked - signed", None),
]):
    line = ("Aug 07 09:12:%02d HOST THOR: %s: MODULE: Filescan MESSAGE: %s "
            "FILE: C:\\\\AD\\\\Tools\\\\%s SHA256: %s" % (10 + i, level, message, name, str(i) * 64))
    if score:
        line += " SCORE: %d" % score
    lines.append(line)
print("\\n".join(lines))
open(log, "w").write("\\n".join(lines) + "\\n")
''')
fake_thor.chmod(fake_thor.stat().st_mode | stat.S_IEXEC)

server = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "dfirconsole.server:app",
     "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
    # To a file, not a pipe: an unread pipe fills up and freezes the server.
    cwd=str(ROOT), env=env, stdout=open(WORK / "server.log", "w"), stderr=subprocess.STDOUT)
time.sleep(3.5)

errors: list[str] = []
failures: list[str] = []


def check(condition: bool, message: str) -> None:
    print(("  ok    " if condition else "  FAIL  ") + message, flush=True)
    if not condition:
        failures.append(message)


def wait_run(page, timeout=180000) -> None:
    page.wait_for_function("() => document.querySelector('#btnRun').disabled", timeout=15000)
    page.wait_for_function("() => !document.querySelector('#btnStop').disabled ||"
                           " !document.querySelector('#btnRun').disabled", timeout=15000)
    page.wait_for_function("() => document.querySelector('#btnStop').disabled", timeout=timeout)
    page.wait_for_timeout(1200)


def go(page, route: str) -> None:
    page.click(f'.nav__item[data-route="{route}"]')
    page.wait_for_timeout(350)


def visible(page, selector: str) -> bool:
    return page.locator(selector).is_visible()


def exercise_reader(page, rows_selector: str, label: str) -> None:
    """Open the first row, walk it with buttons and arrows, copy, close three ways."""
    rows = page.locator(rows_selector)
    count = rows.count()
    if not count:
        check(False, f"{label}: rows to open")
        return
    rows.first.click()
    page.wait_for_selector("#reader:not([hidden])", timeout=4000)
    position = page.inner_text("#readerPos")
    check(position.startswith("1 / "), f"{label}: reader opens on row 1 ({position})")
    if count > 1:
        page.click("#readerNext")
        check(page.inner_text("#readerPos").startswith("2 / "), f"{label}: Next")
        page.click("#readerPrev")
        check(page.inner_text("#readerPos").startswith("1 / "), f"{label}: Prev")
        page.keyboard.press("ArrowRight")
        check(page.inner_text("#readerPos").startswith("2 / "), f"{label}: → key")
        page.keyboard.press("ArrowLeft")
        check(page.inner_text("#readerPos").startswith("1 / "), f"{label}: ← key")
    check(page.is_disabled("#readerPrev"), f"{label}: Prev disabled on row 1")
    check(page.locator(".rfield").count() >= 2, f"{label}: fields shown")
    page.click("#readerCopy")
    page.wait_for_timeout(150)
    copied = page.evaluate("() => navigator.clipboard.readText()")
    check(copied.strip().startswith("{"), f"{label}: Copy puts the JSON on the clipboard")
    page.click("#readerClose")
    check(page.locator("#reader").is_hidden(), f"{label}: Close button")
    rows.first.click()
    page.keyboard.press("Escape")
    check(page.locator("#reader").is_hidden(), f"{label}: Escape")
    rows.first.click()
    page.mouse.click(8, 8)          # the dimmed backdrop, outside the box
    check(page.locator("#reader").is_hidden(), f"{label}: click outside")
    rows.first.focus()
    page.keyboard.press("Enter")
    check(page.locator("#reader").is_visible(), f"{label}: Enter on a focused row")
    page.keyboard.press("Escape")


try:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1600, "height": 1000},
                                      accept_downloads=True)
        context.grant_permissions(["clipboard-read", "clipboard-write"], origin=BASE)
        page = context.new_page()
        page.on("pageerror", lambda e: errors.append(f"[pageerror] {e}"))
        page.on("console", lambda m: errors.append(f"[console] {m.text}")
                if m.type == "error" and "403" not in m.text and "400" not in m.text else None)
        page.goto(BASE + "/", wait_until="networkidle")
        page.wait_for_timeout(1000)
        if os.environ.get("KAGE_UI_TRACE"):   # event-by-event trace, for flaky runs
            page.evaluate("""() => new MutationObserver(() => console.log('[trace] stop=' +
                document.querySelector('#btnStop').disabled + ' ' +
                state.steps.map(s => s.status[0]).join(''))).observe(
                document.querySelector('#btnStop'), {attributes: true})""")
            page.on("console", lambda m: print("      " + m.text) if m.text.startswith("[trace]") else None)
            page.evaluate("""() => { const h = window.handle; window.handle = (e) => {
                if (e.kind !== 'log') console.log('[trace] ev ' + e.kind + ' ' + e.seq + ' ' + (e.state||'') + ' ' + ((e.step||{}).id||'') + ':' + ((e.step||{}).status||'') + ' last=' + lastSeq);
                return h(e); }; }""")


        print("\n— Before any run —")
        for button in ("#btnHtml", "#btnJson"):
            off = page.evaluate(f"""() => {{
                const b = document.querySelector('{button}');
                return getComputedStyle(b).pointerEvents === 'none'
                    && b.getAttribute('aria-disabled') === 'true'; }}""")
            check(off, f"{button} visibly off and not clickable")
        check(page.is_disabled("#btnStop"), "Stop disabled while idle")
        check(page.is_enabled("#btnReset"), "Reset available while idle")
        with page.expect_download() as download:
            page.click("#btnLog")
        text = Path(download.value.path()).read_text()
        check(len(text) > 0, f"Log download works before any run ({text.strip()[:45]}…)")
        check(page.inner_text("#caseName") == "BTN-001", "case name in the header")
        check("demonstration" in page.inner_text("#modeLabel"), "mode label")

        print("\n— Settings drawer —")
        page.click("#btnSettings")
        check(visible(page, "#drawer"), "Settings opens the drawer")
        check(page.get_attribute("#btnSettings", "aria-expanded") == "true", "aria-expanded true")
        check(page.input_value("#setProvider") == "none", "provider defaults to local summary")
        check(page.locator("#setAI").is_hidden() and page.locator("#setModel").is_hidden(),
              "local summary hides key, URL and model")
        page.select_option("#setProvider", "groq")
        check(page.locator("#setAI").is_visible(), "a remote provider shows its key field")
        check("api.groq.com" in page.text_content("#baseUrlHint"), "base URL hint follows the provider")
        check("llama" in (page.get_attribute("#setModel", "placeholder") or ""),
              "model placeholder follows the provider")
        page.select_option("#setProvider", "custom")
        check("required" in page.text_content("#baseUrlHint"), "custom provider asks for a URL")
        page.select_option("#setProvider", "none")

        expected = {"collector": ["#setCylrArgs"], "image": ["#setImagePath", "#setImageBudget"],
                    "custom": ["#setLogsPath"], "live": []}
        every = ["#setCylrArgs", "#setImagePath", "#setImageBudget", "#setLogsPath"]
        for source, shown in expected.items():
            page.select_option("#setLogsSource", source)
            ok = all(page.locator(s).is_visible() == (s in shown) for s in every)
            check(ok, f"source {source}: shows {shown or 'no extra field'}")
        page.select_option("#setLogsSource", "collector")
        check(page.input_value("#setThorTimeout") == "0", "THOR time limit shows the real default")
        check(page.get_attribute("#setThorArgs", "placeholder") == "--nocsv",
              "THOR placeholder matches the value actually used")

        # A refused save must explain itself and keep the drawer open.
        page.route("**/api/settings", lambda route: route.fulfill(
            status=400, content_type="application/json",
            body=json.dumps({"detail": "image_path: file not found"}))
            if route.request.method == "POST" else route.continue_())
        page.click("#btnSaveSettings")
        page.wait_for_timeout(400)
        check(page.locator("#settingsError").is_visible()
              and "file not found" in page.inner_text("#settingsError"),
              "refused save shows the reason")
        check(visible(page, "#drawer"), "drawer stays open on error")
        page.unroute("**/api/settings")

        # And the server's own validation is reachable from the form.
        page.fill("#setLimit", "-5")
        page.click("#btnSaveSettings")
        page.wait_for_timeout(400)
        check(page.locator("#drawer").is_hidden(), "negative indicator limit clamped, save goes through")
        page.click("#btnSettings")
        check(page.input_value("#setLimit") == "0", "clamped value displayed after reopening")
        page.fill("#setCase", "BTN-002")
        page.fill("#setAnalyst", "Tester")
        page.click("#btnSaveSettings")
        page.wait_for_timeout(500)
        check(page.locator("#drawer").is_hidden(), "successful save closes the drawer")
        check(page.locator("#settingsError").is_hidden(), "error cleared after a good save")
        check(page.inner_text("#caseName") == "BTN-002", "header follows the new case name")
        saved = json.loads((WORK / "config.json").read_text())
        check(saved["case_name"] == "BTN-002" and saved["analyst"] == "Tester",
              "settings written to config.json")
        page.click("#btnSettings")
        page.click("#btnSettings")
        check(page.locator("#drawer").is_hidden(), "Settings toggles the drawer closed")
        check(page.get_attribute("#btnSettings", "aria-expanded") == "false", "aria-expanded false")

        print("\n— Step tags —")
        checks = page.locator(".tag .tag__check")
        total = checks.count()
        ticked = sum(1 for c in checks.all() if c.is_checked())
        check(page.text_content("#btnRun") == f"Run {ticked} steps",
              f"Run label counts the ticked steps ({ticked} of {total})")
        for c in checks.all():
            if not c.is_checked():
                c.check()
        check(page.text_content("#btnRun") == "Run the chain", "all ticked: Run the chain")
        for c in checks.all():
            c.uncheck()
        check(page.is_disabled("#btnRun"), "nothing ticked: Run disabled")
        checks.first.check()
        check(page.text_content("#btnRun") == "Run 1 step", "singular label")
        for c in checks.all():
            c.check()

        print("\n— Full chain —")
        page.click("#btnRun")
        page.wait_for_function("() => document.querySelector('#btnRun').disabled", timeout=15000)
        check(page.is_enabled("#btnStop"), "Stop enabled while running")
        check(page.is_disabled("#btnReset"), "Reset disabled while running")
        check(all(c.is_disabled() for c in checks.all()), "step boxes locked while running")
        page.wait_for_function("() => document.querySelector('#btnStop').disabled", timeout=180000)
        page.wait_for_timeout(1500)
        statuses = page.evaluate("() => state.steps.map(s => s.id + ':' + s.status)")
        # No VirusTotal key and Defender untouched in demo: those two skip.
        check(all(s.endswith(":done") or s in ("enrich:skipped", "defender:skipped")
                  for s in statuses), f"every step done or skipped as expected: {statuses}")
        check(page.inner_text("#scoreValue") != "—", f"score {page.inner_text('#scoreValue')}")
        check(page.evaluate("() => !document.querySelector('#btnHtml').classList.contains('is-off')"),
              "Report export switched on")
        check(" UTC" in page.inner_text("#windowLine"), f"window in UTC: {page.inner_text('#windowLine')}")

        print("\n— Counters match their tables —")
        for route, counter, table in [("/alerts", "#nAlerts", "#alertTable"),
                                      ("/indicators", "#nIocs", "#iocTable"),
                                      ("/yara", "#nYara", "#yaraTable")]:
            go(page, route)
            rows = page.locator(f"{table} tbody tr").count()
            shown = int(page.inner_text(counter))
            check(rows == shown and rows > 0, f"{route}: counter {shown}, table {rows}")
        go(page, "/system")
        check(int(page.inner_text("#nSystem")) > 0 and page.locator(".syscard").count() >= 3,
              "system counter and cards")

        print("\n— Alert filters —")
        go(page, "/alerts")
        all_rows = page.locator("#alertTable tbody tr").count()
        for chip in page.locator("#levelChips .chip").all():
            level = chip.get_attribute("data-level")
            chip.click()
            page.wait_for_timeout(120)
            without = page.locator("#alertTable tbody tr").count()
            levels = {c.inner_text().strip().lower()
                      for c in page.locator("#alertTable tbody tr td:nth-child(2)").all()}
            check(without <= all_rows, f"level chip {level} off: {without} of {all_rows} rows")
            chip.click()
            page.wait_for_timeout(120)
        check(page.locator("#alertTable tbody tr").count() == all_rows, "level chips restore the table")
        page.fill("#alertSearch", "zzzz-nothing-matches")
        page.wait_for_timeout(250)
        check(page.locator("#alertTable tbody tr").count() == 0 and visible(page, "#alertEmpty"),
              "search with no match: empty message")
        page.fill("#alertSearch", "")
        page.wait_for_timeout(250)
        check(page.locator("#alertTable tbody tr").count() == all_rows, "clearing the search restores")
        exercise_reader(page, "#alertTable tbody tr", "alerts")

        print("\n— Indicators, System, YARA rows —")
        go(page, "/indicators")
        exercise_reader(page, "#iocTable tbody tr", "indicators")
        go(page, "/system")
        exercise_reader(page, ".syscard .grid tbody tr", "system")
        go(page, "/yara")
        exercise_reader(page, "#yaraTable tbody tr", "yara")
        total_yara = page.locator("#yaraTable tbody tr").count()
        page.fill("#yaraSearch", "rubeus")
        page.wait_for_timeout(250)
        check(page.locator("#yaraTable tbody tr").count() == 1, "YARA search")
        page.fill("#yaraSearch", "")
        for chip in page.locator("#yaraChips .chip").all():
            chip.click()
            page.wait_for_timeout(60)
        check(page.locator("#yaraTable tbody tr").count() == 0, "every YARA chip off: no row")
        for chip in page.locator("#yaraChips .chip").all():
            chip.click()
            page.wait_for_timeout(60)
        check(page.locator("#yaraTable tbody tr").count() == total_yara, "YARA chips restore")

        print("\n— Overview family shortcut —")
        go(page, "/")
        rows = page.locator("#overview .tacrow.clickable")
        check(rows.count() > 0, f"{rows.count()} families on the overview")
        family_label = rows.first.locator("b").inner_text()
        rows.first.click()
        page.wait_for_timeout(500)
        on = [c.get_attribute("data-cat") for c in page.locator("#catChips .chip--cat.is-on").all()]
        check(page.url.endswith("/alerts") and len(on) == 1,
              f"clicking {family_label} opens Alerts on that family only ({on})")
        for cat in [c.get_attribute("data-cat")
                    for c in page.locator("#catChips .chip--cat:not(.is-on)").all()]:
            page.click(f'#catChips .chip--cat[data-cat="{cat}"]')
            page.wait_for_timeout(40)
        check(page.locator("#alertTable tbody tr").count() == all_rows, "families restored")

        print("\n— ATT&CK and Summary —")
        go(page, "/attack")
        check(page.locator("#attack .tacrow").count() > 0, "tactics drawn")
        go(page, "/summary")
        summary = page.inner_text("#aiReport")
        check(len(summary) > 200 and page.locator("#aiEmpty").is_hidden(), "local summary written")
        check("undefined" not in summary and "NaN" not in summary, "no undefined/NaN in the summary")

        print("\n— Log filters —")
        go(page, "/log")
        lines = page.locator("#console2 .line").count()
        page.check("#onlyImportant2")
        page.wait_for_timeout(250)
        hidden_lines = page.locator("#console2 .line[hidden]").count()
        check(page.is_checked("#onlyImportant"), "Log view filter mirrors the overview one")
        check(0 < hidden_lines < lines, f"important only hides {hidden_lines} of {lines} lines")
        page.uncheck("#onlyImportant2")
        page.wait_for_timeout(250)
        check(page.locator("#console2 .line[hidden]").count() == 0, "unchecking shows everything")
        with page.expect_download() as download:
            page.click('.view[data-view="/log"] a[href="/api/console.log"]')
        check(download.value.suggested_filename.endswith("-console.log"), "Log view Download")
        go(page, "/")
        page.uncheck("#autoScroll")
        page.evaluate("() => { const c = document.querySelector('#console'); c.scrollTop = 0; }")
        page.dblclick('.tag[data-step="analyse"] .tag__label')
        wait_run(page)
        check(page.evaluate("() => document.querySelector('#console').scrollTop") == 0,
              "auto-scroll off keeps the log where it was")
        page.check("#autoScroll")
        steps = page.evaluate("() => state.steps.map(s => s.id + ':' + s.status)")
        check(steps == statuses, f"double-click replays one step, rest kept: {steps}")

        print("\n— Exports —")
        with context.expect_page() as new_tab:
            page.click("#btnHtml")
        report = new_tab.value
        report.wait_for_load_state()
        body = report.content()
        check("Kage DFIR Toolkit" in body and "BTN-002" in body, "Report opens in a new tab")
        check('lang="en"' in body and "fonts.googleapis" not in body, "report: English, no external font")
        report.close()
        with page.expect_download() as download:
            page.click("#btnJson")
        data = json.loads(Path(download.value.path()).read_text())
        check(data["case"]["name"] == "BTN-002" if isinstance(data.get("case"), dict)
              else "BTN-002" in json.dumps(data)[:4000], "JSON export carries the case")
        check(all(k in data for k in ("tool", "evidence", "system", "timeline")), "JSON export complete")
        with page.expect_download() as download:
            page.click("#btnLog")
        check(len(Path(download.value.path()).read_text()) > 500, "Log export after a run")

        print("\n— Browser history —")
        go(page, "/alerts")
        go(page, "/yara")
        page.go_back()
        page.wait_for_timeout(300)
        check(page.url.endswith("/alerts") and visible(page, '.view[data-view="/alerts"]'), "Back")
        page.go_forward()
        page.wait_for_timeout(300)
        check(page.url.endswith("/yara") and visible(page, '.view[data-view="/yara"]'), "Forward")

        print("\n— Stop —")
        go(page, "/")
        SLOW.write_text("1")
        page.click("#btnRun")
        page.wait_for_function("() => state.steps.some(s => s.id === 'yara' && s.status === 'running')",
                               timeout=30000)
        page.wait_for_timeout(800)
        check(page.is_enabled("#btnStop"), "Stop enabled during a long scan")
        page.click("#btnStop")
        page.wait_for_function("() => document.querySelector('#btnStop').disabled", timeout=15000)
        page.wait_for_timeout(800)
        SLOW.unlink()
        check("Stop requested" in page.inner_text("#console"), "Stop is logged")
        statuses = page.evaluate("() => Object.fromEntries(state.steps.map(s => [s.id, s.status]))")
        message = page.evaluate("() => state.steps.find(s => s.id === 'yara').message")
        check(statuses["yara"] == "failed" and "Interrupted" in message,
              f"scan interrupted: {statuses['yara']} — {message}")
        check(statuses["enrich"] != "running" and statuses["ai"] != "running", "nothing left running")
        leftover = subprocess.run(["pgrep", "-f", str(fake_thor)], capture_output=True, text=True)
        check(leftover.stdout.strip() == "", "the scanner process was killed")
        check(page.is_enabled("#btnRun") and page.is_enabled("#btnReset"), "controls back after Stop")

        print("\n— Reset —")
        page.click("#btnReset")
        page.wait_for_timeout(800)
        check(page.inner_text("#scoreValue") == "—", "score cleared")
        check(all(page.inner_text(c) == "0" for c in ("#nAlerts", "#nIocs", "#nSystem", "#nYara")),
              "counters back to 0")
        check(page.evaluate("() => document.querySelector('#btnHtml').classList.contains('is-off')"),
              "exports off again")
        check(page.locator("#console .line").count() == 0, "log cleared")
        go(page, "/log")
        check(page.locator("#console2 .line").count() == 0, "Log view cleared too")
        steps = page.evaluate("() => state.steps.map(s => s.status)")
        check(set(steps) == {"pending"}, "every step pending")
        page.reload(wait_until="networkidle")
        page.wait_for_timeout(900)
        check(page.inner_text("#scoreValue") == "—", "reset survives a reload")

        print("\n— Disk image from the interface —")
        go(page, "/")
        page.click("#btnSettings")
        page.uncheck("#setDemo")
        page.select_option("#setLogsSource", "image")
        page.fill("#setImagePath", f'"{FIXTURE}"')     # pasted with quotes, as Explorer copies it
        page.click("#btnSaveSettings")
        page.wait_for_timeout(600)
        check(page.locator("#drawer").is_hidden(), "image settings saved")
        check("kage-fixture.E01" in page.inner_text("#modeLabel"), page.inner_text("#modeLabel"))
        hint = page.locator('.tag[data-step="collect"] .tag__hint').text_content()
        check("kage-fixture.E01" in hint and "administrator" not in hint, f"collect hint: {hint}")
        for c in checks.all():
            c.uncheck()
        for step in ("workspace", "collect", "system"):
            page.locator(f'.tag[data-step="{step}"] .tag__check').check()
        page.click("#btnRun")
        wait_run(page, timeout=120000)
        statuses = page.evaluate("() => Object.fromEntries(state.steps.map(s => [s.id, s.status]))")
        check(statuses["collect"] == "done" and statuses["system"] == "done", f"image run: {statuses}")
        go(page, "/system")
        text = page.inner_text("#sysgrid")
        check("WS-FINANCE-07" in text, "host name read from the image")
        check("Updater" in text and "WinUpdaterSvc" in text, "planted persistence listed")
        cards = " ".join(c.text_content() for c in page.locator(".syscard .eyebrow").all())
        check("Autoruns" in cards, "autoruns card shown for an image")
        exercise_reader(page, ".syscard .grid tbody tr", "image system")
        check("UTC" in text, "image timestamps labelled UTC")
        check(page.text_content("#hostLabel") == "WS-FINANCE-07", "header names the imaged host")
        check("Evidence collected" in page.text_content("#verdictLine"),
              f"verdict line after collection: {page.text_content('#verdictLine')}")
        check("auditpol" in text and "UNKNOWN" not in text.upper().split("AUDIT POLICY")[-1][:400],
              "audit policy: one explanatory line, no wall of unknown rows")
        check("live capture" not in text.lower() or "image" in text.lower(), "no live-capture wording")
        page.screenshot(path=str(WORK / "image-system.png"), full_page=True)

        print("\n— Remote host from the interface —")
        go(page, "/")
        page.click("#btnReset")
        page.wait_for_timeout(600)
        page.click("#btnSettings")
        page.select_option("#setLogsSource", "remote")
        every = ["#setRemoteHost", "#setRemoteUser", "#setRemotePassword", "#setRemoteSsl",
                 "#btnRemoteTest", "#setCylrArgs"]
        check(all(page.locator(s).is_visible() for s in every),
              "remote source shows host, account, password, HTTPS, test and CyLR arguments")
        check(page.locator("#setImagePath").is_hidden(), "image fields hidden for a remote host")
        page.fill("#setRemoteHost", "  WS-FINANCE-07  ")
        page.fill("#setRemoteUser", "ACME\\ir-admin")
        page.fill("#setRemotePassword", "Sup3r-Secret!")
        page.click("#btnRemoteTest")
        page.wait_for_function("() => document.querySelector('#remoteTestResult').className", timeout=15000)
        result = page.text_content("#remoteTestResult")
        check("WS-FINANCE-07" in result and "administrator" in result
              and page.get_attribute("#remoteTestResult", "class") == "is-ok",
              f"Test connection: {result}")
        check(page.input_value("#setRemotePassword") == ""
              and page.get_attribute("#setRemotePassword", "placeholder") == "set for this session",
              "password cleared from the form, kept for the session")
        page.screenshot(path=str(WORK / "remote-settings.png"))
        page.click("#btnSaveSettings")
        page.wait_for_timeout(600)
        saved = (WORK / "config.json").read_text()
        check("Sup3r-Secret!" not in saved and "remote_password" not in saved,
              "password never written to config.json")
        check(json.loads(saved)["remote_host"] == "WS-FINANCE-07", "host name trimmed and saved")
        check(page.text_content("#modeLabel") == "remote · WS-FINANCE-07", page.text_content("#modeLabel"))
        hint = page.locator('.tag[data-step="collect"] .tag__hint').text_content()
        check("WS-FINANCE-07" in hint and "WinRM" in hint, f"collect hint: {hint}")
        for c in checks.all():
            c.uncheck()
        for step in ("workspace", "collect", "system"):
            page.locator(f'.tag[data-step="{step}"] .tag__check').check()
        page.click("#btnRun")
        wait_run(page, timeout=120000)
        statuses = page.evaluate("() => Object.fromEntries(state.steps.map(s => [s.id, s.status]))")
        check(statuses["collect"] == "done" and statuses["system"] == "done", f"remote run: {statuses}")
        log = page.inner_text("#console")
        for needle in ("Connected to WS-FINANCE-07", "Pushing CyLR.exe", "Archive verified: SHA-256",
                       "Removed C:\\Windows\\Temp\\Kage-BTN-002"):
            check(needle in log, f"log: {needle}")
        page.screenshot(path=str(WORK / "remote-overview.png"))
        go(page, "/system")
        text = page.inner_text("#sysgrid")
        check("WS-FINANCE-07" in text and "45.155.205.233" in text,
              "system context of the remote host, sockets included")
        check(page.text_content("#hostLabel") == "WS-FINANCE-07", "header names the remote host")
        page.screenshot(path=str(WORK / "remote-system.png"), full_page=True)
        manifest = json.loads((WORK / "ws" / "output" / "BTN-002-remote-manifest.json").read_text())
        check(manifest["cleaned"] is True and manifest["account"] == "ACME\\ir-admin",
              "remote manifest: account and clean-up recorded")
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
print(f"Every control passed. Screenshots in {WORK}")
