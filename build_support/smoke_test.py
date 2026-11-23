"""Smoke test for a built Kage executable — run by CI after PyInstaller.

    python build_support/smoke_test.py dist/kage.exe [expected-version]

Each check runs the binary from an empty folder, the way a user would after
downloading it: version, environment check, the web console and its assets,
a full demonstration chain, a dead-disk triage of the E01 fixture (which
proves the disk-image engine survived freezing) and a remote triage of a
simulated Windows host.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "kage-fixture.E01"
failures: list[str] = []


def check(condition: bool, message: str) -> None:
    print(("  ok    " if condition else "  FAIL  ") + message, flush=True)
    if not condition:
        failures.append(message)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http(base: str, path: str, payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(base + path, data=data, method="POST" if data else "GET",
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.status, response.read()


class Server:
    def __init__(self, binary: Path, folder: Path, *extra: str, env: dict | None = None) -> None:
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.log = open(folder / "server.log", "w", encoding="utf-8")
        env = {**os.environ, "PYTHONUNBUFFERED": "1", **(env or {})}
        self.process = subprocess.Popen(
            [str(binary), "--no-browser", "--port", str(self.port), *extra],
            cwd=folder, stdout=self.log, stderr=subprocess.STDOUT, env=env)
        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                http(self.base, "/api/state")
                return
            except (urllib.error.URLError, ConnectionError, OSError):
                if self.process.poll() is not None:
                    break
                time.sleep(0.5)
        raise RuntimeError(f"server did not start: {(folder / 'server.log').read_text()}")

    def run(self, steps: list[str], timeout: int = 300) -> dict:
        http(self.base, "/api/run", {"steps": steps})
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, body = http(self.base, "/api/state")
            state = json.loads(body)
            if not state["running"] and any(s["status"] != "pending" for s in state["steps"]):
                return state
            time.sleep(0.5)
        raise RuntimeError("chain did not finish in time")

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.log.close()


def main() -> int:
    binary = Path(sys.argv[1]).resolve()
    expected = sys.argv[2].lstrip("v") if len(sys.argv) > 2 else None
    work = Path(tempfile.mkdtemp(prefix="kage-smoke-"))
    print(f"Smoke test of {binary} ({binary.stat().st_size / 1024 ** 2:.1f} MB)")

    try:
        # -- version and environment check, from an empty folder
        folder = work / "cli"
        folder.mkdir()
        out = subprocess.run([str(binary), "--version"], cwd=folder, capture_output=True,
                             text=True, timeout=120)
        check(out.returncode == 0 and "Kage DFIR Toolkit" in out.stdout,
              f"--version: {out.stdout.strip()}")
        if expected:
            check(out.stdout.strip().endswith(expected),
                  f"version matches the tag ({expected})")
        out = subprocess.run([str(binary), "--check"], cwd=folder, capture_output=True,
                             text=True, timeout=120)
        check(out.returncode == 0, f"--check exits 0 ({out.returncode})")
        check("dissect.target" in out.stdout and "[ok]   module dissect.target" in out.stdout,
              "disk-image engine embedded")
        check("[ok]   module pypsrp" in out.stdout, "WinRM client embedded")
        check(not any(folder.iterdir()), "--version and --check write nothing")

        # -- the console and a full demonstration chain
        folder = work / "demo"
        folder.mkdir()
        server = Server(binary, folder, "--demo")
        try:
            for path in ("/", "/alerts", "/system", "/static/style.css", "/static/app.js",
                         "/static/favicon.png", "/static/fonts/archivo-latin-800-normal.woff2"):
                status, body = http(server.base, path)
                check(status == 200 and len(body) > 100, f"GET {path}")
            _, body = http(server.base, "/")
            check(b"fonts.googleapis.com" not in body, "no external font request")

            state = server.run([s for s in ("workspace", "tools", "collect", "system",
                                            "rules", "timeline", "analyse", "ai")])
            statuses = {s["id"]: s["status"] for s in state["steps"]}
            check(all(statuses[s] == "done" for s in ("collect", "timeline", "analyse", "ai")),
                  f"demonstration chain completed: {statuses}")
            report = state.get("report") or {}
            check(report.get("risk_score", 0) > 0, f"risk score {report.get('risk_score')}")
            _, html = http(server.base, "/api/report.html")
            check(b"Kage DFIR Toolkit" in html and b"Evidence" in html, "printable report")
            _, data = http(server.base, "/api/report.json")
            export = json.loads(data)
            check(export.get("timeline") is not None and export.get("system") is not None
                  and export["tool"].startswith("Kage DFIR Toolkit"),
                  "JSON export: timeline, system context, tool version")
            _, log = http(server.base, "/api/console.log")
            check(len(log) > 200, "session log export")
        finally:
            server.stop()

        # -- dead-disk triage: the frozen dissect engine opening a real E01
        folder = work / "image"
        folder.mkdir()
        image = folder / FIXTURE.name
        shutil.copy(FIXTURE, image)
        server = Server(binary, folder, "--image", str(image))
        try:
            state = server.run(["workspace", "collect", "system"])
            statuses = {s["id"]: s["status"] for s in state["steps"]}
            check(statuses["collect"] == "done" and statuses["system"] == "done",
                  f"image chain completed: {statuses}")
            host = ((state.get("system") or {}).get("host") or {})
            check(host.get("hostname") == "WS-FINANCE-07",
                  f"hostname read from the E01 registry: {host.get('hostname')}")
            check((state.get("image") or {}).get("format") == "EnCase (EWF)", "E01 recognised")
            manifest = folder / "output" / "CASE-001-image-manifest.json"
            check(manifest.exists(), "extraction manifest written next to the executable")
        finally:
            server.stop()

        # -- remote triage, against a simulated Windows host
        sys.path.insert(0, str(ROOT))
        sys.path.insert(0, str(ROOT / "tests" / "fixtures"))
        import simulated_host
        from dfirconsole import image as image_module

        folder = work / "remote"
        (folder / "tools" / "cylr").mkdir(parents=True)
        (folder / "tools" / "cylr" / "CyLR.exe").write_bytes(b"MZ smoke-test CyLR")
        image_module.extract(image_module.open_image(FIXTURE), work / "fixture-logs")
        profile = simulated_host.build_profile(work / "host", work / "fixture-logs" / "Logs")
        server = Server(binary, folder, "--remote", "WS-FINANCE-07",
                        env={"KAGE_REMOTE_SIMULATION": str(profile)})
        try:
            _, body = http(server.base, "/api/state")
            check(json.loads(body)["settings"]["remote_support"] is True,
                  "WinRM client importable inside the executable")
            _, body = http(server.base, "/api/remote/test", {})
            check(json.loads(body).get("hostname") == "WS-FINANCE-07", "connection test")
            state = server.run(["workspace", "collect", "system"])
            statuses = {s["id"]: s["status"] for s in state["steps"]}
            check(statuses["collect"] == "done" and statuses["system"] == "done",
                  f"remote chain completed: {statuses}")
            record = state.get("remote") or {}
            check(record.get("cleaned") is True and len(record.get("archive_sha256", "")) == 64,
                  "archive verified by SHA-256, remote folder removed")
            check(((state.get("system") or {}).get("host") or {}).get("hostname") == "WS-FINANCE-07",
                  "system context read over the remote channel")
        finally:
            server.stop()
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print(f"\n{'All checks passed.' if not failures else f'{len(failures)} check(s) failed.'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
