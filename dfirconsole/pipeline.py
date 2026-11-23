"""Triage execution engine.

Each step is a coroutine that receives the case context and writes to the event
bus. Steps are deliberately independent: an already collected timeline can be
re-analysed without running the collector again.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import sys
import time
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

import httpx

from . import ai as ai_module
from . import image as image_module
from . import remote as remote_module
from . import sysinfo as sysinfo_module
from . import timeline as timeline_module
from .bus import EventBus
from .config import (HAYABUSA_BIN, IS_WINDOWS, LIVE_LOGS, TOOL_SOURCES,
                     Settings, is_admin)
from .enrich import Enricher

PENDING, RUNNING, DONE, FAILED, SKIPPED = "pending", "running", "done", "failed", "skipped"


def human_size(size: int) -> str:
    """A small test collection is not "0 MB"."""
    for unit, scale in (("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024)):
        if size >= scale:
            return f"{size / scale:.1f} {unit}" if size < 10 * scale else f"{size // scale} {unit}"
    return f"{size} B"

# Windows tools crash with NTSTATUS codes returned as unsigned integers.
# Untranslated, the analyst reads "code 3221225477" and learns nothing.
NTSTATUS = {
    0xC0000005: "access violation (the program crashed)",
    0xC0000017: "out of memory",
    0xC000001D: "illegal instruction",
    0xC0000135: "missing DLL",
    0xC0000142: "DLL initialisation failure",
    0xC00000FD: "stack overflow",
    0xC000013A: "interrupted from the keyboard (Ctrl+C)",
    0xC0000409: "stack corruption detected",
}


def explain_exit(code: int) -> str:
    """Readable message for an exit code, crashes included."""
    if code == 0:
        return "success"
    unsigned = code & 0xFFFFFFFF
    if unsigned in NTSTATUS:
        return f"0x{unsigned:08X} — {NTSTATUS[unsigned]}"
    if unsigned >= 0xC0000000:
        return f"0x{unsigned:08X} — abnormal process termination"
    return f"exit code {code}"


class StepFailure(Exception):
    """Business error of a step: message shown to the analyst as-is."""


@dataclass
class StepState:
    id: str
    label: str
    hint: str
    command: str = ""
    admin: bool = False
    optional: bool = False
    default_on: bool = True
    status: str = PENDING
    started: float | None = None
    ended: float | None = None
    message: str = ""
    seal: str = ""
    seal_basis: str = ""
    artifacts: list[str] = field(default_factory=list)

    def public(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "hint": self.hint,
            "command": self.command,
            "admin": self.admin,
            "optional": self.optional,
            "default_on": self.default_on,
            "status": self.status,
            "duration": round((self.ended - self.started), 1)
            if self.started and self.ended
            else None,
            "message": self.message,
            "seal": self.seal,
            "seal_basis": self.seal_basis,
            "artifacts": self.artifacts,
        }


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


class Case:
    """Full state of an analysis case."""

    def __init__(self, settings: Settings, bus: EventBus) -> None:
        self.settings = settings
        self.bus = bus
        self.steps: dict[str, StepState] = {}
        self.order: list[str] = []
        self.report: dict | None = None
        self.system: dict | None = None
        self.thor: dict | None = None
        self.ai: dict | None = None
        self.logs_dir: Path | None = None
        self.image: dict | None = None
        self._image_target = None
        # Remote triage: what was collected from which host, and how.
        self.remote: dict | None = None
        self.running = False
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self._task: asyncio.Task | None = None
        self._define_steps()

    # -- definition -------------------------------------------------------
    def _define_steps(self) -> None:
        specs = [
            ("workspace", "Prepare the workspace", "Folder tree (tools, evidence, output)", "", False, False),
            ("defender", "Exclude the folder from Defender", "Add-MpPreference -ExclusionPath", "powershell Add-MpPreference -ExclusionPath <workspace>", True, True),
            ("tools", "Locate the tooling", "CyLR, Hayabusa and THOR, each in its own folder", "", False, False),
            ("collect", "Collect the artefacts", "CyLR: logs, registry, prefetch, $MFT…", "", True, False),
            ("system", "Capture the system context", "Accounts, open ports, odd folders, log coverage", "", True, True),
            ("rules", "Update the Sigma rules", "hayabusa update-rules", "hayabusa update-rules", False, False),
            ("timeline", "Build the timeline", "Sigma correlation over the collected EVTX", "hayabusa <csv|dfir>-timeline -d <logs> -o hayabusa-output.csv", False, False),
            ("analyse", "Analyse the timeline", "Statistics, alerts, indicator extraction", "", False, False),
            ("yara", "YARA scan (THOR Lite)", "Scope of your choosing — collected artefacts by default", "", True, True),
            ("enrich", "Enrich the indicators", "VirusTotal + AbuseIPDB", "", False, True),
            ("ai", "Write the summary", "Report written up by a language model", "", False, True),
        ]
        for step_id, label, hint, command, admin, optional in specs:
            self.steps[step_id] = StepState(
                id=step_id, label=label, hint=hint, command=command,
                admin=admin, optional=optional,
                # The YARA scan is long and assumes a licensed tool, so the
                # analyst has to ask for it explicitly.
                default_on=step_id != "yara",
            )
            self.order.append(step_id)

    def _refresh_step_hints(self) -> None:
        """Keep step descriptions true to the selected evidence source.

        A disk image needs neither CyLR nor administrator rights, and its
        system context comes from the registry, not from live commands —
        the chain on the left must say so instead of describing a live run.
        """
        source = (self.settings.logs_source or "collector").lower()
        collect, system, tools = self.steps["collect"], self.steps["system"], self.steps["tools"]
        if source == "remote":
            host = self.settings.remote_host or "no host set"
            collect.hint = f"Remote host: {host} — CyLR pushed over WinRM, run, fetched, removed"
            collect.admin = False
            system.hint = f"Same commands as a live capture, run on {host}"
            system.admin = False
            tools.hint = "CyLR (pushed to the remote host) and Hayabusa"
        elif source == "image":
            name = Path(self.settings.image_path).name or "no image selected"
            collect.hint = f"Disk image: {name} — logs, hives, executables"
            collect.admin = False
            system.hint = "Host, accounts, autoruns, odd folders, read from the image"
            system.admin = False
            tools.hint = "Hayabusa (CyLR is not needed for a disk image)"
        elif source in ("live", "custom"):
            collect.hint = ("Event logs read in place (winevt\\Logs)" if source == "live"
                            else f"Event logs from {self.settings.logs_path or 'a chosen folder'}")
            collect.admin = source == "live"
            system.hint = "Accounts, open ports, odd folders, log coverage"
            system.admin = True
            tools.hint = "CyLR, Hayabusa and THOR, each in its own folder"
        else:
            collect.hint = "CyLR: logs, registry, prefetch, $MFT…"
            collect.admin = True
            system.hint = "Accounts, open ports, odd folders, log coverage"
            system.admin = True
            tools.hint = "CyLR, Hayabusa and THOR, each in its own folder"

    # -- state ------------------------------------------------------------
    def snapshot(self) -> dict:
        self._refresh_step_hints()
        return {
            # Last event this snapshot reflects: lets the interface discard a
            # snapshot that arrives after newer events (an HTTP reply racing
            # the WebSocket used to roll a finished run back to "running").
            "seq": self.bus.seq,
            "running": self.running,
            "steps": [self.steps[s].public() for s in self.order],
            "report": self.report,
            "system": self.system,
            "thor": self.thor,
            "ai": self.ai,
            "logs_dir": str(self.logs_dir) if self.logs_dir else None,
            "image": self.image,
            "remote": self.remote,
            "settings": self.settings.public(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

    def _push_step(self, step: StepState) -> None:
        self.bus.emit("step", step=step.public())

    def log(self, message: str, level: str = "info", step: str | None = None,
            ui: bool = True) -> None:
        self.bus.log(message, level=level, step=step, ui=ui)

    # -- running commands -------------------------------------------------
    async def run_command(
        self, args: list[str], cwd: Path, step_id: str, timeout: float = 0,
        heartbeat: float = 0, on_line: Callable[[str], None] | None = None,
    ) -> tuple[int, str]:
        """Run a command, stream its output, and return it for inspection.

        The exit code is not enough: PowerShell returns 0 even when
        Add-MpPreference fails. Steps must be able to re-read the output.
        """
        self.log("$ " + " ".join(args), level="cmd", step=step_id)
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                cwd=str(cwd),
                stdin=asyncio.subprocess.DEVNULL,   # no prompt can block us
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
        except FileNotFoundError as exc:
            raise StepFailure(f"Executable not found: {exc.filename}") from exc
        except OSError as exc:
            if getattr(exc, "winerror", None) == 740:
                raise StepFailure(
                    "This tool requires elevation. Close the console and "
                    "restart it with right-click -> Run as administrator."
                ) from exc
            raise StepFailure(f"Could not launch: {exc}") from exc

        collected: list[str] = []

        def decode(raw: bytes) -> str:
            # Windows tools write cp1252, not UTF-8. Without this, accented
            # error messages come out as mojibake.
            for encoding in ("utf-8", "cp1252"):
                try:
                    return raw.decode(encoding)
                except UnicodeDecodeError:
                    continue
            return raw.decode("utf-8", errors="replace")

        # Past this threshold only a sample reaches the browser.
        # `hayabusa update-rules` emits thousands of lines; inserting them one
        # by one into the DOM freezes the tab.
        UI_BUDGET = 400
        SAMPLE = 25

        async def pump() -> None:
            assert process.stdout is not None
            count = 0
            warned = False
            while line := await process.stdout.readline():
                text = decode(line).rstrip()
                if not text:
                    continue
                collected.append(text)
                count += 1
                count_ref[0] = count
                last_output[0] = time.monotonic()
                if on_line is not None:
                    on_line(text)
                if count <= UI_BUDGET:
                    self.log(text, level="out", step=step_id)
                    continue
                if not warned:
                    warned = True
                    self.log(
                        f"Large output: past {UI_BUDGET} lines, only one in "
                        f"{SAMPLE} is displayed. The log file keeps everything.",
                        level="warn", step=step_id,
                    )
                # Everything goes to disk; the display only gets a sample.
                self.log(text, level="out", step=step_id, ui=count % SAMPLE == 0)
            if count > UI_BUDGET:
                self.log(f"{count} output lines in total.", level="info", step=step_id)

        async def tick() -> None:
            """Report progress without ever interrupting.

            A long scan is an analyst's decision, not an anomaly. We only
            provide what is needed to judge: elapsed time, lines produced, and
            time since the last one — that last figure is what separates
            "slow" from "stuck".
            """
            started = time.monotonic()
            while True:
                await asyncio.sleep(heartbeat)
                minutes = (time.monotonic() - started) / 60
                silence = (time.monotonic() - last_output[0]) / 60
                self.log(
                    f"… still running ({minutes:.0f} min, {count_ref[0]} lines, "
                    f"last output {silence:.0f} min ago)",
                    level="warn", step=step_id,
                )

        count_ref = [0]
        last_output = [time.monotonic()]
        tasks = [pump(), process.wait()]
        beat = asyncio.create_task(tick()) if heartbeat else None

        try:
            if timeout:
                await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout)
            else:
                await asyncio.gather(*tasks)   # no limit imposed
        except asyncio.TimeoutError:
            process.kill()
            raise StepFailure(f"Timed out after {int(timeout)} s")
        except asyncio.CancelledError:
            process.kill()
            raise
        finally:
            if beat:
                beat.cancel()
        return process.returncode or 0, "\n".join(collected)

    async def probe(self, args: list[str], cwd: Path, timeout: float = 60) -> str:
        """Run a short command and return its output without displaying it.

        Used to query a tool's help output and adapt to its version.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *args, cwd=str(cwd),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
            raw, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except (OSError, asyncio.TimeoutError):
            return ""
        for encoding in ("utf-8", "cp1252"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace")

    # -- steps ------------------------------------------------------------
    async def step_workspace(self) -> str:
        settings = self.settings
        for directory in (settings.root, settings.tools_dir, settings.evidence_dir,
                          settings.output_dir, settings.thor_dir):
            directory.mkdir(parents=True, exist_ok=True)
            self.log(f"Folder ready: {directory}", step="workspace")
        from . import APP_FULL_NAME, __version__
        from .config import APP_DIR

        self.log(f"{APP_FULL_NAME} {__version__}", level="ok", step="workspace")
        # Which copy of the code is actually running. Two extracted folders on
        # the same machine is the classic way to spend an hour chasing a bug
        # that was fixed in the other one.
        self.log(f"Code loaded from {APP_DIR}", step="workspace")
        if self.bus.logfile:
            self.log(f"Session log: {self.bus.logfile}", step="workspace")
        free = shutil.disk_usage(settings.root).free / (1024 ** 3)
        self.log(f"Free space: {free:.1f} GB", step="workspace")
        if free < 5:
            self.log("Under 5 GB free — the collection is likely to fail.",
                     level="warn", step="workspace")
        if IS_WINDOWS and not is_admin():
            self.log(
                "Console NOT elevated: Defender, the collector and THOR will "
                "fail. Restart with right-click -> Run as administrator.",
                level="warn", step="workspace",
            )
        else:
            self.log("Administrator rights confirmed.", level="ok", step="workspace")
        return f"{settings.root}"

    async def step_defender(self) -> str:
        if not IS_WINDOWS:
            raise StepFailure("This step is Windows-only.")
        if not is_admin():
            raise StepFailure(
                "Administrator rights required. Restart the console with "
                "right-click -> Run as administrator."
            )
        path = str(self.settings.root)
        _, output = await self.run_command(
            ["powershell", "-NoProfile", "-Command",
             f"Add-MpPreference -ExclusionPath '{path}' ; "
             f"(Get-MpPreference).ExclusionPath"],
            cwd=self.settings.root, step_id="defender", timeout=180,
        )
        # PowerShell returns 0 even when refused, so we re-read the output and
        # require the path to appear in the exclusion list.
        lowered = output.lower()
        if "autorisations suffisantes" in lowered or "must be an administrator" in lowered \
                or "denied" in lowered or "add-mppreference :" in lowered:
            raise StepFailure(
                "Exclusion refused by Defender (insufficient rights). Add it "
                "by hand in Windows Security, or restart as administrator."
            )
        if path.lower() not in lowered:
            raise StepFailure(
                f"{path} does not appear in the exclusion list after the operation."
            )
        return f"{path} excluded from Defender"

    # -- locating the tooling ----------------------------------------------
    def _locate(self, patterns: tuple[str, ...], home: Path | None = None) -> Path | None:
        """Find a binary, its own folder first.

        Each tool owns a folder under tools/, which is where we look before
        widening the search. Patterns are globs so the version number in the
        filename never matters.
        """
        from .config import PROJECT_DIR

        roots: list[Path] = []
        if home is not None:
            roots.append(home)
        roots += [self.settings.tools_dir, self.settings.root, PROJECT_DIR, Path.cwd()]

        seen: set[Path] = set()
        for root in roots:
            if not root.exists() or root in seen:
                continue
            seen.add(root)
            for pattern in patterns:
                match = next((f for f in sorted(root.glob(pattern)) if f.is_file()), None)
                if match:
                    return match
        for root in roots:
            if not root.exists():
                continue
            for pattern in patterns:
                match = next((f for f in sorted(root.rglob(pattern)) if f.is_file()), None)
                if match:
                    return match
        return None

    def find_cylr(self) -> Path | None:
        return self._locate(("CyLR.exe", "cylr.exe", "CyLR"), self.settings.cylr_dir)

    def find_thor(self) -> Path | None:
        return self._locate(("thor64-lite.exe", "thor-lite.exe", "thor64-lite",
                             "thor-lite"), self.settings.thor_dir)

    def find_hayabusa(self) -> Path | None:
        return self._locate((HAYABUSA_BIN, "hayabusa*.exe", "hayabusa*win*",
                             "hayabusa-*-lin-*", "hayabusa-*-mac-*"),
                            self.settings.hayabusa_dir)

    async def _resolve_release(self, client: httpx.AsyncClient, key: str) -> tuple[str, str]:
        """Ask GitHub for the current release asset, fall back to a pinned URL.

        Pinning a version means the download breaks the day upstream moves on;
        resolving it means the console keeps working unattended.
        """
        source = TOOL_SOURCES[key]
        try:
            response = await client.get(
                f"https://api.github.com/repos/{source['repo']}/releases/latest",
                headers={"Accept": "application/vnd.github+json"}, timeout=30,
            )
            if response.status_code == 200:
                data = response.json()
                pattern = re.compile(source["asset"])
                for asset in data.get("assets", []):
                    if pattern.search(asset.get("name", "")):
                        return asset["browser_download_url"], data.get("tag_name", "latest")
        except (httpx.HTTPError, ValueError):
            pass
        return source["fallback"], "pinned fallback"

    async def _fetch_tool(self, client: httpx.AsyncClient, key: str, target_dir: Path) -> Path | None:
        """Download and unpack one tool into its own folder."""
        target_dir.mkdir(parents=True, exist_ok=True)
        url, version = await self._resolve_release(client, key)
        self.log(f"{key}: {version} — {url}", step="tools")

        archive = target_dir / url.rsplit("/", 1)[-1]
        await self._download(client, url, archive, "tools")

        if archive.suffix.lower() == ".zip":
            if not zipfile.is_zipfile(archive):
                self.log(f"{archive.name} is not a usable archive.", level="error", step="tools")
                return None
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(target_dir)
            archive.unlink(missing_ok=True)

        # Some archives nest everything one level down; flatten so the binary
        # sits where the search expects it.
        finder = {"cylr": self.find_cylr, "hayabusa": self.find_hayabusa}[key]
        binary = finder()
        if binary and binary.parent != target_dir:
            try:
                moved = target_dir / binary.name
                if not moved.exists():
                    shutil.copy2(binary, moved)
                    binary = moved
            except OSError:
                pass
        # zipfile drops Unix permission bits: on Linux the extracted binary
        # cannot be launched until it is marked executable again.
        if binary and not IS_WINDOWS:
            try:
                binary.chmod(binary.stat().st_mode | 0o111)
            except OSError:
                pass
        return binary

    async def step_tools(self) -> str:
        """Make sure each tool sits in its own folder, downloading what is missing."""
        settings = self.settings
        for directory in settings.tool_dirs:
            directory.mkdir(parents=True, exist_ok=True)

        if settings.demo_mode:
            self.log("Demonstration mode: no download.", level="warn", step="tools")
            present = [p.name for p in (self.find_cylr(), self.find_hayabusa()) if p]
            return f"{len(present)} tool(s) located" if present else "no tool required"

        found: list[str] = []
        fetched: list[str] = []

        wanted = [("hayabusa", self.find_hayabusa, settings.hayabusa_dir)]
        if (settings.logs_source or "collector").lower() in ("collector", "remote"):
            wanted.insert(0, ("cylr", self.find_cylr, settings.cylr_dir))
        else:
            self.log("CyLR not needed: the evidence source is not a live collection.",
                     step="tools")

        async with httpx.AsyncClient(timeout=900, follow_redirects=True) as client:
            for key, finder, target_dir in wanted:
                binary = finder()
                if binary is not None:
                    self.log(f"{key} already present: {binary}", level="ok", step="tools")
                    found.append(binary.name)
                    continue
                self.log(f"{key} missing — fetching from GitHub.", level="warn", step="tools")
                binary = await self._fetch_tool(client, key, target_dir)
                if binary is None:
                    self.log(f"{key} could not be installed.", level="error", step="tools")
                    continue
                fetched.append(binary.name)

        thor = self.find_thor()
        if thor is None:
            self.log(
                "THOR Lite is not downloadable (Nextron requires registration). "
                f"Drop thor64-lite.exe and its .lic file into {settings.thor_dir}.",
                level="warn", step="tools",
            )
        else:
            self.log(f"thor already present: {thor}", level="ok", step="tools")
            found.append(thor.name)

        for path in (self.find_cylr(), self.find_hayabusa(), thor):
            if path:
                self.log(f"{path.name}  sha256={sha256_file(path)}", step="tools")

        if not self.find_cylr() and not self.find_hayabusa():
            raise StepFailure(
                f"No tool available. Expected folders: {settings.cylr_dir}, "
                f"{settings.hayabusa_dir}, {settings.thor_dir}."
            )
        self.steps["tools"].artifacts = found + fetched
        return f"{len(found)} present, {len(fetched)} downloaded"

    async def _download(self, client: httpx.AsyncClient, url: str, target: Path, step_id: str) -> None:
        self.log(f"Downloading {url}", step=step_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        downloaded = 0
        last_report = 0.0
        async with client.stream("GET", url) as response:
            if response.status_code >= 400:
                raise StepFailure(f"HTTP {response.status_code} on {url}")
            total = int(response.headers.get("content-length") or 0)
            with target.open("wb") as handle:
                async for chunk in response.aiter_bytes(262144):
                    handle.write(chunk)
                    downloaded += len(chunk)
                    now = time.monotonic()
                    if now - last_report > 1.0:
                        last_report = now
                        if total:
                            pct = downloaded * 100 // total
                            self.log(f"  {target.name}: {pct}% ({downloaded // 1048576} MB)",
                                     level="out", step=step_id)
                        else:
                            self.log(f"  {target.name}: {downloaded // 1048576} MB",
                                     level="out", step=step_id)
        self.log(f"Received {downloaded // 1024} KB into {target}", level="ok", step=step_id)

    async def step_collect(self) -> str:
        settings = self.settings
        if settings.demo_mode:
            return await self._demo_collect()

        source = (settings.logs_source or "collector").lower()
        if source in ("live", "custom"):
            return self._use_existing_logs(source)
        if source == "image":
            return await self._collect_from_image()
        if source == "remote":
            cylr = self.find_cylr()
            if cylr is None:
                raise StepFailure(
                    f"CyLR.exe not found. Run the \"Locate the tooling\" step to "
                    f"download it, or drop it into {settings.cylr_dir}: it is "
                    "pushed from here to the remote host.")
            return await self._collect_remote(cylr)

        if not is_admin():
            raise StepFailure(
                "Collection requires elevation to read the logs, the registry "
                "and the raw disk. Restart the console as administrator."
            )

        cylr = self.find_cylr()
        if cylr is None:
            raise StepFailure(
                f"CyLR.exe not found. Run the \"Locate the tooling\" step to "
                f"download it, or drop it into {settings.cylr_dir}."
            )
        return await self._collect_with_cylr(cylr)

    async def _collect_with_cylr(self, cylr: Path) -> str:
        """CyLR with no argument already collects its full default target set.

        We only impose the output folder, the archive name and its own log, so
        that everything lands inside the workspace.
        """
        settings = self.settings
        settings.evidence_dir.mkdir(parents=True, exist_ok=True)
        settings.output_dir.mkdir(parents=True, exist_ok=True)

        archive_name = f"{settings.case_name}.zip".replace(" ", "_")
        args = [
            str(cylr),
            "-od", str(settings.evidence_dir),
            "-of", archive_name,
            "-l", str(settings.output_dir / "cylr.log"),
            *[a for a in settings.cylr_args.split() if a],
        ]
        self.log(f"Collector: CyLR ({cylr})", level="ok", step="collect")

        code, output = await self.run_command(args, cwd=cylr.parent, step_id="collect")

        archive = settings.evidence_dir / archive_name
        if not archive.exists():
            # CyLR falls back to the hostname if -of is refused.
            archive = next(
                (p for p in settings.evidence_dir.glob("*.zip") if p.is_file()), None
            )
        if archive is None or not archive.exists():
            hint = ""
            if "--force-native" not in settings.cylr_args:
                hint = (" If raw NTFS reading fails on this disk, add "
                        "--force-native to the CyLR arguments: it then falls "
                        "back to the Windows API.")
            raise StepFailure(f"CyLR produced no archive — {explain_exit(code)}.{hint}")

        produced = self._unpack_collection(archive)
        self.logs_dir = self._find_logs_dir(extra=produced)
        if self.logs_dir is None:
            raise StepFailure(
                f"Archive {archive.name} unpacked but it contains no event "
                "logs. Try --force-native in the CyLR arguments."
            )
        if code != 0:
            self.log(f"CyLR returned {explain_exit(code)} — collection may be "
                     "partial.", level="warn", step="collect")
        self.steps["collect"].artifacts = [archive.name]
        return f"{human_size(archive.stat().st_size)} collected by CyLR"

    # -- remote triage ----------------------------------------------------
    def _remote_transport(self):
        settings = self.settings
        try:
            return remote_module.open_transport(
                settings.remote_host.strip(), settings.remote_user.strip(),
                settings.remote_password, settings.remote_ssl)
        except remote_module.RemoteError as exc:
            raise StepFailure(str(exc)) from exc

    async def _remote_hello(self, transport) -> dict:
        """Who answered, and with which rights. A session without the
        administrator token reads nothing useful: say so before pushing CyLR."""
        code, text = await asyncio.to_thread(
            transport.run, ["powershell", "-NoProfile", "-Command", remote_module.HELLO], 60)
        try:
            hello = json.loads(text.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            raise StepFailure(f"{transport.host} answered but not as expected: {text[:200]}")
        if not hello.get("admin"):
            raise StepFailure(
                f"Connected to {hello.get('hostname')} but without administrator "
                "rights. Use an account in that host's Administrators group (for a "
                "local account, UAC remote restrictions also apply: "
                "LocalAccountTokenFilterPolicy).")
        return hello

    async def _collect_remote(self, cylr: Path) -> str:
        """Push CyLR, run it on the remote host, fetch and verify the archive,
        leave nothing behind, then continue exactly like a local collection."""
        settings = self.settings
        settings.evidence_dir.mkdir(parents=True, exist_ok=True)
        settings.output_dir.mkdir(parents=True, exist_ok=True)
        transport = self._remote_transport()
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in settings.case_name)
        workdir = f"C:\\Windows\\Temp\\Kage-{safe}"
        archive_name = f"{settings.case_name}.zip".replace(" ", "_")
        record: dict = {"host": settings.remote_host, "transport": "", "workdir": workdir,
                        "started": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        ps = lambda script: ["powershell", "-NoProfile", "-Command", script]  # noqa: E731

        try:
            self.log(f"Connecting to {settings.remote_host or transport.host}…", step="collect")
            hello = await self._remote_hello(transport)
            record.update(hostname=hello.get("hostname"), os=hello.get("os"),
                          transport=transport.label,
                          account=settings.remote_user or "current Windows session")
            self.log(f"Connected to {hello.get('hostname')} ({hello.get('os')}) over "
                     f"{transport.label}, as administrator.", level="ok", step="collect")

            await asyncio.to_thread(transport.run, ps(
                f"New-Item -ItemType Directory -Force -Path {remote_module.ps_quote(workdir)} | Out-Null"), 60)
            remote_cylr = f"{workdir}\\CyLR.exe"
            self.log(f"Pushing {cylr.name} to {workdir}…", step="collect")
            await asyncio.to_thread(transport.put, cylr, remote_cylr)
            record["cylr_sha256"] = remote_module.sha256_file(cylr)

            args = [remote_cylr, "-od", workdir, "-of", archive_name,
                    "-l", f"{workdir}\\cylr.log",
                    *[a for a in settings.cylr_args.split() if a]]
            self.log("Collector: CyLR, running on the remote host (a few minutes, "
                     "the output arrives when it ends)…", level="ok", step="collect")
            code, output = await asyncio.to_thread(transport.run, args, 3600)
            for line in output.splitlines()[-40:]:
                if line.strip():
                    self.log(line.rstrip(), level="out", step="collect")

            remote_archive = f"{workdir}\\{archive_name}"
            _, digest = await asyncio.to_thread(transport.run, ps(
                f"(Get-FileHash -Algorithm SHA256 -LiteralPath "
                f"{remote_module.ps_quote(remote_archive)}).Hash"), 600)
            remote_hash = (digest.strip().splitlines() or [""])[-1].strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", remote_hash):
                raise StepFailure(f"CyLR produced no archive on {hello.get('hostname')} "
                                  f"— {explain_exit(code)}.")

            local = settings.evidence_dir / archive_name
            started = time.monotonic()
            last = [0.0]

            def progress(done: int, total: int) -> None:
                now = time.monotonic()
                if now - last[0] >= 5 or done == total:
                    last[0] = now
                    rate = done / max(now - started, 0.001) / 1024 ** 2
                    self.log(f"Fetching {archive_name}: {human_size(done)} / "
                             f"{human_size(total)} ({rate:.1f} MB/s)", step="collect")

            await asyncio.to_thread(transport.get, remote_archive, local, progress)
            local_hash = remote_module.sha256_file(local)
            if local_hash != remote_hash:
                raise StepFailure(f"Archive damaged in transit: SHA-256 {local_hash[:16]}… "
                                  f"here, {remote_hash[:16]}… on the host. Run the step again.")
            record.update(archive=archive_name, archive_sha256=local_hash,
                          size=local.stat().st_size, cylr_exit=code)
            self.log(f"Archive verified: SHA-256 {local_hash} matches the host's.",
                     level="ok", step="collect")
        except remote_module.RemoteError as exc:
            raise StepFailure(str(exc)) from exc
        finally:
            # Leave the target as it was found, even after a failure.
            try:
                await asyncio.to_thread(transport.run, ps(
                    f"Remove-Item -Recurse -Force -LiteralPath {remote_module.ps_quote(workdir)} "
                    "-ErrorAction SilentlyContinue"), 120)
                self.log(f"Removed {workdir} from the remote host.", step="collect")
                record["cleaned"] = True
            except Exception as exc:  # noqa: BLE001
                self.log(f"Could not remove {workdir} on the remote host: {exc}",
                         level="warn", step="collect")
                record["cleaned"] = False
            transport.close()

        record["ended"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        manifest = settings.output_dir / f"{settings.case_name}-remote-manifest.json"
        manifest.write_text(json.dumps(record, indent=2), encoding="utf-8")
        self.remote = {**record, "manifest": manifest.name}

        produced = self._unpack_collection(local)
        self.logs_dir = self._find_logs_dir(extra=produced)
        if self.logs_dir is None:
            raise StepFailure(f"Archive {archive_name} unpacked but it contains no event "
                              "logs. Try --force-native in the CyLR arguments.")
        self.steps["collect"].artifacts = [archive_name, manifest.name]
        return (f"{human_size(record['size'])} collected by CyLR on "
                f"{record.get('hostname')}, verified")

    async def _system_from_remote(self) -> str:
        transport = self._remote_transport()
        try:
            hello = await self._remote_hello(transport)

            async def run(argv: list[str], timeout: float) -> str:
                _, text = await asyncio.to_thread(transport.run, argv, timeout)
                return text

            async def root_entries() -> list[dict]:
                listing = remote_module.parse_listing(await run(
                    ["powershell", "-NoProfile", "-Command", remote_module.ROOT_LISTING], 120))
                return sysinfo_module.analyse_root_entries(listing, prefix="C:\\")

            self.log(f"Reading the system context of {hello.get('hostname')} over "
                     f"{transport.label}…", step="system")
            return await self._capture_system(run, root_entries, "C:\\", "remote")
        except remote_module.RemoteError as exc:
            raise StepFailure(str(exc)) from exc
        finally:
            transport.close()

    def _unpack_collection(self, archive: Path) -> list[Path]:
        """Unpack the collection archive, flagging whatever looks wrong.

        An archive of a few dozen kilobytes means the collection failed;
        better to say so immediately than let Hayabusa work on nothing.
        """
        size_kb = archive.stat().st_size // 1024
        self.log(f"Archive produced: {archive.name} ({size_kb} KB)", step="collect")

        if not zipfile.is_zipfile(archive):
            self.log(
                f"{archive.name} is not a usable ZIP archive — empty or "
                "interrupted collection.",
                level="error", step="collect",
            )
            return []

        target = self.settings.evidence_dir / archive.stem
        target.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(archive) as zf:
                damaged = zf.testzip()
                if damaged:
                    self.log(f"Archive damaged from {damaged} onwards.",
                             level="warn", step="collect")
                members = zf.namelist()
                zf.extractall(target)
        except (zipfile.BadZipFile, OSError) as exc:
            self.log(f"Could not unpack: {exc}", level="error", step="collect")
            return []

        self.log(f"{len(members)} item(s) extracted into {target}",
                 level="ok", step="collect")
        return [target]

    def _open_image(self):
        """Open the configured image once and reuse it across steps."""
        path = Path(self.settings.image_path.strip().strip('"')) if self.settings.image_path else None
        if path is None or not str(path):
            raise StepFailure("Disk image selected as the evidence source, but no image "
                              "path is set. Fill in Settings → Disk image.")
        if self._image_target is not None and self.image and self.image.get("path") == str(path):
            return self._image_target, path
        try:
            target = image_module.open_image(path)
        except image_module.ImageError as exc:
            raise StepFailure(str(exc)) from exc
        self._image_target = target
        return target, path

    async def _collect_from_image(self) -> str:
        """Dead-disk triage: extract what the chain needs from a disk image.

        No CyLR, no elevation: the image is opened read-only and the event
        logs, registry hives, prefetch and executable content are copied into
        evidence\\<case>\\image, each with its SHA-256 in a manifest.
        """
        settings = self.settings
        loop = asyncio.get_running_loop()

        def progress(message: str, level: str = "info") -> None:
            loop.call_soon_threadsafe(self.log, message, level, "collect")

        self.log(f"Opening {settings.image_path} …", step="collect")
        target, path = await asyncio.to_thread(self._open_image)
        fingerprint = await asyncio.to_thread(image_module.image_fingerprint, path)
        host = await asyncio.to_thread(image_module.describe_host, target, path)
        self.log(f"{fingerprint['format']} · {fingerprint['size'] / 1024 ** 3:.2f} GB · "
                 f"Windows found: {host.get('os_name') or 'unknown edition'} "
                 f"on {host.get('hostname') or 'an unnamed host'}", level="ok", step="collect")

        # Folders flagged at the disk root get their executables extracted
        # too: C:\\Tools is exactly where an intruder leaves things.
        listing = await asyncio.to_thread(image_module.root_listing, target)
        flagged = [e["name"] for e in sysinfo_module.analyse_root_entries(listing)
                   if e["kind"] == "folder"]

        destination = settings.evidence_dir / settings.case_name / "image"
        if destination.exists():
            shutil.rmtree(destination, ignore_errors=True)
        result = await asyncio.to_thread(
            image_module.extract, target, destination, settings.image_files_mb,
            flagged, progress,
        )
        if not result["counts"]["logs"]:
            raise StepFailure(
                f"No event log found in {path.name} under "
                "Windows\\System32\\winevt\\Logs. The timeline cannot be built.")

        manifest = image_module.write_manifest(
            result, fingerprint, host,
            settings.output_dir / f"{settings.case_name}-image-manifest.json",
        )
        self.logs_dir = destination / "Logs"
        self.image = {**fingerprint, "host": host, "counts": result["counts"],
                      "extracted_to": str(destination), "manifest": manifest.name}
        self.log(f"Manifest with {len(result['manifest'])} SHA-256 hashes: {manifest}",
                 level="ok", step="collect")
        self.steps["collect"].artifacts = [manifest.name]
        counts = result["counts"]
        return (f"{counts['logs']} logs · {counts['hives']} hives · "
                f"{counts['files']} executables from {path.name}")

    def _use_existing_logs(self, source: str) -> str:
        """Bypass the collector and work on logs that are already reachable.

        Hayabusa opens EVTX read-only, so reading them in place on a live
        machine works, give or take a few locked files.
        """
        settings = self.settings
        if source == "custom":
            if not settings.logs_path:
                raise StepFailure(
                    "Custom log folder selected but no path configured in the "
                    "settings."
                )
            path = Path(settings.logs_path)
        else:
            path = Path(LIVE_LOGS)

        if not path.is_dir():
            raise StepFailure(f"Folder not found: {path}")

        evtx = list(path.glob("*.evtx"))
        if not evtx:
            raise StepFailure(f"No .evtx file in {path}")

        total_mo = sum(f.stat().st_size for f in evtx) // (1024 * 1024)
        self.logs_dir = path
        self.log(f"Logs read in place: {path}", level="ok", step="collect")
        self.log(f"{len(evtx)} EVTX file(s), {total_mo} MB in total.", step="collect")
        if source == "live":
            self.log(
                "Reading a live machine: no frozen copy, no hash. Avoid this "
                "when the case needs evidentiary value.",
                level="warn", step="collect",
            )
        return f"{len(evtx)} EVTX from {path}"

    def _find_logs_dir(self, extra: list[Path] | None = None) -> Path | None:
        """Find the log folder produced by the collector.

        Collectors write a folder named after the host in their working
        directory; case and location vary by version. Cast a wide net and keep
        the most recent match.
        """
        roots = [self.settings.evidence_dir, *(extra or []), self.settings.root]
        candidates: list[Path] = []
        for root in roots:
            if not root.exists():
                continue
            for name in ("Logs", "logs", "EventLogs", "Event Logs"):
                candidates += [p for p in root.rglob(name) if p.is_dir()]
        if candidates:
            return max(candidates, key=lambda p: p.stat().st_mtime)

        # Fallback: the directory holding the most EVTX files.
        counts: dict[Path, int] = {}
        for root in roots:
            if not root.exists():
                continue
            for evtx in root.rglob("*.evtx"):
                counts[evtx.parent] = counts.get(evtx.parent, 0) + 1
        return max(counts, key=counts.get) if counts else None

    async def _demo_collect(self) -> str:
        from .demo import build_demo_evidence

        self.log("Demonstration mode: generating a synthetic artefact set.",
                 level="warn", step="collect")
        self.logs_dir = build_demo_evidence(self.settings, self.log)
        return str(self.logs_dir)

    async def step_system(self) -> str:
        """Capture the machine's state: accounts, sockets, disk root.

        Everything is read-only. None of this appears in an event log, and it
        is the first thing an analyst asks for.
        """
        settings = self.settings
        if settings.demo_mode:
            from .demo import demo_system

            self.log("Demonstration mode: synthetic system context.",
                     level="warn", step="system")
            self.system = demo_system()
            return self._system_summary()

        if (settings.logs_source or "").lower() == "image":
            return await self._system_from_image()

        if (settings.logs_source or "").lower() == "remote":
            return await self._system_from_remote()

        if not IS_WINDOWS:
            raise StepFailure("Live system capture needs Windows. To analyse a "
                              "host from Linux, use a disk image as the evidence source.")

        async def run(argv: list[str], timeout: float) -> str:
            return await self.probe(argv, cwd=settings.root, timeout=timeout)

        drive = Path(settings.root.anchor or "C:\\")
        return await self._capture_system(
            run, lambda: sysinfo_module.analyse_root(drive), str(drive), "live")

    async def _capture_system(self, run, root_entries, root_path: str, source: str) -> str:
        """The live capture, whatever runs the commands: this machine, or a
        remote host over WinRM. Same commands, same parsers, same findings."""
        context: dict = {"collected_at": time.time(), "source": source}

        # -- machine identity
        self.log("Reading the configuration…", step="system")
        raw = await run(["systeminfo"], 180)
        context["host"] = sysinfo_module.parse_systeminfo(raw)
        # systeminfo prints dates in the host's local time and locale
        # ("1/1/2025, 12:00:00 AM" or "01/01/2025, 00:00:00"); the console and
        # the report work in UTC. One CIM query gives exact instants, plus the
        # release name and time zone the disk-image path already shows.
        context["host"].update(sysinfo_module.parse_osinfo(await run(
            ["powershell", "-NoProfile", "-Command", sysinfo_module.OSINFO_SCRIPT], 120)))

        # -- local accounts and administrators
        self.log("Enumerating accounts…", step="system")
        users_json = await run(
            ["powershell", "-NoProfile", "-Command",
             "Get-LocalUser | Select-Object Name,Enabled,SID,LastLogon,"
             "PasswordLastSet,Description | ConvertTo-Json -Compress"], 120)
        admins_json = await run(
            ["powershell", "-NoProfile", "-Command",
             "Get-LocalGroupMember -Group (Get-LocalGroup -SID "
             "'S-1-5-32-544').Name | Select-Object Name | ConvertTo-Json -Compress"], 120)
        context["users"] = sysinfo_module.parse_users(users_json, admins_json)

        # -- sockets, matched to their owning process
        self.log("Reading connections and listening ports…", step="system")
        tasks = await run(["tasklist", "/fo", "csv", "/nh"], 120)
        netstat = await run(["netstat", "-ano"], 180)
        context["connections"] = sysinfo_module.parse_netstat(
            netstat, sysinfo_module.parse_tasklist(tasks)
        )
        context["network"] = sysinfo_module.network_summary(context["connections"])

        # -- root of the system drive
        self.log("Inspecting the disk root…", step="system")
        context["root_entries"] = await root_entries() if asyncio.iscoroutinefunction(
            root_entries) else root_entries()
        context["root_path"] = root_path

        # -- logging: what the machine was able to see
        self.log("Auditing the logging configuration…", step="system")
        noms = ",".join(f"'{c[0]}'" for c in sysinfo_module.IMPORTANT_CHANNELS)
        channels_json = await run(
            ["powershell", "-NoProfile", "-Command",
             f"Get-WinEvent -ListLog {noms} -ErrorAction SilentlyContinue | "
             "Select-Object LogName,IsEnabled,RecordCount,FileSize,"
             "MaximumSizeInBytes,LastWriteTime | ConvertTo-Json -Compress"], 180)
        auditpol = await run(["auditpol", "/get", "/category:*", "/r"], 120)
        context["coverage"] = sysinfo_module.audit_coverage(
            sysinfo_module.parse_channels(channels_json),
            sysinfo_module.evtx_inventory(self.logs_dir),
            sysinfo_module.parse_auditpol(auditpol),
        )

        context["findings"] = sysinfo_module.system_findings(context)
        self.system = context
        self.bus.emit("system", system=context)
        return self._system_summary()

    async def _system_from_image(self) -> str:
        """Rebuild the system context from the registry of a disk image.

        What a dead disk can tell: identity, accounts, what starts on its own,
        what sits at the disk root, which logs existed. What it cannot: open
        sockets and running processes — the network card says so instead of
        reporting a reassuring zero.
        """
        target, path = await asyncio.to_thread(self._open_image)
        self.log("Reading identity, accounts and autoruns from the image registry…",
                 step="system")
        host = await asyncio.to_thread(image_module.describe_host, target, path)
        users = await asyncio.to_thread(image_module.read_accounts, target)
        autoruns = await asyncio.to_thread(image_module.read_autoruns, target)
        listing = await asyncio.to_thread(image_module.root_listing, target)

        # Ages are measured against the last log write, not today: an image
        # acquired months ago would otherwise show nothing as recent.
        inventory = sysinfo_module.evtx_inventory(self.logs_dir)
        reference = None
        if self.logs_dir and self.logs_dir.exists():
            stamps = [p.stat().st_mtime for p in self.logs_dir.glob("*.evtx")]
            manifest = (self.image or {}).get("manifest")
            if manifest:
                try:
                    data = json.loads((self.settings.output_dir / manifest).read_text())
                    stamps = [datetime.fromisoformat(f["modified"]).timestamp()
                              for f in data.get("files", [])
                              if f.get("category") == "event log" and f.get("modified")] or stamps
                except (OSError, ValueError, KeyError):
                    pass
            reference = max(stamps) if stamps else None

        context: dict = {
            "collected_at": time.time(),
            "source": "image",
            "image": path.name,
            "host": host,
            "users": users,
            "connections": [],
            "network": {"available": False, "listening": 0, "established": 0, "flagged": 0,
                        "note": "Not recoverable from a disk image: sockets only exist "
                                "on a running system."},
            "root_entries": sysinfo_module.analyse_root_entries(listing, reference=reference),
            "root_path": "C:\\",
            "autoruns": autoruns,
            "coverage": sysinfo_module.audit_coverage({}, inventory, {}),
        }
        context["findings"] = sysinfo_module.system_findings(context)
        for entry in autoruns:
            if entry["risk"] in ("high", "medium"):
                context["findings"].append({
                    "level": entry["risk"],
                    "title": f"{entry['kind'].capitalize()} persistence: {entry['name']}",
                    "detail": f"{entry['command']} — {', '.join(entry['flags'])}",
                })
        order = {"high": 0, "medium": 1, "low": 2}
        context["findings"].sort(key=lambda f: order.get(f["level"], 3))
        self.system = context
        self.bus.emit("system", system=context)
        return self._system_summary()

    def _system_summary(self) -> str:
        context = self.system or {}
        users = context.get("users", [])
        network = context.get("network", {})
        roots = context.get("root_entries", [])
        admins = len([u for u in users if u.get("admin")])

        self.log(f"{len(users)} local account(s), {admins} of them administrators.",
                 level="ok", step="system")
        if network.get("available", True):
            self.log(f"{network.get('listening', 0)} listening port(s), "
                     f"{network.get('established', 0)} established connection(s), "
                     f"{network.get('flagged', 0)} flagged.", level="ok", step="system")
        else:
            self.log("Network state: not available from a disk image.", step="system")
        autoruns = context.get("autoruns") or []
        if autoruns:
            risky = [a for a in autoruns if a["risk"] != "normal"]
            self.log(f"{len(autoruns)} autorun(s) read from the registry, "
                     f"{len(risky)} flagged.", level="warn" if risky else "ok", step="system")
        if roots:
            self.log(f"{len(roots)} unusual entry(ies) at the disk root.",
                     level="warn", step="system")

        coverage = context.get("coverage") or {}
        if coverage:
            self.log(f"Logging coverage: {coverage['score']}/100 — "
                     f"{coverage['verdict']}",
                     level="ok" if coverage["score"] >= 75 else "warn", step="system")
            if coverage.get("gaps"):
                self.log("Blind spots: " + ", ".join(coverage["gaps"][:6]),
                         level="warn", step="system")
        for finding in (context.get("findings") or [])[:6]:
            self.log(f"⚑ {finding['title']} — {finding['detail']}",
                     level="warn" if finding["level"] != "high" else "error",
                     step="system")
        coverage_score = (context.get("coverage") or {}).get("score")
        suffix = f" · coverage {coverage_score}/100" if coverage_score is not None else ""
        if not network.get("available", True):
            return (f"{len(users)} accounts · {len(autoruns)} autoruns · "
                    f"{len(roots)} root anomalies{suffix}")
        return (f"{len(users)} accounts · {network.get('listening', 0)} ports · "
                f"{len(roots)} root anomalies{suffix}")

    async def step_rules(self) -> str:
        if self.settings.demo_mode:
            self.log("Demonstration mode: rule update simulated.", level="warn", step="rules")
            await asyncio.sleep(0.4)
            return "Rules simulated"
        hayabusa = self.find_hayabusa()
        if hayabusa is None:
            raise StepFailure(f"Hayabusa not found under {self.settings.tools_dir}. Run the \"Locate the tooling\" step.")
        code, _ = await self.run_command([str(hayabusa), "update-rules"],
                                         cwd=self.settings.tools_dir, step_id="rules", timeout=900)
        if code != 0:
            raise StepFailure(f"update-rules failed — {explain_exit(code)}.")
        rules = self._find_rules_dir()
        return f"Rules in {rules}" if rules else "Sigma rules up to date"

    def _find_rules_dir(self) -> Path | None:
        """Hayabusa looks for its rules in ./rules. Depending on where
        update-rules was run they may live elsewhere, so we find them instead
        of letting the timeline command fail."""
        from .config import PROJECT_DIR

        for candidate in (self.settings.tools_dir / "rules",
                          self.settings.root / "rules",
                          PROJECT_DIR / "rules",
                          Path.cwd() / "rules"):
            if (candidate / "hayabusa").is_dir() or (candidate / "sigma").is_dir():
                return candidate
        return None

    async def _hayabusa_timeline_cmd(self, hayabusa: Path) -> tuple[str, str]:
        """Find the timeline subcommand and its help text.

        Hayabusa 3 called it csv-timeline; version 4 renamed it dfir-timeline.
        Rather than hard-coding a name, we read the help output.
        """
        help_text = await self.probe([str(hayabusa), "help"], cwd=hayabusa.parent)
        if not help_text:
            help_text = await self.probe([str(hayabusa), "--help"], cwd=hayabusa.parent)

        candidates = ("csv-timeline", "dfir-timeline", "json-timeline")

        for candidate in candidates:
            if re.search(rf"\b{candidate}\b", help_text):
                sub_help = await self.probe([str(hayabusa), candidate, "--help"],
                                            cwd=hayabusa.parent)
                return candidate, sub_help

        # The help output gave nothing (empty, unexpected format). Rather than
        # betting on a name, ask each candidate for its own help: the one that
        # answers without "unrecognized" exists.
        self.log("General help unreadable — probing subcommands directly.",
                 level="warn", step="timeline")
        for candidate in candidates:
            sub_help = await self.probe([str(hayabusa), candidate, "--help"],
                                        cwd=hayabusa.parent)
            if sub_help and "unrecognized" not in sub_help.lower():
                self.log(f"Subcommand selected after probing: {candidate}",
                         level="ok", step="timeline")
                return candidate, sub_help

        return "csv-timeline", ""

    @staticmethod
    def _spelling(flag: str, help_text: str) -> str | None:
        """The flag as this version writes it in its help, whatever the case."""
        if not help_text:
            return flag
        match = re.search(r"(?<![\w-])" + re.escape(flag) + r"(?![\w-])", help_text, re.I)
        return match.group(0) if match else None

    @staticmethod
    def _supported(flag: str, help_text: str) -> bool:
        """A flag missing from the help text would fail the whole command."""
        return not help_text or flag in help_text

    async def step_timeline(self) -> str:
        settings = self.settings
        if settings.demo_mode:
            from .demo import build_demo_timeline

            self.log("Demonstration mode: synthetic timeline.", level="warn", step="timeline")
            build_demo_timeline(settings.timeline_csv)
            return str(settings.timeline_csv)

        hayabusa = self.find_hayabusa()
        if hayabusa is None:
            raise StepFailure(f"Hayabusa not found under {settings.tools_dir}. Run the \"Locate the tooling\" step.")
        logs = self.logs_dir or self._find_logs_dir()
        if not logs:
            raise StepFailure("No log directory: run the collection first.")
        self.logs_dir = logs
        settings.output_dir.mkdir(parents=True, exist_ok=True)

        subcommand, sub_help = await self._hayabusa_timeline_cmd(hayabusa)
        self.log(f"Hayabusa subcommand: {subcommand}", step="timeline")

        args = [str(hayabusa), subcommand, "-d", str(logs),
                "-o", str(settings.timeline_csv)]
        # Hayabusa 3+ spells these in lower case (--rfc-3339, --utc). Matching
        # "--RFC-3339" and "--UTC" exactly meant both were silently dropped,
        # and the timeline came out in the analyst's local time.
        for flag in ("--no-wizard", "--rfc-3339", "--utc"):
            spelled = self._spelling(flag, sub_help)
            if spelled:
                args.append(spelled)
            else:
                self.log(f"Option {flag} absent from this version — skipped.",
                         step="timeline", ui=False)
        # The verbose profile carries each rule's ATT&CK tactics (the kill
        # chain axis) and the log file every detection came from.
        if self._supported("--profile", sub_help):
            args += ["--profile", "verbose"]

        rules = self._find_rules_dir()
        if rules and self._supported("-r", sub_help):
            args += ["-r", str(rules)]
            self.log(f"Sigma rules: {rules}", step="timeline")
        elif not rules:
            self.log("No rule folder found — run update-rules first.",
                     level="warn", step="timeline")

        code, output = await self.run_command(args, cwd=settings.tools_dir,
                                              step_id="timeline")

        # Last resort: Hayabusa names the expected subcommand itself
        # ("tip: a similar subcommand exists: 'dfir-timeline'"). Take it and
        # replay once rather than failing over a rename.
        if "unrecognized subcommand" in output:
            tip = re.search(r"similar subcommand exists:\s*'([\w-]+)'", output)
            if tip and tip.group(1) != subcommand:
                corrected = tip.group(1)
                self.log(f"Hayabusa suggests '{corrected}' — retrying.",
                         level="warn", step="timeline")
                args[1] = corrected
                code, output = await self.run_command(args, cwd=settings.tools_dir,
                                                      step_id="timeline")

        if "unrecognized subcommand" in output or "unexpected argument" in output:
            raise StepFailure(
                "Hayabusa refused the command: "
                + (output.strip().splitlines()[0] if output.strip() else "empty output")
            )
        if code != 0 and not settings.timeline_csv.exists():
            raise StepFailure(f"{args[1]} failed — {explain_exit(code)}.")
        size = settings.timeline_csv.stat().st_size // 1024
        return f"hayabusa-output.csv ({size} KB)"

    async def step_analyse(self) -> str:
        path = self.settings.timeline_csv
        if not path.exists():
            raise StepFailure(f"Timeline missing: {path}")
        self.log(f"Reading {path}", step="analyse")
        report = await asyncio.to_thread(timeline_module.analyse_csv, path)
        if report.errors:
            for error in report.errors[:5]:
                self.log(error, level="warn", step="analyse")
        self.report = report.to_dict()
        levels = self.report["levels"]
        self.log(
            f"{self.report['total']} events — critical {levels['critical']}, "
            f"high {levels['high']}, medium {levels['medium']}",
            level="ok", step="analyse",
        )
        self.log(f"{len(self.report['iocs'])} indicator(s) extracted.", step="analyse")
        self.steps["analyse"].artifacts = [path.name]
        self._merge_system_iocs()
        self._rescore()
        return f"score {self.report['risk_score']}/100 — {self.report['verdict']}"

    def _rescore(self) -> None:
        """Recompute the score with every source available at this point.

        The timeline alone can only report severity and kill-chain breadth.
        Reputation, YARA hits and live connections arrive from other steps, so
        the score is refreshed whenever one of them lands.
        """
        if not self.report:
            return

        iocs = self.report.get("iocs", [])
        external = {
            "malicious": len([i for i in iocs if i.get("threat") == "malicious"]),
            "suspicious": len([i for i in iocs if i.get("threat") == "suspicious"]),
            "yara_alerts": len((self.thor or {}).get("alerts", [])),
            # Only connections already judged suspicious corroborate anything:
            # a browser talking to Google used to add 4 points to every case.
            "live_connections": len(sysinfo_module.suspicious_peers(
                (self.system or {}).get("connections", []))),
            "coverage": ((self.system or {}).get("coverage") or {}).get("score"),
        }

        report = timeline_module.TimelineReport()
        report.levels = Counter(self.report.get("levels", {}))
        report.tactics = Counter(dict(self.report.get("tactics", [])))
        report.distinct_rules = self.report.get("distinct_rules")
        breakdown = report.score_breakdown(external)

        self.report["risk_score"] = breakdown["score"]
        self.report["score_breakdown"] = breakdown
        self.report["verdict"] = timeline_module.TimelineReport.verdict_for(
            breakdown["score"], breakdown["confidence"]
        )
        self.bus.emit("report", report=self.report)

    def _merge_yara_iocs(self) -> None:
        """Feed YARA hits into the indicator list.

        A hash flagged by a YARA rule is exactly what an analyst wants to look
        up on VirusTotal — leaving it stranded on its own page would mean
        retyping it by hand.
        """
        if not self.report or not self.thor:
            return
        existing = {(i["type"], i["value"].lower()) for i in self.report["iocs"]}
        added = 0
        for alert in self.thor.get("alerts", []):
            digest = (alert.get("sha256") or "").strip()
            if not digest or ("sha256", digest.lower()) in existing:
                continue
            existing.add(("sha256", digest.lower()))
            added += 1
            self.report["iocs"].insert(0, {
                "type": "sha256", "value": digest, "count": 1,
                "max_level": "critical",
                "rules": [alert.get("message") or alert.get("rule") or "YARA hit"],
                "enrichment": None, "source": "YARA scan",
                "file": alert.get("file", ""),
            })
        if added:
            self.log(f"{added} hash(es) from YARA detections added to indicators.",
                     level="ok", step="yara")
        self._rescore()

    def _merge_system_iocs(self) -> None:
        """Feed the remote peers of active connections into the indicators.

        An address being talked to at triage time is at least as interesting as
        one seen in a three-day-old log entry — and it appears nowhere in the
        timeline.
        """
        if not self.report or not self.system:
            return
        existing = {(i["type"], i["value"]) for i in self.report["iocs"]}
        added = 0
        for connection in self.system.get("connections", []):
            peer = connection.get("remote_ip", "")
            if connection.get("state") != "ESTABLISHED" or not sysinfo_module.is_public_ip(peer):
                continue
            if ("ip", peer) in existing:
                continue
            existing.add(("ip", peer))
            added += 1
            self.report["iocs"].append({
                "type": "ip", "value": peer, "count": 1,
                # Still worth a reputation check, but a connection nothing
                # flagged is not raised to "medium" any more.
                "max_level": {"high": "high", "medium": "medium"}.get(connection["risk"], "low"),
                "rules": [f"active connection — {connection.get('process') or 'PID ' + str(connection['pid'])}"],
                "enrichment": None, "source": "active connection",
            })
        if added:
            self.log(f"{added} address(es) from active connections added to the "
                     "indicators.", level="ok", step="analyse")

    async def step_yara(self) -> str:
        """YARA scan with THOR Lite, over the scope the analyst chose.

        No time limit by default: sweeping a whole disk legitimately takes
        hours, and that is an analyst's decision, not an anomaly to interrupt.
        """
        settings = self.settings
        thor = self.find_thor()
        if thor is None:
            raise StepFailure(
                "THOR Lite not found. Nextron requires registration: drop "
                f"thor64-lite.exe and its licence file into {settings.thor_dir}."
            )
        if not is_admin():
            raise StepFailure(
                "THOR Lite requires elevation. Restart the console as administrator."
            )

        target = self._scan_target()
        if not target.exists():
            raise StepFailure(f"Scan folder not found: {target}")

        self.log(f"Scanner: THOR Lite ({thor})", level="ok", step="yara")
        self.log(f"Scope: {target}", step="yara")
        if target.parent == target:  # volume root
            self.log("Sweeping a whole volume — expect several hours. This step "
                     "has no time limit.", level="warn", step="yara")

        extra = [a for a in settings.thor_args.split() if a]
        if not any(a in ("-p", "--path") for a in extra):
            extra += ["-p", str(target)]

        log_path = settings.output_dir / "thor-lite.log"
        limit = settings.thor_timeout_min * 60 if settings.thor_timeout_min else 0
        if limit:
            self.log(f"Automatic abort after {settings.thor_timeout_min} min.",
                     step="yara")
        else:
            self.log("No time limit: the scan will run to completion.", step="yara")

        live: dict = {"alerts": [], "entries": [], "warnings": 0, "notices": 0,
                      "infos": 0, "scanned": None}
        self.thor = live
        seen = {"lines": 0, "parsed": 0}

        def on_line(text: str) -> None:
            """Surface each verdict as it comes out, without waiting for the end."""
            seen["lines"] += 1
            entry = timeline_module.parse_thor_line(text)
            if entry is None:
                return
            seen["parsed"] += 1
            live["entries"].append(entry)
            if entry["raw_level"] == "alert":
                live["alerts"].append(entry)
                self.log(
                    f"⚑ {entry['message'][:120]}"
                    + (f" — {entry['file']}" if entry["file"] else ""),
                    level="error", step="yara",
                )
            elif entry["raw_level"] == "warning":
                live["warnings"] += 1
            elif entry["raw_level"] == "notice":
                live["notices"] += 1
            else:
                live["infos"] += 1
            # Every verdict reaches the screen, "nothing to report" included:
            # the YARA page must fill up during the scan, not only when
            # something is found.
            self.bus.emit("yara", alert=entry, total=len(live["entries"]))

        code, _ = await self.run_command(
            [str(thor), *extra, "--logfile", str(log_path)],
            cwd=thor.parent, step_id="yara",
            timeout=limit, heartbeat=180, on_line=on_line,
        )

        # The log file is authoritative at the end of the scan: it also holds
        # whatever the stream reader may have missed.
        from_file = timeline_module.parse_thor_log(log_path)
        if len(from_file["entries"]) >= len(live["entries"]):
            self.thor = from_file

        # Separate "THOR found nothing" from "I could not read its output".
        self.log(
            f"{seen['lines']} output line(s), {seen['parsed']} parsed as "
            f"verdicts, {len(self.thor['alerts'])} alert(s) kept.",
            step="yara",
        )
        if seen["lines"] > 50 and seen["parsed"] == 0:
            self.log(
                "No line matched the expected format: the THOR log was produced "
                f"({log_path}) but its format is unrecognised. Attach it so the "
                "parser can be fixed.",
                level="warn", step="yara",
            )
        if not self.thor["alerts"]:
            self.log(
                f"No detection over {target}. Check that the scope really holds "
                "the expected files and that THOR loaded its signatures.",
                level="warn", step="yara",
            )
        if code not in (0, 1):
            self.log(f"THOR finished — {explain_exit(code)}.", level="warn", step="yara")
        self.steps["yara"].artifacts = [log_path.name]
        self._merge_yara_iocs()
        self.log(f"{len(self.thor['alerts'])} alert(s), "
                 f"{self.thor['warnings']} warning(s), "
                 f"{self.thor['notices']} notice(s) — "
                 f"{len(self.thor.get('entries', []))} verdict(s) in total.",
                 level="ok", step="yara")
        return f"{len(self.thor['alerts'])} alert(s) over {target.name or target}"

    def _scan_target(self) -> Path:
        """Scan scope: the one requested, otherwise the collected artefacts."""
        if self.settings.yara_path.strip():
            return Path(self.settings.yara_path.strip())
        # From a disk image, scan what was extracted from it — not every
        # collection that ever landed in evidence\.
        if self.image and Path(self.image.get("extracted_to", "")).exists():
            return Path(self.image["extracted_to"])
        return self.settings.evidence_dir

    async def step_enrich(self) -> str:
        if not self.report:
            raise StepFailure("No report to enrich: run the timeline analysis first.")
        settings = self.settings
        if not settings.virustotal_key and not settings.abuseipdb_key:
            raise StepFailure("No VirusTotal or AbuseIPDB key configured.")

        enricher = Enricher(
            vt_key=settings.virustotal_key,
            abuse_key=settings.abuseipdb_key,
            cache_path=settings.output_dir / "enrichment-cache.json",
        )
        iocs = self.report["iocs"]

        def progress(index: int, total: int, ioc: dict) -> None:
            self.log(
                f"[{index}/{total}] {ioc['type']} {ioc['value']} → {ioc.get('threat')}",
                level="ok" if ioc.get("threat") in ("clean", "unknown") else "warn",
                step="enrich",
            )
            self.bus.emit("ioc", ioc=ioc)

        limit = settings.enrich_limit or len(iocs)
        self.log(f"{len(iocs)} indicator(s) to check"
                 + ("" if settings.enrich_limit else " (no cap)"), step="enrich")
        enriched = await enricher.enrich(iocs, limit=limit, on_progress=progress)
        flagged = [i for i in enriched if i.get("threat") in ("malicious", "suspicious")]
        self._rescore()
        return f"{len(enriched)} checked, {len(flagged)} flagged"

    async def step_ai(self) -> str:
        if not self.report:
            raise StepFailure("No report to summarise.")
        settings = self.settings
        from .ai import PROVIDERS

        spec = PROVIDERS.get((settings.ai_provider or "").lower())
        target = settings.ai_base_url.strip() or (spec or {}).get("base_url") or \
            "https://api.anthropic.com"
        if spec is not None and spec["dialect"] == "local":
            # Nothing leaves the machine: say so instead of naming an API.
            self.log("Provider: none — summary written locally, nothing is sent.",
                     step="ai")
        else:
            self.log(f"Provider: {(spec or {}).get('label', settings.ai_provider)} "
                     f"→ {target}", step="ai")
            self.log("Sending the summary to the model…", step="ai")
        self.ai = await ai_module.analyse(
            self.report,
            api_key=settings.anthropic_key,
            model=settings.ai_model,
            provider=settings.ai_provider,
            base_url=settings.ai_base_url,
            max_chars=settings.ai_max_chars,
            system=self.system,
            thor=self.thor,
            context={
                "case": settings.case_name,
                "analyst": settings.analyst,
                "hosts": [c for c, _ in self.report.get("computers", [])],
                "coverage": (self.system or {}).get("coverage"),
            },
        )
        if self.ai.get("note"):
            self.log(self.ai["note"], level="warn", step="ai")
        self.bus.emit("ai", ai=self.ai)
        return self.ai.get("verdict", "Summary produced")

    # -- orchestration ----------------------------------------------------
    def _seal(self, step: StepState) -> tuple[str, str]:
        """Seal a completed step.

        When the step produced files, the seal is the SHA-256 of their contents
        — re-running the hash later proves the artefact was not altered. When
        it produced none, the seal only covers the execution record (step,
        start time, result), and says so.
        """
        digest = hashlib.sha256()
        hashed: list[str] = []
        for name in step.artifacts:
            for folder in (self.settings.output_dir, self.settings.evidence_dir,
                           self.settings.tools_dir):
                candidate = folder / name
                if candidate.is_file():
                    digest.update(sha256_file(candidate).encode())
                    hashed.append(name)
                    break

        if hashed:
            return digest.hexdigest()[:16], "content of " + ", ".join(hashed)

        digest.update(f"{step.id}|{step.started}|{step.message}".encode())
        return digest.hexdigest()[:16], "execution record (no file produced)"

    def _handlers(self) -> dict[str, Callable[[], Awaitable[str]]]:
        return {
            "workspace": self.step_workspace,
            "defender": self.step_defender,
            "tools": self.step_tools,
            "collect": self.step_collect,
            "system": self.step_system,
            "rules": self.step_rules,
            "timeline": self.step_timeline,
            "analyse": self.step_analyse,
            "yara": self.step_yara,
            "enrich": self.step_enrich,
            "ai": self.step_ai,
        }

    async def run(self, step_ids: list[str]) -> None:
        if self.running:
            raise RuntimeError("A run is already in progress.")
        handlers = self._handlers()
        unknown = [s for s in step_ids if s not in handlers]
        if unknown:
            raise ValueError(f"Unknown steps: {unknown}")

        self.running = True
        self.started_at = time.time()
        self.finished_at = None
        self.bus.emit("run", state="started", steps=step_ids)

        try:
            for step_id in step_ids:
                step = self.steps[step_id]
                step.status = RUNNING
                step.started = time.time()
                step.message = ""
                self._push_step(step)
                self.log(f"▶ {step.label}", level="head", step=step_id)
                try:
                    message = await handlers[step_id]()
                    step.status = DONE
                    step.message = message
                    step.seal, step.seal_basis = self._seal(step)
                    self.log(f"✔ {step.label} — {message}", level="ok", step=step_id)
                except StepFailure as exc:
                    step.status = SKIPPED if step.optional else FAILED
                    step.message = str(exc)
                    level = "warn" if step.optional else "error"
                    self.log(f"✖ {step.label} — {exc}", level=level, step=step_id)
                except asyncio.CancelledError:
                    step.status = FAILED
                    step.message = "Interrupted by the analyst."
                    step.ended = time.time()
                    self._push_step(step)
                    raise
                except Exception as exc:  # noqa: BLE001 — we want the raw message
                    step.status = FAILED
                    step.message = f"{exc.__class__.__name__}: {exc}"
                    self.log(f"✖ {step.label} — {step.message}", level="error", step=step_id)
                finally:
                    step.ended = time.time()
                    self._push_step(step)

                if step.status == FAILED and not step.optional:
                    self.log("Chain stopped: the next step depends on this one.",
                             level="error", step=step_id)
                    break
        finally:
            self.running = False
            self.finished_at = time.time()
            self.bus.emit("run", state="finished", snapshot=self.snapshot())

    def start(self, step_ids: list[str]) -> None:
        self._task = asyncio.create_task(self.run(step_ids))

    def cancel(self) -> bool:
        if self._task and not self._task.done():
            self._task.cancel()
            self.log("Stop requested.", level="warn")
            return True
        return False

    def reset(self) -> None:
        for step in self.steps.values():
            step.status = PENDING
            step.message = ""
            step.seal = step.seal_basis = ""
            step.started = step.ended = None
            step.artifacts = []
        self.report = self.thor = self.ai = self.system = None
        self.logs_dir = None
        self.image = None
        self._image_target = None
        self.remote = None
        self.started_at = self.finished_at = None
        self.bus.clear_history()


def python_bin() -> str:
    return sys.executable or "python"
