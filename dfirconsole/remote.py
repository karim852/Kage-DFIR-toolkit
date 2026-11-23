"""Remote triage: run the usual chain against another Windows host.

From the analyst's workstation, over WinRM (PowerShell Remoting, the channel
Windows administrators already use), Kage:

1. opens a session with an administrator account of the target;
2. pushes the same CyLR.exe it would run locally into a temporary folder;
3. runs it there, with the same arguments;
4. fetches the archive in chunks and checks its SHA-256 against the one the
   target computed;
5. removes everything it left on the target;
6. runs the very same system-context commands as a live capture (systeminfo,
   Get-LocalUser, netstat, auditpol…) and feeds their output to the very same
   parsers.

The archive then goes through the exact local path of a CyLR collection:
unpack, Hayabusa, analysis. Same evidence in, same results out.

Two transports share one small interface:

- `WinRMTransport`, the real one (pypsrp, pure Python, works from Windows and
  from Linux);
- `SimulatedTransport`, a host made of files. It answers commands from
  recorded outputs and serves a folder as its C: drive. Tests and the browser
  runs use it, through the KAGE_REMOTE_SIMULATION environment variable, to
  exercise the whole remote path without a Windows machine.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Callable, Protocol

SIMULATION_ENV = "KAGE_REMOTE_SIMULATION"
PASSWORD_ENV = "KAGE_REMOTE_PASSWORD"
CHUNK = 4 * 1024 * 1024
RC_MARK = "__KAGE_RC__="


class RemoteError(Exception):
    """A remote operation failed, with a message an analyst can act on."""


def available() -> bool:
    """Whether the WinRM client library is installed (always true in the exe)."""
    try:
        import pypsrp.client  # noqa: F401
    except ImportError:
        return False
    return True


def ps_quote(text: str) -> str:
    """Single-quoted PowerShell literal."""
    return "'" + str(text).replace("'", "''") + "'"


def as_powershell(argv: list[str]) -> str:
    """The script a command line becomes on the target.

    Native tools are called through PowerShell too: one channel, one decoding
    (PowerShell hands back text, whatever the console code page of the target),
    and the exit code travels on a marker line.
    """
    if (len(argv) >= 3 and Path(argv[0]).name.lower() in ("powershell", "powershell.exe")
            and "-Command" in argv):
        return argv[argv.index("-Command") + 1]
    call = "& " + " ".join(ps_quote(a) for a in argv)
    return (f"$ErrorActionPreference = 'Continue'; "
            f"$out = {call} 2>&1 | Out-String -Width 4096; $out; "
            f"'{RC_MARK}' + $LASTEXITCODE")


def split_exit_code(text: str) -> tuple[int, str]:
    lines = (text or "").rstrip().splitlines()
    if lines and lines[-1].startswith(RC_MARK):
        value = lines[-1][len(RC_MARK):].strip()
        return (int(value) if value.lstrip("-").isdigit() else 0), "\n".join(lines[:-1])
    return 0, text or ""


class Transport(Protocol):
    host: str
    label: str

    def run(self, argv: list[str], timeout: float = 600) -> tuple[int, str]: ...
    def put(self, local: Path, remote: str) -> None: ...
    def get(self, remote: str, local: Path,
            progress: Callable[[int, int], None] | None = None) -> None: ...
    def close(self) -> None: ...


# =========================================================================
# WinRM
# =========================================================================
@dataclass
class WinRMTransport:
    """PowerShell Remoting through pypsrp.

    Leave the user empty on a domain workstation: the current Windows session
    authenticates (Kerberos), no password typed or stored. Fill it in for a
    workgroup host or another account.
    """

    host: str
    username: str = ""
    password: str = ""
    ssl: bool = False
    port: int = 0
    cert_validation: bool = True
    label: str = "WinRM"
    _client: object = field(default=None, repr=False)
    _pool: object = field(default=None, repr=False)

    def _connect(self):
        if self._client is not None:
            return self._client
        try:
            from pypsrp.client import Client
        except ImportError as exc:
            raise RemoteError("Remote triage needs the pypsrp package: "
                              "pip install pypsrp") from exc
        options = {
            "ssl": self.ssl,
            "port": self.port or (5986 if self.ssl else 5985),
            "auth": "negotiate",
            "cert_validation": self.cert_validation,
            "operation_timeout": 20,
            "read_timeout": 30,
            "connection_timeout": 15,
            "encryption": "auto",
        }
        if self.username:
            options["username"] = self.username
            options["password"] = self.password
        self.label = f"WinRM {'HTTPS' if self.ssl else 'HTTP'}:{options['port']}"
        self._client = Client(self.host, **options)
        return self._client

    def _explain(self, exc: Exception) -> RemoteError:
        text = f"{type(exc).__name__}: {exc}"
        low = text.lower()
        if "401" in low or "credentials" in low or "logon failure" in low or "auth" in low:
            hint = ("the target refused the credentials. Use an administrator "
                    "account of that host, as DOMAIN\\user or .\\user for a local one.")
        elif "timed out" in low or "connection" in low or "max retries" in low:
            hint = ("no WinRM answer. On the target, as administrator: "
                    "Enable-PSRemoting -Force, and allow TCP 5985 (5986 for HTTPS) "
                    "from this workstation.")
        elif "certificate" in low or "ssl" in low:
            hint = "the HTTPS certificate was not trusted; check the name or use HTTP."
        else:
            hint = "see the detail above."
        return RemoteError(f"{self.host}: {hint} ({text[:300]})")

    def run(self, argv: list[str], timeout: float = 600) -> tuple[int, str]:
        client = self._connect()
        script = as_powershell(argv)
        try:
            output, streams, had_errors = client.execute_ps(script)
        except Exception as exc:  # noqa: BLE001 — pypsrp/requests raise many types
            raise self._explain(exc) from exc
        code, text = split_exit_code(output)
        if had_errors and not text.strip():
            errors = "\n".join(str(e) for e in getattr(streams, "error", [])[:5])
            return (code or 1), errors
        return code, text

    def put(self, local: Path, remote: str) -> None:
        client = self._connect()
        try:
            client.copy(str(local), remote)
        except Exception as exc:  # noqa: BLE001
            raise self._explain(exc) from exc

    def _pool_open(self):
        """One runspace pool reused for every chunk: a pool per chunk costs
        a full WinRM handshake each time."""
        if self._pool is None:
            from pypsrp.powershell import RunspacePool
            self._pool = RunspacePool(self._connect().wsman)
            self._pool.open()
        return self._pool

    def get(self, remote: str, local: Path,
            progress: Callable[[int, int], None] | None = None) -> None:
        """Chunked download. pypsrp's own fetch holds the whole file in memory
        as one base64 string, which a multi-GB collection does not survive."""
        from pypsrp.powershell import PowerShell

        size_code, size_text = self.run(
            ["powershell", "-NoProfile", "-Command", f"(Get-Item -LiteralPath {ps_quote(remote)}).Length"])
        try:
            total = int(size_text.strip().splitlines()[-1])
        except (ValueError, IndexError) as exc:
            raise RemoteError(f"{remote} not found on {self.host}") from exc

        local.parent.mkdir(parents=True, exist_ok=True)
        done = 0
        try:
            pool = self._pool_open()
            with open(local, "wb") as handle:
                while done < total:
                    length = min(CHUNK, total - done)
                    shell = PowerShell(pool)
                    shell.add_script(
                        "param($p, $o, $n) $f = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite');"
                        " try { $f.Seek($o, 'Begin') | Out-Null; $b = New-Object byte[] $n;"
                        " $r = $f.Read($b, 0, $n); [Convert]::ToBase64String($b, 0, $r) }"
                        " finally { $f.Close() }"
                    ).add_argument(remote).add_argument(done).add_argument(length)
                    shell.invoke()
                    if shell.had_errors or not shell.output:
                        raise RemoteError(f"read failed at byte {done} of {remote}")
                    data = base64.b64decode(shell.output[0])
                    if not data:
                        raise RemoteError(f"empty read at byte {done} of {remote}")
                    handle.write(data)
                    done += len(data)
                    if progress:
                        progress(done, total)
        except RemoteError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise self._explain(exc) from exc

    def close(self) -> None:
        if self._pool is not None:
            try:
                self._pool.close()
            except Exception:  # noqa: BLE001
                pass
            self._pool = None
        self._client = None


# =========================================================================
# Simulation
# =========================================================================
@dataclass
class SimulatedTransport:
    """A Windows host made of files, for tests and offline rehearsal.

    Profile layout::

        profile/
          host.json            {"hostname": "...", "admin": true}
          commands/            recorded outputs, one file per command
            systeminfo.txt  tasklist.txt  netstat.txt  auditpol.txt
            users.json  admins.json  channels.json
          C/                   the target's system drive

    Remote paths (C:\\...) map into C/. A CyLR run zips the drive's event
    logs and registry hives the way CyLR lays them out, so the archive takes
    the normal collection path on the workstation.
    """

    profile: Path
    host: str = ""
    label: str = "simulated WinRM"
    calls: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.profile = Path(self.profile)
        meta = self._meta()
        self.host = self.host or meta.get("hostname", "SIMULATED-HOST")

    def _meta(self) -> dict:
        path = self.profile / "host.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def _local(self, remote: str) -> Path:
        win = PureWindowsPath(remote)
        if win.drive.upper() != "C:":
            raise RemoteError(f"only the C: drive is simulated, not {remote}")
        return self.profile.joinpath("C", *win.parts[1:])

    def _recorded(self, name: str) -> str:
        path = self.profile / "commands" / name
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def run(self, argv: list[str], timeout: float = 600) -> tuple[int, str]:
        script = as_powershell(argv)
        self.calls.append(script)
        tool = Path(PureWindowsPath(argv[0]).name).name.lower()
        if self._meta().get("unreachable"):
            raise RemoteError(f"{self.host}: no WinRM answer (simulated outage)")

        if tool.startswith("cylr"):
            return self._cylr(argv)
        for name in ("systeminfo", "tasklist", "netstat", "auditpol"):
            if tool.startswith(name):
                return 0, self._recorded(f"{name}.txt")

        if "Get-LocalUser" in script:
            return 0, self._recorded("users.json")
        if "Get-LocalGroupMember" in script:
            return 0, self._recorded("admins.json")
        if "Get-WinEvent -ListLog" in script:
            return 0, self._recorded("channels.json")
        if "KAGE-OSINFO" in script:
            return 0, self._recorded("osinfo.json")
        if "KAGE-ROOT-LISTING" in script:
            return 0, json.dumps(self._root_listing())
        if "KAGE-HELLO" in script:
            return 0, json.dumps({"hostname": self.host,
                                  "admin": self._meta().get("admin", True),
                                  "os": self._meta().get("os", "Windows 10 Pro")})
        if "Get-FileHash" in script:
            match = re.search(r"-LiteralPath '([^']+)'", script)
            path = self._local(match.group(1).replace("''", "'"))
            return 0, hashlib.sha256(path.read_bytes()).hexdigest().upper()
        if "New-Item -ItemType Directory" in script:
            match = re.search(r"-Path '([^']+)'", script)
            self._local(match.group(1)).mkdir(parents=True, exist_ok=True)
            return 0, ""
        if "Remove-Item" in script:
            match = re.search(r"-LiteralPath '([^']+)'", script)
            shutil.rmtree(self._local(match.group(1)), ignore_errors=True)
            return 0, ""
        if ").Length" in script:
            match = re.search(r"-LiteralPath '([^']+)'", script)
            return 0, str(self._local(match.group(1)).stat().st_size)
        return 0, ""

    def _root_listing(self) -> list[dict]:
        root = self.profile / "C"
        times = self._meta().get("root_created", {})
        listing = []
        for child in sorted(root.iterdir()):
            listing.append({"name": child.name, "is_dir": child.is_dir(),
                            "created": times.get(child.name, child.stat().st_mtime)})
        return listing

    def _cylr(self, argv: list[str]) -> tuple[int, str]:
        out_dir = argv[argv.index("-od") + 1]
        name = argv[argv.index("-of") + 1]
        destination = self._local(str(PureWindowsPath(out_dir) / name))
        drive = self.profile / "C"
        picked = 0
        with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
            for pattern in ("Windows/System32/winevt/Logs/*.evtx",
                            "Windows/System32/config/SAM", "Windows/System32/config/SYSTEM",
                            "Windows/System32/config/SOFTWARE",
                            "Windows/System32/config/SECURITY", "Windows/Prefetch/*.pf"):
                for item in sorted(drive.glob(pattern)):
                    archive.write(item, f"C/{item.relative_to(drive).as_posix()}")
                    picked += 1
        return 0, f"Collected {picked} artefacts into {name}"

    def put(self, local: Path, remote: str) -> None:
        target = self._local(remote)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(local, target)

    def get(self, remote: str, local: Path,
            progress: Callable[[int, int], None] | None = None) -> None:
        source = self._local(remote)
        total = source.stat().st_size
        local.parent.mkdir(parents=True, exist_ok=True)
        done = 0
        with open(source, "rb") as reader, open(local, "wb") as writer:
            while chunk := reader.read(CHUNK):
                writer.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)

    def close(self) -> None:
        pass


def open_transport(host: str, username: str = "", password: str = "",
                   ssl: bool = False) -> Transport:
    """The real transport, or the simulated host when the environment asks."""
    simulation = os.environ.get(SIMULATION_ENV)
    if simulation:
        return SimulatedTransport(Path(simulation), host=host if host and host != "simulated" else "")
    if not host:
        raise RemoteError("Remote host selected as the evidence source, but no host "
                          "name is set. Fill in Settings → Remote host.")
    return WinRMTransport(host=host, username=username, password=password, ssl=ssl)


# What the system step runs on the target, written once for both paths.
HELLO = ("# KAGE-HELLO\n"
         "$p = New-Object Security.Principal.WindowsPrincipal("
         "[Security.Principal.WindowsIdentity]::GetCurrent());"
         "[pscustomobject]@{hostname=$env:COMPUTERNAME;"
         "admin=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);"
         "os=(Get-CimInstance Win32_OperatingSystem).Caption} | ConvertTo-Json -Compress")

ROOT_LISTING = ("# KAGE-ROOT-LISTING\n"
                "Get-ChildItem -LiteralPath 'C:\\' -Force -ErrorAction SilentlyContinue | "
                "Select-Object Name,@{n='is_dir';e={$_.PSIsContainer}},"
                "@{n='created';e={[DateTimeOffset]::new($_.CreationTimeUtc).ToUnixTimeSeconds()}} | "
                "ConvertTo-Json -Compress")


def parse_listing(text: str) -> list[dict]:
    try:
        data = json.loads(text or "[]")
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return [{"name": d.get("Name") or d.get("name"), "is_dir": bool(d.get("is_dir")),
             "created": d.get("created")} for d in data if (d.get("Name") or d.get("name"))]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
