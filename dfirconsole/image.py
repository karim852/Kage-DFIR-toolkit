"""Dead-disk triage: E01, VMDK, VHD/VHDX, QCOW2 and raw images.

A disk image cannot be asked anything — no `netstat`, no `Get-LocalUser`. What
it does hold is everything Windows wrote down: the event logs, the registry
hives, the files. This module opens the image read-only, finds the Windows
volume, pulls out what the rest of the chain already knows how to analyse, and
reconstructs the system context from the registry instead of from live
commands.

The heavy lifting is done by dissect (Fox-IT), a pure-Python forensic
framework: it reads the container formats, the partition tables, NTFS and the
registry without mounting anything and without native dependencies.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import struct
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable

SUPPORTED_SUFFIXES = {
    ".e01": "EnCase (EWF)", ".ex01": "EnCase v2 (EWF2)", ".s01": "SMART (EWF)",
    ".vmdk": "VMware VMDK", ".vhd": "Hyper-V VHD", ".vhdx": "Hyper-V VHDX",
    ".qcow2": "QEMU QCOW2", ".vdi": "VirtualBox VDI",
    ".raw": "raw", ".dd": "raw", ".img": "raw", ".bin": "raw", ".001": "raw (split)",
}

# Executable content worth handing to THOR. Documents are left out on purpose:
# they would dominate the size budget for little YARA value.
EXECUTABLE_SUFFIXES = {
    ".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".msi", ".jar",
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".hta", ".lnk",
}

# Where droppers, staging scripts and user-launched payloads actually land.
HOT_LOCATIONS = (
    "Users/*/Downloads", "Users/*/Desktop", "Users/*/Documents",
    "Users/*/AppData/Local/Temp", "Users/*/AppData/Roaming",
    "Users/Public", "ProgramData", "Windows/Temp", "PerfLogs",
)

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_FILES = 5000
MAX_DEPTH = 6

Progress = Callable[[str, str], None]


class ImageError(Exception):
    """A problem with the image itself, worded for the analyst."""


def available() -> bool:
    try:
        import dissect.target  # noqa: F401
    except ImportError:
        return False
    return True


def describe_format(path: Path) -> str:
    return SUPPORTED_SUFFIXES.get(path.suffix.lower(), "unrecognised extension")


def open_image(path: Path):
    """Open the image read-only and make sure it holds a Windows system."""
    if not available():
        raise ImageError("Disk image support needs the dissect package: "
                         "pip install dissect.target")
    path = Path(path)
    if not path.exists():
        raise ImageError(f"Image not found: {path}")
    if path.is_dir():
        raise ImageError(f"{path} is a folder — point to the image file itself "
                         "(the .E01, .vmdk, .vhdx or raw file).")

    from dissect.target import Target

    # dissect reports every plugin it cannot load at WARNING; on an image
    # that is mostly noise about artefacts the disk simply does not have.
    logging.getLogger("dissect").setLevel(logging.ERROR)
    try:
        target = Target.open(str(path))
    except Exception as exc:  # noqa: BLE001 — dissect raises many types
        raise ImageError(f"Could not open {path.name}: {exc}") from exc

    if (target.os or "").lower() != "windows":
        raise ImageError(
            f"No Windows installation found in {path.name} "
            f"(detected: {target.os or 'nothing'}). Check that the image "
            "contains the system volume, not only a data partition."
        )
    return target


def _safe(callable_, default=None):
    try:
        value = callable_()
    except Exception:  # noqa: BLE001
        return default
    return default if value is None else value


def _iso(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).isoformat()
    return str(value)


def _filetime(raw: bytes, offset: int) -> str:
    if len(raw) < offset + 8:
        return ""
    ticks = struct.unpack_from("<Q", raw, offset)[0]
    if ticks in (0, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
        return ""
    try:
        moment = datetime.fromtimestamp(ticks / 10_000_000 - 11644473600, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    return moment.isoformat()


def _reg_value(target, key: str, name: str):
    return _safe(lambda: target.registry.value(key, name).value)


# =========================================================================
# Identity
# =========================================================================
CURRENT_VERSION = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def describe_host(target, image: Path) -> dict:
    """The same fields `systeminfo` gives on a live host, read from the hives."""
    build = _reg_value(target, CURRENT_VERSION, "CurrentBuild") or ""
    display = _reg_value(target, CURRENT_VERSION, "DisplayVersion") or ""
    product = _reg_value(target, CURRENT_VERSION, "ProductName") or ""
    major = _reg_value(target, CURRENT_VERSION, "CurrentMajorVersionNumber")
    minor = _reg_value(target, CURRENT_VERSION, "CurrentMinorVersionNumber")
    version = f"{major}.{minor}.{build}" if major is not None else str(build)

    domain = (_reg_value(target, r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                         "Domain")
              or _reg_value(target, r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                            "NV Domain") or "")
    timezone_name = _reg_value(target, r"HKLM\SYSTEM\CurrentControlSet\Control"
                                       r"\TimeZoneInformation", "TimeZoneKeyName") or ""

    return {
        "hostname": _safe(lambda: target.hostname, "") or "",
        "os_name": product,
        "os_version": f"{version}{' (' + display + ')' if display else ''}",
        "install_date": _iso(_safe(lambda: target.install_date)),
        "boot_time": "",
        "manufacturer": "",
        "model": f"Disk image · {describe_format(image)}",
        "domain": domain or "WORKGROUP",
        "logon_server": "",
        "timezone": timezone_name,
        "hotfix_count": "",
    }


# =========================================================================
# Accounts, read straight from the SAM hive
# =========================================================================
SAM_ACCOUNT = r"HKLM\SAM\SAM\Domains\Account"
ADMINISTRATORS_ALIAS = r"HKLM\SAM\SAM\Domains\Builtin\Aliases\00000220"


def _parse_sid(raw: bytes, offset: int) -> tuple[str, int]:
    revision, count = raw[offset], raw[offset + 1]
    authority = int.from_bytes(raw[offset + 2:offset + 8], "big")
    subs = struct.unpack_from(f"<{count}I", raw, offset + 8)
    return f"S-{revision}-{authority}" + "".join(f"-{s}" for s in subs), 8 + 4 * count


def machine_sid(target) -> str:
    """The machine SID closes the account domain's V value."""
    raw = _reg_value(target, SAM_ACCOUNT, "V")
    if not isinstance(raw, bytes) or len(raw) < 12:
        return ""
    parts = struct.unpack_from("<III", raw, len(raw) - 12)
    if not any(parts):
        return ""
    return "S-1-5-21-" + "-".join(str(p) for p in parts)


def _administrator_sids(target) -> list[str]:
    raw = _reg_value(target, ADMINISTRATORS_ALIAS, "C")
    if not isinstance(raw, bytes) or len(raw) < 0x34:
        return []
    offset = struct.unpack_from("<I", raw, 0x28)[0] + 0x34
    count = struct.unpack_from("<I", raw, 0x30)[0]
    members = []
    for _ in range(min(count, 512)):
        if offset + 8 > len(raw):
            break
        try:
            sid, length = _parse_sid(raw, offset)
        except (IndexError, struct.error):
            break
        members.append(sid)
        offset += length
    return members


# Domain groups commonly nested into the local Administrators group.
WELL_KNOWN_DOMAIN_RIDS = {
    512: "Domain Admins", 513: "Domain Users", 518: "Schema Admins",
    519: "Enterprise Admins", 520: "Group Policy Creator Owners",
}


def read_accounts(target) -> list[dict]:
    """Local accounts with the same shape as the live `parse_users`."""
    machine = machine_sid(target)
    admin_sids = _administrator_sids(target)
    admin_rids = {int(sid.rsplit("-", 1)[1]) for sid in admin_sids
                  if machine and sid.startswith(machine + "-")}

    names = _safe(lambda: target.registry.key(SAM_ACCOUNT + r"\Users\Names"))
    accounts: list[dict] = []
    for entry in (_safe(lambda: list(names.subkeys()), []) if names else []):
        values = _safe(lambda: list(entry.values()), [])
        if not values:
            continue
        rid = int(values[0].type)
        f_value = _reg_value(target, SAM_ACCOUNT + rf"\Users\{rid:08X}", "F") or b""
        flags_word = struct.unpack_from("<H", f_value, 0x38)[0] if len(f_value) >= 0x3A else 0
        disabled = bool(flags_word & 0x0001)
        last_logon = _filetime(f_value, 0x08)
        password_set = _filetime(f_value, 0x18)

        account = {
            "name": entry.name,
            "enabled": not disabled,
            "admin": rid in admin_rids,
            "last_logon": last_logon,
            "created": password_set,
            "sid": f"{machine}-{rid}" if machine else f"RID {rid}",
            "description": "",
            "flags": [],
        }
        if rid == 500:
            account["flags"].append("built-in administrator account")
        if account["admin"] and rid != 500:
            account["flags"].append("member of the Administrators group")
        if rid == 501 and not disabled:
            account["flags"].append("Guest account enabled")
        if not last_logon:
            account["flags"].append("never logged on")
        accounts.append(account)

    known = {a["sid"] for a in accounts}
    for sid in admin_sids:
        if sid in known or (machine and sid.startswith(machine + "-")):
            continue
        rid = int(sid.rsplit("-", 1)[1]) if sid.rsplit("-", 1)[-1].isdigit() else 0
        label = WELL_KNOWN_DOMAIN_RIDS.get(rid) if sid.startswith("S-1-5-21-") else None
        accounts.append({
            "name": label or sid, "enabled": None, "admin": True, "last_logon": "",
            "created": "", "sid": sid, "description": "",
            "flags": ["non-local administrator (domain)"],
        })

    accounts.sort(key=lambda a: (not a["admin"], a["name"].lower()))
    return accounts


# =========================================================================
# Persistence: what starts on its own
# =========================================================================
SUSPICIOUS_LOCATION = re.compile(
    r"\\(users\\public|programdata|windows\\temp|appdata\\local\\temp|"
    r"appdata\\roaming|perflogs|temp)\\|\\downloads\\",
    re.I,
)
SCRIPT_HOSTS = re.compile(
    r"(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin)\.exe",
    re.I,
)
SYSTEM_PATH = re.compile(
    r"^(\"?)(%?systemroot%?|%windir%|c:\\windows|\\systemroot|system32|"
    r"c:\\program files)", re.I,
)


def _assess_command(command: str) -> list[str]:
    reasons = []
    if SUSPICIOUS_LOCATION.search(command):
        reasons.append("runs from a user-writable location")
    if SCRIPT_HOSTS.search(command):
        reasons.append("launches a script host or LOLBin")
    return reasons


def read_autoruns(target) -> list[dict]:
    """Run keys and auto-start services, flagged when they look planted."""
    entries: list[dict] = []

    for record in _safe(lambda: list(target.runkeys()), []):
        command = str(getattr(record, "command", "") or "")
        command = re.sub(r"^\(executable='(.*?)', args=\[(.*)\]\)$",
                         lambda m: m.group(1) + (" " + m.group(2).replace("'", "")
                                                 .replace(", ", " ") if m.group(2) else ""),
                         command)
        reasons = _assess_command(command)
        entries.append({
            "kind": "run key", "name": str(record.name), "command": command,
            "location": str(getattr(record, "key", "")),
            "user": str(getattr(record, "username", "") or ""),
            "flags": reasons, "risk": "high" if reasons else "normal",
        })

    for record in _safe(lambda: list(target.services()), []):
        start = str(getattr(record, "start", ""))
        image = str(getattr(record, "imagepath", "") or "")
        if "auto" not in start.lower() or not image:
            continue
        reasons = _assess_command(image)
        if not reasons and SYSTEM_PATH.search(image.strip()):
            continue
        if not reasons:
            reasons.append("auto-start service outside Windows and Program Files")
        entries.append({
            "kind": "service", "name": str(record.name), "command": image,
            "location": str(getattr(record, "displayname", "") or ""),
            "user": "", "flags": reasons, "risk": "high" if len(reasons) > 1
            or "user-writable" in reasons[0] else "medium",
        })

    order = {"high": 0, "medium": 1, "normal": 2}
    entries.sort(key=lambda e: (order[e["risk"]], e["kind"], e["name"].lower()))
    return entries


# =========================================================================
# Disk root
# =========================================================================
def root_listing(target) -> list[dict]:
    """Entries at the root of the system volume, with their NTFS birth time."""
    root = target.fs.path("sysvol/")
    listing = []
    for child in _safe(lambda: list(root.iterdir()), []):
        stat = _safe(lambda c=child: c.lstat())
        born = getattr(stat, "st_birthtime", None) or getattr(stat, "st_ctime", None)
        listing.append({
            "name": child.name,
            "is_dir": _safe(child.is_dir, False),
            "created": float(born) if born else None,
        })
    return listing


# =========================================================================
# Extraction
# =========================================================================
def _sha256_stream(handle) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _copy(source, destination: Path) -> tuple[str, int]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest, size = hashlib.sha256(), 0
    with source.open("rb") as reader, open(destination, "wb") as writer:
        for chunk in iter(lambda: reader.read(1024 * 1024), b""):
            writer.write(chunk)
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _relative(path) -> str:
    text = str(path).replace("\\", "/")
    for prefix in ("sysvol/", "/sysvol/"):
        if text.lower().startswith(prefix):
            text = text[len(prefix):]
    return text.lstrip("/")


def _windows_path(relative: str) -> str:
    return "C:\\" + relative.replace("/", "\\")


def _walk(path, depth: int = 0):
    if depth > MAX_DEPTH:
        return
    for child in _safe(lambda: list(path.iterdir()), []):
        if _safe(child.is_symlink, False):
            continue
        if _safe(child.is_dir, False):
            yield from _walk(child, depth + 1)
        elif _safe(child.is_file, False):
            yield child


def _expand(target, pattern: str):
    parts = PurePosixPath(pattern).parts
    paths = [target.fs.path("sysvol")]
    for part in parts:
        nxt = []
        for base in paths:
            if part == "*":
                nxt.extend(c for c in _safe(lambda b=base: list(b.iterdir()), [])
                           if _safe(c.is_dir, False))
            else:
                match = next((c for c in _safe(lambda b=base: list(b.iterdir()), [])
                              if c.name.lower() == part.lower()), None)
                if match is not None:
                    nxt.append(match)
        paths = nxt
    return paths


def extract(target, destination: Path, files_budget_mb: int = 1024,
            extra_roots: list[str] | None = None,
            progress: Progress | None = None) -> dict:
    """Pull logs, hives and executable content out of the image.

    Returns a manifest: every extracted file with its path in the image, its
    size and its SHA-256, so the extraction itself can be verified later.
    """
    say = progress or (lambda message, level="info": None)
    destination.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []
    counts = {"logs": 0, "hives": 0, "prefetch": 0, "files": 0, "skipped": 0}

    def take(source, relative_dest: str, category: str) -> None:
        digest, size = _copy(source, destination / relative_dest)
        stat = _safe(source.lstat)
        manifest.append({
            "category": category,
            "image_path": _windows_path(_relative(source)),
            "extracted_to": relative_dest.replace("\\", "/"),
            "size": size,
            "sha256": digest,
            "modified": _iso(datetime.fromtimestamp(stat.st_mtime, timezone.utc))
            if stat else "",
        })

    # -- event logs: what Hayabusa needs
    logs = target.fs.path("sysvol/Windows/System32/winevt/Logs")
    for evtx in sorted(_safe(lambda: list(logs.iterdir()), []), key=lambda p: p.name.lower()):
        if evtx.name.lower().endswith(".evtx") and _safe(evtx.is_file, False):
            take(evtx, f"Logs/{evtx.name}", "event log")
            counts["logs"] += 1
    say(f"{counts['logs']} event log(s) extracted.", "ok" if counts["logs"] else "warn")

    # -- registry: system hives, then one NTUSER.DAT per profile
    config = target.fs.path("sysvol/Windows/System32/config")
    for hive in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"):
        source = config.joinpath(hive)
        if _safe(source.is_file, False):
            take(source, f"Registry/{hive}", "registry hive")
            counts["hives"] += 1
    amcache = target.fs.path("sysvol/Windows/AppCompat/Programs/Amcache.hve")
    if _safe(amcache.is_file, False):
        take(amcache, "Registry/Amcache.hve", "registry hive")
        counts["hives"] += 1
    for profile in _expand(target, "Users/*"):
        ntuser = profile.joinpath("NTUSER.DAT")
        if _safe(ntuser.is_file, False):
            take(ntuser, f"Registry/Users/{profile.name}/NTUSER.DAT", "registry hive")
            counts["hives"] += 1
    say(f"{counts['hives']} registry hive(s) extracted.", "ok")

    # -- prefetch: small, and proof of execution
    prefetch = target.fs.path("sysvol/Windows/Prefetch")
    for item in _safe(lambda: list(prefetch.iterdir()), []):
        if item.name.lower().endswith(".pf") and _safe(item.is_file, False):
            take(item, f"Prefetch/{item.name}", "prefetch")
            counts["prefetch"] += 1

    # -- executable content from where payloads land, for the YARA scan
    budget = max(0, files_budget_mb) * 1024 * 1024
    spent = 0
    seen: set[str] = set()
    patterns = list(HOT_LOCATIONS) + [r for r in (extra_roots or [])]
    for pattern in patterns:
        for base in _expand(target, pattern):
            for item in _walk(base):
                key = str(item).lower()
                if key in seen or PurePosixPath(item.name).suffix.lower() not in EXECUTABLE_SUFFIXES:
                    continue
                seen.add(key)
                size = getattr(_safe(item.lstat), "st_size", 0) or 0
                if (size > MAX_FILE_BYTES or spent + size > budget
                        or counts["files"] >= MAX_FILES):
                    counts["skipped"] += 1
                    continue
                take(item, f"Files/{_relative(item)}", "file")
                counts["files"] += 1
                spent += size
    say(f"{counts['files']} executable file(s) extracted for the YARA scan "
        f"({spent // 1024} KB)"
        + (f", {counts['skipped']} skipped over the size budget." if counts["skipped"] else "."),
        "ok" if counts["files"] else "info")

    return {"counts": counts, "bytes": spent, "manifest": manifest}


def image_fingerprint(path: Path, full: bool = False) -> dict:
    """Identify the image container without necessarily hashing all of it.

    A full SHA-256 of a 500 GB image takes most of an hour, so by default only
    the size and the hash of the first segment's first 64 MB are recorded —
    enough to tell two images apart. EWF images carry their own acquisition
    hash; `ewfverify` is the right tool to check it.
    """
    path = Path(path)
    stat = path.stat()
    with open(path, "rb") as handle:
        if full:
            digest, read = _sha256_stream(handle)
        else:
            sample = handle.read(64 * 1024 * 1024)
            digest, read = hashlib.sha256(sample).hexdigest(), len(sample)
    segments = sorted(p.name for p in path.parent.glob(path.stem + ".*")
                      if re.fullmatch(r"\.(e|s|ex)\d{2}|\.\d{3}", p.suffix.lower()))
    return {
        "path": str(path),
        "format": describe_format(path),
        "size": stat.st_size,
        "segments": segments or [path.name],
        "sha256": digest,
        "sha256_scope": "full file" if full or read == stat.st_size
        else f"first {read // (1024 * 1024)} MB",
    }


def write_manifest(result: dict, fingerprint: dict, host: dict, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps({
        "image": fingerprint,
        "host": host,
        "counts": result["counts"],
        "files": result["manifest"],
    }, indent=2), encoding="utf-8")
    return destination
