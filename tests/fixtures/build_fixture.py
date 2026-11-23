"""Build the dead-disk test fixture: a small Windows disk in E01, VMDK and VHDX.

Everything inside the image is authored here — registry hives, folder tree,
placeholder files — so the fixture carries no third-party data. The event logs
are placeholders with a valid EVTX signature: the image tests check that Kage
finds, extracts and hashes them, not what Hayabusa makes of them.

Requires Linux with ntfs-3g (mkntfs + FUSE), qemu-img and ewfacquire. The
committed images are the output; rebuild only when the fixture must change:

    python tests/fixtures/build_fixture.py
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
SECTOR = 512
PARTITION_START = 2048            # 1 MiB, as Windows aligns it
VOLUME_SIZE = 40 * 1024 * 1024


# =========================================================================
# Minimal regf writer
# =========================================================================
# Just enough of the Windows registry hive format for dissect to read keys
# and values: base block, one hive bin, nk/vk/lh/sk cells, value lists.

REG_SZ, REG_BINARY, REG_DWORD = 1, 3, 4


def _filetime(epoch: float) -> int:
    return int((epoch + 11644473600) * 10_000_000)


@dataclass
class Key:
    name: str
    values: list[tuple[str, int, bytes]] = field(default_factory=list)
    subkeys: dict[str, "Key"] = field(default_factory=dict)

    def path(self, *parts: str) -> "Key":
        node = self
        for part in parts:
            node = node.subkeys.setdefault(part.lower(), Key(part))
        return node

    def string(self, name: str, text: str) -> "Key":
        self.values.append((name, REG_SZ, (text + "\0").encode("utf-16-le")))
        return self

    def dword(self, name: str, number: int) -> "Key":
        self.values.append((name, REG_DWORD, struct.pack("<I", number)))
        return self

    def binary(self, name: str, data: bytes) -> "Key":
        self.values.append((name, REG_BINARY, data))
        return self

    def typed(self, name: str, value_type: int, data: bytes = b"") -> "Key":
        """SAM\\...\\Names subkeys store the RID as the value *type*."""
        self.values.append((name, value_type, data))
        return self


def _lh_hash(name: str) -> int:
    value = 0
    for char in name.upper():
        value = (value * 37 + ord(char)) & 0xFFFFFFFF
    return value


def write_hive(root: Key, destination: Path, label: str) -> None:
    cells = bytearray(b"\0" * 32)          # hbin header, patched at the end
    now = _filetime(time.time())

    def allocate(payload: bytes) -> int:
        size = len(payload) + 4
        size += (-size) % 8
        offset = len(cells)
        cells.extend(struct.pack("<i", -size) + payload + b"\0" * (size - 4 - len(payload)))
        return offset

    # One shared security cell: flink/blink point back to itself.
    descriptor = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 0)
    sk_offset = len(cells)
    allocate(b"sk" + struct.pack("<HIIII", 0, sk_offset, sk_offset, 1, len(descriptor))
             + descriptor)

    def emit(key: Key, parent: int, is_root: bool) -> int:
        name = key.name.encode("ascii")
        header_size = 0x4C
        nk_offset = allocate(b"\0" * (header_size + len(name)))

        value_offsets = []
        for value_name, value_type, data in key.values:
            vname = value_name.encode("ascii")
            if len(data) <= 4:
                size_field = len(data) | 0x80000000
                data_field = struct.unpack("<I", data.ljust(4, b"\0"))[0]
            else:
                size_field = len(data)
                data_field = allocate(data)
            value_offsets.append(allocate(
                b"vk" + struct.pack("<HIIIHH", len(vname), size_field, data_field,
                                    value_type, 1, 0) + vname))
        values_list = (allocate(b"".join(struct.pack("<I", o) for o in value_offsets))
                       if value_offsets else 0xFFFFFFFF)

        children = sorted(key.subkeys.values(), key=lambda k: k.name.upper())
        child_offsets = [emit(child, nk_offset, False) for child in children]
        subkey_list = 0xFFFFFFFF
        if child_offsets:
            body = b"".join(struct.pack("<II", off, _lh_hash(child.name))
                            for off, child in zip(child_offsets, children))
            subkey_list = allocate(b"lh" + struct.pack("<H", len(children)) + body)

        flags = 0x20 | (0x04 | 0x08 if is_root else 0)
        record = (b"nk" + struct.pack(
            "<HQIIIIIIIIIIIIIIIHH",
            flags, now, 0, parent if not is_root else 0xFFFFFFFF,
            len(children), 0, subkey_list, 0xFFFFFFFF,
            len(key.values), values_list, sk_offset, 0xFFFFFFFF,
            max((len(c.name) * 2 for c in children), default=0), 0,
            max((len(v[0]) * 2 for v in key.values), default=0),
            max((len(v[2]) for v in key.values), default=0),
            0, len(name), 0) + name)
        start = nk_offset + 4
        cells[start:start + len(record)] = record
        return nk_offset

    root_offset = emit(root, 0, True)

    # Pad the bin to a 4 KiB multiple with one free cell.
    remainder = (-len(cells)) % 4096
    if remainder:
        if remainder < 8:
            remainder += 4096
        cells.extend(struct.pack("<i", remainder) + b"\0" * (remainder - 4))
    cells[0:32] = b"hbin" + struct.pack("<IIQQI", 0, len(cells), 0, now, 0)

    base = bytearray(4096)
    struct.pack_into("<4sIIQIIIIIII", base, 0, b"regf", 1, 1, now, 1, 5, 0, 1,
                     root_offset, len(cells), 1)
    base[0x30:0x30 + 64] = label.encode("utf-16-le")[:64].ljust(64, b"\0")
    checksum = 0
    for (dword,) in struct.iter_unpack("<I", bytes(base[:0x1FC])):
        checksum ^= dword
    checksum = {0: 1, 0xFFFFFFFF: 0xFFFFFFFE}.get(checksum, checksum)
    struct.pack_into("<I", base, 0x1FC, checksum)

    destination.write_bytes(bytes(base) + bytes(cells))


# =========================================================================
# Fixture content
# =========================================================================
DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"
HOSTNAME = "WS-FINANCE-07"
DOMAIN_ADMINS = "S-1-5-21-3623811015-3361044348-30300820-512"
INSTALLED = 1735689600            # 2025-01-01 00:00:00 UTC
LAST_LOGON = 1767225600           # 2026-01-01 00:00:00 UTC

# name, rid, disabled, last logon, member of Administrators
ACCOUNTS = [
    ("Administrator", 500, True, 0, True),
    ("Guest", 501, True, 0, False),
    ("j.martel", 1001, False, LAST_LOGON, False),
    ("svc_backup", 1003, False, 0, True),
]


def _sid_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    authority, subs = int(parts[2]), [int(p) for p in parts[3:]]
    return (struct.pack("<BB", 1, len(subs)) + authority.to_bytes(6, "big")
            + b"".join(struct.pack("<I", s) for s in subs))


def _sam_f(disabled: bool, last_logon: int) -> bytes:
    """The fixed-length F value: last logon at 0x08, ACB flags at 0x38."""
    data = bytearray(0x50)
    struct.pack_into("<H", data, 0, 2)
    if last_logon:
        struct.pack_into("<Q", data, 0x08, _filetime(last_logon))
    struct.pack_into("<I", data, 0x30, 0)
    struct.pack_into("<H", data, 0x38, 0x0011 if disabled else 0x0010)
    return bytes(data)


def _alias_c(members: list[str]) -> bytes:
    """Builtin alias C value: header, then member SIDs at 0x34 + offset."""
    sids = b"".join(_sid_bytes(s) for s in members)
    header = bytearray(0x34)
    struct.pack_into("<I", header, 0x28, 0)            # members offset
    struct.pack_into("<I", header, 0x30, len(members))  # member count
    return bytes(header) + sids


def build_hives(config: Path) -> None:
    system = Key("ROOT")
    system.path("Select").dword("Current", 1).dword("Default", 1)
    control = system.path("ControlSet001", "Control")
    control.path("ComputerName", "ComputerName").string("ComputerName", HOSTNAME)
    control.path("TimeZoneInformation").string("TimeZoneKeyName", "W. Europe Standard Time")
    services = system.path("ControlSet001", "Services")
    services.path("Tcpip", "Parameters").string("Domain", "acme.local") \
        .string("Hostname", HOSTNAME.lower())
    services.path("EventLog").dword("Start", 2)
    # A service whose binary lives in ProgramData: the kind of persistence a
    # dead-disk triage has to surface without any live system to ask.
    services.path("WinUpdaterSvc").string("ImagePath", r"C:\ProgramData\updater\svc.exe") \
        .dword("Start", 2).dword("Type", 0x10).string("DisplayName", "Windows Updater")
    write_hive(system, config / "SYSTEM", "SYSTEM")

    software = Key("ROOT")
    current = software.path("Microsoft", "Windows NT", "CurrentVersion")
    current.string("ProductName", "Windows 10 Pro").string("CurrentBuild", "19045") \
        .string("CurrentBuildNumber", "19045").string("DisplayVersion", "22H2") \
        .string("CurrentVersion", "6.3").dword("CurrentMajorVersionNumber", 10) \
        .dword("CurrentMinorVersionNumber", 0).dword("InstallDate", INSTALLED) \
        .string("RegisteredOwner", "ACME").string("EditionID", "Professional")
    profiles = current.path("ProfileList")
    profiles.path("S-1-5-18").string("ProfileImagePath", r"%systemroot%\system32\config\systemprofile")
    for name, rid, _disabled, _logon, _admin in ACCOUNTS:
        if name in ("Guest",):
            continue
        profiles.path(f"{DOMAIN_SID}-{rid}").string("ProfileImagePath", rf"C:\Users\{name}")
    run = software.path("Microsoft", "Windows", "CurrentVersion", "Run")
    run.string("SecurityHealth", r"%windir%\system32\SecurityHealthSystray.exe")
    run.string("Updater", r"C:\Users\Public\update.exe -silent")
    write_hive(software, config / "SOFTWARE", "SOFTWARE")

    sam = Key("ROOT")
    account = sam.path("SAM", "Domains", "Account")
    # The machine SID's three sub-authorities close the account domain's V.
    machine = [int(x) for x in DOMAIN_SID.split("-")[4:]]
    account.binary("V", b"\0" * 0x40 + struct.pack("<III", *machine))
    users = account.path("Users")
    for name, rid, disabled, logon, _admin in ACCOUNTS:
        users.path("Names", name).typed("", rid)
        users.path(f"{rid:08X}").binary("F", _sam_f(disabled, logon)) \
            .binary("V", b"\0" * 0xCC)
    admins = [f"{DOMAIN_SID}-{rid}" for _n, rid, _d, _l, admin in ACCOUNTS if admin]
    admins.append(DOMAIN_ADMINS)      # a domain group, not a local account
    sam.path("SAM", "Domains", "Builtin", "Aliases", "00000220").binary("C", _alias_c(admins))
    write_hive(sam, config / "SAM", "SAM")

    write_hive(Key("ROOT"), config / "SECURITY", "SECURITY")


def _evtx(size: int, records: int = 0) -> bytes:
    """An EVTX placeholder: valid file header and, when `records` is set, one
    chunk header declaring that many records — enough for Kage to count them,
    no event content."""
    header = bytearray(4096)
    header[0:8] = b"ElfFile\0"
    struct.pack_into("<HHH", header, 0x24, 0x80, 1, 3)
    body = bytearray(size - 4096)
    if records:
        body[0:8] = b"ElfChnk\0"
        struct.pack_into("<QQQQ", body, 0x08, 1, records, 1, records)
    return bytes(header) + bytes(body)


def populate(mount: Path) -> None:
    for folder in ("Windows/System32/config", "Windows/System32/winevt/Logs",
                   "Windows/Temp", "Windows/Prefetch", "Program Files", "Program Files (x86)",
                   "ProgramData/updater", "Users/j.martel/Downloads",
                   "Users/j.martel/AppData/Local/Temp", "Users/Public", "Users/svc_backup",
                   "Users/Administrator", "PerfLogs", "$Recycle.Bin", "Tools", "Temp"):
        (mount / folder).mkdir(parents=True, exist_ok=True)

    build_hives(mount / "Windows/System32/config")

    logs = mount / "Windows/System32/winevt/Logs"
    (logs / "Security.evtx").write_bytes(_evtx(1024 * 1024, records=4821))
    (logs / "System.evtx").write_bytes(_evtx(512 * 1024, records=1290))
    (logs / "Application.evtx").write_bytes(_evtx(256 * 1024, records=377))
    (logs / "Microsoft-Windows-PowerShell%4Operational.evtx").write_bytes(_evtx(69632))
    (logs / "Windows PowerShell.evtx").write_bytes(_evtx(256 * 1024, records=52))

    placeholder = b"MZ" + b"\0" * 62 + b"Kage dead-disk fixture placeholder\r\n"
    for path in ("Users/Public/update.exe", "ProgramData/updater/svc.exe",
                 "Users/j.martel/Downloads/invoice_2026.pdf.exe",
                 "Tools/mimi.exe"):
        (mount / path).write_bytes(placeholder)
    (mount / "Windows/Temp/stage.ps1").write_text("Write-Output 'fixture'\r\n")
    (mount / "Users/j.martel/AppData/Local/Temp/run.bat").write_text("@echo fixture\r\n")
    (mount / "Users/j.martel/Downloads/notes.txt").write_text("not collected: not executable\r\n")
    (mount / "Windows/Prefetch/UPDATE.EXE-1A2B3C4D.pf").write_bytes(b"MAM\x04" + b"\0" * 60)


def _mbr(total_sectors: int) -> bytes:
    mbr = bytearray(512)
    entry = struct.pack("<B3sB3sII", 0x00, b"\xfe\xff\xff", 0x07, b"\xfe\xff\xff",
                        PARTITION_START, total_sectors - PARTITION_START)
    mbr[0x1BE:0x1BE + 16] = entry
    struct.pack_into("<I", mbr, 0x1B8, 0x4B414745)          # disk signature "KAGE"
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr)


def build(output: Path, with_vhdx: bool = False) -> None:
    work = Path(tempfile.mkdtemp(prefix="kage-fixture-"))
    volume, disk, mount = work / "volume.ntfs", work / "disk.raw", work / "mnt"
    try:
        with open(volume, "wb") as handle:
            handle.truncate(VOLUME_SIZE)
        subprocess.run(["mkntfs", "-F", "-Q", "-q", "-L", "OS", "-p", str(PARTITION_START),
                        "-H", "255", "-S", "63", str(volume)], check=True)
        mount.mkdir()
        subprocess.run(["ntfs-3g", str(volume), str(mount)], check=True)
        try:
            populate(mount)
        finally:
            subprocess.run(["fusermount", "-u", str(mount)], check=False)
            subprocess.run(["umount", str(mount)], check=False,
                           stderr=subprocess.DEVNULL)

        total = PARTITION_START + VOLUME_SIZE // SECTOR
        with open(disk, "wb") as handle:
            handle.write(_mbr(total))
            handle.write(b"\0" * (PARTITION_START * SECTOR - SECTOR))
            handle.write(volume.read_bytes())

        output.mkdir(parents=True, exist_ok=True)
        for stale in output.glob("kage-fixture.*"):
            stale.unlink()
        subprocess.run(["ewfacquire", "-u", "-q", "-t", str(output / "kage-fixture"),
                        "-f", "encase6", "-c", "deflate:best", "-C", "KAGE-FIXTURE",
                        "-D", "Kage dead-disk test fixture", "-E", "1", "-e", "Kage",
                        "-N", "Synthetic image, no real data", str(disk)],
                       check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["qemu-img", "convert", "-q", "-f", "raw", "-O", "vmdk",
                        "-o", "subformat=streamOptimized", str(disk),
                        str(output / "kage-fixture.vmdk")], check=True)
        # VHDX stays out of the repository: even dynamic, it weighs 18 MB
        # for this 40 MB volume. The tests build one on the fly instead.
        if with_vhdx:
            subprocess.run(["qemu-img", "convert", "-q", "-f", "raw", "-O", "vhdx",
                            "-o", "subformat=dynamic,block_size=1M", str(disk),
                            str(output / "kage-fixture.vhdx")], check=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    for image in sorted(output.glob("kage-fixture.*")):
        print(f"{image.name:24} {image.stat().st_size // 1024:>6} KB")


if __name__ == "__main__":
    arguments = [a for a in sys.argv[1:] if not a.startswith("--")]
    build(Path(arguments[0]) if arguments else HERE, with_vhdx="--with-vhdx" in sys.argv)
