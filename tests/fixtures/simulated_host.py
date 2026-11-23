"""A Windows host made of files, for the remote and live paths.

    python tests/fixtures/simulated_host.py <profile-dir> [--logs <folder of .evtx>]

The same profile answers both ways of reaching a host:

- remotely, through `dfirconsole.remote.SimulatedTransport`
  (KAGE_REMOTE_SIMULATION=<profile-dir>);
- locally, through `LocalHost.probe`, which tests patch in place of the
  console's own command runner to play a live capture on Linux.

The recorded outputs are what Windows 10 actually prints for each command,
so the parsers see exactly what they see on a real machine.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dfirconsole.remote import SimulatedTransport  # noqa: E402

HOSTNAME = "WS-FINANCE-07"

SYSTEMINFO = f"""
Host Name:                 {HOSTNAME}
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19045 N/A Build 19045
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
Original Install Date:     1/1/2025, 12:00:00 AM
System Boot Time:          11/20/2026, 8:02:11 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
Domain:                    acme.local
Logon Server:              \\\\DC01
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB5031356
                           [02]: KB5032189
                           [03]: KB5033372
"""

TASKLIST = "\n".join([
    '"System","4","Services","0","1,024 K"',
    '"svchost.exe","968","Services","0","12,000 K"',
    '"lsass.exe","704","Services","0","20,000 K"',
    '"TermService.exe","1284","Services","0","8,000 K"',
    '"update.exe","6612","Console","1","4,096 K"',
    '"chrome.exe","3320","Console","1","210,000 K"',
])

NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       968
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1284
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    10.20.4.11:52233       45.155.205.233:8443    ESTABLISHED     6612
  TCP    10.20.4.11:52251       142.250.75.238:443     ESTABLISHED     3320
  UDP    0.0.0.0:5353           *:*                                    968
"""

def _sid(value: str) -> dict:
    """ConvertTo-Json turns a SecurityIdentifier into an object, not a string."""
    domain = value.rsplit("-", 1)[0]
    return {"BinaryLength": 28, "AccountDomainSid": {"BinaryLength": 24, "Value": domain},
            "Value": value}


USERS = json.dumps([
    {"Name": "Administrator", "Enabled": False, "SID": _sid("S-1-5-21-1004336348-1177238915-682003330-500"),
     "LastLogon": None, "PasswordLastSet": "/Date(1735689600000)/", "Description": "Built-in account"},
    {"Name": "svc_backup", "Enabled": True, "SID": _sid("S-1-5-21-1004336348-1177238915-682003330-1002"),
     "LastLogon": None, "PasswordLastSet": "/Date(1763337600000)/", "Description": ""},
    {"Name": "j.martel", "Enabled": True, "SID": _sid("S-1-5-21-1004336348-1177238915-682003330-1001"),
     "LastLogon": "/Date(1767225600000)/", "PasswordLastSet": "/Date(1735689600000)/", "Description": ""},
    {"Name": "Guest", "Enabled": False, "SID": _sid("S-1-5-21-1004336348-1177238915-682003330-501"),
     "LastLogon": None, "PasswordLastSet": None, "Description": ""},
])

ADMINS = json.dumps([
    {"Name": f"{HOSTNAME}\\Administrator"}, {"Name": f"{HOSTNAME}\\svc_backup"},
    {"Name": "ACME\\Domain Admins"},
])

CHANNELS = json.dumps([
    {"LogName": "Security", "IsEnabled": True, "RecordCount": 4821, "FileSize": 1052672,
     "MaximumSizeInBytes": 20971520},
    {"LogName": "System", "IsEnabled": True, "RecordCount": 1290, "FileSize": 528384},
    {"LogName": "Application", "IsEnabled": True, "RecordCount": 377, "FileSize": 266240},
    {"LogName": "Windows PowerShell", "IsEnabled": True, "RecordCount": 52, "FileSize": 266240},
    {"LogName": "Microsoft-Windows-PowerShell/Operational", "IsEnabled": True,
     "RecordCount": 0, "FileSize": 69632},
])

AUDITPOL = "\n".join([
    "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting",
    f"{HOSTNAME},System,Logon,{{0CCE9215-69AE-11D9-BED3-505054503030}},Success and Failure,",
    f"{HOSTNAME},System,Logoff,{{0CCE9216-69AE-11D9-BED3-505054503030}},Success,",
    f"{HOSTNAME},System,Process Creation,{{0CCE922B-69AE-11D9-BED3-505054503030}},No Auditing,",
    f"{HOSTNAME},System,Special Logon,{{0CCE921B-69AE-11D9-BED3-505054503030}},Success,",
    f"{HOSTNAME},System,User Account Management,{{0CCE9235-69AE-11D9-BED3-505054503030}},Success,",
    f"{HOSTNAME},System,Credential Validation,{{0CCE923F-69AE-11D9-BED3-505054503030}},No Auditing,",
])

OSINFO = json.dumps({"install": 1735689600, "boot": 1795161731, "build": "10.0.19045",
                     "release": "22H2", "timezone": "W. Europe Standard Time"})

# Creation times at the disk root, fixed so every run sees the same ages.
ROOT_CREATED = {"Windows": 1735689600, "Users": 1735689600, "Program Files": 1735689600,
                "ProgramData": 1735689600, "PerfLogs": 1735689600,
                "Tools": 1763510400, "Temp": 1763510400}


def build_profile(destination: Path, logs: Path | None = None, hostname: str = HOSTNAME,
                  admin: bool = True) -> Path:
    """Write a profile. `logs` is a folder of .evtx files placed in the
    target's winevt\\Logs; without it, the fixture disk's placeholder logs."""
    destination = Path(destination)
    shutil.rmtree(destination, ignore_errors=True)
    commands = destination / "commands"
    commands.mkdir(parents=True)
    outputs = {"systeminfo.txt": SYSTEMINFO.replace(HOSTNAME, hostname),
               "tasklist.txt": TASKLIST, "netstat.txt": NETSTAT,
               "users.json": USERS, "admins.json": ADMINS.replace(HOSTNAME, hostname),
               "channels.json": CHANNELS, "osinfo.json": OSINFO, "auditpol.txt": AUDITPOL.replace(HOSTNAME, hostname)}
    for name, text in outputs.items():
        (commands / name).write_text(text, encoding="utf-8")
    (destination / "host.json").write_text(json.dumps({
        "hostname": hostname, "admin": admin, "os": "Microsoft Windows 10 Pro",
        "root_created": ROOT_CREATED}), encoding="utf-8")

    drive = destination / "C"
    for folder in ROOT_CREATED:
        (drive / folder).mkdir(parents=True, exist_ok=True)
    (drive / "Tools" / "mimi.exe").write_bytes(b"MZ" + b"\0" * 510)
    target_logs = drive / "Windows" / "System32" / "winevt" / "Logs"
    target_logs.mkdir(parents=True, exist_ok=True)
    if logs is not None:
        for evtx in sorted(Path(logs).glob("*.evtx")):
            shutil.copy(evtx, target_logs / evtx.name)
    (drive / "Windows" / "Temp").mkdir(parents=True, exist_ok=True)
    return destination


class LocalHost:
    """The same profile, answering as the machine the console runs on."""

    WINDOWS_COMMANDS = ("systeminfo", "tasklist", "netstat", "auditpol", "powershell")

    def __init__(self, profile: Path, fallback=None) -> None:
        self.profile = Path(profile)
        self._transport = SimulatedTransport(self.profile)
        # Anything that is not a Windows command (Hayabusa asked for its help
        # text, say) still runs for real.
        self._fallback = fallback

    async def probe(self, args: list[str], cwd=None, timeout: float = 60) -> str:
        tool = Path(str(args[0])).name.lower()
        if self._fallback is not None and not tool.startswith(self.WINDOWS_COMMANDS):
            return await self._fallback(args, cwd=cwd, timeout=timeout)
        return self._transport.run(list(args), timeout)[1]

    def root_entries(self) -> list[dict]:
        from dfirconsole import sysinfo

        listing = self._transport._root_listing()
        return sysinfo.analyse_root_entries(listing, prefix="C:\\")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("--logs", type=Path)
    parser.add_argument("--hostname", default=HOSTNAME)
    parser.add_argument("--no-admin", action="store_true")
    args = parser.parse_args()
    build_profile(args.profile, args.logs, args.hostname, admin=not args.no_admin)
    print(f"Simulated host {args.hostname} written to {args.profile}")


if __name__ == "__main__":
    main()
