"""Demonstration data set.

Two purposes: validating the chain without a Windows box at hand, and showing
the dashboard to someone before a real engagement. The simulated scenario is a
classic intrusion — malicious attachment, encoded PowerShell, Defender
neutralised, credential theft, persistence, C2, then preparation for
encryption.
"""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

HEADER = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID",
          "RecordID", "Details", "ExtraFieldInfo"]

HOST = "DESKTOP-R7K2QX1"

# EICAR test-file hash: recognised by every engine, completely harmless.
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

SCENARIO = [
    (0, "Suspicious Office Child Process", "high", "Security", "4688",
     r"ParentImage: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE | "
     r"Image: C:\Windows\System32\cmd.exe | User: CORP\j.martel"),
    (3, "PowerShell EncodedCommand Execution", "critical", "Microsoft-Windows-PowerShell/Operational", "4104",
     r"ScriptBlock: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA... | "
     "Downloads from hxxp://45.155.205.233/panel/x.ps1"),
    (4, "Remote Payload Download via PowerShell", "high", "Microsoft-Windows-PowerShell/Operational", "4104",
     r"Net.WebClient DownloadFile 45.155.205.233 -> C:\Users\j.martel\AppData\Local\Temp\svhost.exe | "
     f"SHA256={EICAR}"),
    (7, "Windows Defender Real-Time Protection Disabled", "critical", "Microsoft-Windows-Windows Defender/Operational", "5001",
     "Set-MpPreference -DisableRealtimeMonitoring $true executed by CORP\\j.martel"),
    (9, "AMSI Bypass Pattern Detected", "high", "Microsoft-Windows-PowerShell/Operational", "4104",
     "ScriptBlock contains [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"),
    (12, "LSASS Memory Access by Non-System Process", "critical", "Microsoft-Windows-Sysmon/Operational", "10",
     r"SourceImage: C:\Users\j.martel\AppData\Local\Temp\svhost.exe | TargetImage: C:\Windows\System32\lsass.exe | "
     "GrantedAccess: 0x1010 | MD5=3f2a1c9d8b7e6f5a4c3b2a1908f7e6d5"),
    (14, "Credential Dumping Tool Signature", "critical", "Microsoft-Windows-Sysmon/Operational", "1",
     r"CommandLine: svhost.exe sekurlsa::logonpasswords | Hashdump output written to C:\Windows\Temp\out.txt"),
    (18, "Scheduled Task Created for Persistence", "high", "Microsoft-Windows-TaskScheduler/Operational", "106",
     r"TaskName: \Microsoft\Windows\UpdateOrchestrator\SysHealth | "
     r"Action: C:\Users\j.martel\AppData\Roaming\svhost.exe /silent"),
    (19, "Registry Run Key Modification", "medium", "Microsoft-Windows-Sysmon/Operational", "13",
     r"TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SysHealth | "
     r"Details: C:\Users\j.martel\AppData\Roaming\svhost.exe"),
    (24, "Suspicious Outbound Connection to Rare Destination", "high", "Microsoft-Windows-Sysmon/Operational", "3",
     "DestinationIp: 185.220.101.34 | DestinationPort: 443 | Image: svhost.exe | "
     "DestinationHostname: cdn-update-delivery.xyz"),
    (26, "Beaconing Pattern Detected", "high", "Microsoft-Windows-Sysmon/Operational", "3",
     "DestinationIp: 45.155.205.233 | DestinationPort: 8443 | Interval: 60s +/- 3s | JA3 matched known C2 profile"),
    (31, "DNS Query to Newly Registered Domain", "medium", "Microsoft-Windows-Sysmon/Operational", "22",
     "QueryName: telemetry-sync-node.top | QueryResults: 185.220.101.34"),
    (35, "Local Account Created", "high", "Security", "4720",
     "TargetUserName: svc_backup1 | SubjectUserName: j.martel | New account added to Administrators"),
    (36, "User Added to Privileged Group", "critical", "Security", "4732",
     "Group: Administrators | Member: CORP\\svc_backup1"),
    (42, "Remote Service Installed", "high", "System", "7045",
     r"ServiceName: PSEXESVC | ImagePath: %SystemRoot%\PSEXESVC.exe | Target: 10.20.4.19"),
    (44, "Lateral Movement via SMB Admin Share", "high", "Security", "5145",
     r"ShareName: \\*\ADMIN$ | SourceAddress: 10.20.4.11 | Account: svc_backup1"),
    (50, "Volume Shadow Copies Deleted", "critical", "Security", "4688",
     "CommandLine: vssadmin.exe delete shadows /all /quiet | User: CORP\\svc_backup1"),
    (51, "Boot Configuration Tampering", "critical", "Security", "4688",
     "CommandLine: bcdedit /set {default} recoveryenabled No"),
    (55, "Security Event Log Cleared", "critical", "Security", "1102",
     "The audit log was cleared | SubjectUserName: svc_backup1"),
    (58, "Archive Utility Staging Large Dataset", "medium", "Microsoft-Windows-Sysmon/Operational", "1",
     r"CommandLine: 7z.exe a -pInfected C:\Windows\Temp\bkp.7z C:\Users\ | Size: 4.2GB"),
    (60, "Data Transfer to External Host", "high", "Microsoft-Windows-Sysmon/Operational", "3",
     "DestinationIp: 194.26.29.156 | DestinationPort: 21 | BytesSent: 4402653184"),
]

NOISE_RULES = [
    ("Windows Update Service Started", "informational", "System", "7036"),
    ("User Logon", "informational", "Security", "4624"),
    ("Group Policy Applied", "informational", "System", "1502"),
    ("Scheduled Task Completed", "informational", "Microsoft-Windows-TaskScheduler/Operational", "102"),
    ("Print Spooler Started", "low", "System", "7036"),
    ("Time Synchronised with Domain Controller", "informational", "System", "37"),
    ("Antivirus Signature Updated", "informational", "Microsoft-Windows-Windows Defender/Operational", "2000"),
    ("Certificate Chain Validated", "low", "Application", "1001"),
]


def build_demo_timeline(target: Path, seed: int = 7, noise: int = 420) -> Path:
    """Write a CSV in Hayabusa timeline format."""
    rng = random.Random(seed)
    base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=6)
    rows: list[list[str]] = []
    record = 41000

    for offset, rule, level, channel, event_id, details in SCENARIO:
        record += rng.randint(3, 40)
        ts = base + timedelta(minutes=offset, seconds=rng.randint(0, 55))
        rows.append([ts.isoformat(), rule, level, HOST, channel, event_id,
                     str(record), details, "OriginalFileName: svhost.exe"])

    for _ in range(noise):
        rule, level, channel, event_id = rng.choice(NOISE_RULES)
        record += rng.randint(1, 25)
        ts = base + timedelta(minutes=rng.randint(-90, 70), seconds=rng.randint(0, 59))
        rows.append([ts.isoformat(), rule, level, HOST, channel, event_id, str(record),
                     f"Routine event | Provider: Microsoft-Windows-{channel.split('/')[0]}", ""])

    rows.sort(key=lambda r: r[0])
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(HEADER)
        writer.writerows(rows)
    return target


def build_demo_evidence(settings, log: Callable[..., None]) -> Path:
    """Recreate the tree a real collection produces, without the artefacts."""
    root = settings.evidence_dir / HOST
    structure = ["Logs", "Registry", "Prefetch", "Browsers", "MFT", "Network"]
    for name in structure:
        (root / name).mkdir(parents=True, exist_ok=True)
    for evtx in ("Security.evtx", "System.evtx", "Microsoft-Windows-Sysmon%4Operational.evtx",
                 "Microsoft-Windows-PowerShell%4Operational.evtx"):
        placeholder = root / "Logs" / evtx
        if not placeholder.exists():
            placeholder.write_bytes(b"ElfFile\x00" + b"\x00" * 512)
    log(f"Simulated collection: {root} ({len(structure)} categories)", level="ok", step="collect")
    return root / "Logs"


# --- demonstration system context -----------------------------------------
def demo_system() -> dict:
    """Reproduce a believable Windows snapshot for the scenario host."""
    from . import sysinfo

    netstat = """
  Proto  Adresse locale         Adresse distante       État            PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       968
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1284
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       4200
  TCP    10.20.4.11:52233       45.155.205.233:8443    ESTABLISHED     6612
  TCP    10.20.4.11:52240       185.220.101.34:443     ESTABLISHED     6612
  TCP    10.20.4.11:52251       142.250.75.238:443     ESTABLISHED     3320
  TCP    10.20.4.11:52260       10.20.4.19:445         ESTABLISHED     4
  TCP    127.0.0.1:8787         0.0.0.0:0              LISTENING       9100
  UDP    0.0.0.0:5353           *:*                                    1500
"""
    tasks = (
        '"svchost.exe","968","Services","0","12 000 K"\n'
        '"System","4","Services","0","1 000 K"\n'
        '"TermService.exe","1284","Services","0","8 000 K"\n'
        '"lsass.exe","4200","Services","0","20 000 K"\n'
        '"powershell.exe","6612","Console","1","54 000 K"\n'
        '"chrome.exe","3320","Console","1","210 000 K"\n'
        '"python.exe","9100","Console","1","40 000 K"\n'
        '"dns.exe","1500","Services","0","6 000 K"'
    )
    connections = sysinfo.parse_netstat(netstat, sysinfo.parse_tasklist(tasks))

    users = [
        {"name": "Administrator", "enabled": True, "admin": True,
         "last_logon": "2026-08-05T08:04:00+00:00", "created": "2026-01-03T09:12:00+00:00",
         "sid": "S-1-5-21-1804630481-1004336348-1177238915-500",
         "description": "Built-in administration account",
         "flags": ["built-in administrator account"]},
        {"name": "svc_backup1", "enabled": True, "admin": True, "last_logon": "",
         "created": "2026-08-05T07:49:00+00:00",
         "sid": "S-1-5-21-1804630481-1004336348-1177238915-1050", "description": "",
         "flags": ["member of the Administrators group", "never logged on",
                   "created during the incident window"]},
        {"name": "j.martel", "enabled": True, "admin": False,
         "last_logon": "2026-08-05T06:58:00+00:00", "created": "2026-01-04T10:00:00+00:00",
         "sid": "S-1-5-21-1804630481-1004336348-1177238915-1001", "description": "",
         "flags": []},
        {"name": "Guest", "enabled": False, "admin": False, "last_logon": "",
         "created": "", "sid": "S-1-5-21-1804630481-1004336348-1177238915-501",
         "description": "", "flags": ["never logged on"]},
    ]

    root_entries = [
        {"name": "Tools", "path": "C:\\Tools", "kind": "folder",
         "created": "2026-08-05T07:12:00+00:00", "age_days": 0.2,
         "flags": ["non-standard entry at the disk root",
                   "name suggests tooling or a temporary drop",
                   "created 0 day(s) ago"], "risk": "high"},
        {"name": "Temp", "path": "C:\\Temp", "kind": "folder",
         "created": "2026-08-05T07:15:00+00:00", "age_days": 0.2,
         "flags": ["frequently abused location", "created 0 day(s) ago"],
         "risk": "high"},
        {"name": "PerfLogs", "path": "C:\\PerfLogs", "kind": "folder",
         "created": "2026-01-03T09:12:00+00:00", "age_days": 214.0,
         "flags": ["frequently abused location"], "risk": "medium"},
    ]

    context = {
        "collected_at": datetime.now(timezone.utc).timestamp(),
        "host": {
            "hostname": HOST, "os_name": "Microsoft Windows 11 Entreprise",
            "os_version": "10.0.22631", "install_date": "03/01/2026, 09:12:44",
            "boot_time": "05/08/2026, 06:02:11", "domain": "dollarcorp.local",
            "manufacturer": "innotek GmbH", "model": "VirtualBox",
            "logon_server": "\\\\DCORP-DC", "hotfix_count": "12",
        },
        "users": users,
        "connections": connections,
        "network": sysinfo.network_summary(connections),
        "root_entries": root_entries,
        "root_path": "C:\\",
    }
    import json as _json

    channels = sysinfo.parse_channels(_json.dumps([
        {"LogName": "Security", "IsEnabled": True, "RecordCount": 84213,
         "FileSize": 20971520, "MaximumSizeInBytes": 20971520},
        {"LogName": "System", "IsEnabled": True, "RecordCount": 12045, "FileSize": 4194304},
        {"LogName": "Application", "IsEnabled": True, "RecordCount": 8110, "FileSize": 3145728},
        {"LogName": "Windows PowerShell", "IsEnabled": True, "RecordCount": 1902,
         "FileSize": 1048576},
        {"LogName": "Microsoft-Windows-PowerShell/Operational", "IsEnabled": True,
         "RecordCount": 0, "FileSize": 69632},
        {"LogName": "Microsoft-Windows-WinRM/Operational", "IsEnabled": False,
         "RecordCount": 0, "FileSize": 69632},
        {"LogName": "Microsoft-Windows-TaskScheduler/Operational", "IsEnabled": True,
         "RecordCount": 4021, "FileSize": 2097152},
        {"LogName": "Microsoft-Windows-Windows Defender/Operational", "IsEnabled": True,
         "RecordCount": 615, "FileSize": 1048576},
        {"LogName": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
         "IsEnabled": True, "RecordCount": 88, "FileSize": 1048576},
    ]))
    audit = sysinfo.parse_auditpol(
        "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\n"
        f"{HOST},System,Logon,{{0}},Success and Failure,\n"
        f"{HOST},System,Logoff,{{1}},Success,\n"
        f"{HOST},System,Process Creation,{{2}},No Auditing,\n"
        f"{HOST},System,Special Logon,{{3}},Success,\n"
        f"{HOST},System,User Account Management,{{4}},Success,\n"
        f"{HOST},System,Security Group Management,{{5}},Success,\n"
        f"{HOST},System,Audit Policy Change,{{6}},Success,\n"
        f"{HOST},System,Credential Validation,{{7}},No Auditing,\n"
        f"{HOST},System,Registry,{{8}},No Auditing,\n"
        f"{HOST},System,File System,{{9}},No Auditing,\n"
    )
    context["coverage"] = sysinfo.audit_coverage(channels, {}, audit)
    context["findings"] = sysinfo.system_findings(context)
    return context
