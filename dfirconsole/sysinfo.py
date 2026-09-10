"""System context: what the timeline does not tell you.

An EVTX triage describes what happened. It says nothing about who holds an
account on the machine, which ports are listening right now, or what suspicious
folder is sitting at the root of the disk. Those three are the first things an
analyst asks for, and read-only commands are enough to get them.

Every function here is a pure parser: text in, structures out. Running the
commands stays in the pipeline, which keeps this module testable without a
Windows box.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

# --- notoriously exposed ports --------------------------------------------
NOTABLE_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos kpasswd",
    636: "LDAPS", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5985: "WinRM", 5986: "WinRM TLS",
    5357: "WSDAPI", 8080: "HTTP alt", 8443: "HTTPS alt", 9001: "Tor", 4444: "Metasploit",
}

# Listening ports worth a comment on a workstation.
RISKY_LISTEN = {23, 21, 3389, 5985, 5986, 445, 1433, 3306, 4444, 5432}

# Processes that have no business opening a network socket.
UNEXPECTED_NETWORK_PROCESSES = re.compile(
    r"^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|"
    r"bitsadmin|notepad|calc|winword|excel|msaccess)\.exe$", re.I
)

# --- disk root -----------------------------------------------------
# Entries expected at the root of a modern Windows install. Anything else is
# worth a look: attackers love C:\Temp, C:\Intel and C:\PerfLogs.
STANDARD_ROOT = {
    "windows", "program files", "program files (x86)", "programdata", "users",
    "$recycle.bin", "system volume information", "recovery", "perflogs",
    "$winreagent", "documents and settings", "pagefile.sys", "swapfile.sys",
    "hiberfil.sys", "dumpstack.log", "dumpstack.log.tmp", "bootmgr", "bootnxt",
    "msdia80.dll", "$getcurrent", "$sysreset", "$windows.~bt", "$windows.~ws",
    "onedrivetemp", "inetpub", "config.msi", "drivers", "intel", "amd", "nvidia",
}

# Root folders that are regularly abused: present on every machine, but also
# the first destination of a dropper.
WATCHED_ROOT = {
    "temp", "tmp", "intel", "perflogs", "inetpub", "users\\public", "windows\\temp",
}

SUSPICIOUS_ROOT_HINTS = re.compile(
    r"^(tools?|scripts?|share|shared|dump|dumps|loot|exfil|payload|backdoor|"
    r"hack|pentest|redteam|ad|kali|mimikatz|priv|exp|poc|test123|new folder)$", re.I
)


# =========================================================================
# Accounts
# =========================================================================
def parse_powershell_json(text: str) -> list[dict]:
    """PowerShell returns either a single object or a list; normalise to a list."""
    text = (text or "").strip()
    start = text.find("[")
    brace = text.find("{")
    if start == -1 or (brace != -1 and brace < start):
        start = brace
    if start == -1:
        return []
    try:
        data = json.loads(text[start:])
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [data]
    return [item for item in data if isinstance(item, dict)]


def _ps_date(value) -> str:
    """PowerShell serialises dates as /Date(1735689600000)/."""
    if not value:
        return ""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat()
    match = re.search(r"/Date\((\d+)", str(value))
    if match:
        return datetime.fromtimestamp(int(match.group(1)) / 1000, timezone.utc).isoformat()
    return str(value)[:32]


def parse_users(users_json: str, admins_json: str = "") -> list[dict]:
    """Local accounts, with Administrators group membership."""
    admins = set()
    for entry in parse_powershell_json(admins_json):
        name = str(entry.get("Name") or entry.get("name") or "")
        admins.add(name.split("\\")[-1].lower())

    accounts: list[dict] = []
    for entry in parse_powershell_json(users_json):
        name = str(entry.get("Name") or entry.get("name") or "").strip()
        if not name:
            continue
        enabled = entry.get("Enabled")
        account = {
            "name": name,
            "enabled": bool(enabled) if enabled is not None else None,
            "admin": name.lower() in admins,
            "last_logon": _ps_date(entry.get("LastLogon")),
            "created": _ps_date(entry.get("PasswordLastSet") or entry.get("Created")),
            "sid": str(entry.get("SID") or entry.get("Sid") or ""),
            "description": str(entry.get("Description") or "")[:120],
            "flags": [],
        }

        # The SID ends with the RID: 500 is the built-in administrator.
        rid = account["sid"].rsplit("-", 1)[-1] if account["sid"] else ""
        if rid == "500":
            account["flags"].append("built-in administrator account")
        if account["admin"] and rid not in ("500",):
            account["flags"].append("member of the Administrators group")
        if account["enabled"] and rid == "501":
            account["flags"].append("Guest account enabled")
        if not account["last_logon"]:
            account["flags"].append("never logged on")
        accounts.append(account)

    # Administrators missing from Get-LocalUser are domain accounts.
    known = {a["name"].lower() for a in accounts}
    for admin in sorted(admins - known):
        accounts.append({
            "name": admin, "enabled": None, "admin": True, "last_logon": "",
            "created": "", "sid": "", "description": "",
            "flags": ["non-local administrator (domain)"],
        })

    accounts.sort(key=lambda a: (not a["admin"], a["name"].lower()))
    return accounts


# =========================================================================
# Network
# =========================================================================
RE_NETSTAT = re.compile(
    r"^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(?:(\w+)\s+)?(\d+)\s*$", re.I
)


def _split_endpoint(endpoint: str) -> tuple[str, int | None]:
    """Split host and port, handling bracketed IPv6."""
    endpoint = endpoint.strip()
    if endpoint.startswith("["):
        host, _, port = endpoint.rpartition("]:")
        return host.lstrip("["), int(port) if port.isdigit() else None
    host, _, port = endpoint.rpartition(":")
    return host, int(port) if port.isdigit() else None


def is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_multicast
                or addr.is_reserved or addr.is_link_local or addr.is_unspecified)


def parse_tasklist(text: str) -> dict[int, str]:
    """Map each PID to its executable, from `tasklist /fo csv`."""
    mapping: dict[int, str] = {}
    for line in (text or "").splitlines():
        parts = [p.strip('" ') for p in line.split('","')]
        if len(parts) < 2:
            continue
        name = parts[0].strip('"')
        pid = parts[1].strip('"')
        if pid.isdigit():
            mapping[int(pid)] = name
    return mapping


def parse_netstat(text: str, processes: dict[int, str] | None = None) -> list[dict]:
    """Parse `netstat -ano` and qualify every socket."""
    processes = processes or {}
    connections: list[dict] = []

    for line in (text or "").splitlines():
        match = RE_NETSTAT.match(line)
        if not match:
            continue
        proto, local, remote, state, pid = match.groups()
        local_ip, local_port = _split_endpoint(local)
        remote_ip, remote_port = _split_endpoint(remote)
        pid_value = int(pid)
        process = processes.get(pid_value, "")

        entry = {
            "proto": proto.upper(),
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": (state or "").upper() or ("LISTENING" if proto.upper() == "UDP" else ""),
            "pid": pid_value,
            "process": process,
            "service": NOTABLE_PORTS.get(local_port or -1)
                       or NOTABLE_PORTS.get(remote_port or -1) or "",
            "flags": [],
            "risk": "normal",
        }

        listening = entry["state"] in ("LISTENING", "LISTEN")
        exposed = local_ip in ("0.0.0.0", "::", "[::]", "*")

        if listening and exposed and (local_port in RISKY_LISTEN):
            entry["flags"].append(f"exposed listener on {NOTABLE_PORTS.get(local_port, local_port)}")
            entry["risk"] = "high"
        elif listening and exposed and (local_port or 0) > 1024:
            entry["flags"].append("listening on all interfaces")
            entry["risk"] = "medium"

        if entry["state"] == "ESTABLISHED" and is_public_ip(remote_ip):
            entry["flags"].append("active connection to the Internet")
            entry["risk"] = "medium" if entry["risk"] == "normal" else entry["risk"]

        if process and UNEXPECTED_NETWORK_PROCESSES.match(process):
            entry["flags"].append(f"{process} should not open a socket")
            entry["risk"] = "high"

        if remote_port in (4444, 9001, 1337, 8443) and entry["state"] == "ESTABLISHED":
            entry["flags"].append(f"remote port {remote_port} is associated with offensive tooling")
            entry["risk"] = "high"

        connections.append(entry)

    order = {"high": 0, "medium": 1, "normal": 2}
    connections.sort(key=lambda c: (order[c["risk"]], -(c["local_port"] or 0)))
    return connections


def network_summary(connections: list[dict]) -> dict:
    listening = [c for c in connections if c["state"] in ("LISTENING", "LISTEN")]
    established = [c for c in connections if c["state"] == "ESTABLISHED"]
    return {
        "total": len(connections),
        "listening": len(listening),
        "established": len(established),
        "public_peers": sorted({c["remote_ip"] for c in established
                                if is_public_ip(c["remote_ip"])}),
        "flagged": len([c for c in connections if c["risk"] != "normal"]),
    }


# =========================================================================
# Disk root
# =========================================================================
def analyse_root(root: Path, recent_days: int = 30) -> list[dict]:
    """Spot what has no business at the root of the system drive."""
    entries: list[dict] = []
    if not root.exists():
        return entries

    now = datetime.now(timezone.utc).timestamp()
    try:
        children = list(root.iterdir())
    except (OSError, PermissionError):
        return entries

    for child in children:
        name = child.name
        lowered = name.lower()
        try:
            stat = child.stat()
            created = datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat()
            age_days = (now - stat.st_ctime) / 86400
        except (OSError, PermissionError):
            created, age_days = "", 9999

        flags: list[str] = []
        risk = "normal"

        if lowered not in STANDARD_ROOT:
            flags.append("non-standard entry at the disk root")
            risk = "medium"
        if lowered in WATCHED_ROOT:
            flags.append("frequently abused location")
            risk = "medium" if risk == "normal" else risk
        if SUSPICIOUS_ROOT_HINTS.match(lowered):
            flags.append("name suggests tooling or a temporary drop")
            risk = "high"
        if name.startswith(".") or name != name.strip():
            flags.append("hidden name or stray whitespace")
            risk = "high"
        if age_days < recent_days and lowered not in STANDARD_ROOT:
            flags.append(f"created {age_days:.0f} day(s) ago")
            risk = "high"

        if not flags:
            continue

        entries.append({
            "name": name,
            "path": str(child),
            "kind": "folder" if child.is_dir() else "file",
            "created": created,
            "age_days": round(age_days, 1) if age_days < 9999 else None,
            "flags": flags,
            "risk": risk,
        })

    order = {"high": 0, "medium": 1, "normal": 2}
    entries.sort(key=lambda e: (order[e["risk"]], e["name"].lower()))
    return entries


# =========================================================================
# Host
# =========================================================================
SYSTEMINFO_FIELDS = {
    "os_name": ("Nom du système d'exploitation", "OS Name"),
    "os_version": ("Version du système", "OS Version"),
    "install_date": ("Date d'installation originale", "Original Install Date"),
    "boot_time": ("Heure de démarrage du système", "System Boot Time"),
    "manufacturer": ("Fabricant du système", "System Manufacturer"),
    "model": ("Modèle du système", "System Model"),
    "domain": ("Domaine", "Domain"),
    "logon_server": ("Serveur d'ouverture de session", "Logon Server"),
    "hostname": ("Nom de l'hôte", "Host Name"),
}


def parse_systeminfo(text: str) -> dict:
    """Extract the essentials from `systeminfo`, in English or French."""
    values: dict[str, str] = {}
    raw: dict[str, str] = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key and value:
            raw[key.lower()] = value

    for field, labels in SYSTEMINFO_FIELDS.items():
        for label in labels:
            if label.lower() in raw:
                values[field] = raw[label.lower()]
                break

    hotfixes = re.findall(r"KB\d{6,}", text or "")
    values["hotfix_count"] = str(len(set(hotfixes)))
    return values


def system_findings(context: dict) -> list[dict]:
    """Cross-cutting findings, phrased for a report."""
    findings: list[dict] = []

    for account in context.get("users", []):
        if account.get("admin") and account.get("enabled") is not False:
            findings.append({
                "level": "medium",
                "title": f"Active administrator account: {account['name']}",
                "detail": ", ".join(account.get("flags") or []) or "member of Administrators",
            })
        if "never logged on" in (account.get("flags") or []) and account.get("enabled"):
            findings.append({
                "level": "low",
                "title": f"Enabled account never used: {account['name']}",
                "detail": "a dormant but enabled account is a quiet way back in",
            })

    for connection in context.get("connections", []):
        if connection["risk"] == "high":
            findings.append({
                "level": "high",
                "title": f"{connection['proto']} {connection['local_port']} — "
                         f"{connection['process'] or 'PID ' + str(connection['pid'])}",
                "detail": " ; ".join(connection["flags"]),
            })

    for entry in context.get("root_entries", []):
        if entry["risk"] == "high":
            findings.append({
                "level": "high",
                "title": f"Suspicious {entry['kind']}: {entry['path']}",
                "detail": " ; ".join(entry["flags"]),
            })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f["level"], 9))
    return findings


# =========================================================================
# Logging and audit policy
# =========================================================================
# A triage is only worth what the machine agreed to record. Without Sysmon and
# without process-creation auditing, half the Sigma rules have nothing to chew
# on — and "nothing conclusive" stops meaning anything. So we measure what
# could have been seen, not only what was seen.
IMPORTANT_CHANNELS: list[tuple[str, str, str, str]] = [
    # (channel, EVTX file, label, importance)
    ("Security", "Security.evtx", "Security", "critical"),
    ("Microsoft-Windows-Sysmon/Operational",
     "Microsoft-Windows-Sysmon%4Operational.evtx", "Sysmon", "critical"),
    ("Microsoft-Windows-PowerShell/Operational",
     "Microsoft-Windows-PowerShell%4Operational.evtx", "PowerShell (script blocks)", "critical"),
    ("System", "System.evtx", "System", "important"),
    ("Windows PowerShell", "Windows PowerShell.evtx", "PowerShell (classic)", "important"),
    ("Microsoft-Windows-TaskScheduler/Operational",
     "Microsoft-Windows-TaskScheduler%4Operational.evtx", "Scheduled tasks", "important"),
    ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
     "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
     "RDP sessions", "important"),
    ("Microsoft-Windows-WinRM/Operational",
     "Microsoft-Windows-WinRM%4Operational.evtx", "WinRM", "important"),
    ("Microsoft-Windows-Windows Defender/Operational",
     "Microsoft-Windows-Windows Defender%4Operational.evtx", "Defender", "important"),
    ("Microsoft-Windows-WMI-Activity/Operational",
     "Microsoft-Windows-WMI-Activity%4Operational.evtx", "WMI", "important"),
    ("Application", "Application.evtx", "Application", "useful"),
    ("Microsoft-Windows-Bits-Client/Operational",
     "Microsoft-Windows-Bits-Client%4Operational.evtx", "BITS", "useful"),
    ("Microsoft-Windows-CodeIntegrity/Operational",
     "Microsoft-Windows-CodeIntegrity%4Operational.evtx", "Code integrity", "useful"),
    ("Microsoft-Windows-AppLocker/EXE and DLL",
     "Microsoft-Windows-AppLocker%4EXE and DLL.evtx", "AppLocker", "useful"),
    ("Microsoft-Windows-DNS-Client/Operational",
     "Microsoft-Windows-DNS-Client%4Operational.evtx", "DNS queries", "useful"),
    ("Microsoft-Windows-NTLM/Operational",
     "Microsoft-Windows-NTLM%4Operational.evtx", "NTLM", "useful"),
]

IMPORTANCE_WEIGHT = {"critical": 3, "important": 2, "useful": 1}

# Audit subcategories that decide how rich the Security log will be.
AUDIT_SUBCATEGORIES: list[tuple[tuple[str, ...], str, str]] = [
    (("Process Creation", "Création du processus"), "Process creation", "critical"),
    (("Logon", "Ouvrir la session"), "Logon", "critical"),
    (("Logoff", "Fermer la session"), "Logoff", "important"),
    (("Special Logon", "Ouverture de session spéciale"), "Special logon", "important"),
    (("Account Lockout", "Verrouillage du compte"), "Account lockout", "important"),
    (("Credential Validation", "Validation des informations d'identification"),
     "Credential validation", "critical"),
    (("Kerberos Authentication Service", "Service d'authentification Kerberos"),
     "Kerberos", "important"),
    (("User Account Management", "Gestion des comptes d'utilisateur"),
     "User account management", "critical"),
    (("Security Group Management", "Gestion des groupes de sécurité"),
     "Security group management", "critical"),
    (("Audit Policy Change", "Modification de la stratégie d'audit"),
     "Audit policy change", "important"),
    (("Detailed File Share", "Partage de fichiers détaillé"),
     "Detailed file share", "useful"),
    (("Registry", "Registre"), "Registry", "useful"),
    (("File System", "Système de fichiers"), "File system", "useful"),
]

AUDIT_OFF = re.compile(r"^(no auditing|aucun audit|)$", re.I)


def parse_channels(json_text: str) -> dict[str, dict]:
    """Output of `Get-WinEvent -ListLog … | ConvertTo-Json`."""
    channels: dict[str, dict] = {}
    for entry in parse_powershell_json(json_text):
        name = str(entry.get("LogName") or entry.get("logName") or "")
        if not name:
            continue
        channels[name.lower()] = {
            "enabled": bool(entry.get("IsEnabled", True)),
            "records": int(entry.get("RecordCount") or 0),
            "size": int(entry.get("FileSize") or 0),
            "max_size": int(entry.get("MaximumSizeInBytes") or 0),
            "last_write": _ps_date(entry.get("LastWriteTime")),
        }
    return channels


def evtx_inventory(logs_dir: Path | None) -> dict[str, dict]:
    """What the collection actually contains, file by file."""
    inventory: dict[str, dict] = {}
    if not logs_dir or not Path(logs_dir).is_dir():
        return inventory
    for evtx in Path(logs_dir).glob("*.evtx"):
        try:
            size = evtx.stat().st_size
        except OSError:
            size = 0
        inventory[evtx.name.lower()] = {"size": size, "path": str(evtx)}
    return inventory


def parse_auditpol(csv_text: str) -> dict[str, str]:
    """Output of `auditpol /get /category:* /r` (CSV format)."""
    settings: dict[str, str] = {}
    for line in (csv_text or "").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 5 or parts[2].lower() in ("subcategory", "sous-catégorie"):  # noqa: RUF001
            continue
        subcategory, inclusion = parts[2], parts[4]
        if subcategory:
            settings[subcategory.lower()] = inclusion
    return settings


def audit_coverage(channels: dict[str, dict], inventory: dict[str, dict],
                   audit: dict[str, str]) -> dict:
    """Assess logging state and derive a coverage score.

    Read it next to the risk score: "risk 78, coverage 35" means the verdict
    rests on a third of the available information.
    """
    rows: list[dict] = []
    obtained = possible = 0

    for channel, filename, label, importance in IMPORTANT_CHANNELS:
        weight = IMPORTANCE_WEIGHT[importance]
        possible += weight

        live = channels.get(channel.lower())
        collected = inventory.get(filename.lower())
        records = live["records"] if live else 0
        size = (live or {}).get("size") or (collected or {}).get("size") or 0
        enabled = live["enabled"] if live else None

        if live is None and collected is None:
            verdict, comment = "missing", "channel not found — no logging at all"
        elif enabled is False:
            verdict, comment = "disabled", "channel present but disabled"
        elif records == 0 and size <= 69632:
            # 68 KB is the size of an empty EVTX: present but never written to.
            verdict, comment = "empty", "channel enabled but no event recorded"
        else:
            verdict = "active"
            # The event count already has its own column. What matters here is
            # "how far back does this channel go?", which decides how deep the
            # investigation can reach.
            last = (live or {}).get("last_write", "")
            if last:
                comment = f"last written {last[:16].replace('T', ' ')}"
            elif size:
                comment = f"{size // 1024} KB collected"
            else:
                comment = "populated"
            obtained += weight

        rows.append({
            "channel": channel, "label": label, "importance": importance,
            "verdict": verdict, "comment": comment, "records": records,
            "size": size, "collected": collected is not None,
            "last_write": (live or {}).get("last_write", ""),
        })

    audit_rows: list[dict] = []
    for names, label, importance in AUDIT_SUBCATEGORIES:
        weight = IMPORTANCE_WEIGHT[importance]
        value = ""
        for name in names:
            if name.lower() in audit:
                value = audit[name.lower()]
                break
        if not audit:
            state = "unknown"
        elif AUDIT_OFF.match(value.strip()):
            state = "disabled"
        else:
            state = value.strip()
        audit_rows.append({"label": label, "importance": importance,
                           "state": state, "raw": value})
        if audit:
            possible += weight
            if state not in ("disabled", "unknown"):
                obtained += weight

    score = round(100 * obtained / possible) if possible else 0
    gaps = [r["label"] for r in rows
            if r["importance"] == "critical" and r["verdict"] != "active"]
    gaps += [r["label"] for r in audit_rows
             if r["importance"] == "critical" and r["state"] == "disabled"]

    return {
        "channels": rows,
        "audit": audit_rows,
        "score": score,
        "gaps": gaps,
        "verdict": ("solid coverage" if score >= 75 else
                    "partial coverage" if score >= 45 else
                    "weak coverage — temper the conclusions"),
    }
