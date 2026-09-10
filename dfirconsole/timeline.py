"""Reading and exploiting the CSV timeline produced by Hayabusa.

Hayabusa's column set depends on the output profile, so nothing is assumed:
columns are located by name with synonyms, and missing fields are tolerated.
"""

from __future__ import annotations

import csv
import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterable

LEVELS = ["critical", "high", "medium", "low", "informational"]
LEVEL_WEIGHT = {"critical": 40, "high": 15, "medium": 4, "low": 1, "informational": 0}

_COLUMNS = {
    "timestamp": ["timestamp", "datetime", "date"],
    "rule": ["ruletitle", "rule", "title"],
    "level": ["level"],
    "computer": ["computer", "hostname", "host"],
    "channel": ["channel"],
    "event_id": ["eventid", "eventidname", "id"],
    "record_id": ["recordid"],
    "details": ["details"],
    "extra": ["extrafieldinfo", "extrafield", "extra"],
}

RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_SHA256 = re.compile(r"\b[A-Fa-f0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[A-Fa-f0-9]{40}\b")
RE_MD5 = re.compile(r"\b[A-Fa-f0-9]{32}\b")
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|ru|cn|io|xyz|top|info|biz|online|site|club|pw|cc|su|tk|me|dev|shop)\b"
)
RE_PATH = re.compile(r"[A-Za-z]:\\\\?[^\s\"',;|<>]{3,120}")

# Domains that appear constantly in Windows logs. Surfacing them would drown
# the analyst in noise.
DOMAIN_ALLOWLIST = {
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
    "microsoftonline.com", "live.com", "office.com", "msn.com", "bing.com",
    "digicert.com", "verisign.com", "akamai.net", "azureedge.net",
}

# Alert families. Analysts do not read a timeline by severity but by nature:
# "show me the logons", "show me the infections". Event IDs decide when known,
# keywords take over otherwise.
CATEGORIES: list[tuple[str, str]] = [
    ("auth", "Authentication & accounts"),
    ("infection", "Infection & malware"),
    ("execution", "Execution & persistence"),
    ("network", "Network & lateral movement"),
    ("evasion", "Evasion & log tampering"),
    ("other", "Other"),
]
CATEGORY_LABELS = dict(CATEGORIES)

CATEGORY_EVENT_IDS: dict[str, str] = {}
for _cat, _ids in {
    "auth": "4624 4625 4634 4647 4648 4672 4720 4722 4723 4724 4725 4726 4728 "
            "4732 4733 4738 4740 4756 4767 4768 4769 4771 4776 4778 4779 1149",
    "infection": "1006 1007 1008 1015 1116 1117 1118 1119 5007 2001 2003 2004",
    "execution": "1 4688 4697 7045 106 140 200 201 4698 4699 4700 4702 11 12 13 "
                 "4103 4104 800 600",
    "network": "3 22 5140 5142 5145 5156 5158 21 24 25 1024",
    "evasion": "104 1102 1100 4719 4739 4907 4906 5001 5010 5012 5101 2 4658",
}.items():
    for _eid in _ids.split():
        CATEGORY_EVENT_IDS.setdefault(_eid, _cat)

CATEGORY_KEYWORDS: list[tuple[str, str]] = [
    ("auth", r"logon|login|logoff|credential|kerberos|ntlm|password|account|"
             r"brute|lockout|privileg|token|impersonat|sid history|golden|silver|"
             r"kerberoast|asrep|dcsync|lsass|mimikatz|hashdump|sam dump|ntds"),
    ("infection", r"malware|trojan|ransom|virus|backdoor|implant|payload|dropper|"
                  r"webshell|rootkit|yara|defender alert|antivirus|threat detected|"
                  r"quarantin|infected|cobalt|meterpreter|beacon|keylog"),
    ("execution", r"process creat|command line|powershell|scheduled task|service "
                  r"install|autorun|run key|startup|wmi subscription|mshta|rundll32|"
                  r"regsvr32|wscript|cscript|encoded command|script block|dll load|"
                  r"persist|image load|new service"),
    ("network", r"network connection|smb|rdp|remote desktop|psexec|wmiexec|winrm|"
                r"lateral|admin\$|share|dns query|http|https|ftp|proxy|tunnel|"
                r"c2 |beacon|exfil|upload|download|port|socket|connection to"),
    ("evasion", r"clear|delete|wipe|disable|bypass|obfuscat|amsi|etw|masquerad|"
                r"timestomp|shadow cop|vssadmin|bcdedit|wbadmin|audit polic|"
                r"tamper|unload|uninstall|hide|hidden|anti.?forensic"),
]
CATEGORY_RE = [(name, re.compile(pattern, re.I)) for name, pattern in CATEGORY_KEYWORDS]


def categorise(text: str, event_id: str = "") -> str:
    """Assign an alert to one of the families.

    The event ID is the most reliable signal; keywords are only consulted when
    it is unknown or missing.
    """
    eid = re.sub(r"\D", "", event_id or "")
    by_id = CATEGORY_EVENT_IDS.get(eid) if eid else None
    by_words = [name for name, pattern in CATEGORY_RE if pattern.search(text)]

    # Both signals agree: no ambiguity.
    if by_id and by_id in by_words:
        return by_id
    # They disagree: the text is more specific than the ID. A 4688 really is a
    # process creation, but "vssadmin delete shadows" belongs under evasion,
    # and that is where the analyst will look for it.
    if by_words:
        return by_words[0]
    if by_id:
        return by_id
    return "other"


# Keyword -> ATT&CK tactic. Deliberately readable and editable: Hayabusa does
# not always populate the MITRE field, depending on the profile.
TACTIC_KEYWORDS: list[tuple[str, str]] = [
    ("Initial Access", "phish|attachment|exploit public|drive-by|rdp brute"),
    ("Execution", "powershell|wmi|cmd|mshta|rundll32|regsvr32|wscript|cscript|encoded command|script block"),
    ("Persistence", "run key|autorun|scheduled task|service install|startup|registry persist|wmi subscription"),
    ("Privilege Escalation", "token|uac|sedebug|privilege|elevat|potato"),
    ("Defense Evasion", "clear log|disable|obfuscat|amsi|etw|bypass|delete shadow|defender|masquerad|timestomp"),
    ("Credential Access", "lsass|mimikatz|ntds|sam dump|dcsync|credential|kerberoast|hashdump"),
    ("Discovery", "whoami|net user|net group|nltest|systeminfo|enumerat|recon|arp -a"),
    ("Lateral Movement", "psexec|smbexec|wmiexec|remote service|rdp|admin\\$|pass the hash|winrm"),
    ("Collection", "archive|rar |7z |zip |screen capture|keylog|clipboard"),
    ("Command and Control", "beacon|c2|reverse shell|dns tunnel|http proxy|cobalt|meterpreter|ngrok"),
    ("Exfiltration", "exfil|upload|ftp |curl |bitsadmin|transfer"),
    ("Impact", "ransom|encrypt|vssadmin|bcdedit|wbadmin|wipe|shadow copy delete"),
]
TACTIC_RE = [(name, re.compile(pattern, re.I)) for name, pattern in TACTIC_KEYWORDS]


# Our own tooling writes to the Windows event log while it runs: THOR logs to
# Application, and scanning a folder full of offensive binaries makes Hayabusa
# flag our own scanner. Those events describe the investigation, not the
# incident, and they must not inflate the alert count.
SELF_NOISE = re.compile(
    r"thor(64)?-lite|thor\.exe|\bTHOR\b\s*:|nextron|"
    r"cylr(_win)?[-.]|hayabusa[-\w.]*\.exe|hayabusa\s+v?\d|"
    r"dfir-console|dfirconsole|Effective argument list|"
    r"MODULE:\s*(Startup|Filescan|ProcessCheck|Init)",
    re.I,
)


def is_self_noise(text: str) -> bool:
    """True when an event was produced by the triage itself."""
    return bool(SELF_NOISE.search(text))


def _norm(name: str) -> str:
    return re.sub(r"[^a-z]", "", (name or "").lower())


def _map_columns(fieldnames: Iterable[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    normalized = {_norm(f): f for f in fieldnames or []}
    for key, candidates in _COLUMNS.items():
        for candidate in candidates:
            if candidate in normalized:
                mapping[key] = normalized[candidate]
                break
    return mapping


def _level(raw: str) -> str:
    value = (raw or "").strip().lower()
    aliases = {"crit": "critical", "hi": "high", "med": "medium", "info": "informational", "informational": "informational"}
    value = aliases.get(value, value)
    return value if value in LEVELS else "informational"


def _tactics(text: str) -> list[str]:
    return [name for name, pattern in TACTIC_RE if pattern.search(text)]


def _is_routable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_multicast
        or addr.is_reserved or addr.is_link_local or addr.is_unspecified
    )


def _parse_ts(raw: str) -> str:
    """Return an ISO timestamp when parseable, otherwise the original string."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    candidate = raw.replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S.%f %z", "%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.fromisoformat(candidate) if fmt is None else datetime.strptime(raw, fmt)
            return dt.isoformat()
        except ValueError:
            continue
    return raw


class TimelineReport:
    """Analysis result: aggregates, findings and indicators ready for enrichment."""

    def __init__(self) -> None:
        self.total = 0
        self.levels: Counter = Counter()
        self.rules: Counter = Counter()
        self.computers: Counter = Counter()
        self.channels: Counter = Counter()
        self.event_ids: Counter = Counter()
        self.tactics: Counter = Counter()
        self.categories: Counter = Counter()
        self.self_noise = 0
        self.findings: list[dict] = []
        self.iocs: dict[str, dict] = {}
        self.first_seen: str | None = None
        self.last_seen: str | None = None
        self.hourly: Counter = Counter()  # tranches de 10 minutes
        self.errors: list[str] = []

    # -- collection -------------------------------------------------------
    def _add_ioc(self, kind: str, value: str, level: str, rule: str) -> None:
        key = f"{kind}:{value.lower()}"
        entry = self.iocs.get(key)
        if entry is None:
            entry = {
                "type": kind,
                "value": value,
                "count": 0,
                "max_level": "informational",
                "rules": [],
                "enrichment": None,
            }
            self.iocs[key] = entry
        entry["count"] += 1
        if LEVELS.index(level) < LEVELS.index(entry["max_level"]):
            entry["max_level"] = level
        if rule and rule not in entry["rules"]:
            entry["rules"] = (entry["rules"] + [rule])[:5]

    def ingest(self, row: dict, cols: dict[str, str]) -> None:
        get = lambda key: (row.get(cols.get(key, ""), "") or "").strip()  # noqa: E731

        level = _level(get("level"))
        rule = get("rule") or "(untitled rule)"
        details = get("details")
        extra = get("extra")
        blob = f"{rule} {details} {extra}"
        timestamp = _parse_ts(get("timestamp"))

        # Events generated by our own tooling are counted apart, never as
        # findings: they document the investigation, not the incident.
        if level != "informational" and is_self_noise(blob):
            self.self_noise += 1
            return

        self.total += 1
        self.levels[level] += 1
        self.rules[rule] += 1
        if get("computer"):
            self.computers[get("computer")] += 1
        if get("channel"):
            self.channels[get("channel")] += 1
        if get("event_id"):
            self.event_ids[get("event_id")] += 1

        if timestamp:
            if self.first_seen is None or timestamp < self.first_seen:
                self.first_seen = timestamp
            if self.last_seen is None or timestamp > self.last_seen:
                self.last_seen = timestamp
            self.hourly[timestamp[:15]] += 1

        tactics = _tactics(blob)
        for tactic in tactics:
            self.tactics[tactic] += 1

        category = categorise(blob, get("event_id"))
        # Counted over the alerts that actually reach the table, so a family
        # badge never promises rows the analyst cannot find.
        if level in ("critical", "high", "medium"):
            self.categories[category] += 1

        if level in ("critical", "high", "medium"):
            self.findings.append({
                "timestamp": timestamp,
                "level": level,
                "rule": rule,
                "computer": get("computer"),
                "channel": get("channel"),
                "event_id": get("event_id"),
                "details": details[:600],
                "tactics": tactics,
                "category": category,
            })

        # Indicators are only pulled from events that carry a signal.
        if level == "informational":
            return
        for ip in RE_IPV4.findall(blob):
            if _is_routable(ip):
                self._add_ioc("ip", ip, level, rule)
        for match in RE_SHA256.findall(blob):
            self._add_ioc("sha256", match, level, rule)
        seen_hashes = set(RE_SHA256.findall(blob))
        for match in RE_SHA1.findall(blob):
            if not any(match in h for h in seen_hashes):
                self._add_ioc("sha1", match, level, rule)
        for match in RE_MD5.findall(blob):
            if not any(match in h for h in seen_hashes):
                self._add_ioc("md5", match, level, rule)
        for domain in RE_DOMAIN.findall(blob):
            root = ".".join(domain.lower().split(".")[-2:])
            if root not in DOMAIN_ALLOWLIST:
                self._add_ioc("domain", domain.lower(), level, rule)

    # -- output -----------------------------------------------------------
    # -- risk model -------------------------------------------------------
    # Four independent axes, each capped, then summed. Capping every axis is
    # what stops a single noisy rule firing 300 times from producing the same
    # verdict as a genuine multi-stage intrusion.
    #
    #   Severity      0-45   volume and gravity of correlated detections
    #   Kill chain    0-25   how many distinct ATT&CK tactics are represented
    #   Reputation    0-20   indicators confirmed malicious by an external source
    #   Corroboration 0-10   independent sources agreeing (YARA, live sockets)
    #
    # The score is a triage priority, not a proof. It is always published with
    # its breakdown so a reader can disagree with a component rather than with
    # an opaque number.
    SEVERITY_CAP, CHAIN_CAP, REPUTATION_CAP, CORROBORATION_CAP = 45, 25, 20, 10

    # Tactics that only matter once something else already happened. Discovery
    # alone is an administrator; discovery plus credential access is not.
    DECISIVE_TACTICS = {
        "Credential Access", "Lateral Movement", "Command and Control",
        "Exfiltration", "Impact", "Persistence", "Defense Evasion",
    }

    def score_breakdown(self, external: dict | None = None) -> dict:
        """Compute the risk score and show every component."""
        external = external or {}

        # -- severity: log-compressed weighted volume
        raw = sum(LEVEL_WEIGHT[level] * count for level, count in self.levels.items())
        severity = min(self.SEVERITY_CAP, round(6.5 * (raw ** 0.5))) if raw else 0

        # -- kill chain: breadth of the attack, with decisive tactics weighted
        tactics = set(self.tactics)
        decisive = tactics & self.DECISIVE_TACTICS
        chain = min(self.CHAIN_CAP, 3 * len(tactics) + 3 * len(decisive))

        # -- reputation: only externally confirmed indicators count
        malicious = external.get("malicious", 0)
        suspicious = external.get("suspicious", 0)
        reputation = min(self.REPUTATION_CAP, 10 * malicious + 3 * suspicious)

        # -- corroboration: agreement between independent sources
        corroboration = 0
        reasons: list[str] = []
        if external.get("yara_alerts"):
            corroboration += 6
            reasons.append(f"{external['yara_alerts']} YARA detection(s)")
        if external.get("live_connections"):
            corroboration += 4
            reasons.append(f"{external['live_connections']} active connection(s) to public hosts")
        corroboration = min(self.CORROBORATION_CAP, corroboration)

        total = severity + chain + reputation + corroboration
        return {
            "score": int(total),
            "components": [
                {"name": "Severity", "value": int(severity), "max": self.SEVERITY_CAP,
                 "detail": (f"{self.levels.get('critical', 0)} critical, "
                            f"{self.levels.get('high', 0)} high, "
                            f"{self.levels.get('medium', 0)} medium")},
                {"name": "Kill chain", "value": int(chain), "max": self.CHAIN_CAP,
                 "detail": (f"{len(tactics)} ATT&CK tactic(s), {len(decisive)} decisive"
                            if tactics else "no tactic inferred")},
                {"name": "Reputation", "value": int(reputation), "max": self.REPUTATION_CAP,
                 "detail": (f"{malicious} malicious, {suspicious} suspicious indicator(s)"
                            if (malicious or suspicious)
                            else "no indicator confirmed externally")},
                {"name": "Corroboration", "value": int(corroboration),
                 "max": self.CORROBORATION_CAP,
                 "detail": " · ".join(reasons) or "single source of evidence"},
            ],
            "confidence": self._confidence(external),
        }

    def _confidence(self, external: dict) -> str:
        """How much the verdict can be relied upon.

        Confidence is about evidence quality, not severity: a hundred alerts
        from one source and no external confirmation is a loud but fragile
        finding.
        """
        sources = 1
        if external.get("malicious") or external.get("suspicious"):
            sources += 1
        if external.get("yara_alerts"):
            sources += 1
        if external.get("live_connections"):
            sources += 1

        coverage = external.get("coverage")
        if sources >= 3 and (coverage is None or coverage >= 45):
            return "high"
        if sources >= 2:
            return "medium"
        return "low"

    @property
    def risk_score(self) -> int:
        return self.score_breakdown()["score"]

    @staticmethod
    def verdict_for(score: int, confidence: str = "low") -> str:
        """Wording that reflects both severity and evidence quality.

        A high score built on a single source is a strong lead, not a
        confirmation — claiming otherwise is how a triage tool loses an
        analyst's trust.
        """
        if score >= 70:
            return ("Compromise confirmed by multiple sources" if confidence == "high"
                    else "Compromise highly likely — corroboration still limited")
        if score >= 45:
            return ("Likely compromise — containment recommended" if confidence != "low"
                    else "Strong indications of compromise from a single source")
        if score >= 25:
            return "Suspicious activity requiring qualification"
        if score >= 10:
            return "Weak signals, no established compromise"
        return "Nothing conclusive"

    @property
    def verdict(self) -> str:
        breakdown = self.score_breakdown()
        return self.verdict_for(breakdown["score"], breakdown["confidence"])

    def top_findings(self, limit: int | None = None) -> list[dict]:
        """Every alert, most severe first. No arbitrary cap: a truncated list
        makes the family counts lie."""
        order = {level: index for index, level in enumerate(LEVELS)}
        ranked = sorted(
            self.findings,
            key=lambda f: (order.get(f["level"], 9), f["timestamp"]),
        )
        return ranked[:limit] if limit else ranked

    def ranked_iocs(self, limit: int = 1000) -> list[dict]:
        order = {level: index for index, level in enumerate(LEVELS)}
        return sorted(
            self.iocs.values(),
            key=lambda i: (order.get(i["max_level"], 9), -i["count"]),
        )[:limit]

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "levels": {level: self.levels.get(level, 0) for level in LEVELS},
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "score_breakdown": self.score_breakdown(),
            "self_noise": self.self_noise,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "top_rules": self.rules.most_common(15),
            "computers": self.computers.most_common(10),
            "channels": self.channels.most_common(10),
            "event_ids": self.event_ids.most_common(12),
            "tactics": self.tactics.most_common(),
            "categories": [
                {"id": cid, "label": label, "count": self.categories.get(cid, 0)}
                for cid, label in CATEGORIES
            ],
            "activity": sorted(self.hourly.items())[-144:],
            "findings": self.top_findings(),
            "iocs": self.ranked_iocs(),
            "errors": self.errors,
        }


def analyse_csv(path: Path, max_rows: int = 500_000) -> TimelineReport:
    report = TimelineReport()
    if not path.exists():
        report.errors.append(f"Timeline not found: {path}")
        return report

    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        cols = _map_columns(reader.fieldnames or [])
        if "level" not in cols and "rule" not in cols:
            report.errors.append(
                "Unrecognised Hayabusa columns — check the profile used for the timeline."
            )
            return report
        for index, row in enumerate(reader):
            if index >= max_rows:
                report.errors.append(f"Reading truncated at {max_rows} rows.")
                break
            try:
                report.ingest(row, cols)
            except Exception as exc:  # one malformed row must not stop the run
                report.errors.append(f"Row {index + 2} skipped: {exc}")
    return report


# THOR writes key/value lines, usually prefixed with a timestamp and hostname:
# "Aug 05 12:14:22 HOST THOR: Alert: MODULE: ... MESSAGE: ...". The level is
# therefore searched anywhere in the line, not only at the start.
# THOR's start-up banner and closing summary, matched by message rather than by
# module: these describe the scanner, not the host being examined, and they were
# filling the YARA view with a dozen rows before the first real verdict.
THOR_BANNER = re.compile(
    r"\b("
    r"Thor\s+(Version|Build|Scan\s+(started|finished)|Lite)"
    r"|Run\s+on\s+system|Running\s+as\s+user|Netbios\s+Domain"
    r"|User\s+has\s+admin\s+rights|Working\s+Directory"
    r"|Effective\s+argument\s+list|Program\s+Directory|Log\s+Directory"
    r"|Platform(\s+DeepEval)?\s*:|Platform\s+DeepEval"
    r"|Language\s*:\s*\w+[-\w]*,\s*Zone|System\s+Uptime"
    r"|Scan\s+took|Scanned\s+\d+|Total\s+scan\s+time|Elapsed\s+time"
    r"|License\s+(expires|holder|type)|Signature\s+database"
    r"|Init(ialization)?\s+(done|complete)|Loading\s+signatures"
    r"|Reading\s+config|Using\s+config"
    r")\b",
    re.I,
)

RE_THOR_LEVEL = re.compile(r"\b(Alert|Warning|Notice|Info|Error)\s*:", re.I)
RE_THOR_FIELD = re.compile(r"\b([A-Z][A-Z0-9_]{2,})\s*:\s*(.*?)(?=\s+[A-Z][A-Z0-9_]{2,}\s*:|$)")

# Levels below "Alert" are kept: a file examined and found clean is
# information, not noise. That is what separates "scan found nothing" from
# "scan looked at nothing".
THOR_LEVEL_MAP = {"alert": "critical", "warning": "high", "notice": "medium",
                  "info": "informational"}


def parse_thor_line(line: str) -> dict | None:
    """Turn a THOR output line into a structured verdict.

    Called during the scan rather than after it, so detections appear as they
    happen instead of waiting for the log file to be parsed at the end.
    """
    match = RE_THOR_LEVEL.search(line)
    if not match:
        return None
    raw_level = match.group(1).lower()
    if raw_level not in THOR_LEVEL_MAP:
        return None
    body_text = line[match.end():]

    # THOR opens every scan with a banner — version, build, host, user, working
    # directory, argument list, uptime — and closes it with a summary. Those
    # lines are matched by name, whatever module or level they carry, because
    # relying only on "has no file" would break the day THOR reformats them.
    if THOR_BANNER.search(body_text):
        return None

    # Beyond the named banner, the general rule still applies: a verdict that
    # names no object is scan progress, not a finding.
    if raw_level in ("info", "notice"):
        if not re.search(r"\b(FILE|FILE_\d+|PATH|OBJECT|SHA256|SHA256_\d+|MD5)\s*:",
                         body_text):
            return None
        if re.search(r"\bMODULE\s*:\s*(Startup|Init|Config|License|Update)\b",
                     body_text, re.I):
            return None

    # A word like "Alert:" quoted inside a message must not create a duplicate:
    # only the first occurrence in the line is kept.
    prefix = line[: match.start()]
    if RE_THOR_LEVEL.search(prefix):
        return None

    body = line[match.end():].strip()
    fields = {k: v.strip() for k, v in RE_THOR_FIELD.findall(body) if v.strip()}

    score = fields.get("SCORE") or fields.get("TOTAL_SCORE")
    try:
        score_value = int(re.sub(r"\D", "", score)) if score else None
    except ValueError:
        score_value = None

    return {
        "level": THOR_LEVEL_MAP[raw_level],
        "raw_level": raw_level,
        "message": fields.get("MESSAGE") or fields.get("MESSAGE_1") or body[:200],
        "file": (fields.get("FILE") or fields.get("FILE_1") or fields.get("PATH")
                 or fields.get("OBJECT") or ""),
        "module": fields.get("MODULE") or fields.get("SUBSCAN") or "",
        "rule": fields.get("RULE") or fields.get("REASON_1") or fields.get("SIGNATURE") or "",
        "score": score_value,
        "sha256": fields.get("SHA256") or fields.get("SHA256_1") or "",
        "fields": fields,
        "raw": line[:1000],
    }


def parse_thor_log(path: Path) -> dict:
    """Minimal extraction of THOR Lite verdicts (key/value text format)."""
    result = {"alerts": [], "entries": [], "warnings": 0, "notices": 0,
              "infos": 0, "scanned": None}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        entry = parse_thor_line(line)
        if entry is None:
            continue
        result["entries"].append(entry)
        if entry["raw_level"] == "alert":
            result["alerts"].append(entry)
        elif entry["raw_level"] == "warning":
            result["warnings"] += 1
        elif entry["raw_level"] == "notice":
            result["notices"] += 1
        else:
            result["infos"] += 1
    result["alerts"] = result["alerts"][:400]
    result["entries"] = result["entries"][:2000]
    return result
