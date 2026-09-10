"""End-to-end tests, runnable without a Windows machine."""

from __future__ import annotations

import asyncio
import json
import os
import time
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfirconsole import ai, timeline  # noqa: E402
from collections import Counter

from dfirconsole.bus import EventBus  # noqa: E402
from dfirconsole.config import Settings  # noqa: E402
from dfirconsole.demo import build_demo_timeline  # noqa: E402
from dfirconsole.enrich import threat_level  # noqa: E402
from dfirconsole.pipeline import Case  # noqa: E402


@pytest.fixture()
def workspace(tmp_path: Path) -> Settings:
    settings = Settings(workspace=str(tmp_path / "dfir"), demo_mode=True, case_name="TEST-001")
    for directory in (settings.root, settings.tools_dir, settings.evidence_dir,
                      settings.output_dir, settings.thor_dir):
        directory.mkdir(parents=True, exist_ok=True)
    return settings


# --- timeline parsing -----------------------------------------------------
def test_timeline_parsing(tmp_path: Path) -> None:
    csv_path = build_demo_timeline(tmp_path / "hayabusa-output.csv")
    report = timeline.analyse_csv(csv_path).to_dict()

    assert report["total"] > 400
    assert report["levels"]["critical"] >= 6
    assert report["levels"]["high"] >= 8
    assert not report["errors"]
    assert report["first_seen"] and report["last_seen"]
    assert report["first_seen"] <= report["last_seen"]


def test_ioc_extraction(tmp_path: Path) -> None:
    csv_path = build_demo_timeline(tmp_path / "t.csv")
    report = timeline.analyse_csv(csv_path).to_dict()
    values = {i["value"] for i in report["iocs"]}
    types = {i["type"] for i in report["iocs"]}

    # Public IPs from the scenario are kept, internal ones dropped.
    assert "45.155.205.233" in values
    assert "185.220.101.34" in values
    assert "10.20.4.19" not in values
    assert "10.20.4.11" not in values

    assert "sha256" in types and "ip" in types and "domain" in types
    assert "cdn-update-delivery.xyz" in values
    # Informational noise must not produce any indicator.
    assert all(i["max_level"] != "informational" for i in report["iocs"])


def test_domain_allowlist_filters_noise() -> None:
    report = timeline.TimelineReport()
    cols = {"level": "Level", "rule": "RuleTitle", "details": "Details"}
    report.ingest(
        {"Level": "high", "RuleTitle": "Test", "Details": "contacted windowsupdate.com and evil-panel.top"},
        cols,
    )
    values = {i["value"] for i in report.iocs.values()}
    assert "evil-panel.top" in values
    assert "windowsupdate.com" not in values


def test_tactics_and_scoring(tmp_path: Path) -> None:
    csv_path = build_demo_timeline(tmp_path / "t.csv")
    report = timeline.analyse_csv(csv_path).to_dict()
    tactics = dict(report["tactics"])

    for expected in ("Credential Access", "Defense Evasion", "Impact", "Persistence"):
        assert expected in tactics, f"missing tactic: {expected}"

    assert 0 <= report["risk_score"] <= 100
    breakdown = report["score_breakdown"]
    assert breakdown["score"] == report["risk_score"]
    assert sum(c["value"] for c in breakdown["components"]) == breakdown["score"]
    # Timeline alone: no external corroboration, so confidence stays low.
    assert breakdown["confidence"] == "low"
    assert report["risk_score"] >= 60
    assert "compromise" in report["verdict"].lower()


def test_empty_and_malformed_csv(tmp_path: Path) -> None:
    missing = timeline.analyse_csv(tmp_path / "nonexistent.csv")
    assert missing.errors and missing.total == 0

    bogus = tmp_path / "bogus.csv"
    bogus.write_text("colonneA,colonneB\n1,2\n", encoding="utf-8")
    assert timeline.analyse_csv(bogus).errors


def test_column_aliases(tmp_path: Path) -> None:
    path = tmp_path / "alias.csv"
    path.write_text(
        "datetime,title,Level,host,Details\n"
        "2026-01-04T10:00:00+00:00,Mimikatz detected,critical,PC1,lsass dump 45.155.205.233\n",
        encoding="utf-8",
    )
    report = timeline.analyse_csv(path).to_dict()
    assert report["total"] == 1
    assert report["levels"]["critical"] == 1
    assert any(i["value"] == "45.155.205.233" for i in report["iocs"])


# --- enrichment verdicts --------------------------------------------------
@pytest.mark.parametrize(
    "enrichment,expected",
    [
        ({"virustotal": {"found": True, "malicious": 42, "harmless": 10}}, "malicious"),
        ({"abuseipdb": {"score": 92, "reports": 300}}, "malicious"),
        ({"virustotal": {"found": True, "malicious": 2, "harmless": 60}}, "suspicious"),
        ({"abuseipdb": {"score": 30}}, "suspicious"),
        ({"virustotal": {"found": True, "malicious": 0, "harmless": 70}}, "clean"),
        ({"virustotal": {"found": False}}, "unknown"),
        ({}, "unchecked"),
    ],
)
def test_threat_level(enrichment: dict, expected: str) -> None:
    assert threat_level({"enrichment": enrichment}) == expected


# --- local summary --------------------------------------------------------
def test_local_ai_fallback(tmp_path: Path) -> None:
    csv_path = build_demo_timeline(tmp_path / "t.csv")
    report = timeline.analyse_csv(csv_path).to_dict()
    result = asyncio.run(ai.analyse(report, api_key=""))

    for key in ("verdict", "summary", "containment", "next_steps", "key_findings"):
        assert key in result
    assert result["generated_by"] == "local"
    assert "key configured" in result["note"]


def test_ai_json_extraction() -> None:
    assert ai._extract_json('```json\n{"verdict": "ok"}\n```') == {"verdict": "ok"}
    assert ai._extract_json('Here you go: {"a": 1} done') == {"a": 1}
    assert ai._extract_json("pas de json ici") is None


# --- full pipeline --------------------------------------------------------
def test_full_pipeline_demo(workspace: Settings) -> None:
    bus = EventBus()
    case = Case(workspace, bus)

    asyncio.run(case.run(["workspace", "collect", "rules", "timeline", "analyse",
                          "yara", "enrich", "ai"]))

    statuses = {s.id: s.status for s in case.steps.values()}
    assert statuses["workspace"] == "done"
    assert statuses["collect"] == "done"
    assert statuses["timeline"] == "done"
    assert statuses["analyse"] == "done"
    # Optional steps without prerequisites: flagged, never blocking.
    assert statuses["yara"] == "skipped"
    assert statuses["enrich"] == "skipped"
    assert statuses["ai"] == "done"

    assert case.report and case.report["total"] > 0
    assert case.ai and case.ai["generated_by"] == "local"
    assert workspace.timeline_csv.exists()
    assert (workspace.evidence_dir / "DESKTOP-R7K2QX1" / "Logs").is_dir()

    seals = [(s.seal, s.seal_basis) for s in case.steps.values() if s.status == "done"]
    assert all(len(seal) == 16 for seal, _ in seals)
    # Every seal states what it covers.
    assert all(basis for _, basis in seals)
    analyse = case.steps["analyse"]
    assert "hayabusa-output.csv" in analyse.seal_basis


def test_failed_step_stops_the_chain(workspace: Settings) -> None:
    bus = EventBus()
    case = Case(workspace, bus)
    # "analyse" without a timeline: blocking failure, "ai" must not start.
    asyncio.run(case.run(["analyse", "ai"]))
    assert case.steps["analyse"].status == "failed"
    assert case.steps["ai"].status == "pending"


def test_bus_history_and_subscribers() -> None:
    bus = EventBus()
    queue = bus.subscribe()
    bus.log("first message")
    bus.emit("step", step={"id": "x"})
    assert queue.qsize() == 2
    assert len(bus.backlog()) == 2
    bus.unsubscribe(queue)
    bus.log("after unsubscribing")
    assert queue.qsize() == 2


# --- HTTP layer -----------------------------------------------------------
def test_http_api(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DFIR_CONFIG", str(tmp_path / "config.json"))
    from fastapi.testclient import TestClient

    from dfirconsole import server

    server.settings.workspace = str(tmp_path / "dfir")
    server.settings.demo_mode = True
    server.case.reset()

    with TestClient(server.app) as client:
        assert client.get("/").status_code == 200

        state = client.get("/api/state").json()
        assert len(state["steps"]) == 11
        assert state["settings"]["keys"]["virustotal"] is False
        assert "virustotal_key" not in state["settings"]  # no secret exposed

        assert client.get("/api/report.json").status_code == 404
        assert client.post("/api/run", json={"steps": ["unknown"]}).status_code == 400

        response = client.post("/api/run", json={
            "steps": ["workspace", "collect", "timeline", "analyse", "ai"]})
        assert response.status_code == 200

        for _ in range(400):
            if not client.get("/api/state").json()["running"]:
                break
            import time
            time.sleep(0.05)

        final = client.get("/api/state").json()
        assert final["running"] is False
        assert final["report"]["total"] > 0

        report = client.get("/api/report.json")
        assert report.status_code == 200
        assert "attachment" in report.headers["content-disposition"]

        page = client.get("/api/report.html")
        assert page.status_code == 200
        assert "Triage report" in page.text
        assert "45.155.205.233" in page.text


def test_websocket_stream(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DFIR_CONFIG", str(tmp_path / "config.json"))
    from fastapi.testclient import TestClient

    from dfirconsole import server

    server.settings.workspace = str(tmp_path / "dfir2")
    server.settings.demo_mode = True
    server.case.reset()

    with TestClient(server.app) as client:
        with client.websocket_connect("/ws") as ws:
            hello = ws.receive_json()
            assert hello["kind"] == "hello"
            assert "snapshot" in hello

            client.post("/api/run", json={"steps": ["workspace"]})
            kinds = [ws.receive_json()["kind"] for _ in range(4)]
            assert "step" in kinds or "log" in kinds


# --- adapting to the Hayabusa version ------------------------------------
def test_hayabusa_subcommand_detection(workspace: Settings) -> None:
    """Hayabusa 3 exposes csv-timeline; version 4 renamed it dfir-timeline."""
    case = Case(workspace, EventBus())
    binary = workspace.tools_dir / "hayabusa.exe"
    binary.write_bytes(b"MZ")

    helps = {
        "v3": "Commands:\n  csv-timeline  Save the timeline in CSV format\n  update-rules",
        "v4": "Commands:\n  dfir-timeline  Save the timeline\n  update-rules",
        "empty": "",
    }
    expected = {"v3": "csv-timeline", "v4": "dfir-timeline", "empty": "csv-timeline"}

    for version, help_text in helps.items():
        async def fake_probe(args, cwd, timeout=60, _help=help_text):
            return _help

        case.probe = fake_probe  # type: ignore[assignment]
        subcommand, _ = asyncio.run(case._hayabusa_timeline_cmd(binary))
        assert subcommand == expected[version], f"{version} : {subcommand}"


def test_unsupported_flags_are_dropped() -> None:
    """A flag missing from the help text would fail the whole command."""
    help_text = "Options:\n  -d <DIR>\n  -o <FILE>\n  --no-wizard\n  -r <RULES>"
    assert Case._supported("--no-wizard", help_text)
    assert Case._supported("-r", help_text)
    assert not Case._supported("--RFC-3339", help_text)
    # Unreadable help: drop nothing and let the tool decide.
    assert Case._supported("--RFC-3339", "")


def test_ansi_sequences_are_stripped() -> None:
    from dfirconsole.bus import strip_ansi

    assert strip_ansi("[0m[38;2;0;255;0mUpdated Sigma rules: [0m4762") == \
        "Updated Sigma rules: 4762"
    assert strip_ansi("\x1b[32mvert\x1b[0m") == "vert"


def test_session_logfile(tmp_path: Path) -> None:
    """Every case keeps its full log on disk."""
    bus = EventBus()
    log_path = tmp_path / "CASE-X-console.log"
    bus.attach_file(log_path)
    bus.log("visible in the interface", level="ok", step="collect")
    bus.log("disk only", level="out", step="collect", ui=False)

    contenu = log_path.read_text(encoding="utf-8")
    assert "visible in the interface" in contenu
    assert "disk only" in contenu
    # Only the first one was broadcast.
    assert len([e for e in bus.backlog() if e["kind"] == "log"]) == 1


# --- YARA scan scope ------------------------------------------------------
def test_scan_target_defaults_to_collection(workspace: Settings) -> None:
    """With no instruction, scan the collected artefacts, not the whole disk."""
    case = Case(workspace, EventBus())
    assert case._scan_target() == workspace.evidence_dir


def test_scan_target_honours_analyst_choice(workspace: Settings) -> None:
    """The requested scope wins, including a volume root."""
    workspace.yara_path = "/tmp"
    case = Case(workspace, EventBus())
    assert case._scan_target() == Path("/tmp")

    workspace.yara_path = "   "          # field left empty
    assert Case(workspace, EventBus())._scan_target() == workspace.evidence_dir


def test_yara_step_is_unchecked_by_default(workspace: Settings) -> None:
    """Long and licence-bound: this step does not run unless asked for."""
    case = Case(workspace, EventBus())
    defaults = {s.id: s.default_on for s in case.steps.values()}
    assert defaults["yara"] is False
    assert all(v for k, v in defaults.items() if k != "yara")


def test_yara_absent_scanner_does_not_break_chain(workspace: Settings) -> None:
    """Without THOR the step is skipped and the chain carries on."""
    case = Case(workspace, EventBus())
    asyncio.run(case.run(["yara", "workspace"]))
    assert case.steps["yara"].status == "skipped"
    assert case.steps["workspace"].status == "done"


# --- streaming THOR verdicts ----------------------------------------------
@pytest.mark.parametrize(
    "line,expected",
    [
        ("Alert: MODULE: Filescan MESSAGE: Malware file found FILE: C:\\T\\x.exe SCORE: 100",
         ("critical", "Malware file found", "C:\\T\\x.exe", 100)),
        ("Warning: MODULE: ProcessCheck MESSAGE: Suspicious process",
         ("high", "Suspicious process", "", None)),
        ("Notice: MODULE: Autoruns MESSAGE: Unusual entry FILE: C:\\a.lnk",
         ("medium", "Unusual entry", "C:\\a.lnk", None)),
    ],
)
def test_thor_line_parsing(line: str, expected: tuple) -> None:
    entry = timeline.parse_thor_line(line)
    assert entry is not None
    assert (entry["level"], entry["message"], entry["file"], entry["score"]) == expected


def test_thor_line_ignores_noise() -> None:
    """Progress lines must not inflate the alert count."""
    for line in ("Info: scanning C:\\Windows", "", "   ", "Scan finished in 42s"):
        assert timeline.parse_thor_line(line) is None


def test_thor_log_counts_by_level(tmp_path: Path) -> None:
    log = tmp_path / "thor.log"
    log.write_text(
        "Info: start\n"
        "Alert: MESSAGE: Malware found FILE: a.exe SCORE: 90\n"
        "Warning: MESSAGE: Odd file FILE: b.dll\n"
        "Notice: MESSAGE: Known good FILE: c.exe\n"
        "Alert: MESSAGE: Webshell FILE: d.aspx SCORE: 120\n",
        encoding="utf-8",
    )
    result = timeline.parse_thor_log(log)
    assert len(result["alerts"]) == 2
    assert result["warnings"] == 1 and result["notices"] == 1
    assert result["alerts"][1]["score"] == 120


# --- key file -------------------------------------------------------------
def test_keyfile_parsing(tmp_path: Path, monkeypatch) -> None:
    """Forgiving format: comments, export, quotes, spaces."""
    path = tmp_path / "apikeys.env"
    path.write_text(
        "# commentaire\n"
        "export VT_API_KEY = \"vt-123\"\n"
        "ABUSEIPDB_API_KEY='abuse-456'\n"
        "AI_PROVIDER=openai\n"
        "AI_BASE_URL=http://localhost:11434/v1\n"
        "line invalide sans egal\n",
        encoding="utf-8",
    )
    from dfirconsole import config

    values = config.read_keyfile(path)
    assert values["virustotal_key"] == "vt-123"
    assert values["abuseipdb_key"] == "abuse-456"
    assert values["ai_provider"] == "openai"
    assert values["ai_base_url"] == "http://localhost:11434/v1"


def test_keyfile_absent_is_harmless(tmp_path: Path) -> None:
    from dfirconsole import config

    assert config.read_keyfile(tmp_path / "rien.env") == {}


# --- THOR output formats --------------------------------------------------
@pytest.mark.parametrize(
    "line",
    [
        "Alert: MODULE: Filescan MESSAGE: Malware found FILE: C:\\x.exe SCORE: 90",
        "Aug 05 12:14:22 STUDENT-W11 THOR: Alert: MODULE: Filescan "
        "MESSAGE: Malware found FILE: C:\\x.exe SCORE: 90",
        "20260805T121422Z STUDENT-W11 Alert: MESSAGE: Malware found "
        "FILE: C:\\x.exe SCORE: 90",
    ],
)
def test_thor_prefixed_lines(line: str) -> None:
    """THOR often prefixes its lines with a timestamp and hostname."""
    entry = timeline.parse_thor_line(line)
    assert entry is not None, "prefixed line not recognised"
    assert entry["level"] == "critical"
    assert entry["file"] == "C:\\x.exe"
    assert entry["score"] == 90


# --- AI providers ---------------------------------------------------------
def test_each_provider_has_its_own_endpoint() -> None:
    """Choosing Groq must never end up at OpenAI."""
    from dfirconsole.ai import PROVIDERS

    urls = {k: v["base_url"] for k, v in PROVIDERS.items() if v["base_url"]}
    assert "groq.com" in urls["groq"]
    assert "mistral.ai" in urls["mistral"]
    assert "openrouter.ai" in urls["openrouter"]
    assert "localhost" in urls["ollama"]
    assert len(set(urls.values())) == len(urls), "two providers share a URL"


def test_unknown_provider_falls_back_locally() -> None:
    report = {"levels": {}, "findings": [], "iocs": [], "tactics": [], "top_rules": []}
    result = asyncio.run(ai.analyse(report, api_key="x", provider="inexistant"))
    assert result["generated_by"] == "local"
    assert "Unknown provider" in result["note"]


def test_ollama_needs_no_key() -> None:
    from dfirconsole.ai import PROVIDERS

    assert PROVIDERS["ollama"]["needs_key"] is False
    assert PROVIDERS["groq"]["needs_key"] is True


# --- alert families -------------------------------------------------------
@pytest.mark.parametrize(
    "text,event_id,expected",
    [
        ("Logon Failure NTLM brute force", "4625", "auth"),
        ("Defender Alert Severe Trojan:Win32/Leonem", "1116", "infection"),
        ("PowerShell EncodedCommand Execution", "4104", "execution"),
        ("Suspicious Outbound Connection DestinationIp 45.155.205.233", "3", "network"),
        ("Security Event Log Cleared", "1102", "evasion"),
        ("Windows Defender Real-Time Protection Disabled", "5001", "evasion"),
        # The ID says "process creation", the text says "log tampering":
        # the text must win, because that is what the analyst searches for.
        ("CommandLine: vssadmin.exe delete shadows /all /quiet", "4688", "evasion"),
        ("Lateral Movement via SMB Admin Share", "5145", "network"),
        ("Scheduled Task Created for Persistence", "106", "execution"),
        ("Print Spooler Started", "7036", "other"),
    ],
)
def test_alert_categories(text: str, event_id: str, expected: str) -> None:
    assert timeline.categorise(text, event_id) == expected


def test_categories_reported(tmp_path: Path) -> None:
    """The report carries the six family counts and each alert its own."""
    csv_path = build_demo_timeline(tmp_path / "t.csv")
    report = timeline.analyse_csv(csv_path).to_dict()

    families = {c["id"]: c["count"] for c in report["categories"]}
    assert set(families) == {"auth", "infection", "execution", "network",
                             "evasion", "other"}
    assert families["evasion"] > 0 and families["execution"] > 0
    assert all("category" in f for f in report["findings"])


# --- system context -------------------------------------------------------
def test_netstat_parsing_and_risk() -> None:
    from dfirconsole import sysinfo

    netstat = (
        "  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1284\n"
        "  TCP    10.20.4.11:52233       45.155.205.233:8443    ESTABLISHED     6612\n"
        "  TCP    10.20.4.11:52240       10.20.4.19:445         ESTABLISHED     4\n"
        "  TCP    127.0.0.1:8787         0.0.0.0:0              LISTENING       9100\n"
    )
    tasks = ('"TermService.exe","1284","Services","0","8 000 K"\n'
             '"powershell.exe","6612","Console","1","54 000 K"\n'
             '"System","4","Services","0","1 000 K"\n'
             '"python.exe","9100","Console","1","40 000 K"')

    connections = sysinfo.parse_netstat(netstat, sysinfo.parse_tasklist(tasks))
    by_port = {c["local_port"]: c for c in connections}

    assert by_port[3389]["risk"] == "high"          # exposed RDP
    assert by_port[52233]["risk"] == "high"         # powershell to the Internet
    assert by_port[52240]["risk"] == "normal"       # internal SMB: nothing to report
    assert by_port[8787]["risk"] == "normal"        # loopback

    resume = sysinfo.network_summary(connections)
    assert resume["established"] == 2
    assert resume["public_peers"] == ["45.155.205.233"]


def test_private_addresses_are_not_public() -> None:
    from dfirconsole import sysinfo

    for interne in ("10.20.4.19", "192.168.1.1", "172.16.0.5", "127.0.0.1", "0.0.0.0"):
        assert not sysinfo.is_public_ip(interne)
    assert sysinfo.is_public_ip("45.155.205.233")


def test_local_users_and_admins() -> None:
    from dfirconsole import sysinfo

    users = json.dumps([
        {"Name": "Administrateur", "Enabled": True, "SID": "S-1-5-21-1-2-3-500"},
        {"Name": "svc_backup1", "Enabled": True, "SID": "S-1-5-21-1-2-3-1050"},
        {"Name": "j.martel", "Enabled": True, "SID": "S-1-5-21-1-2-3-1001",
         "LastLogon": "/Date(1785920000000)/"},
    ])
    admins = json.dumps([{"Name": "POSTE\\Administrateur"},
                         {"Name": "DOMAINE\\svc_backup1"}])

    accounts = {u["name"]: u for u in sysinfo.parse_users(users, admins)}
    assert accounts["Administrateur"]["admin"]
    assert "built-in administrator account" in accounts["Administrateur"]["flags"]
    assert accounts["svc_backup1"]["admin"]
    assert "never logged on" in accounts["svc_backup1"]["flags"]
    assert not accounts["j.martel"]["admin"]
    # Administrators are listed first.
    assert sysinfo.parse_users(users, admins)[0]["admin"]


def test_root_anomalies(tmp_path: Path) -> None:
    from dfirconsole import sysinfo

    for nom in ("Windows", "Users", "Program Files", "Tools", "Temp"):
        (tmp_path / nom).mkdir()
    old = time.time() - 400 * 86400
    for nom in ("Windows", "Users", "Program Files"):
        os.utime(tmp_path / nom, (old, old))

    entries_by_name = {e["name"]: e for e in sysinfo.analyse_root(tmp_path)}
    assert "Windows" not in entries_by_name and "Users" not in entries_by_name
    assert entries_by_name["Tools"]["risk"] == "high"
    assert entries_by_name["Temp"]["risk"] == "high"


def test_system_findings_are_ordered() -> None:
    from dfirconsole.demo import demo_system

    context = demo_system()
    levels_seen = [f["level"] for f in context["findings"]]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert levels_seen == sorted(levels_seen, key=lambda n: order[n])
    assert any("C:\\Tools" in f["title"] for f in context["findings"])


def test_active_connections_become_iocs(workspace: Settings) -> None:
    """An address contacted during triage must reach the indicators."""
    case = Case(workspace, EventBus())
    asyncio.run(case.run(["workspace", "collect", "system", "timeline", "analyse"]))

    values = {i["value"] for i in case.report["iocs"]}
    assert "185.220.101.34" in values
    from_network = [i for i in case.report["iocs"] if i.get("source") == "connexion active"]
    assert from_network, "no address came from the active connections"
    # Internal peers stay out.
    assert "10.20.4.19" not in values


# --- logging coverage -----------------------------------------------------
def test_coverage_detects_missing_and_empty_channels() -> None:
    """Separate a missing channel, a disabled one and an empty one."""
    from dfirconsole import sysinfo

    channels = sysinfo.parse_channels(json.dumps([
        {"LogName": "Security", "IsEnabled": True, "RecordCount": 84213,
         "FileSize": 20971520},
        {"LogName": "Microsoft-Windows-PowerShell/Operational", "IsEnabled": True,
         "RecordCount": 0, "FileSize": 69632},
        {"LogName": "Microsoft-Windows-WinRM/Operational", "IsEnabled": False,
         "RecordCount": 0, "FileSize": 69632},
    ]))
    result = sysinfo.audit_coverage(channels, {}, {})
    by_label = {c["label"]: c for c in result["channels"]}

    assert by_label["Security"]["verdict"] == "active"
    assert by_label["Sysmon"]["verdict"] == "missing"
    assert by_label["PowerShell (script blocks)"]["verdict"] == "empty"
    assert by_label["WinRM"]["verdict"] == "disabled"
    # Missing critical channels are announced as blind spots.
    assert "Sysmon" in result["gaps"]
    assert 0 <= result["score"] <= 100


def test_coverage_reads_auditpol() -> None:
    from dfirconsole import sysinfo

    csv_text = (
        "Machine Name,Policy Target,Subcategory,Subcategory GUID,"
        "Inclusion Setting,Exclusion Setting\n"
        "PC,System,Logon,{0},Success and Failure,\n"
        "PC,System,Process Creation,{1},No Auditing,\n"
    )
    audit = sysinfo.parse_auditpol(csv_text)
    assert audit["logon"] == "Success and Failure"

    result = sysinfo.audit_coverage({}, {}, audit)
    states = {a["label"]: a["state"] for a in result["audit"]}
    assert states["Logon"] == "Success and Failure"
    assert states["Process creation"] == "disabled"
    assert "Process creation" in result["gaps"]


def test_coverage_uses_collected_files_when_live_is_unavailable(tmp_path: Path) -> None:
    """On an offline collection, the files are authoritative."""
    from dfirconsole import sysinfo

    logs = tmp_path / "Logs"
    logs.mkdir()
    (logs / "Security.evtx").write_bytes(b"\x00" * 5_000_000)
    (logs / "Microsoft-Windows-Sysmon%4Operational.evtx").write_bytes(b"\x00" * 2_000_000)

    inventory = sysinfo.evtx_inventory(logs)
    assert len(inventory) == 2

    result = sysinfo.audit_coverage({}, inventory, {})
    by_label = {c["label"]: c for c in result["channels"]}
    assert by_label["Security"]["verdict"] == "active"
    assert by_label["Sysmon"]["collected"] is True
    assert by_label["WinRM"]["verdict"] == "missing"


def test_thor_keeps_clean_verdicts(tmp_path: Path) -> None:
    """The YARA page must fill up even when everything is clean."""
    log = tmp_path / "thor.log"
    log.write_text(
        "Info: Scanning started\n"
        "Aug 07 09:12:11 PC THOR: Notice: MODULE: Filescan MESSAGE: File checked "
        "FILE: C:\\ok.exe SHA256: bb22\n"
        "Aug 07 09:12:12 PC THOR: Info: MODULE: Filescan MESSAGE: Clean "
        "FILE: C:\\clean.exe SHA256: cc33\n"
        "Aug 07 09:12:13 PC THOR: Alert: MODULE: Filescan MESSAGE: Malware "
        "FILE: C:\\bad.exe SCORE: 90\n"
        "Scan finished in 12s\n",
        encoding="utf-8",
    )
    result = timeline.parse_thor_log(log)
    assert len(result["entries"]) == 3      # progress lines are dropped
    assert len(result["alerts"]) == 1
    assert result["notices"] == 1 and result["infos"] == 1
    levels_seen = {e["level"] for e in result["entries"]}
    assert "informational" in levels_seen and "critical" in levels_seen


def test_key_preview_never_leaks(tmp_path: Path, monkeypatch) -> None:
    """The preview identifies the key without allowing its use."""
    monkeypatch.setenv("DFIR_KEYS", str(tmp_path / "k.env"))
    (tmp_path / "k.env").write_text("VT_API_KEY=abcdef0123456789abcdef0123456789\n")

    import importlib
    from dfirconsole import config as config_module

    importlib.reload(config_module)
    public = config_module.Settings.load().public()

    preview = public["key_previews"]["virustotal"]
    assert preview and "abcdef0123456789abcdef0123456789" not in preview
    assert public["key_origins"]["virustotal_key"] == "k.env"
    assert "virustotal_key" not in public


# --- collector ------------------------------------------------------------
def test_collection_requires_cylr(tmp_path: Path) -> None:
    """CyLR is the collector: no silent substitution, ever."""
    settings = Settings(workspace=str(tmp_path / "ws"), demo_mode=False)
    for directory in (settings.root, settings.tools_dir, settings.evidence_dir,
                      settings.output_dir, *settings.tool_dirs):
        directory.mkdir(parents=True, exist_ok=True)
    # An unrelated binary lying around must not be picked up as a collector.
    (settings.tools_dir / "notarealcollector.exe").write_bytes(b"MZ")

    case = Case(settings, EventBus())
    asyncio.run(case.run(["collect"]))

    assert case.steps["collect"].status == "failed"
    assert "CyLR.exe not found" in case.steps["collect"].message


def test_real_cylr_collection_path(tmp_path: Path, monkeypatch) -> None:
    """Exercises the actual (non-demo) collection path end to end.

    Demo mode bypasses _collect_with_cylr entirely, which is exactly how a
    refactor once deleted that method without a single test noticing — every
    other collection test runs with demo_mode=True. This one does not.
    """
    import stat

    settings = Settings(workspace=str(tmp_path / "ws"), demo_mode=False,
                        case_name="REAL-TEST")
    for directory in (settings.root, settings.tools_dir, settings.evidence_dir,
                      settings.output_dir, *settings.tool_dirs):
        directory.mkdir(parents=True, exist_ok=True)

    fake_cylr = settings.cylr_dir / "CyLR.exe"
    fake_cylr.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, zipfile, os\n"
        "a = sys.argv[1:]\n"
        "path = os.path.join(a[a.index('-od') + 1], a[a.index('-of') + 1])\n"
        "with zipfile.ZipFile(path, 'w') as zf:\n"
        "    zf.writestr('HOST/C/Windows/System32/winevt/Logs/Security.evtx', "
        "b'ElfFile\\x00' * 50)\n"
        "print('Collection complete.')\n"
    )
    fake_cylr.chmod(fake_cylr.stat().st_mode | stat.S_IEXEC)

    monkeypatch.setattr("dfirconsole.pipeline.is_admin", lambda: True)
    case = Case(settings, EventBus())
    asyncio.run(case.run(["collect"]))

    step = case.steps["collect"]
    assert step.status == "done", step.message
    assert step.artifacts == ["REAL-TEST.zip"]
    assert case.logs_dir is not None and case.logs_dir.name == "Logs"
    assert list(case.logs_dir.glob("*.evtx"))


def test_cylr_producing_no_archive_fails_clearly(tmp_path: Path, monkeypatch) -> None:
    """A silent CyLR must fail with a diagnosable message, never an
    AttributeError from a missing method."""
    import stat

    settings = Settings(workspace=str(tmp_path / "ws"), demo_mode=False)
    for directory in (settings.root, settings.tools_dir, settings.evidence_dir,
                      settings.output_dir, *settings.tool_dirs):
        directory.mkdir(parents=True, exist_ok=True)

    silent = settings.cylr_dir / "CyLR.exe"
    silent.write_text("#!/usr/bin/env python3\nprint('nothing produced')\n")
    silent.chmod(silent.stat().st_mode | stat.S_IEXEC)

    monkeypatch.setattr("dfirconsole.pipeline.is_admin", lambda: True)
    case = Case(settings, EventBus())
    asyncio.run(case.run(["collect"]))

    assert case.steps["collect"].status == "failed"
    assert "no archive" in case.steps["collect"].message
    assert "AttributeError" not in case.steps["collect"].message


def test_no_phantom_methods_in_pipeline() -> None:
    """Guard against a refactor deleting a method that is still called.

    This is the check that would have caught the missing _collect_with_cylr
    before it reached a live host.
    """
    import ast

    source = (Path(__file__).resolve().parents[1] / "dfirconsole" / "pipeline.py")
    tree = ast.parse(source.read_text(encoding="utf-8"))

    defined = {n.name for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    called = {n.attr for n in ast.walk(tree)
              if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
              and n.value.id == "self"}

    # Data attributes assigned on self, which are not method calls.
    data_attributes = {"_task"}
    missing = {m for m in called
               if m.startswith("_") and not m.startswith("__")
               and m not in defined and m not in data_attributes}
    assert not missing, f"called but never defined: {sorted(missing)}"


def test_each_tool_has_its_own_folder(tmp_path: Path) -> None:
    settings = Settings(workspace=str(tmp_path / "ws"))
    assert settings.cylr_dir.name == "cylr"
    assert settings.hayabusa_dir.name == "hayabusa"
    assert settings.thor_dir.name == "thor"
    assert len(settings.tool_dirs) == 3


def test_tools_are_found_in_their_own_folder(tmp_path: Path) -> None:
    """A tool in its dedicated folder wins over a stray copy elsewhere."""
    settings = Settings(workspace=str(tmp_path / "ws"))
    for directory in (settings.root, settings.tools_dir, *settings.tool_dirs):
        directory.mkdir(parents=True, exist_ok=True)
    (settings.tools_dir / "CyLR.exe").write_bytes(b"stray")
    (settings.cylr_dir / "CyLR.exe").write_bytes(b"correct")

    case = Case(settings, EventBus())
    assert case.find_cylr().parent == settings.cylr_dir


def test_timeline_command_is_unchanged(workspace: Settings) -> None:
    """Guard against a translation pass mangling the Hayabusa invocation."""
    import inspect

    source = inspect.getsource(Case.step_timeline)
    for fragment in ('"-d", str(logs)', '"-o", str(settings.timeline_csv)',
                     '"--no-wizard", "--RFC-3339", "--UTC"', '"-r", str(rules)'):
        assert fragment in source, f"missing from the command: {fragment}"


# --- risk model -----------------------------------------------------------
def test_score_components_are_capped_and_sum_to_total() -> None:
    """No single axis can carry the whole score on its own."""
    report = timeline.TimelineReport()
    # A single rule firing 3000 times must not reach the same verdict as a
    # genuine multi-stage intrusion.
    report.levels = Counter({"medium": 3000})
    breakdown = report.score_breakdown()

    severity = next(c for c in breakdown["components"] if c["name"] == "Severity")
    assert severity["value"] == severity["max"]
    assert breakdown["score"] == sum(c["value"] for c in breakdown["components"])
    assert breakdown["score"] <= 100
    # Volume alone, with no corroboration, stays below "confirmed".
    assert breakdown["confidence"] == "low"


def test_external_evidence_raises_score_and_confidence() -> None:
    report = timeline.TimelineReport()
    report.levels = Counter({"critical": 3, "high": 5})
    report.tactics = Counter({"Credential Access": 2, "Lateral Movement": 1,
                              "Impact": 1, "Discovery": 4})

    alone = report.score_breakdown()
    corroborated = report.score_breakdown({
        "malicious": 2, "suspicious": 1, "yara_alerts": 3,
        "live_connections": 2, "coverage": 70,
    })

    assert corroborated["score"] > alone["score"]
    assert alone["confidence"] == "low"
    assert corroborated["confidence"] == "high"


def test_verdict_wording_respects_confidence() -> None:
    """A high score on a single source is a lead, not a confirmation."""
    confirmed = timeline.TimelineReport.verdict_for(85, "high")
    lonely = timeline.TimelineReport.verdict_for(85, "low")
    assert "confirmed" in confirmed.lower()
    assert "confirmed" not in lonely.lower()
    assert timeline.TimelineReport.verdict_for(5, "low") == "Nothing conclusive"


# --- self-generated noise -------------------------------------------------
@pytest.mark.parametrize("text", [
    "CommandLine: C:\\DFIR\\tools\\thor\\thor64-lite.exe --nocsv -p C:\\AD",
    "Image: C:\\DFIR\\tools\\cylr\\CyLR.exe -od evidence",
    "CommandLine: hayabusa-4.0.0-win-x64.exe dfir-timeline -d Logs",
    "Effective argument list: [--path C:\\AD\\Tools]",
])
def test_own_tooling_is_not_an_alert(text: str) -> None:
    assert timeline.is_self_noise(text)


@pytest.mark.parametrize("text", [
    "CommandLine: powershell.exe -nop -w hidden -enc SQBFAFgA",
    "ProcessCreate: C:\\AD\\Tools\\Rubeus.exe kerberoast",
    "CommandLine: vssadmin.exe delete shadows /all /quiet",
])
def test_attacker_tooling_is_still_an_alert(text: str) -> None:
    assert not timeline.is_self_noise(text)


def test_self_noise_is_counted_apart(tmp_path: Path) -> None:
    """Excluded events are reported, never silently dropped."""
    path = tmp_path / "t.csv"
    path.write_text(
        "Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details\n"
        "2026-08-07T09:00:00+00:00,Suspicious Process,critical,PC,Security,4688,1,"
        "CommandLine: C:\\DFIR\\tools\\thor\\thor64-lite.exe --nocsv\n"
        "2026-08-07T09:01:00+00:00,Credential Dumping,critical,PC,Security,4688,2,"
        "CommandLine: mimikatz.exe sekurlsa::logonpasswords\n",
        encoding="utf-8",
    )
    report = timeline.analyse_csv(path).to_dict()
    assert report["total"] == 1
    assert report["self_noise"] == 1
    assert len(report["findings"]) == 1


# --- alert counts must match the table ------------------------------------
def test_family_counts_match_the_alert_list(tmp_path: Path) -> None:
    """A family badge must never promise rows the analyst cannot find."""
    csv_path = build_demo_timeline(tmp_path / "t.csv")
    report = timeline.analyse_csv(csv_path).to_dict()

    total_families = sum(c["count"] for c in report["categories"])
    assert total_families == len(report["findings"])

    from collections import Counter as _Counter
    per_family = _Counter(f["category"] for f in report["findings"])
    for entry in report["categories"]:
        assert entry["count"] == per_family.get(entry["id"], 0), entry["id"]


def test_alerts_are_not_truncated(tmp_path: Path) -> None:
    """Every critical/high/medium event reaches the list — no arbitrary cap."""
    header = "Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details\n"
    rows = "".join(
        f"2026-08-07T09:{i % 60:02d}:00+00:00,Rule {i},high,PC,Security,4688,{i},detail {i}\n"
        for i in range(900)
    )
    path = tmp_path / "big.csv"
    path.write_text(header + rows, encoding="utf-8")

    report = timeline.analyse_csv(path).to_dict()
    assert report["levels"]["high"] == 900
    assert len(report["findings"]) == 900
    assert sum(c["count"] for c in report["categories"]) == 900


# --- branding -------------------------------------------------------------
def test_product_name_is_consistent() -> None:
    """The name appears in four places; they must not drift apart."""
    from dfirconsole import APP_FULL_NAME, APP_NAME

    assert APP_NAME == "KAGE"
    assert APP_FULL_NAME == "Kage DFIR Toolkit"

    web = Path(__file__).resolve().parents[1] / "dfirconsole" / "web"
    html = (web / "index.html").read_text(encoding="utf-8")
    assert "<title>Kage — DFIR Toolkit</title>" in html
    assert ">KAGE<" in html

    # The Python package name is deliberately unchanged: `python -m dfirconsole`
    # and every existing config keep working across the rename.
    assert (Path(__file__).resolve().parents[1] / "dfirconsole").is_dir()


def test_report_header_carries_the_name(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DFIR_CONFIG", str(tmp_path / "config.json"))
    from fastapi.testclient import TestClient

    from dfirconsole import server

    server.settings.workspace = str(tmp_path / "ws")
    server.settings.demo_mode = True
    server.case.reset()

    with TestClient(server.app) as client:
        client.post("/api/run", json={"steps": ["workspace", "collect",
                                                "timeline", "analyse"]})
        for _ in range(400):
            if not client.get("/api/state").json()["running"]:
                break
            time.sleep(0.05)

        page = client.get("/api/report.html").text
        assert "Kage DFIR Toolkit" in page
        assert "Kage · Triage report" in page


# --- default workspace tracks the launch directory -------------------------
def test_workspace_defaults_to_launch_directory(tmp_path: Path, monkeypatch) -> None:
    """A fresh config, or none at all, follows wherever the console starts."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DFIR_CONFIG", str(tmp_path / "config.json"))
    import importlib
    from dfirconsole import config as config_module

    importlib.reload(config_module)
    settings = config_module.Settings.load()
    assert settings.workspace == str(tmp_path)


def test_workspace_is_not_pinned_after_first_save(tmp_path: Path, monkeypatch) -> None:
    """Saving from folder A must not freeze the workspace when later launched
    from folder B — only an explicit override should stick."""
    import importlib
    from dfirconsole import config as config_module

    folder_a = tmp_path / "case-a"
    folder_b = tmp_path / "case-b"
    folder_a.mkdir()
    folder_b.mkdir()
    cfg = tmp_path / "config.json"
    monkeypatch.setenv("DFIR_CONFIG", str(cfg))

    monkeypatch.chdir(folder_a)
    importlib.reload(config_module)
    settings = config_module.Settings.load()
    assert settings.workspace == str(folder_a)
    settings.save()

    # Nothing concrete was pinned to disk — the default stayed "auto".
    saved = json.loads(cfg.read_text())
    assert saved["workspace"] == ""

    monkeypatch.chdir(folder_b)
    importlib.reload(config_module)
    settings_b = config_module.Settings.load()
    assert settings_b.workspace == str(folder_b)


def test_explicit_workspace_survives_a_relaunch(tmp_path: Path, monkeypatch) -> None:
    """A path the analyst actually typed is never silently discarded."""
    import importlib
    from dfirconsole import config as config_module

    folder_a = tmp_path / "case-a"
    other = tmp_path / "elsewhere"
    folder_a.mkdir()
    other.mkdir()
    cfg = tmp_path / "config.json"
    monkeypatch.setenv("DFIR_CONFIG", str(cfg))
    monkeypatch.chdir(folder_a)

    importlib.reload(config_module)
    settings = config_module.Settings.load()
    settings.workspace = str(other)
    settings.save()

    monkeypatch.chdir(folder_a)  # relaunch from the original folder
    importlib.reload(config_module)
    reloaded = config_module.Settings.load()
    assert reloaded.workspace == str(other)


def test_config_example_workspace_is_treated_as_auto(tmp_path: Path, monkeypatch) -> None:
    """config.example.json ships with "workspace": "" — copying it verbatim
    must not pin an empty path."""
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config.json"
    cfg.write_text('{"workspace": "", "case_name": "X"}')
    monkeypatch.setenv("DFIR_CONFIG", str(cfg))

    import importlib
    from dfirconsole import config as config_module

    importlib.reload(config_module)
    settings = config_module.Settings.load()
    assert settings.workspace == str(tmp_path)


# --- THOR banner never reaches the YARA view ------------------------------
@pytest.mark.parametrize("line", [
    "Info: MODULE: Startup MESSAGE: Thor Version: 10.7.29",
    "Info: MODULE: Startup MESSAGE: Thor Build: fad1e86a48b7 (2026-02-12 11:42:03)",
    "Info: MODULE: Startup MESSAGE: Run on system: student-w11",
    "Info: MODULE: Startup MESSAGE: Running as user: DOLLARCORP\\Administrator",
    "Info: MODULE: Startup MESSAGE: Netbios Domain: STUDENT-W11",
    "Info: MODULE: Startup MESSAGE: User has admin rights: yes",
    "Info: MODULE: Startup MESSAGE: Working Directory: C:\\DFIR\\dfir-console",
    "Info: MODULE: Startup MESSAGE: Thor Scan started",
    "Info: MODULE: Startup MESSAGE: Effective argument list: [--path C:\\AD --nocsv]",
    "Info: MODULE: Startup MESSAGE: Platform: Windows 11 Pro",
    "Info: MODULE: Startup MESSAGE: Platform DeepEval",
    "Info: MODULE: Startup MESSAGE: Language: en-GB, Zone: CEST",
    "Info: MODULE: Startup MESSAGE: System Uptime: 0.55 days",
    # Same messages under a different module, or with no module at all —
    # matching on MODULE alone would let these through.
    "Info: Thor Version: 10.7.29",
    "Notice: MODULE: Filescan MESSAGE: Run on system: student-w11",
    "Info: MODULE: Filescan MESSAGE: Effective argument list: [--path C:\\AD]",
    "Info: MODULE: Filescan MESSAGE: Scan took 42 seconds",
    # Banner text wins even when the line carries a file and an Alert level.
    "Alert: MODULE: Filescan MESSAGE: Thor Scan finished FILE: C:\\x SHA256: aa",
])
def test_thor_banner_is_dropped(line: str) -> None:
    assert timeline.parse_thor_line(line) is None, f"banner line kept: {line}"


@pytest.mark.parametrize("line,level", [
    ("Alert: MODULE: Filescan MESSAGE: YARA rule HKTL_Rubeus "
     "FILE: C:\\AD\\Rubeus.exe SHA256: aa11 SCORE: 100", "critical"),
    ("Warning: MODULE: Filescan MESSAGE: Suspicious filename "
     "FILE: C:\\Temp\\svchost32.exe SHA256: bb22", "high"),
    ("Notice: MODULE: Filescan MESSAGE: File checked - signed "
     "FILE: C:\\Windows\\explorer.exe SHA256: cc33", "medium"),
    ("Info: MODULE: Filescan MESSAGE: Clean "
     "FILE: C:\\Windows\\notepad.exe SHA256: dd44", "informational"),
])
def test_real_verdicts_survive_the_banner_filter(line: str, level: str) -> None:
    """Filtering the banner must not cost a single genuine verdict."""
    entry = timeline.parse_thor_line(line)
    assert entry is not None, f"verdict dropped: {line}"
    assert entry["level"] == level
    assert entry["file"]


def test_yara_view_starts_with_a_real_finding(tmp_path: Path) -> None:
    """A full THOR log must yield verdicts only — the banner never shows."""
    log = tmp_path / "thor.log"
    log.write_text(
        "Info: MODULE: Startup MESSAGE: Thor Version: 10.7.29\n"
        "Info: MODULE: Startup MESSAGE: Run on system: student-w11\n"
        "Info: MODULE: Startup MESSAGE: Working Directory: C:\\DFIR\n"
        "Info: MODULE: Startup MESSAGE: Effective argument list: [--nocsv]\n"
        "Alert: MODULE: Filescan MESSAGE: YARA rule HKTL_Rubeus "
        "FILE: C:\\AD\\Rubeus.exe SHA256: aa11 SCORE: 100\n"
        "Info: MODULE: Filescan MESSAGE: Clean FILE: C:\\ok.exe SHA256: bb22\n"
        "Info: MODULE: Startup MESSAGE: Scan took 42 seconds\n",
        encoding="utf-8",
    )
    result = timeline.parse_thor_log(log)
    assert len(result["entries"]) == 2
    assert result["entries"][0]["message"].startswith("YARA rule")
    assert all(entry["file"] for entry in result["entries"])


# --- secrets never reach the repository ------------------------------------
def test_gitignore_covers_every_secret_shape() -> None:
    """The template is tracked; anything holding real values is not.

    A .bak or .local copy of the key file leaks exactly as badly as the
    original, so the patterns are deliberately wide.
    """
    root = Path(__file__).resolve().parents[1]
    rules = (root / ".gitignore").read_text(encoding="utf-8")

    for pattern in ("apikeys.env", "apikeys.env.*", ".env", "*.key", "*.pem",
                    "*.lic", "config.json"):
        assert pattern in rules, f"missing from .gitignore: {pattern}"

    # The template must stay tracked, or nobody knows which variables exist.
    assert "!apikeys.env.example" in rules
    assert (root / "apikeys.env.example").is_file()


def test_key_template_holds_no_value() -> None:
    """Shipping a filled-in template is how credentials leak by accident."""
    root = Path(__file__).resolve().parents[1]
    template = (root / "apikeys.env.example").read_text(encoding="utf-8")

    for line in template.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        # AI_PROVIDER carries a default; every credential must be empty.
        if name.strip().upper() in {"AI_PROVIDER"}:
            continue
        assert not value.strip(), f"{name.strip()} ships with a value"

    # Every variable the loader understands should be documented here.
    for variable in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "AI_PROVIDER",
                     "AI_API_KEY", "AI_MODEL"):
        assert variable in template, f"{variable} missing from the template"


def test_no_secret_file_ships_in_the_tree() -> None:
    """Guard against a real key file being packaged by mistake."""
    root = Path(__file__).resolve().parents[1]
    for name in ("apikeys.env", ".env", "config.json"):
        assert not (root / name).exists(), f"{name} must not ship"
    assert not list(root.rglob("*.lic")), "a THOR licence must not ship"
