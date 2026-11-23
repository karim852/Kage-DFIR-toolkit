"""Remote triage, on a simulated Windows host (tests/fixtures/simulated_host.py).

The point of these tests: the same host, reached remotely or locally, gives
the same evidence and the same system context.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from dfirconsole import config, pipeline, remote, sysinfo  # noqa: E402
from dfirconsole.bus import EventBus  # noqa: E402
from dfirconsole.config import Settings  # noqa: E402
from dfirconsole.pipeline import Case  # noqa: E402
import simulated_host  # noqa: E402

E01 = ROOT / "tests" / "fixtures" / "kage-fixture.E01"


def _digest(folder: Path) -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.glob("*.evtx"))}


@pytest.fixture(scope="module")
def fixture_logs(tmp_path_factory) -> Path:
    """The fixture disk's event logs, so every source starts from the same files."""
    dissect = pytest.importorskip("dissect.target")  # noqa: F841
    from dfirconsole import image

    out = tmp_path_factory.mktemp("logs")
    image.extract(image.open_image(E01), out)
    return out / "Logs"


@pytest.fixture
def host(tmp_path: Path, fixture_logs: Path, monkeypatch) -> Path:
    profile = simulated_host.build_profile(tmp_path / "host", fixture_logs)
    monkeypatch.setenv(remote.SIMULATION_ENV, str(profile))
    return profile


@pytest.fixture
def remote_case(tmp_path: Path):
    def build(**overrides) -> Case:
        settings = Settings(workspace=str(tmp_path / "ws"), demo_mode=False,
                            case_name="RMT-TEST", logs_source="remote",
                            remote_host="WS-FINANCE-07", ai_provider="none", **overrides)
        cylr = settings.cylr_dir / "CyLR.exe"
        cylr.parent.mkdir(parents=True, exist_ok=True)
        cylr.write_bytes(b"MZ simulated CyLR")
        return Case(settings, EventBus())
    return build


# --- helpers --------------------------------------------------------------
def test_native_commands_travel_through_powershell() -> None:
    script = remote.as_powershell(["netstat", "-ano"])
    assert script.startswith("$ErrorActionPreference")
    assert "& 'netstat' '-ano' 2>&1 | Out-String" in script
    assert remote.split_exit_code("line\n__KAGE_RC__=3") == (3, "line")
    assert remote.split_exit_code("no marker") == (0, "no marker")
    # A PowerShell command line is sent as its own script, untouched.
    assert remote.as_powershell(["powershell", "-NoProfile", "-Command", "Get-Date"]) == "Get-Date"
    assert remote.ps_quote("it's") == "'it''s'"


def test_root_listing_parser() -> None:
    text = json.dumps([{"Name": "Tools", "is_dir": True, "created": 1763510400}])
    assert remote.parse_listing(text) == [{"name": "Tools", "is_dir": True, "created": 1763510400}]
    assert remote.parse_listing(json.dumps({"Name": "x", "is_dir": False, "created": 1}))[0]["name"] == "x"
    assert remote.parse_listing("not json") == []


# --- the chain --------------------------------------------------------------
def test_remote_collection_end_to_end(remote_case, host: Path, fixture_logs: Path) -> None:
    case = remote_case()
    asyncio.run(case.run(["workspace", "collect", "system"]))

    collect = case.steps["collect"]
    assert collect.status == "done", collect.message
    assert "verified" in collect.message
    # Exactly the files that sit on the host, byte for byte.
    assert _digest(case.logs_dir) == _digest(fixture_logs)

    record = case.remote
    assert record["hostname"] == "WS-FINANCE-07"
    assert record["cleaned"] is True
    assert len(record["archive_sha256"]) == 64
    archive = case.settings.evidence_dir / record["archive"]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == record["archive_sha256"]
    manifest = json.loads((case.settings.output_dir / "RMT-TEST-remote-manifest.json").read_text())
    assert manifest["cylr_sha256"] == hashlib.sha256(b"MZ simulated CyLR").hexdigest()
    assert "RMT-TEST-remote-manifest.json" in collect.seal_basis

    from dfirconsole import report
    label = report._evidence_label(case.settings, case)
    assert label.startswith("Remote host · WS-FINANCE-07 over WinRM")
    assert record["archive_sha256"][:16] in label

    # Nothing left behind on the target.
    assert not (host / "C" / "Windows" / "Temp" / "Kage-RMT-TEST").exists()

    system = case.system
    assert case.steps["system"].status == "done", case.steps["system"].message
    assert system["source"] == "remote"
    assert system["host"]["hostname"] == "WS-FINANCE-07"
    # UTC instants and release name, like the disk-image path gives them.
    host_info = system["host"]
    assert host_info["install_date"] == "2025-01-01T00:00:00+00:00"
    assert host_info["os_version"] == "10.0.19045 (22H2)"
    assert host_info["timezone"] == "W. Europe Standard Time"
    accounts = {a["name"]: a for a in system["users"]}
    # The SID arrives as an object, the RID is still read.
    assert "built-in administrator account" in accounts["Administrator"]["flags"]
    assert accounts["Domain Admins"]["admin"] is True
    c2 = next(c for c in system["connections"] if c["remote_ip"] == "45.155.205.233")
    assert c2["process"] == "update.exe" and c2["remote_port"] == 8443
    flagged = {e["name"] for e in system["root_entries"]}
    assert {"Tools", "Temp", "PerfLogs"} <= flagged
    security = next(r for r in system["coverage"]["channels"] if r["label"] == "Security")
    assert security["records"] == 4821


def test_live_and_remote_capture_agree(remote_case, host: Path, fixture_logs: Path,
                                       monkeypatch, tmp_path: Path) -> None:
    """The same host, captured live and captured remotely: same context."""
    remote_run = remote_case()
    asyncio.run(remote_run.run(["collect", "system"]))

    local = simulated_host.LocalHost(host)
    live = Case(Settings(workspace=str(tmp_path / "live"), demo_mode=False,
                         logs_source="custom", logs_path=str(fixture_logs),
                         ai_provider="none"), EventBus())
    monkeypatch.setattr(pipeline, "IS_WINDOWS", True)
    monkeypatch.setattr(live, "probe", local.probe)
    monkeypatch.setattr(sysinfo, "analyse_root", lambda drive: local.root_entries())
    asyncio.run(live.run(["collect", "system"]))
    assert live.steps["system"].status == "done", live.steps["system"].message

    def comparable(context: dict) -> dict:
        # root_path names the drive the console runs from: "C:\\" on
        # Windows, "/" for this test on Linux. Everything else must match.
        return {k: v for k, v in context.items()
                if k not in ("collected_at", "source", "root_path")}

    assert comparable(live.system) == comparable(remote_run.system)
    assert _digest(live.logs_dir) == _digest(remote_run.logs_dir)


def test_same_logs_from_image_and_remote(remote_case, host: Path) -> None:
    """Dead disk and remote host carrying the same logs feed Hayabusa the
    same bytes, so the timeline cannot differ."""
    pytest.importorskip("dissect.target")
    case = remote_case()
    asyncio.run(case.run(["collect"]))
    image_case = Case(Settings(workspace=str(Path(case.settings.workspace).parent / "img"),
                               demo_mode=False, logs_source="image", image_path=str(E01),
                               ai_provider="none"), EventBus())
    asyncio.run(image_case.run(["collect"]))
    assert _digest(image_case.logs_dir) == _digest(case.logs_dir)


# --- failures ---------------------------------------------------------------
def test_account_without_admin_rights_is_refused(remote_case, host: Path) -> None:
    meta = json.loads((host / "host.json").read_text())
    (host / "host.json").write_text(json.dumps({**meta, "admin": False}))
    case = remote_case()
    asyncio.run(case.run(["collect"]))
    assert case.steps["collect"].status == "failed"
    assert "without administrator rights" in case.steps["collect"].message


def test_unreachable_host_fails_clearly(remote_case, host: Path) -> None:
    meta = json.loads((host / "host.json").read_text())
    (host / "host.json").write_text(json.dumps({**meta, "unreachable": True}))
    case = remote_case()
    asyncio.run(case.run(["collect", "system"]))
    assert case.steps["collect"].status == "failed"
    assert "no WinRM answer" in case.steps["collect"].message
    # Like any failed collection, the chain stops there.
    assert case.steps["system"].status == "pending"


def test_damaged_transfer_is_caught_and_cleaned_up(remote_case, host: Path, monkeypatch) -> None:
    original = remote.SimulatedTransport.get

    def corrupt(self, source, local, progress=None):
        original(self, source, local, progress)
        with open(local, "r+b") as handle:
            handle.seek(10)
            handle.write(b"\xff\xff")

    monkeypatch.setattr(remote.SimulatedTransport, "get", corrupt)
    case = remote_case()
    asyncio.run(case.run(["collect"]))
    assert case.steps["collect"].status == "failed"
    assert "damaged in transit" in case.steps["collect"].message
    assert not (host / "C" / "Windows" / "Temp" / "Kage-RMT-TEST").exists()


def test_missing_host_name_is_explained(remote_case, monkeypatch) -> None:
    monkeypatch.delenv(remote.SIMULATION_ENV, raising=False)
    case = remote_case()
    case.settings.remote_host = ""
    asyncio.run(case.run(["collect"]))
    assert case.steps["collect"].status == "failed"
    assert "no host name is set" in case.steps["collect"].message


def test_steps_describe_the_remote_host(remote_case) -> None:
    case = remote_case()
    case._refresh_step_hints()
    assert "WS-FINANCE-07" in case.steps["collect"].hint
    assert case.steps["collect"].admin is False
    assert "WinRM" in case.steps["collect"].hint


# --- secrets ----------------------------------------------------------------
def test_password_is_never_written(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(config, "KEYS_PATH", tmp_path / "apikeys.env")
    settings = Settings(workspace=str(tmp_path), remote_host="pc1", remote_user=".\\admin",
                        remote_password="S3cret!")
    settings.save()
    saved = (tmp_path / "config.json").read_text()
    assert "S3cret!" not in saved and "remote_password" not in saved
    public = settings.public()
    assert public["remote_password_set"] is True
    assert "S3cret!" not in json.dumps(public)


# --- the real transport, against a stand-in pypsrp client --------------------
class _FakeClient:
    scripts: list[str] = []

    def __init__(self, server, **options):
        self.server, self.options = server, options

    def execute_ps(self, script):
        _FakeClient.scripts.append(script)
        if "netstat" in script:
            return "Active Connections\n__KAGE_RC__=0", None, False
        raise ConnectionError("Max retries exceeded with url: /wsman")


def test_winrm_transport_uses_negotiate_and_explains_errors(monkeypatch) -> None:
    pytest.importorskip("pypsrp")
    import pypsrp.client

    monkeypatch.setattr(pypsrp.client, "Client", _FakeClient)
    transport = remote.WinRMTransport("pc1", username="ACME\\ir", password="x")
    assert transport.run(["netstat", "-ano"]) == (0, "Active Connections")
    options = transport._client.options
    assert options["auth"] == "negotiate" and options["port"] == 5985
    assert options["username"] == "ACME\\ir"
    assert transport.label == "WinRM HTTP:5985"
    with pytest.raises(remote.RemoteError, match="Enable-PSRemoting"):
        transport.run(["powershell", "-NoProfile", "-Command", "Get-Date"])

    # No account given: the current Windows session authenticates, no password sent.
    implicit = remote.WinRMTransport("pc1", ssl=True)
    implicit.run(["netstat", "-ano"])
    assert "username" not in implicit._client.options
    assert implicit._client.options["port"] == 5986
