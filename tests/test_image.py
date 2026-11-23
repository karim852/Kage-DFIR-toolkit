"""Dead-disk triage tests, on the committed E01 and VMDK fixtures.

The fixture is a 40 MB Windows disk built by tests/fixtures/build_fixture.py:
real NTFS, real registry hives, placeholder event logs, planted persistence.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("dissect.target")

from dfirconsole import image, sysinfo  # noqa: E402
from dfirconsole.bus import EventBus  # noqa: E402
from dfirconsole.config import Settings  # noqa: E402
from dfirconsole.pipeline import Case  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
E01 = FIXTURES / "kage-fixture.E01"
VMDK = FIXTURES / "kage-fixture.vmdk"
MACHINE_SID = "S-1-5-21-1004336348-1177238915-682003330"


@pytest.fixture(scope="module")
def e01_target():
    return image.open_image(E01)


@pytest.fixture
def image_case(tmp_path: Path):
    def build(path: Path = E01, **overrides) -> Case:
        settings = Settings(workspace=str(tmp_path / "ws"), demo_mode=False,
                            case_name="IMG-TEST", logs_source="image",
                            image_path=str(path), ai_provider="none", **overrides)
        return Case(settings, EventBus())
    return build


# --- opening -------------------------------------------------------------
@pytest.mark.parametrize("path", [E01, VMDK], ids=["E01", "VMDK"])
def test_both_formats_open_and_identify_the_host(path: Path) -> None:
    target = image.open_image(path)
    host = image.describe_host(target, path)
    assert host["hostname"] == "WS-FINANCE-07"
    assert host["os_name"] == "Windows 10 Pro"
    assert host["os_version"] == "10.0.19045 (22H2)"
    assert host["install_date"].startswith("2025-01-01")
    assert host["domain"] == "acme.local"
    assert host["timezone"] == "W. Europe Standard Time"
    assert image.describe_format(path) in host["model"]


def test_raw_image_opens(tmp_path: Path, e01_target) -> None:
    """A raw dd image: write out the disk the E01 contains and reopen it."""
    disk = e01_target.disks[0]
    raw = tmp_path / "disk.raw"
    disk.seek(0)
    with open(raw, "wb") as handle:
        while chunk := disk.read(4 * 1024 * 1024):
            handle.write(chunk)
    assert image.describe_host(image.open_image(raw), raw)["hostname"] == "WS-FINANCE-07"


@pytest.mark.skipif(shutil.which("qemu-img") is None, reason="qemu-img not installed")
@pytest.mark.parametrize("fmt", ["vhdx", "vpc", "qcow2", "vdi"])
def test_converted_images_open(tmp_path: Path, fmt: str) -> None:
    """The formats too large to commit, converted on the fly from the VMDK."""
    suffix = {"vpc": "vhd"}.get(fmt, fmt)
    disk = tmp_path / f"disk.{suffix}"
    subprocess.run(["qemu-img", "convert", "-q", "-f", "vmdk", "-O", fmt,
                    str(VMDK), str(disk)], check=True)
    assert image.describe_host(image.open_image(disk), disk)["hostname"] == "WS-FINANCE-07"


def test_missing_image_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(image.ImageError, match="Image not found"):
        image.open_image(tmp_path / "nope.E01")


def test_folder_instead_of_image_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(image.ImageError, match="is a folder"):
        image.open_image(tmp_path)


def test_image_without_windows_is_refused(tmp_path: Path) -> None:
    blank = tmp_path / "blank.raw"
    blank.write_bytes(b"\0" * (4 * 1024 * 1024))
    with pytest.raises(image.ImageError):
        image.open_image(blank)


# --- registry ------------------------------------------------------------
def test_machine_sid_comes_from_the_sam(e01_target) -> None:
    assert image.machine_sid(e01_target) == MACHINE_SID


def test_accounts_read_from_the_sam(e01_target) -> None:
    accounts = {a["name"]: a for a in image.read_accounts(e01_target)}

    assert accounts["Administrator"]["sid"] == f"{MACHINE_SID}-500"
    assert accounts["Administrator"]["enabled"] is False
    assert accounts["Administrator"]["admin"] is True
    assert "built-in administrator account" in accounts["Administrator"]["flags"]

    assert accounts["svc_backup"]["enabled"] is True
    assert accounts["svc_backup"]["admin"] is True
    assert "member of the Administrators group" in accounts["svc_backup"]["flags"]

    assert accounts["j.martel"]["admin"] is False
    assert accounts["j.martel"]["last_logon"].startswith("2026-01-01")
    assert accounts["Guest"]["enabled"] is False

    # A domain group nested into local Administrators, named, not a raw SID.
    assert accounts["Domain Admins"]["admin"] is True
    assert "non-local administrator (domain)" in accounts["Domain Admins"]["flags"]


def test_planted_persistence_is_flagged(e01_target) -> None:
    autoruns = {a["name"]: a for a in image.read_autoruns(e01_target)}
    assert autoruns["Updater"]["risk"] == "high"
    assert autoruns["Updater"]["command"] == r"C:\Users\Public\update.exe -silent"
    assert autoruns["WinUpdaterSvc"]["kind"] == "service"
    assert autoruns["WinUpdaterSvc"]["risk"] == "high"
    # The legitimate Windows entry stays unflagged.
    assert autoruns["SecurityHealth"]["risk"] == "normal"


def test_disk_root_from_the_image(e01_target) -> None:
    listing = image.root_listing(e01_target)
    flagged = {e["name"]: e for e in sysinfo.analyse_root_entries(listing)}
    assert set(flagged) == {"Tools", "Temp", "PerfLogs"}
    assert flagged["Tools"]["risk"] == "high"
    # NTFS metadata files are read from the raw volume but are not anomalies.
    assert not any(name.startswith("$") for name in flagged)


# --- extraction ----------------------------------------------------------
def test_extraction_and_manifest(tmp_path: Path, e01_target) -> None:
    result = image.extract(e01_target, tmp_path / "out", extra_roots=["Tools"])
    counts = result["counts"]
    assert counts["logs"] == 5
    assert counts["hives"] == 4
    assert counts["prefetch"] == 1
    assert counts["files"] == 6

    extracted = {e["image_path"]: e for e in result["manifest"]}
    assert r"C:\Tools\mimi.exe" in extracted
    assert r"C:\Users\j.martel\Downloads\notes.txt" not in extracted   # not executable

    # Every hash in the manifest matches the file actually written.
    for entry in result["manifest"]:
        written = (tmp_path / "out" / entry["extracted_to"]).read_bytes()
        assert hashlib.sha256(written).hexdigest() == entry["sha256"]
        assert len(written) == entry["size"]


def test_size_budget_is_respected(tmp_path: Path, e01_target) -> None:
    result = image.extract(e01_target, tmp_path / "out", files_budget_mb=0)
    assert result["counts"]["files"] == 0
    assert result["counts"]["skipped"] > 0
    assert result["counts"]["logs"] == 5          # logs are never budgeted


def test_record_counts_come_from_chunk_headers(tmp_path: Path, e01_target) -> None:
    image.extract(e01_target, tmp_path / "out")
    logs = tmp_path / "out" / "Logs"
    assert sysinfo.evtx_record_count(logs / "Security.evtx") == 4821
    assert sysinfo.evtx_record_count(logs / "Microsoft-Windows-PowerShell%4Operational.evtx") == 0
    not_evtx = tmp_path / "x.evtx"
    not_evtx.write_bytes(b"MZ" + b"\0" * 100)
    assert sysinfo.evtx_record_count(not_evtx) is None


def test_fingerprint(tmp_path: Path) -> None:
    fingerprint = image.image_fingerprint(E01)
    assert fingerprint["format"] == "EnCase (EWF)"
    assert fingerprint["segments"] == ["kage-fixture.E01"]
    assert fingerprint["sha256"] == hashlib.sha256(E01.read_bytes()).hexdigest()
    assert fingerprint["sha256_scope"] == "full file"


# --- the chain -----------------------------------------------------------
def test_image_chain_collect_and_system(image_case) -> None:
    """The real (non-demo) path: no CyLR, no elevation, no Windows needed."""
    case = image_case()
    asyncio.run(case.run(["workspace", "collect", "system"]))

    assert case.steps["collect"].status == "done", case.steps["collect"].message
    assert case.steps["system"].status == "done", case.steps["system"].message
    assert case.logs_dir is not None and case.logs_dir.name == "Logs"
    assert len(list(case.logs_dir.glob("*.evtx"))) == 5

    manifest = case.settings.output_dir / "IMG-TEST-image-manifest.json"
    data = json.loads(manifest.read_text())
    assert data["image"]["format"] == "EnCase (EWF)"
    assert data["host"]["hostname"] == "WS-FINANCE-07"
    assert "IMG-TEST-image-manifest.json" in case.steps["collect"].seal_basis

    system = case.system
    assert system["source"] == "image"
    assert system["network"]["available"] is False
    titles = [f["title"] for f in system["findings"]]
    assert "Run key persistence: Updater" in titles
    assert "Service persistence: WinUpdaterSvc" in titles
    assert "Domain principal in local Administrators: Domain Admins" in titles
    assert system["coverage"]["score"] > 0
    security = next(r for r in system["coverage"]["channels"] if r["label"] == "Security")
    assert security["verdict"] == "active" and security["records"] == 4821


def test_image_steps_describe_the_image(image_case) -> None:
    case = image_case()
    case._refresh_step_hints()
    assert case.steps["collect"].admin is False
    assert "kage-fixture.E01" in case.steps["collect"].hint
    assert case.steps["system"].admin is False
    assert "CyLR is not needed" in case.steps["tools"].hint


def test_yara_scope_is_the_extraction(image_case) -> None:
    case = image_case()
    asyncio.run(case.run(["collect"]))
    assert case._scan_target() == Path(case.image["extracted_to"])


def test_image_source_without_a_path_fails_clearly(image_case) -> None:
    case = image_case()
    case.settings.image_path = ""
    asyncio.run(case.run(["collect"]))
    assert case.steps["collect"].status == "failed"
    assert "no image path is set" in case.steps["collect"].message


def test_reset_forgets_the_image(image_case) -> None:
    case = image_case()
    asyncio.run(case.run(["collect"]))
    assert case.image is not None
    case.reset()
    assert case.image is None and case._image_target is None
