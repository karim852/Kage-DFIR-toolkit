"""Every evidence source, same evidence, same results — with the real Hayabusa.

    python tests/e2e_sources.py --hayabusa <folder with hayabusa + rules> \\
                                --logs <folder of real .evtx> [--images <folder>]

Local-only: it needs a Hayabusa build and real attack logs (for instance the
hayabusa-sample-evtx repository), which the repository does not ship.

One host, reached seven ways:

  collector   CyLR on the machine itself (a stand-in CyLR zips the host's logs)
  live        logs read in place, system context from local commands
  custom      a folder of .evtx
  remote      CyLR pushed and run over WinRM (simulated host)
  image       the same disk as E01, VMDK, VHDX, VHD, QCOW2, VDI and raw
              (from --images, or built here when qemu-img is available)

Every source runs collect → system → timeline → analyse. The script then
checks that the score, the alert counts per level, the alert families, the
indicators and the event count are identical everywhere, and that the system
context is identical for the three ways of reaching a running host.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from dfirconsole import config, pipeline, remote, sysinfo  # noqa: E402
from dfirconsole.bus import EventBus  # noqa: E402
from dfirconsole.config import Settings  # noqa: E402
from dfirconsole.pipeline import Case  # noqa: E402
import simulated_host  # noqa: E402

FAKE_CYLR = """#!/usr/bin/env python3
# Stand-in for CyLR.exe on Linux: zips the simulated host's logs the way CyLR does.
import sys, zipfile, pathlib
args = sys.argv[1:]
out = pathlib.Path(args[args.index("-od") + 1]) / args[args.index("-of") + 1]
drive = pathlib.Path({drive!r})
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for f in sorted(drive.glob("Windows/System32/winevt/Logs/*.evtx")):
        z.write(f, "C/" + f.relative_to(drive).as_posix())
print("CyLR stand-in: archive written to", out)
"""


def summary(case: Case) -> dict:
    report = case.report or {}
    return {
        "score": report.get("risk_score"),
        "events": report.get("total"),
        "levels": report.get("levels"),
        "families": sorted((c.get("id"), c.get("count")) for c in report.get("categories", [])
                           if isinstance(c, dict)),
        "indicators": len(report.get("iocs") or []),
        "coverage": ((case.system or {}).get("coverage") or {}).get("score"),
    }


def system_view(case: Case) -> dict:
    return {k: v for k, v in (case.system or {}).items()
            if k not in ("collected_at", "source", "root_path")}


async def run_source(name: str, work: Path, hayabusa: Path, profile: Path, logs: Path,
                     image: Path | None = None) -> Case:
    workspace = work / name
    settings = Settings(workspace=str(workspace), demo_mode=False, case_name=f"E2E-{name}",
                        ai_provider="none", remote_host="WS-FINANCE-07")
    shutil.copytree(hayabusa, settings.hayabusa_dir)
    for binary in settings.hayabusa_dir.glob("hayabusa*"):
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    case = Case(settings, EventBus())
    local = simulated_host.LocalHost(profile, fallback=case.probe)

    if name == "collector":
        settings.logs_source = "collector"
        cylr = settings.cylr_dir / "CyLR.exe"
        cylr.parent.mkdir(parents=True, exist_ok=True)
        cylr.write_text(FAKE_CYLR.format(drive=str(profile / "C")))
        cylr.chmod(0o755)
    elif name == "live":
        settings.logs_source = "live"
        pipeline.LIVE_LOGS = profile / "C" / "Windows" / "System32" / "winevt" / "Logs"
    elif name == "custom":
        settings.logs_source = "custom"
        settings.logs_path = str(logs)
    elif name == "remote":
        settings.logs_source = "remote"
        cylr = settings.cylr_dir / "CyLR.exe"
        cylr.parent.mkdir(parents=True, exist_ok=True)
        cylr.write_bytes(b"MZ CyLR pushed to the simulated host")
    else:
        settings.logs_source = "image"
        settings.image_path = str(image)

    if name in ("collector", "live", "custom"):
        # A running host reached locally: Windows commands answered by the profile.
        pipeline.IS_WINDOWS = True
        case.probe = local.probe
        sysinfo.analyse_root = lambda drive: local.root_entries()
    await case.run(["workspace", "collect", "system", "timeline", "analyse"])
    pipeline.IS_WINDOWS = config.IS_WINDOWS
    return case


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hayabusa", type=Path, required=True)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--images", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp(prefix="kage-e2e-"))
    profile = simulated_host.build_profile(work / "host", args.logs)
    os.environ[remote.SIMULATION_ENV] = str(profile)
    original_root, original_live = sysinfo.analyse_root, pipeline.LIVE_LOGS

    images: dict[str, Path] = {}
    if args.images:
        for path in sorted(args.images.iterdir()):
            images[path.suffix.lower().lstrip(".")] = path

    sources = ["collector", "live", "custom", "remote", *[f"image-{k}" for k in images]]
    results: dict[str, dict] = {}
    systems: dict[str, dict] = {}
    failures: list[str] = []
    for name in sources:
        image = images.get(name.split("-", 1)[1]) if name.startswith("image-") else None
        case = asyncio.run(run_source(name, work, args.hayabusa, profile, args.logs, image))
        sysinfo.analyse_root, pipeline.LIVE_LOGS = original_root, original_live
        statuses = {s: case.steps[s].status for s in ("collect", "system", "timeline", "analyse")}
        if any(v != "done" for v in statuses.values()):
            failures.append(f"{name}: {statuses} "
                            f"{[case.steps[s].message for s in statuses if statuses[s] != 'done']}")
        results[name] = summary(case)
        systems[name] = system_view(case)
        r = results[name]
        print(f"{name:14} score {r['score']!s:>4}  events {r['events']!s:>4}  "
              f"levels {r['levels']}  indicators {r['indicators']}  coverage {r['coverage']}")

    # The timeline only depends on the logs: identical for every source.
    reference = results["custom"]
    for name, result in results.items():
        diff = [k for k in ("events", "levels", "families") if result[k] != reference[k]]
        if diff:
            failures.append(f"{name}: timeline differs from the log folder on {diff}")
    # Score, indicators and coverage also use the system context. A running
    # host (collector, live, remote) has sockets and auditpol; a disk image
    # has neither. So: identical within each family.
    full = ("score", "events", "levels", "families", "indicators", "coverage")
    for family in (["collector", "live", "remote"], [n for n in results if n.startswith("image-")]):
        for name in family[1:]:
            diff = [k for k in full if results[name][k] != results[family[0]][k]]
            if diff:
                failures.append(f"{name} differs from {family[0]} on {diff}")
    for name in ("live", "remote"):
        if systems[name] != systems["collector"]:
            changed = [k for k in systems[name] if systems[name].get(k) != systems["collector"].get(k)]
            failures.append(f"system context of {name} differs from collector on {changed}")

    print()
    if failures:
        print("FAILURES:")
        for failure in failures:
            print("  ", failure)
    else:
        print(f"Same results from all {len(results)} sources.")
    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    else:
        print(f"Workspaces kept in {work}")
    (Path(tempfile.gettempdir()) / "kage-e2e-results.json").write_text(
        json.dumps({"results": results}, indent=2, default=str))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
