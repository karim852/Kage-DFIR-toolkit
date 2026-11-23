"""Environment check before a live run.

    kage.exe --check                 # from the executable
    python preflight.py              # from the sources
    python preflight.py D:\\CASE42  # check another workspace
"""

from __future__ import annotations

import ctypes
import importlib.util
import os
import platform
import shutil
import sys
from pathlib import Path

from .config import HAYABUSA_BIN, Settings

OK, WARN, BAD = "  [ok]   ", "  [!]    ", "  [X]    "
problems: list[str] = []
warnings: list[str] = []


def check(condition: bool, label: str, fix: str = "", blocking: bool = True) -> bool:
    if condition:
        print(OK + label)
        return True
    print((BAD if blocking else WARN) + label + (f"\n           → {fix}" if fix else ""))
    (problems if blocking else warnings).append(label)
    return False


def is_admin() -> bool:
    if platform.system() != "Windows":
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    problems.clear()
    warnings.clear()
    argv = sys.argv[1:] if argv is None else argv
    workspace = Path(argv[0]) if argv else Settings.load().root
    settings = Settings.load()
    settings.workspace = str(workspace)

    print(f"\nWorkspace   : {workspace}")
    print(f"System      : {platform.system()} {platform.release()}")
    print(f"Python      : {sys.version.split()[0]}\n")

    print("Dependencies")
    for module in ("fastapi", "uvicorn", "httpx", "pydantic"):
        check(importlib.util.find_spec(module) is not None, f"module {module}",
              "pip install -r requirements.txt")
    # Only the disk-image source needs dissect; live triage works without it.
    check(importlib.util.find_spec("dissect") is not None
          and importlib.util.find_spec("dissect.target") is not None,
          "module dissect.target (disk images)",
          "pip install dissect.target — only needed for E01/VMDK/VHDX/raw images",
          blocking=False)

    check(importlib.util.find_spec("pypsrp") is not None,
          "module pypsrp (remote hosts over WinRM)",
          "pip install pypsrp — only needed for remote triage", blocking=False)

    print("\nRights and disk space")
    check(is_admin(), "console running as administrator",
          "the collector, the Defender exclusion and THOR all need it", blocking=False)
    check(sys.version_info >= (3, 10), "Python 3.10 or newer")
    if workspace.exists():
        free = shutil.disk_usage(workspace).free / (1024 ** 3)
        check(free >= 10, f"free space: {free:.1f} GB",
              "a collection easily reaches several GB", blocking=False)

    print("\nFolder tree")
    # A first launch has no tree yet: one line says so instead of six caveats.
    folders = (settings.root, settings.tools_dir, settings.evidence_dir,
               settings.output_dir, *settings.tool_dirs)
    missing = [d for d in folders if not d.is_dir()]
    if len(missing) == len(folders) or (missing and settings.root not in missing
                                         and not settings.tools_dir.is_dir()):
        print(OK + "not prepared yet: the \"Prepare the workspace\" step creates it")
    else:
        for directory in folders:
            check(directory.is_dir(), str(directory),
                  f"mkdir {directory} — or run the \"Prepare the workspace\" step",
                  blocking=False)

    print("\nEvidence source")
    source = settings.logs_source
    if source == "image":
        image = Path(settings.image_path.strip().strip('"')) if settings.image_path else None
        check(image is not None and image.is_file(),
              f"disk image{': ' + str(image) if image else ''}",
              "set the image path in Settings, or start with --image <file>",
              blocking=False)
    elif source == "remote":
        check(bool(settings.remote_host), f"remote host{': ' + settings.remote_host if settings.remote_host else ''}"
              f"{' as ' + settings.remote_user if settings.remote_user else ''}",
              "set the host in Settings, or start with --remote <host>", blocking=False)
        print("  [i]    to test it now: Settings → Test connection in the console")
    elif source == "custom":
        logs = Path(settings.logs_path) if settings.logs_path else None
        check(logs is not None and logs.is_dir(), f"log folder{': ' + str(logs) if logs else ''}",
              "set the folder of .evtx files in Settings", blocking=False)
    else:
        print(OK + {"collector": "live host, collected with CyLR",
                    "live": "live host, logs read in place"}.get(source, source))
        if platform.system() != "Windows":
            check(False, "live triage on this system",
                  "live collection needs Windows; on Linux use a disk image or a log folder",
                  blocking=False)

    print("\nTooling")
    if settings.logs_source in ("collector", "remote"):
        cylr = next(iter(settings.cylr_dir.glob("CyLR*.exe")), None)
        check(cylr is not None, f"CyLR in {settings.cylr_dir}",
              "the \"Locate the tooling\" step downloads it", blocking=False)
    hayabusa = next((f for pattern in (HAYABUSA_BIN, "hayabusa*.exe")
                     for f in settings.hayabusa_dir.glob(pattern) if f.is_file()), None)
    check(hayabusa is not None, f"Hayabusa in {settings.hayabusa_dir}",
          "the \"Locate the tooling\" step downloads it", blocking=False)

    # Sigma rules: the classic trap is that they land wherever update-rules ran.
    candidates = [settings.tools_dir / "rules", settings.root / "rules",
                  Path(__file__).resolve().parent / "rules", Path.cwd() / "rules"]
    found = next((c for c in candidates
                  if (c / "hayabusa").is_dir() or (c / "sigma").is_dir()), None)
    check(found is not None, f"Sigma rules{': ' + str(found) if found else ''}",
          "the \"Update the Sigma rules\" step fetches them",
          blocking=False)

    names = ("thor64-lite.exe", "thor-lite.exe")
    roots = [settings.thor_dir, settings.tools_dir, settings.root,
             Path(__file__).resolve().parent]
    thor = next((root / name for root in roots for name in names
                 if (root / name).exists()), None)
    if thor is None:
        for root in roots:
            if root.exists():
                thor = next((f for name in names for f in root.rglob(name)), None)
                if thor:
                    break
    check(thor is not None, f"THOR Lite{': ' + str(thor) if thor else ''}",
          "optional step — it will simply be skipped", blocking=False)
    if thor:
        licence = next(iter(thor.parent.glob("*.lic")), None)
        check(licence is not None, "THOR licence file (*.lic)",
              "THOR refuses to start without a licence", blocking=False)

    print("\nEnrichment and summary")
    for label, value in (("VirusTotal", settings.virustotal_key),
                         ("AbuseIPDB", settings.abuseipdb_key)):
        check(bool(value), f"{label} key",
              "set it in Settings — otherwise indicators stay unchecked", blocking=False)
    # The summary always gets written: locally when no provider is chosen.
    from .ai import PROVIDERS
    provider = (settings.ai_provider or "").lower()
    spec = None if provider in ("aucun", "local", "") else PROVIDERS.get(provider)
    if spec is None or spec["dialect"] == "local":
        print(OK + "summary written locally (no provider, nothing leaves the machine)")
    else:
        check(bool(settings.anthropic_key) or not spec.get("needs_key"),
              f"{spec['label']} key",
              "set it in Settings — otherwise the local summary is used", blocking=False)

    print()
    if problems:
        print(f"{len(problems)} blocking issue(s) to fix before running.")
        return 1
    if warnings:
        print(f"Ready, with {len(warnings)} caveat(s): the affected steps will be "
              "skipped without breaking the chain.")
    else:
        print("Environment complete. Happy hunting.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
