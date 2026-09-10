"""Environment check before a live run.

    python preflight.py            # checks the current workspace
    python preflight.py D:\\CASE42  # checks another workspace
"""

from __future__ import annotations

import ctypes
import importlib.util
import os
import platform
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dfirconsole.config import HAYABUSA_BIN, Settings  # noqa: E402

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


def main() -> int:
    workspace = Path(sys.argv[1]) if len(sys.argv) > 1 else Settings.load().root
    settings = Settings.load()
    settings.workspace = str(workspace)

    print(f"\nWorkspace   : {workspace}")
    print(f"System      : {platform.system()} {platform.release()}")
    print(f"Python      : {sys.version.split()[0]}\n")

    print("Dependencies")
    for module in ("fastapi", "uvicorn", "httpx", "pydantic"):
        check(importlib.util.find_spec(module) is not None, f"module {module}",
              "pip install -r requirements.txt")

    print("\nRights and disk space")
    check(is_admin(), "console running as administrator",
          "the collector, the Defender exclusion and THOR all need it", blocking=False)
    check(sys.version_info >= (3, 10), "Python 3.10 or newer")
    if workspace.exists():
        free = shutil.disk_usage(workspace).free / (1024 ** 3)
        check(free >= 10, f"free space: {free:.1f} GB",
              "a collection easily reaches several GB", blocking=False)

    print("\nFolder tree")
    for directory in (settings.root, settings.tools_dir, settings.evidence_dir,
                      settings.output_dir, *settings.tool_dirs):
        check(directory.is_dir(), str(directory),
              f"mkdir {directory} — or run the \"Prepare the workspace\" step",
              blocking=False)

    print("\nTooling")
    cylr = next(iter(settings.cylr_dir.glob("CyLR*.exe")), None)
    hayabusa = next(iter(settings.hayabusa_dir.glob("hayabusa*.exe")), None)
    check(cylr is not None, f"CyLR in {settings.cylr_dir}",
          "the \"Locate the tooling\" step downloads it", blocking=False)
    check(hayabusa is not None, f"Hayabusa in {settings.hayabusa_dir}",
          "the \"Locate the tooling\" step downloads it", blocking=False)

    # Sigma rules: the classic trap is that they land wherever update-rules ran.
    candidates = [settings.tools_dir / "rules", settings.root / "rules",
                  Path(__file__).resolve().parent / "rules", Path.cwd() / "rules"]
    found = next((c for c in candidates
                  if (c / "hayabusa").is_dir() or (c / "sigma").is_dir()), None)
    check(found is not None, f"Sigma rules{': ' + str(found) if found else ''}",
          "run update-rules — the console will find the folder wherever it is",
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

    print("\nAPI keys")
    for label, value in (("VirusTotal", settings.virustotal_key),
                         ("AbuseIPDB", settings.abuseipdb_key),
                         ("Anthropic", settings.anthropic_key)):
        check(bool(value), f"{label} key",
              "set it in Settings — otherwise the step is skipped", blocking=False)

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


if __name__ == "__main__":
    raise SystemExit(main())
