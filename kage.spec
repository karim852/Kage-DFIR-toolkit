# PyInstaller build for Kage DFIR Toolkit — one self-contained executable.
#
#     pip install -r requirements.txt pyinstaller
#     pyinstaller kage.spec            ->  dist/kage.exe  (dist/kage on Linux)
#
# What is inside: the console, its web interface and fonts, the disk-image
# engine (dissect) and the WinRM client for remote hosts (pypsrp). What stays outside, next to the executable: config.json,
# apikeys.env and the tools/ folder — CyLR and Hayabusa download themselves on
# first use, THOR Lite is placed by hand (Nextron's licence forbids bundling).

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH)
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "build_support"))
from dfirconsole import APP_FULL_NAME, __version__  # noqa: E402

hiddenimports = (
    collect_submodules("uvicorn")
    # dissect loads its loaders, containers and plugins by name at run time.
    + collect_submodules("dissect")
    + collect_submodules("flow.record")
    # Remote triage: WinRM client and its authentication back-ends.
    + collect_submodules("pypsrp")
    + collect_submodules("spnego")
    + ["dfirconsole.preflight", "dfirconsole.server", "dfirconsole.cli"]
)

datas = [
    (str(ROOT / "dfirconsole" / "web"), "dfirconsole/web"),
    (str(ROOT / "LICENSE"), "."),
]
# dissect.target finds its plugins by walking its own folder for .py files.
# Frozen, that folder does not exist unless the sources ship as data.
datas += collect_data_files("dissect.target", include_py_files=True)
# pypsrp reads its PowerShell helper scripts from its package folder.
datas += collect_data_files("pypsrp")

icon = ROOT / "build_support" / "kage.ico"
version_file = None
if sys.platform == "win32":
    from version_info import write_version_file  # noqa: E402  (build_support/)

    version_file = write_version_file(ROOT / "build" / "kage-version.txt",
                                      __version__, APP_FULL_NAME)

a = Analysis(
    [str(ROOT / "kage.py")],
    pathex=[str(ROOT), str(ROOT / "build_support")],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "PIL", "pytest",
              "playwright", "IPython"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="kage",
    console=True,                 # the window shows the URL and keeps Kage alive
    icon=str(icon) if icon.exists() else None,
    version=str(version_file) if version_file else None,
    upx=False,                    # UPX-packed binaries trip antivirus heuristics
    runtime_tmpdir=None,
)
