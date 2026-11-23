"""Kage DFIR Toolkit — entry point for the standalone executable.

PyInstaller freezes this script into kage.exe; from the sources it behaves
exactly like `python -m dfirconsole`.
"""

from dfirconsole.cli import main

if __name__ == "__main__":
    main()
