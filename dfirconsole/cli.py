"""Command line for Kage — the entry point of both kage.exe and `python -m`.

Options that only report something (--version, --check) are handled before
the server module is imported: importing it opens the session log, and a
check must not write anything.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    from . import APP_FULL_NAME

    parser = argparse.ArgumentParser(
        prog="kage",
        description=f"{APP_FULL_NAME} — Windows triage: live host, remote host or disk image.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="address to listen on (default: 127.0.0.1, local only)")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--demo", action="store_true", help="force demonstration mode")
    parser.add_argument("--image", metavar="PATH",
                        help="start on a disk image (E01, VMDK, VHD/VHDX, QCOW2, VDI, raw)")
    parser.add_argument("--remote", metavar="HOST",
                        help="start on a remote Windows host, collected over WinRM")
    parser.add_argument("--remote-user", metavar="USER", default="",
                        help="administrator account of the remote host (DOMAIN\\user or "
                             ".\\user); empty = the current Windows session. The password "
                             "is asked once, or read from KAGE_REMOTE_PASSWORD")
    parser.add_argument("--check", action="store_true",
                        help="check the environment (rights, tools, keys) and exit")
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    browser = parser.add_mutually_exclusive_group()
    browser.add_argument("--browser", dest="browser", action="store_true", default=None,
                         help="open the console in the default browser")
    browser.add_argument("--no-browser", dest="browser", action="store_false",
                         help="do not open a browser")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if args.version:
        from . import APP_FULL_NAME, __version__

        print(f"{APP_FULL_NAME} {__version__}")
        return
    if args.check:
        from .preflight import main as preflight

        raise SystemExit(preflight([]))
    if args.image and args.remote:
        parser.error("choose --image or --remote, not both")
    if args.image and not Path(args.image).expanduser().is_file():
        parser.error(f"disk image not found: {Path(args.image).expanduser().resolve()}")

    if args.remote_user and not args.remote:
        parser.error("--remote-user needs --remote HOST")
    if args.remote and args.remote_user and not os.environ.get("KAGE_REMOTE_PASSWORD"):
        import getpass

        # Asked once, kept in memory for the session, never written.
        try:
            os.environ["KAGE_REMOTE_PASSWORD"] = getpass.getpass(
                f"Password for {args.remote_user} on {args.remote}: ")
        except (EOFError, KeyboardInterrupt):
            parser.error("no terminal to ask the password in: set KAGE_REMOTE_PASSWORD, "
                         "or type it in Settings once the console is open")

    from .server import serve

    serve(args)


if __name__ == "__main__":  # pragma: no cover
    main()
