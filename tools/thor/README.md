# THOR Lite

YARA and IOC scanning. **This one cannot be downloaded** — Nextron requires
registration, so no automated fetch is possible.

Get the archive from <https://www.nextron-systems.com/thor-lite/>, then copy
into this folder:

- `thor64-lite.exe`
- the licence file (`*.lic`) — THOR refuses to start without it
- the `config\`, `signatures\` and `custom-signatures\` folders from the archive

**Keep them together.** THOR is launched from the directory holding its
executable and resolves its signatures relative to that directory.

Without this, the YARA step reports itself as *skipped* and the rest of the
chain carries on normally.
