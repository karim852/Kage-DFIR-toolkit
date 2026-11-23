## What's new

**Dead-disk triage.** Point Kage at an E01, VMDK, VHD/VHDX, QCOW2, VDI or raw
image (`--image <file>` or Settings → Evidence source). It reads the event
logs, registry hives, accounts, persistence and suspicious executables straight
from the image, read-only, and writes a manifest with the SHA-256 of every file
it extracted. Works from Windows and from Linux.

**Remote triage.** Run the chain on another Windows host you administer, over
WinRM (`--remote <host>` or Settings → Evidence source → Remote host, with a
**Test connection** button). CyLR is pushed, run, fetched in chunks, checked by
SHA-256 against the host's own hash, then removed. The system context comes
from the same commands and parsers as a live capture. Password kept in memory
only. Works from the Linux build too.

**Risk score recalibrated on real attacks.** Severity counts distinct rules
instead of raw repeats, the kill chain uses each rule's own ATT&CK tags, and
only flagged sockets corroborate. On about 1 000 cases built from the public
Hayabusa samples, one technique now scores around 27, three around 49, a full
chain around 65; before, everything bigger than one technique sat on 70.
Hayabusa's UTC and RFC 3339 options were also silently dropped on version 3+
(they changed case): timelines are now really in UTC.

**One executable.** `kage.exe` carries the console, its interface and fonts, and
the disk-image engine. No Python, no install.

**Fixes found by testing every control**
- The live view could freeze on "running" when the browser fell behind a fast
  chain; it now resynchronises on its own.
- Indicators open in the reading pane like every other table.
- Enter on a table row no longer opens and closes the reader in one go.
- Report and JSON buttons stay off until there is a report.
- All times are UTC with the year, in the console, the report and the exports;
  install and boot times of a live or remote host are read as exact UTC instants.
- Live capture: the built-in Administrator (RID 500) was never recognised,
  because PowerShell serialises the SID as an object. Fixed.
- The report and the header say so when the logs name another host than the
  one examined.
- The local summary no longer claims to call an API; key fields are hidden
  when no provider is chosen.
- `--check` and `--version` write nothing; the environment check follows the
  chosen evidence source and summary provider.

## Download

| File | For |
|---|---|
| `kage-windows-x64.exe` | Windows 10 / 11 / Server — live triage and disk images |
| `kage-linux-x64` | Linux — disk images (E01, VMDK, VHD/VHDX, QCOW2, VDI, raw) and remote Windows hosts |
| `SHA256SUMS.txt` | checksums of both, to verify the download |

## First launch

1. Put `kage-windows-x64.exe` in an empty folder — everything Kage creates lands next to it.
2. Right-click → **Run as administrator** for a live triage (a disk image does not need it).
3. The console opens in your browser at `http://127.0.0.1:8787`.

CyLR and Hayabusa download themselves into `tools\` the first time they are needed.
**THOR Lite is not included** — Nextron's licence forbids redistribution. Drop the
whole THOR Lite folder (binary, `.lic` licence, `signatures\`, `config\`) into
`tools\thor\` to enable the YARA scan.

Verify the download: `certutil -hashfile kage-windows-x64.exe SHA256` and compare with `SHA256SUMS.txt`.
