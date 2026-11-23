"""Windows version resource for kage.exe (File → Properties → Details)."""

from pathlib import Path


def write_version_file(path: Path, version: str, product: str) -> Path:
    numbers = [int(p) for p in version.split(".")[:3]] + [0]
    while len(numbers) < 4:
        numbers.append(0)
    tuple_text = ", ".join(str(n) for n in numbers[:4])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({tuple_text}), prodvers=({tuple_text}),
                    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
                    date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'k0r1m'),
      StringStruct('FileDescription', '{product} — Windows triage console'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', 'kage'),
      StringStruct('LegalCopyright', 'MIT License'),
      StringStruct('OriginalFilename', 'kage.exe'),
      StringStruct('ProductName', '{product}'),
      StringStruct('ProductVersion', '{version}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding="utf-8")
    return path
