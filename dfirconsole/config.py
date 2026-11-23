"""Configuration of the analysis workstation.

All configuration lives in a single JSON file next to the application
(`config.json`). API keys are never returned to the browser in clear text: the
API only exposes a configured / not-configured flag and a masked preview.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
# Frozen as a single executable (PyInstaller), the code runs from a temporary
# folder deleted on exit: anything that must survive — config.json,
# apikeys.env, the tools — belongs next to the .exe instead.
FROZEN = bool(getattr(sys, "frozen", False))
PROJECT_DIR = Path(sys.executable).resolve().parent if FROZEN else APP_DIR.parent
CONFIG_PATH = Path(os.environ.get("DFIR_CONFIG", PROJECT_DIR / "config.json"))
# Key file kept separate from the rest: it can stay out of the repository, be
# copied from one workstation to another, or live on an encrypted USB stick.
KEYS_PATH = Path(os.environ.get("DFIR_KEYS", PROJECT_DIR / "apikeys.env"))

_KEY_ALIASES = {
    "virustotal_key": ("VT_API_KEY", "VIRUSTOTAL_API_KEY", "VIRUSTOTAL"),
    "abuseipdb_key": ("ABUSEIPDB_API_KEY", "ABUSEIPDB"),
    "anthropic_key": ("ANTHROPIC_API_KEY", "AI_API_KEY", "OPENAI_API_KEY"),
    "ai_model": ("AI_MODEL",),
    "ai_provider": ("AI_PROVIDER",),
    "ai_base_url": ("AI_BASE_URL", "OPENAI_BASE_URL"),
    "remote_password": ("KAGE_REMOTE_PASSWORD",),
}


def read_keyfile(path: Path = KEYS_PATH) -> dict[str, str]:
    """Read a `KEY=value` file, .env style.

    Forgiving: # comments, blank lines, quotes, spaces around the equals sign,
    and an `export` prefix for anyone recycling a shell script.
    """
    values: dict[str, str] = {}
    if not path.exists():
        return values
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return values

    raw: dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.lower().startswith("export "):
            line = line[7:]
        name, _, value = line.partition("=")
        raw[name.strip().upper()] = value.strip().strip("'\"")

    for field, aliases in _KEY_ALIASES.items():
        for alias in aliases:
            if raw.get(alias):
                values[field] = raw[alias]
                break
    return values

IS_WINDOWS = platform.system() == "Windows"

# Tools are resolved from their GitHub releases rather than a pinned URL, so a
# new upstream version does not silently break the download. The pinned URL is
# only a fallback for when the API is unreachable or rate-limited.
TOOL_SOURCES = {
    "cylr": {
        "repo": "orlikoski/CyLR",
        "asset": r"CyLR_win-x64\.zip$",
        "fallback": "https://github.com/orlikoski/CyLR/releases/download/2.2.0/CyLR_win-x64.zip",
        "binary": "CyLR.exe",
    },
    "hayabusa": {
        "repo": "Yamato-Security/hayabusa",
        # Dead-disk triage runs on Linux too, so Hayabusa follows the host OS.
        "asset": (r"hayabusa-[\d.]+-win-x64\.zip$" if IS_WINDOWS
                  else r"hayabusa-[\d.]+-lin-x64-gnu\.zip$"),
        "fallback": ("https://github.com/Yamato-Security/hayabusa/releases/download/v4.0.0/"
                     + ("hayabusa-4.0.0-win-x64.zip" if IS_WINDOWS
                        else "hayabusa-4.0.0-lin-x64-gnu.zip")),
        "binary": "hayabusa*.exe" if IS_WINDOWS else "hayabusa-*-lin-*",
    },
}
HAYABUSA_BIN = "hayabusa-*-win-x64.exe" if IS_WINDOWS else "hayabusa-*-lin-x64-*"
LIVE_LOGS = "C:\\Windows\\System32\\winevt\\Logs"

# THOR Lite is distributed after registration with Nextron, so it cannot be
# downloaded without a licence. We only detect it if dropped in manually.
THOR_HINT = "https://github.com/NextronSystems/thor-lite"


def default_workspace() -> str:
    """The directory the console was launched from.

    The tooling usually sits next to the code already; forcing an absolute path
    would mean moving everything. One exception: an executable started through
    an elevation prompt can inherit C:\\Windows\\System32 as its working
    directory — evidence must never land there, so the folder holding the
    executable is used instead.
    """
    cwd = Path.cwd()
    if FROZEN:
        system_root = Path(os.environ.get("SystemRoot", r"C:\\Windows")).resolve()
        try:
            inside_windows = cwd.resolve() == system_root or system_root in cwd.resolve().parents
        except OSError:
            inside_windows = False
        if inside_windows:
            return str(PROJECT_DIR)
    return str(cwd)


def is_admin() -> bool:
    """True when the process is elevated. CyLR, THOR and the Defender exclusion
    all depend on it."""
    if not IS_WINDOWS:
        return os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _remote_support() -> bool:
    try:
        import pypsrp.client  # noqa: F401
    except ImportError:
        return False
    return True


def _image_support() -> bool:
    try:
        import dissect.target  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass
class Settings:
    workspace: str = field(default_factory=default_workspace)
    case_name: str = "CASE-001"
    analyst: str = ""
    demo_mode: bool = not IS_WINDOWS
    virustotal_key: str = ""
    abuseipdb_key: str = ""
    # No provider until one is chosen: defaulting to Anthropic printed "no
    # Anthropic key configured" on every report of someone who never asked
    # for Anthropic.
    ai_provider: str = "none"   # anthropic | openai | groq | mistral | openrouter | ollama | custom | none
    ai_base_url: str = ""       # for any OpenAI-compatible service
    anthropic_key: str = ""
    # Empty = the provider's own default model. A fixed Claude model name here
    # was sent to Groq or Mistral as-is when the provider changed.
    ai_model: str = ""
    # collector | remote | image | live | custom — "image" opens a disk image
    # (E01, VMDK, VHD/VHDX, QCOW2, raw); "live" reads winevt\Logs in place;
    # "remote" runs the collection on another Windows host over WinRM.
    logs_source: str = "collector"
    remote_host: str = ""
    # Empty = the current Windows session (Kerberos on a domain): nothing
    # typed, nothing stored.
    remote_user: str = ""
    # Never written to config.json: kept for the session, or read from
    # apikeys.env / the KAGE_REMOTE_PASSWORD environment variable.
    remote_password: str = field(default="", repr=False)
    remote_ssl: bool = False
    image_path: str = ""
    # Size budget for executables pulled out of an image for the YARA scan.
    image_files_mb: int = 1024
    cylr_args: str = "-v"
    # Only the CSV suppression is imposed; --quick is deliberately absent
    # because it skips files the analyst explicitly pointed the scan at.
    thor_args: str = "--nocsv"
    # 0 = no limit: the analyst decides the scope of the scan and therefore
    # its duration. Sweeping C:\ legitimately takes hours.
    thor_timeout_min: int = 0
    # Empty = the artefacts collected under evidence\
    yara_path: str = ""
    logs_path: str = ""
    # 0 = no cap. Small free tiers (Groq: 12 000 tokens/min) need roughly
    # 30 000 characters or less.
    ai_max_chars: int = 0
    # 0 = every extracted indicator. Capping at an arbitrary number meant the
    # most interesting one could sit just below the cut.
    enrich_limit: int = 0
    auto_enrich: bool = True

    # --- persistence -----------------------------------------------------
    @classmethod
    def load(cls) -> "Settings":
        data = {}
        if CONFIG_PATH.exists():
            try:
                data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in data.items() if k in known}

        # An empty or missing workspace always means "wherever this was
        # launched from" — never a literal empty path. This also covers
        # config.example.json copied verbatim, which ships with "".
        if not str(clean.get("workspace") or "").strip():
            clean.pop("workspace", None)  # let the default_factory run

        settings = cls(**clean)

        # Priority order, weakest to strongest:
        # config.json  <  apikeys.env  <  environment variables.
        for field, value in read_keyfile().items():
            if field in known and value:
                setattr(settings, field, value)

        settings.virustotal_key = os.environ.get("VT_API_KEY", settings.virustotal_key)
        settings.abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", settings.abuseipdb_key)
        settings.anthropic_key = os.environ.get("ANTHROPIC_API_KEY", settings.anthropic_key)
        settings.remote_password = os.environ.get("KAGE_REMOTE_PASSWORD", settings.remote_password)
        return settings

    def save(self) -> None:
        data = asdict(self)

        # If the workspace on disk is still whatever this run would derive on
        # its own, store it as empty rather than a frozen path. Otherwise the
        # very first save pins the workspace forever, and a later launch from
        # a different folder — a different case, a different drive — keeps
        # reusing wherever the console happened to run first. Only a value
        # the analyst actually typed something different for should stick.
        if data.get("workspace", "").rstrip("\\/") == default_workspace().rstrip("\\/"):
            data["workspace"] = ""
        # A key coming from apikeys.env must not be copied into config.json,
        # otherwise it freezes there and the dedicated file loses its purpose.
        from_file = read_keyfile()
        for field in from_file:
            if field.endswith("_key") and data.get(field) == from_file[field]:
                data[field] = ""
        # An administrator password of another machine has no business in a
        # plain JSON file next to the executable.
        data.pop("remote_password", None)
        CONFIG_PATH.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # --- safe views ------------------------------------------------------
    @staticmethod
    def _preview(value: str) -> str:
        """A recognisable preview that does not disclose the key.

        Enough to confirm the right one was loaded, never enough to use it:
        start, length, end.
        """
        if not value:
            return ""
        if len(value) <= 10:
            return value[:2] + "…" + value[-1:]
        return f"{value[:5]}…{value[-4:]} ({len(value)} chars)"

    def _origins(self) -> dict[str, str]:
        """Where each key comes from — the first question asked when a key
        does not work."""
        from_file = read_keyfile()
        origins: dict[str, str] = {}
        for field, env_name in (("virustotal_key", "VT_API_KEY"),
                                ("abuseipdb_key", "ABUSEIPDB_API_KEY"),
                                ("anthropic_key", "ANTHROPIC_API_KEY")):
            value = getattr(self, field)
            if not value:
                origins[field] = ""
            elif os.environ.get(env_name) == value:
                origins[field] = "environment variable"
            elif from_file.get(field) == value:
                origins[field] = KEYS_PATH.name
            else:
                origins[field] = "config.json"
        return origins

    def public(self) -> dict:
        """Browser-safe view, no secrets."""
        return {
            "workspace": self.workspace,
            "case_name": self.case_name,
            "analyst": self.analyst,
            "demo_mode": self.demo_mode,
            "ai_provider": self.ai_provider,
            "ai_base_url": self.ai_base_url,
            "ai_model": self.ai_model,
            "logs_source": self.logs_source,
            "image_path": self.image_path,
            "image_files_mb": self.image_files_mb,
            "image_support": _image_support(),
            "remote_host": self.remote_host,
            "remote_user": self.remote_user,
            "remote_ssl": self.remote_ssl,
            "remote_password_set": bool(self.remote_password),
            "remote_support": _remote_support(),
            "cylr_args": self.cylr_args,
            "thor_args": self.thor_args,
            "thor_timeout_min": self.thor_timeout_min,
            "yara_path": self.yara_path,
            "logs_path": self.logs_path,
            "ai_max_chars": self.ai_max_chars,
            "enrich_limit": self.enrich_limit,
            "auto_enrich": self.auto_enrich,
            "keyfile": str(KEYS_PATH),
            "keyfile_present": KEYS_PATH.exists(),
            "keys": {
                "virustotal": bool(self.virustotal_key),
                "abuseipdb": bool(self.abuseipdb_key),
                "anthropic": bool(self.anthropic_key),
            },
            "key_previews": {
                "virustotal": self._preview(self.virustotal_key),
                "abuseipdb": self._preview(self.abuseipdb_key),
                "anthropic": self._preview(self.anthropic_key),
            },
            "key_origins": self._origins(),
            "platform": platform.system(),
            "python": sys.version.split()[0],
        }

    # --- paths -----------------------------------------------------------
    @property
    def root(self) -> Path:
        return Path(self.workspace)

    @property
    def tools_dir(self) -> Path:
        return self.root / "tools"

    @property
    def evidence_dir(self) -> Path:
        return self.root / "evidence"

    @property
    def output_dir(self) -> Path:
        return self.root / "output"

    @property
    def timeline_csv(self) -> Path:
        return self.output_dir / "hayabusa-output.csv"

    # One folder per tool: dropping an archive in the wrong place was costing
    # more time than the download itself.
    @property
    def cylr_dir(self) -> Path:
        return self.tools_dir / "cylr"

    @property
    def hayabusa_dir(self) -> Path:
        return self.tools_dir / "hayabusa"

    @property
    def thor_dir(self) -> Path:
        return self.tools_dir / "thor"

    @property
    def tool_dirs(self) -> tuple[Path, ...]:
        return (self.cylr_dir, self.hayabusa_dir, self.thor_dir)
