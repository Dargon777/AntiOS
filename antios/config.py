from __future__ import annotations

import os
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GeneralConfig:
    computer_name_prefix: str = "LAB"
    backup_path: str = "antios-backup.json"
    color: str = "auto"


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    file: str = ""


@dataclass(frozen=True)
class AppConfig:
    general: GeneralConfig = GeneralConfig()
    logging: LoggingConfig = LoggingConfig()

    def to_dict(self) -> dict[str, Any]:
        return {
            "general": asdict(self.general),
            "logging": asdict(self.logging),
        }


def default_config_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        return root / "AntiOS" / "antios.toml"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    root = Path(xdg) if xdg else Path.home() / ".config"
    return root / "antios" / "antios.toml"


def _color(value: Any) -> str:
    color = str(value or "auto").lower()
    if color not in {"auto", "always", "never"}:
        raise ValueError("general.color must be one of: auto, always, never")
    return color


def _level(value: Any) -> str:
    level = str(value or "INFO").upper()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("logging.level must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
    return level


def load_config(path: str | Path | None = None) -> AppConfig:
    target = Path(path) if path else default_config_path()
    if not target.exists():
        return AppConfig()

    data = tomllib.loads(target.read_text(encoding="utf-8"))
    general = data.get("general") or {}
    logging_data = data.get("logging") or {}

    prefix = str(general.get("computer_name_prefix", "LAB")).strip() or "LAB"
    if len(prefix) > 6:
        raise ValueError("general.computer_name_prefix must be 6 characters or fewer")

    return AppConfig(
        general=GeneralConfig(
            computer_name_prefix=prefix,
            backup_path=str(general.get("backup_path", "antios-backup.json")),
            color=_color(general.get("color", "auto")),
        ),
        logging=LoggingConfig(
            level=_level(logging_data.get("level", "INFO")),
            file=str(logging_data.get("file", "")),
        ),
    )


def render_default_config() -> str:
    return """# AntiOS v2 configuration
[general]
computer_name_prefix = "LAB"
backup_path = "antios-backup.json"
color = "auto" # auto | always | never

[logging]
level = "INFO"
file = "" # empty disables file logging
"""


def write_default_config(
    path: str | Path | None = None,
    *,
    overwrite: bool = False,
) -> Path:
    target = Path(path) if path else default_config_path()
    if target.exists() and not overwrite:
        raise FileExistsError(f"Configuration already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_default_config(), encoding="utf-8")
    return target
