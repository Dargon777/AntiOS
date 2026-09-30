from pathlib import Path

import pytest

from antios.config import AppConfig, load_config, render_default_config, write_default_config


def test_missing_config_uses_defaults(tmp_path):
    config = load_config(tmp_path / "missing.toml")
    assert config == AppConfig()


def test_write_and_load_default_config(tmp_path):
    path = tmp_path / "antios.toml"
    created = write_default_config(path)
    assert created == path
    assert path.read_text(encoding="utf-8") == render_default_config()

    config = load_config(path)
    assert config.general.computer_name_prefix == "LAB"
    assert config.general.color == "auto"
    assert config.logging.level == "INFO"


def test_config_rejects_invalid_color(tmp_path):
    path = tmp_path / "antios.toml"
    path.write_text(
        '[general]\ncolor = "rainbow"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_config(path)


def test_config_rejects_long_prefix(tmp_path):
    path = tmp_path / "antios.toml"
    path.write_text(
        '[general]\ncomputer_name_prefix = "TOOLONG"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_config(path)

def test_config_rejects_empty_backup_path(tmp_path):
    path = tmp_path / "antios.toml"
    path.write_text(
        '[general]\nbackup_path = ""\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_config(path)
