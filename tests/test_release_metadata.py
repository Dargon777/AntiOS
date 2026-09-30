from pathlib import Path
import tomllib

from antios import __version__


def test_release_version_matches_package_version():
    release_version = Path("release/VERSION").read_text(encoding="utf-8").strip()
    assert release_version == __version__


def test_release_tag_is_alpha_5():
    tag = Path("release/TAG").read_text(encoding="utf-8").strip()
    assert tag == "v2.0.0-alpha.5"


def test_package_declares_apache_2_license():
    metadata = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["license"] == "Apache-2.0"
    assert "LICENSE" in metadata["project"]["license-files"]
    assert "NOTICE" in metadata["project"]["license-files"]


def test_package_exposes_gui_script():
    metadata = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["gui-scripts"]["antios-gui"] == "antios.dashboard:main"


def test_trust_docs_are_present():
    assert Path("PRIVACY.md").is_file()
    assert Path("SUPPORT.md").is_file()


def test_license_and_notice_are_present():
    license_text = Path("LICENSE").read_text(encoding="utf-8")
    notice = Path("NOTICE").read_text(encoding="utf-8")

    assert "Apache License" in license_text
    assert "Version 2.0" in license_text
    assert "Copyright 2026 Dargon777" in notice
    assert "does not retroactively relicense" in notice
