from pathlib import Path

from antios import __version__


def test_release_version_matches_package_version():
    release_version = Path("release/VERSION").read_text(encoding="utf-8").strip()
    assert release_version == __version__


def test_release_tag_is_alpha_1():
    tag = Path("release/TAG").read_text(encoding="utf-8").strip()
    assert tag == "v2.0.0-alpha.1"
