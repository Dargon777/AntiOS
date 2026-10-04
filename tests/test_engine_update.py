from pathlib import Path
from types import SimpleNamespace

import pytest

from antios import engine_update


class Scanner:
    def __init__(self, **kwargs):
        self.metadata = {
            "version": "ClamAV test",
            "database_freshness": "current",
            "peer_verification_required": False,
        }

    def close(self):
        pass


def test_update_uses_argument_vector_without_shell(tmp_path, monkeypatch):
    exe = tmp_path / "freshclam"
    exe.write_text("fixture")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="updated", stderr="")

    monkeypatch.setattr(engine_update.subprocess, "run", fake_run)
    result = engine_update.update_clamav_database(
        executable=exe,
        scanner_factory=Scanner,
    )

    assert result["success"] is True
    command, kwargs = calls[0]
    assert command == [str(exe.resolve()), "--stdout"]
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is engine_update.subprocess.DEVNULL


def test_failed_freshclam_never_reports_ready(tmp_path, monkeypatch):
    exe = tmp_path / "freshclam"
    exe.write_text("fixture")
    monkeypatch.setattr(
        engine_update.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=2, stdout="", stderr="network error"),
    )
    result = engine_update.update_clamav_database(executable=exe, scanner_factory=Scanner)
    assert result["success"] is False
    assert result["engine"]["available"] is False


def test_stale_database_never_reports_ready(tmp_path, monkeypatch):
    exe = tmp_path / "freshclam"
    exe.write_text("fixture")
    monkeypatch.setattr(
        engine_update.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="ok", stderr=""),
    )

    class Stale(Scanner):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.metadata["database_freshness"] = "stale"

    result = engine_update.update_clamav_database(executable=exe, scanner_factory=Stale)
    assert result["success"] is False


def test_config_file_must_be_regular_and_existing(tmp_path):
    exe = tmp_path / "freshclam"
    exe.write_text("fixture")
    with pytest.raises(FileNotFoundError):
        engine_update.update_clamav_database(
            executable=exe,
            config_file=tmp_path / "missing.conf",
            scanner_factory=Scanner,
        )


def test_timeout_bounds(tmp_path):
    exe = tmp_path / "freshclam"
    exe.write_text("fixture")
    with pytest.raises(ValueError):
        engine_update.update_clamav_database(executable=exe, timeout=0)
