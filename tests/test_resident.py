from pathlib import Path
from types import SimpleNamespace

from antios import resident


def test_default_resident_roots_are_bounded(tmp_path, monkeypatch):
    home = tmp_path / "User"
    local = home / "AppData" / "Local"
    roaming = home / "AppData" / "Roaming"
    for path in (
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
        local / "Temp",
        roaming / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    ):
        path.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(roaming))
    roots = resident.default_resident_roots()
    assert 1 <= len(roots) <= 16
    assert home / "Downloads" in roots
    assert local / "Temp" in roots


def test_configure_resident_guard_uses_persistent_task(monkeypatch, tmp_path):
    exe = tmp_path / "AntiOS-Guard.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(resident, "_guard_executable", lambda: exe)
    captured = {}
    def fake_startup(*args, **kwargs):
        captured["args"] = args
        return {"exit_code": 0}

    monkeypatch.setattr(resident, "_run_startup_script", fake_startup)
    root = tmp_path / "Downloads"
    root.mkdir()
    result = resident.configure_resident_guard(roots=(root,))
    assert result["configured"] is True
    args = captured["args"]
    assert "-Apply" in args
    assert "-EngineServiceName" in args
    assert "clamd" in args


def test_ensure_resident_guard_repairs_stopped_state(monkeypatch):
    states = iter([
        {"state": "not-running", "running": False},
        {"state": "monitoring", "running": True},
    ])
    monkeypatch.setattr(resident, "read_guard_state", lambda **kwargs: next(states))
    monkeypatch.setattr(
        resident,
        "configure_resident_guard",
        lambda **kwargs: {"configured": True, "roots": [r"C:\\Users\\Test\\Downloads"]},
    )
    result = resident.ensure_resident_guard(wait_seconds=0)
    assert result["running"] is True
    assert result["changed"] is True


def test_disable_resident_guard_stops_and_unregisters(monkeypatch):
    monkeypatch.setattr(
        resident,
        "read_guard_state",
        lambda **kwargs: {"state": "stopped", "running": False, "stop": kwargs.get("stop")},
    )
    monkeypatch.setattr(
        resident,
        "_run_startup_script",
        lambda *args, **kwargs: {"exit_code": 0, "args": list(args)},
    )
    result = resident.disable_resident_guard()
    assert result["configured"] is False
    assert result["previous"]["stop"] is True
