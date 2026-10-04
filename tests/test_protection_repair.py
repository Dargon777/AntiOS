from types import SimpleNamespace

from antios import protection_repair


def test_repair_wrapper_builds_preview_command(monkeypatch, tmp_path):
    script = tmp_path / "protection-repair.ps1"
    script.write_text("# fixture")
    monkeypatch.setattr(protection_repair, "_script_path", lambda: script)
    monkeypatch.setattr(protection_repair, "_is_windows", lambda: True)
    monkeypatch.setattr(
        protection_repair,
        "system_executable",
        lambda _relative: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(
            returncode=0,
            stdout='{"kind":"antios-protection-repair","dry_run":true,"issues":[],"actions":[]}',
            stderr="",
        )

    monkeypatch.setattr(protection_repair.subprocess, "run", fake_run)
    result = protection_repair.run_protection_repair()
    assert result["dry_run"] is True
    assert "-Apply" not in captured["command"]


def test_repair_wrapper_apply_and_update_flags(monkeypatch, tmp_path):
    script = tmp_path / "protection-repair.ps1"
    script.write_text("# fixture")
    monkeypatch.setattr(protection_repair, "_script_path", lambda: script)
    monkeypatch.setattr(protection_repair, "_is_windows", lambda: True)
    monkeypatch.setattr(
        protection_repair,
        "system_executable",
        lambda _relative: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(
            returncode=0,
            stdout='{"kind":"antios-protection-repair","dry_run":false,"issues":["x"],"actions":["y"]}',
            stderr="",
        )

    monkeypatch.setattr(protection_repair.subprocess, "run", fake_run)
    result = protection_repair.run_protection_repair(apply=True, update_signatures=True)
    assert result["dry_run"] is False
    assert "-Apply" in captured["command"]
    assert "-UpdateSignatures" in captured["command"]
