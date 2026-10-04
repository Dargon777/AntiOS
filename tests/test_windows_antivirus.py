import os
import subprocess

import pytest

from antios import windows_antivirus


def test_defender_only_runs_allowlisted_operations(monkeypatch):
    monkeypatch.setattr(windows_antivirus, "_is_windows", lambda: True)
    monkeypatch.setattr(
        windows_antivirus,
        "_powershell_executable",
        lambda: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    calls = []
    def runner(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
    result = windows_antivirus.defender_action("quick", runner=runner)
    assert result["verdict"] == "see-windows-security"
    assert calls[0][0][-1].endswith("Start-MpScan -ScanType QuickScan")
    assert "shell" not in calls[0][1]
    with pytest.raises(ValueError):
        windows_antivirus.defender_action("quick; Remove-Item *", runner=runner)
    assert len(calls) == 1


def test_defender_failures_are_not_reported_as_completed(monkeypatch):
    monkeypatch.setattr(windows_antivirus, "_is_windows", lambda: True)
    monkeypatch.setattr(
        windows_antivirus,
        "_powershell_executable",
        lambda: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    def runner(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="service disabled")
    with pytest.raises(OSError, match="service disabled"):
        windows_antivirus.defender_action("update", runner=runner)


@pytest.mark.skipif(os.name != "nt", reason="Windows AMSI native integration")
def test_native_amsi_accepts_benign_buffer():
    try:
        provider = windows_antivirus.AmsiScanner()
    except OSError as exc:
        pytest.skip(f"No AMSI provider on this Windows runner: {exc}")
    try:
        try:
            result = provider.scan(b"plain harmless native API test text", "antios-test.txt")
        except OSError as exc:
            pytest.skip(f"AMSI provider unavailable: {exc}")
        assert result < 32768
    finally:
        provider.close()
