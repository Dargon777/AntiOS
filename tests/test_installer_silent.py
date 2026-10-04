from pathlib import Path


def test_installer_runs_protection_helpers_without_console_windows():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert 'ExecWait '"$SYSDIR\\WindowsPowerShell' not in source
    assert source.count("nsExec::Exec") >= 5
    assert "-WindowStyle Hidden" in source


def test_installer_still_requests_normal_uac_consent():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert "RequestExecutionLevel admin" in source
