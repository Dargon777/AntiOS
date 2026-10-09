from pathlib import Path


def test_installer_runs_protection_helpers_without_console_windows():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert "ExecWait '\"$SYSDIR\\\\WindowsPowerShell" not in source
    assert source.count("nsExec::Exec") >= 5
    assert "-WindowStyle Hidden" in source


def test_installer_still_requests_normal_uac_consent():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert "RequestExecutionLevel admin" in source



def test_installer_manages_control_center_autostart_separately_from_guard():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert "dashboard-startup.ps1" in source
    assert "AntiOS Control Center" not in source  # task identity belongs to the script
    assert "-Apply -AllowManagedUnsigned" in source
    assert "dashboard-startup.ps1\" -Uninstall -Apply" in source


def test_fresh_install_autostart_does_not_override_existing_install_preference():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    assert 'ReadRegStr $ExistingVersion HKLM "${INSTALL_KEY}" "Version"' in source
    assert '${If} $ExistingVersion == ""' in source
