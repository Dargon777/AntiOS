"""Regression contracts for exhaustive static audit and native Windows cleanup."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_full_source_audit_requires_every_tracked_file_and_line():
    script = (ROOT / "scripts/audit-all-sources.py").read_text("utf-8")
    assert '"git", "ls-files", "-z"' in script
    assert "for path in paths:" in script
    assert "for number, line in enumerate(lines, 1):" in script
    assert '"sha256": hashlib.sha256(raw).hexdigest()' in script
    assert '"errors": []' in script
    assert "return 1 if errors else 0" in script


def test_per_user_uninstaller_never_recursively_erases_unknown_files():
    source = (ROOT / "scripts/uninstall.ps1").read_text("utf-8")
    assert "Remove-Item -Recurse -Force $InstallDir" not in source
    assert "Remove-Item -Recurse -Force $StartMenuDir" not in source
    assert "install-manifest.json" in source
    assert "Assert-NoReparsePoint" in source
    assert "GetFullPath" in source
    assert "Remove-EmptyDirectory" in source
    assert "Refusing a reparse point" in source
    assert source.index("foreach ($entry in @($manifest.files))") < source.index("& $Guard stop")


def test_per_user_installer_manifest_lists_only_source_files():
    source = (ROOT / "scripts/install.ps1").read_text("utf-8")
    assert "Get-ChildItem -LiteralPath $folder -Recurse -Force" in source
    assert "install-manifest.json" in source
    assert "$owned.Add" in source
    assert "($manifest | ConvertTo-Json" in source
    assert "ReparsePoint" in source
    assert source.index("$owned.Add") < source.index("Copy-Item -Force $CliSource")


def test_managed_clamd_uninstall_refuses_foreign_scm_services():
    source = (ROOT / "scripts/protection-engine.ps1").read_text("utf-8")
    uninstall = source.split("if ($Uninstall) {", 1)[1].split("if (-not $ClamAVDirectory)", 1)[0]
    assert "Assert-ManagedClamdService" in uninstall
    assert "Assert-NoReparseTree" in uninstall
    assert "Refusing to unregister a non-AntiOS" in uninstall
    assert "sc.exe" in uninstall and "delete $EngineServiceName" in uninstall
    assert "--uninstall-service" not in uninstall
    assert uninstall.index("Assert-ManagedClamdService") < uninstall.index("Stop-Service")
    assert uninstall.index("Assert-NoReparseTree") < uninstall.index("Stop-Service")
    assert source.count("Assert-ManagedClamdService") >= 3



def test_elevated_bootstrap_never_extracts_clamav_into_user_temp():
    source = (ROOT / "scripts/protection-bootstrap.ps1").read_text("utf-8")
    assert "[IO.Path]::GetTempPath()" not in source
    assert "AntiOS-ClamAV-Staging-" in source
    assert "GetFolderPath('ProgramFiles')" in source
    assert "SetSecurityDescriptorSddlForm" in source
    assert "ReparsePoint" in source
    assert "SHA256" in source
    assert "RequireValidSignature $true" in source


def test_build_scripts_deny_arbitrary_recursive_cleanup_locations():
    for filename, approved in (
        ("scripts/stage-installer.ps1", "installer-stage"),
        ("scripts/build-hardened-windows.ps1", "hardened-dist"),
    ):
        source = (ROOT / filename).read_text("utf-8")
        assert "cnotmatch" in source
        assert approved in source
        assert "ReparsePoint" in source
        assert "refusing recursive cleanup" in source
        assert source.count("param(") >= 1
