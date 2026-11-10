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


def test_release_publication_requires_enabled_authenticode_signing():
    workflow = (ROOT / ".github/workflows/windows-release.yml").read_text("utf-8")
    assert "Refuse unsigned master publication" in workflow
    assert "vars.ENABLE_ARTIFACT_SIGNING != 'true'" in workflow
    publish = workflow.split("  publish-release:", 1)[1]
    assert "vars.ENABLE_ARTIFACT_SIGNING == 'true'" in publish
    assert "gh release upload" in publish
    assert 'gh release view "$tag" --json isDraft' in publish
    assert '"$draft" != "true"' in publish
    assert "gh release create" not in publish
    assert 'gh release edit "$tag"' in publish
    assert '--notes-file release/RELEASE_NOTES.md' in publish
    assert '--target "$GITHUB_SHA"' in publish
    assert "          --draft" in publish
    assert 'test "$(gh release view "$tag" --json isDraft' in publish
    assert publish.index('gh release edit "$tag"') < publish.index('gh release upload "$tag"')
    assert "gh release edit \"$tag\" --draft=false" not in publish


def test_current_install_scripts_never_bootstrap_clamav():
    installer = (ROOT / "installer/AntiOS.nsi").read_text("utf-8")
    install = installer.split('Section "AntiOS" SecMain', 1)[1].split('Section "Uninstall"', 1)[0]
    active = install.split("antios_legacy_upgrade_safe:", 1)[1]
    assert "protection-bootstrap.ps1" not in active
    assert "clamav-windows.json" not in active
    assert "Install-AmsiProvider.ps1" not in active


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
