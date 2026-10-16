"""Installer transaction contract independent of the Windows NSIS runtime."""
from pathlib import Path
import re


def test_nsis_stage_is_complete_before_guard_shutdown():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    start = source.index('  StrCpy $StageDir "$INSTDIR\\_antios_next"')
    staged = source.index('  File /r "${SOURCE_DIR}\\*.*"', start)
    uninstaller = source.index('  WriteUninstaller "$StageDir\\Uninstall.exe"', staged)
    verify = source.index('  !insertmacro ANTIOS_EACH_APP_ITEM ANTIOS_CHECK_STAGED', uninstaller)
    shutdown = source.index('  ; Stop the previous persistent Guard task', verify)
    activated = source.index('  !insertmacro ANTIOS_EACH_APP_ITEM ANTIOS_SWAP_APP_ITEM', shutdown)
    rollback = source.index('  !insertmacro ANTIOS_EACH_APP_ITEM ANTIOS_RESTORE_APP_ITEM', activated)
    registry = source.index('  WriteRegStr HKLM "${INSTALL_KEY}" "Version" "${APP_VERSION}"', rollback)
    assert start < staged < uninstaller < verify < shutdown < activated < rollback < registry
    assert 'IfErrors antios_staging_failed' in source
    assert 'IfErrors antios_transaction_failed' in source
    assert 'RMDir /r "$BackupDir"' in source
    assert 'IfFileExists "$BackupDir" 0 +4' in source


def test_nsis_transaction_only_manages_known_app_paths_not_clamav_service():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    manifest = source.split("!macro ANTIOS_EACH_APP_ITEM OP", 1)[1].split("!macroend", 1)[0]
    names = re.findall(r'!insertmacro \${OP} "([^"]+)"', manifest)
    assert len(names) >= 30
    assert len(names) == len(set(names))
    assert {"AntiOS.exe", "AntiOS-GUI.exe", "AntiOS-Guard.exe",
            "Uninstall.exe", "_cli", "_gui", "_guard"} <= set(names)
    assert "ClamAV" not in names and "ProgramData" not in names
    # The uninstaller is created inside the isolated stage, never generated
    # by overwriting the installed copy after activation.
    assert source.count('WriteUninstaller "$StageDir\\Uninstall.exe"') == 1
    assert 'WriteUninstaller "$INSTDIR\\Uninstall.exe"' not in source


def test_nsis_transaction_manifest_matches_staged_payload_names():
    source = Path("installer/AntiOS.nsi").read_text(encoding="utf-8")
    manifest = source.split("!macro ANTIOS_EACH_APP_ITEM OP", 1)[1].split("!macroend", 1)[0]
    names = set(re.findall(r'!insertmacro \${OP} "([^"]+)"', manifest))
    stage_source = Path("scripts/stage-installer.ps1").read_text(encoding="utf-8")
    for name in names - {"Uninstall.exe", "_cli", "_gui", "_guard",
                         "AntiOS.exe", "AntiOS-GUI.exe", "AntiOS-Guard.exe"}:
        assert name in stage_source, f"Transaction item missing from staged payload: {name}"
