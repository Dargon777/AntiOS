Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"

!ifndef APP_VERSION
  !define APP_VERSION "2.0.0a28"
!endif
!ifndef NUMERIC_VERSION
  !define NUMERIC_VERSION "2.0.28.0"
!endif
!ifndef SOURCE_DIR
  !define SOURCE_DIR "..\installer-stage"
!endif
!ifndef OUTPUT_FILE
  !define OUTPUT_FILE "..\installer-output\AntiOS-Setup.exe"
!endif
!ifndef ICON_FILE
  !define ICON_FILE "..\build\icons\app_main.ico"
!endif

!define PRODUCT_NAME "AntiOS"
!define PUBLISHER "DargonITP"
!define INSTALL_KEY "Software\DargonITP\AntiOS"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntiOS"
!define APP_PATH_KEY "Software\Microsoft\Windows\CurrentVersion\App Paths\AntiOS-GUI.exe"

Var SkipEngine
Var ExistingVersion
Var StageDir
Var BackupDir
Var RollbackFailed

; Application payload only: DO NOT put managed ClamAV or ProgramData in this
; transaction. ClamAV\clamd.exe can be a live SCM service, and its files must
; never be moved with GUI/CLI application binaries.
!macro ANTIOS_EACH_APP_ITEM OP
  !insertmacro ${OP} "AntiOS.exe"
  !insertmacro ${OP} "AntiOS-GUI.exe"
  !insertmacro ${OP} "AntiOS-Guard.exe"
  !insertmacro ${OP} "Uninstall.exe"
  !insertmacro ${OP} "_cli"
  !insertmacro ${OP} "_gui"
  !insertmacro ${OP} "_guard"
  !insertmacro ${OP} "AntiOS-AmsiProvider.dll"
  !insertmacro ${OP} "guard-startup.ps1"
  !insertmacro ${OP} "dashboard-startup.ps1"
  !insertmacro ${OP} "protection-engine.ps1"
  !insertmacro ${OP} "clamav-trust.ps1"
  !insertmacro ${OP} "clamav-repair-validation.ps1"
  !insertmacro ${OP} "protection-bootstrap.ps1"
  !insertmacro ${OP} "protection-repair.ps1"
  !insertmacro ${OP} "protection-first-run.ps1"
  !insertmacro ${OP} "Install-AmsiProvider.ps1"
  !insertmacro ${OP} "LICENSE.microsoft"
  !insertmacro ${OP} "COEXISTENCE.md"
  !insertmacro ${OP} "clamav-windows.json"
  !insertmacro ${OP} "clamav-config"
  !insertmacro ${OP} "README.md"
  !insertmacro ${OP} "README.ru.md"
  !insertmacro ${OP} "README.es.md"
  !insertmacro ${OP} "README.zh-CN.md"
  !insertmacro ${OP} "README.fi.md"
  !insertmacro ${OP} "README.pl.md"
  !insertmacro ${OP} "README.mn.md"
  !insertmacro ${OP} "PRIVACY.md"
  !insertmacro ${OP} "SUPPORT.md"
  !insertmacro ${OP} "SECURITY.md"
  !insertmacro ${OP} "CHANGELOG.md"
  !insertmacro ${OP} "CODE_OF_CONDUCT.md"
  !insertmacro ${OP} "LICENSE"
  !insertmacro ${OP} "NOTICE"
  !insertmacro ${OP} "uninstall-manifest.nsh"
!macroend

!macro ANTIOS_CHECK_STAGED ITEM
  IfFileExists "$StageDir\${ITEM}" +2 0
    Goto antios_staging_failed
!macroend

!macro ANTIOS_SWAP_APP_ITEM ITEM
  IfFileExists "$StageDir\${ITEM}" +2 0
    Goto antios_transaction_failed
  IfFileExists "$INSTDIR\${ITEM}" 0 +4
    ClearErrors
    Rename "$INSTDIR\${ITEM}" "$BackupDir\${ITEM}"
    IfErrors antios_transaction_failed
  ClearErrors
  Rename "$StageDir\${ITEM}" "$INSTDIR\${ITEM}"
  IfErrors antios_transaction_failed
!macroend

!macro ANTIOS_RESTORE_APP_ITEM ITEM
  ; An item absent from staging has already been activated. Move it out of
  ; the way so the previous item can return to its original path.
  IfFileExists "$StageDir\${ITEM}" +6 0
    IfFileExists "$INSTDIR\${ITEM}" 0 +5
      ClearErrors
      Rename "$INSTDIR\${ITEM}" "$StageDir\${ITEM}"
      IfErrors 0 +2
        StrCpy $RollbackFailed "1"
  IfFileExists "$BackupDir\${ITEM}" 0 +5
    ClearErrors
    Rename "$BackupDir\${ITEM}" "$INSTDIR\${ITEM}"
    IfErrors 0 +2
      StrCpy $RollbackFailed "1"
!macroend

; Compiler-generated from exactly the files shipped by stage-installer.ps1.
; Individual deletes/empty-directory removals preserve unrelated user data.
!include "${SOURCE_DIR}\uninstall-manifest.nsh"

Name "${PRODUCT_NAME} ${APP_VERSION}"
OutFile "${OUTPUT_FILE}"
InstallDir "$PROGRAMFILES64\AntiOS"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetCompressorDictSize 64
CRCCheck on
BrandingText "DargonITP"
ShowInstDetails nevershow
ShowUninstDetails nevershow
Icon "${ICON_FILE}"
UninstallIcon "${ICON_FILE}"

VIProductVersion "${NUMERIC_VERSION}"
VIAddVersionKey /LANG=1033 "CompanyName" "${PUBLISHER}"
VIAddVersionKey /LANG=1033 "FileDescription" "AntiOS Antivirus & Windows Diagnostics Setup"
VIAddVersionKey /LANG=1033 "FileVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=1033 "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey /LANG=1033 "ProductVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=1033 "LegalCopyright" "Copyright 2026 Dargon777 and AntiOS contributors"

!define MUI_ABORTWARNING
!define MUI_ICON "${ICON_FILE}"
!define MUI_UNICON "${ICON_FILE}"
!define MUI_LANGDLL_REGISTRY_ROOT HKLM
!define MUI_LANGDLL_REGISTRY_KEY "${INSTALL_KEY}"
!define MUI_LANGDLL_REGISTRY_VALUENAME "InstallerLanguage"
!define MUI_FINISHPAGE_RUN "$INSTDIR\AntiOS-GUI.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch AntiOS"
!define MUI_FINISHPAGE_NOREBOOTSUPPORT

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Russian"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP|MB_OK "AntiOS requires 64-bit Windows." /SD IDOK
    Abort
  ${EndIf}

  ${GetParameters} $R0
  ${GetOptions} "$R0" "/NOENGINE=" $R1
  ${If} $R1 == "1"
    StrCpy $SkipEngine "1"
  ${Else}
    StrCpy $SkipEngine "0"
  ${EndIf}

  SetRegView 64
  SetShellVarContext all
  ReadRegStr $ExistingVersion HKLM "${INSTALL_KEY}" "Version"
  ReadRegStr $0 HKLM "${INSTALL_KEY}" "InstallDir"
  ${If} $0 != ""
    StrCpy $INSTDIR $0
  ${EndIf}

  !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
  !insertmacro MUI_UNGETLANGUAGE
FunctionEnd

Section "AntiOS" SecMain
  SectionIn RO
  SetRegView 64

  ; The Setup runs as administrator. Never extract binaries or execute
  ; follow-up maintenance scripts through a substituted junction/reparse
  ; install directory. This check happens before stopping the old Guard.
  IfFileExists "$INSTDIR" 0 antios_path_preflight_done
    System::Call 'kernel32::GetFileAttributesW(w "$INSTDIR") i .r0'
    IntOp $1 $0 & 0x400
    ${If} $1 != 0
      SetErrorLevel 27
      MessageBox MB_ICONSTOP|MB_OK "AntiOS cannot install into a directory with a reparse point or an unreadable target." /SD IDOK
      Abort
    ${EndIf}
antios_path_preflight_done:

  ; Extract the complete new payload and generate its uninstaller before
  ; stopping the previous Guard or replacing one installed application file.
  ; A residual staging/backup directory may indicate interrupted recovery:
  ; do not delete or reuse it automatically.
  StrCpy $StageDir "$INSTDIR\_antios_next"
  StrCpy $BackupDir "$INSTDIR\_antios_previous"
  IfFileExists "$StageDir" 0 +4
    SetErrorLevel 29
    MessageBox MB_ICONSTOP|MB_OK "AntiOS found a pending update directory. Preserve it and recover the previous installation before retrying." /SD IDOK
    Abort
  IfFileExists "$BackupDir" 0 +4
    SetErrorLevel 29
    MessageBox MB_ICONSTOP|MB_OK "AntiOS found a previous-version backup. Preserve it and resolve the interrupted update before retrying." /SD IDOK
    Abort

  ClearErrors
  CreateDirectory "$INSTDIR"
  IfErrors antios_staging_failed
  CreateDirectory "$StageDir"
  IfErrors antios_staging_failed
  CreateDirectory "$BackupDir"
  IfErrors antios_staging_failed
  SetOutPath "$StageDir"
  SetOverwrite on
  ClearErrors
  File /r "${SOURCE_DIR}\*.*"
  IfErrors antios_staging_failed
  WriteUninstaller "$StageDir\Uninstall.exe"
  IfErrors antios_staging_failed
  ; Every shipped component must be present before any part of the previous
  ; installation is touched. The engine-owned ClamAV folder stays in place.
  !insertmacro ANTIOS_EACH_APP_ITEM ANTIOS_CHECK_STAGED
  Goto antios_staging_ready

antios_staging_failed:
  ; SetOutPath changes Setup's working directory. Windows refuses to remove
  ; its own current directory; leave the staging tree before cleanup.
  SetOutPath "$INSTDIR"
  RMDir /r "$StageDir"
  RMDir "$BackupDir"
  SetErrorLevel 28
  MessageBox MB_ICONSTOP|MB_OK "AntiOS could not prepare the complete update. The previous installation was not replaced." /SD IDOK
  Abort

antios_staging_ready:
  ; Extraction leaves NSIS with StageDir as its working directory. Both
  ; the failure rollback and successful activation need to remove StageDir,
  ; so switch back before any file moves/cleanup.
  SetOutPath "$INSTDIR"
  ; Stop the previous persistent Guard task before replacing binaries. A stale
  ; heartbeat can belong to a still-live process holding guard.lock, so the
  ; cooperative Guard stop alone is not sufficient for upgrades.
  IfFileExists "$INSTDIR\guard-startup.ps1" 0 +3
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\guard-startup.ps1" -Uninstall -Apply'
    Pop $1
  IfFileExists "$INSTDIR\AntiOS-Guard.exe" 0 +4
    nsExec::Exec '"$INSTDIR\AntiOS-Guard.exe" stop'
    Pop $0
    Sleep 1000

  ; Promote app-owned files by rename on the *same volume*. Every existing
  ; item is first moved to the local recovery directory. If any rename fails,
  ; reverse all completed moves and preserve the prior registered version.
  StrCpy $RollbackFailed "0"
  !insertmacro ANTIOS_EACH_APP_ITEM ANTIOS_SWAP_APP_ITEM
  Goto antios_payload_copy_ok

antios_transaction_failed:
  !insertmacro ANTIOS_EACH_APP_ITEM ANTIOS_RESTORE_APP_ITEM
  ${If} $RollbackFailed == "0"
    RMDir /r "$StageDir"
    RMDir "$BackupDir"
    MessageBox MB_ICONSTOP|MB_OK "AntiOS could not activate the update. The previous application files were restored." /SD IDOK
  ${Else}
    MessageBox MB_ICONSTOP|MB_OK "AntiOS could not complete or fully restore the application files. Recovery directories were preserved. Do not launch AntiOS until repaired." /SD IDOK
  ${EndIf}
  SetErrorLevel 28
  Abort

antios_payload_copy_ok:
  ; Both app executables and runtime folders were committed together. The
  ; ClamAV service and its data were never renamed, removed or copied.
  ; An unexpected leftover staged file is a packaging mismatch, not success:
  ; restore the old application rather than silently omitting that file.
  ClearErrors
  RMDir "$StageDir"
  IfErrors antios_transaction_failed
  ; Normalize startup state with the newly installed script as well. This also
  ; repairs upgrades from older builds whose uninstall path was broken.
  IfFileExists "$INSTDIR\guard-startup.ps1" 0 +3
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\guard-startup.ps1" -Uninstall -Apply'
    Pop $1

  ; The new Uninstall.exe was generated and staged with the payload before
  ; touching the previous installed app.
  WriteRegStr HKLM "${INSTALL_KEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${INSTALL_KEY}" "Version" "${APP_VERSION}"
  WriteRegStr HKLM "${APP_PATH_KEY}" "" "$INSTDIR\AntiOS-GUI.exe"
  WriteRegStr HKLM "${APP_PATH_KEY}" "Path" "$INSTDIR"

  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "AntiOS"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\AntiOS-GUI.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1

  CreateDirectory "$SMPROGRAMS\AntiOS"
  CreateShortCut "$SMPROGRAMS\AntiOS\AntiOS.lnk" "$INSTDIR\AntiOS-GUI.exe" "" "$INSTDIR\AntiOS-GUI.exe" 0
  CreateShortCut "$SMPROGRAMS\AntiOS\AntiOS Command Line.lnk" "$INSTDIR\AntiOS.exe" "" "$INSTDIR\AntiOS.exe" 0
  CreateShortCut "$SMPROGRAMS\AntiOS\Uninstall AntiOS.lnk" "$INSTDIR\Uninstall.exe"
  CreateShortCut "$COMMONDESKTOP\AntiOS.lnk" "$INSTDIR\AntiOS-GUI.exe" "" "$INSTDIR\AntiOS-GUI.exe" 0

  ; Fresh installs enable the Control Center at user logon. Upgrades preserve
  ; the existing task/config choice so a user who disabled it is not overridden.
  ${If} $ExistingVersion == ""
    IfFileExists "$INSTDIR\dashboard-startup.ps1" 0 control_center_done
    DetailPrint "Enabling AntiOS Control Center startup..."
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\dashboard-startup.ps1" -Apply -AllowManagedUnsigned'
    Pop $4
    WriteRegDWORD HKLM "${INSTALL_KEY}" "DashboardStartupExitCode" $4
control_center_done:
  ${EndIf}

  ${If} $SkipEngine != "1"
    DetailPrint "Bootstrapping AntiOS protection engine..."
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\protection-bootstrap.ps1" -ManifestPath "$INSTDIR\clamav-windows.json" -Apply'
    Pop $0
    ${If} $0 == "error"
      StrCpy $0 9001
    ${EndIf}
    WriteRegDWORD HKLM "${INSTALL_KEY}" "ProtectionBootstrapExitCode" $0
    ${If} $0 == 0
      nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\protection-first-run.ps1" -Apply'
      Pop $2
      ${If} $2 == "error"
        StrCpy $2 9001
      ${EndIf}
      WriteRegDWORD HKLM "${INSTALL_KEY}" "ProtectionFirstRunExitCode" $2
      ; AMSI coexistence is optional and secondary. Registration succeeds only
      ; for a valid Authenticode-signed provider and never changes Defender/WSC.
      IfFileExists "$INSTDIR\AntiOS-AmsiProvider.dll" 0 amsi_done
      IfFileExists "$INSTDIR\Install-AmsiProvider.ps1" 0 amsi_done
      DetailPrint "Configuring AntiOS AMSI coexistence provider..."
      nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\Install-AmsiProvider.ps1" -ProviderDll "$INSTDIR\AntiOS-AmsiProvider.dll" -Apply'
      Pop $3
      ${If} $3 == "error"
        StrCpy $3 9001
      ${EndIf}
      WriteRegDWORD HKLM "${INSTALL_KEY}" "AmsiProviderExitCode" $3
      ${If} $3 != 0
        DetailPrint "AntiOS AMSI provider was not registered; Defender and Windows security policy remain unchanged."
      ${EndIf}
amsi_done:
    ${Else}
      IfSilent bootstrap_done bootstrap_notice
bootstrap_notice:
      MessageBox MB_ICONEXCLAMATION|MB_OK "AntiOS was installed, but the protection engine could not be initialized. Open AntiOS and run Protection Repair after checking your Internet connection."
bootstrap_done:
    ${EndIf}
  ${Else}
    WriteRegDWORD HKLM "${INSTALL_KEY}" "ProtectionBootstrapSkipped" 1
  ${EndIf}

  ; A successful install retires only its own app-file rollback area. A crash
  ; before this point leaves the backup for explicit manual recovery.
  RMDir /r "$BackupDir"
SectionEnd

Section "Uninstall"
  SetRegView 64
  ; Check the install root and every packaged subdirectory before invoking
  ; elevated lifecycle scripts or deleting files. A substituted junction
  ; would otherwise redirect deletion into an unrelated directory.
  !insertmacro ANTIOS_UNINSTALL_CHECK_PATHS
  SetOutPath "$TEMP"
  IfFileExists "$INSTDIR\Install-AmsiProvider.ps1" 0 +3
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\Install-AmsiProvider.ps1" -Uninstall -Apply'
    Pop $0
  IfFileExists "$INSTDIR\AntiOS-Guard.exe" 0 +3
    nsExec::Exec '"$INSTDIR\AntiOS-Guard.exe" stop'
    Pop $0
  IfFileExists "$INSTDIR\guard-startup.ps1" 0 +3
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\guard-startup.ps1" -Uninstall -Apply'
    Pop $0
  IfFileExists "$INSTDIR\dashboard-startup.ps1" 0 +3
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\dashboard-startup.ps1" -Uninstall -Apply'
    Pop $0
  IfFileExists "$INSTDIR\protection-engine.ps1" 0 +3
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\protection-engine.ps1" -Uninstall -Apply'
    Pop $0

  Delete "$COMMONDESKTOP\AntiOS.lnk"
  Delete "$SMPROGRAMS\AntiOS\AntiOS.lnk"
  Delete "$SMPROGRAMS\AntiOS\AntiOS Command Line.lnk"
  Delete "$SMPROGRAMS\AntiOS\Uninstall AntiOS.lnk"
  RMDir "$SMPROGRAMS\AntiOS"

  DeleteRegKey HKLM "${APP_PATH_KEY}"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  DeleteRegKey HKLM "${INSTALL_KEY}"

  ; Delete only filenames from the trusted build manifest. Non-recursive
  ; RMDir preserves unknown files, recovery trees and any user-added folders.
  !insertmacro ANTIOS_UNINSTALL_OWNED_PAYLOAD
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
