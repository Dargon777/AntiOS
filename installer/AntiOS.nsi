Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"

!ifndef APP_VERSION
  !define APP_VERSION "2.0.0a24"
!endif
!ifndef NUMERIC_VERSION
  !define NUMERIC_VERSION "2.0.24.0"
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
    MessageBox MB_ICONSTOP|MB_OK "AntiOS requires 64-bit Windows."
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
  ReadRegStr $0 HKLM "${INSTALL_KEY}" "InstallDir"
  ${If} $0 != ""
    StrCpy $INSTDIR $0
  ${EndIf}

  !insertmacro MUI_LANGDLL_DISPLAY
FunctionEnd

Function un.onInit
  SetRegView 64
  !insertmacro MUI_UNGETLANGUAGE
FunctionEnd

Section "AntiOS" SecMain
  SectionIn RO
  SetRegView 64

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

  SetOutPath "$INSTDIR"
  SetOverwrite on
  File /r "${SOURCE_DIR}\*.*"

  ; Normalize startup state with the newly installed script as well. This also
  ; repairs upgrades from older builds whose uninstall path was broken.
  IfFileExists "$INSTDIR\guard-startup.ps1" 0 +3
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\guard-startup.ps1" -Uninstall -Apply'
    Pop $1

  WriteUninstaller "$INSTDIR\Uninstall.exe"

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

  CreateDirectory "$COMMONPROGRAMS\AntiOS"
  CreateShortCut "$COMMONPROGRAMS\AntiOS\AntiOS.lnk" "$INSTDIR\AntiOS-GUI.exe" "" "$INSTDIR\AntiOS-GUI.exe" 0
  CreateShortCut "$COMMONPROGRAMS\AntiOS\AntiOS Command Line.lnk" "$INSTDIR\AntiOS.exe" "" "$INSTDIR\AntiOS.exe" 0
  CreateShortCut "$COMMONPROGRAMS\AntiOS\Uninstall AntiOS.lnk" "$INSTDIR\Uninstall.exe"
  CreateShortCut "$COMMONDESKTOP\AntiOS.lnk" "$INSTDIR\AntiOS-GUI.exe" "" "$INSTDIR\AntiOS-GUI.exe" 0

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

SectionEnd

Section "Uninstall"
  SetRegView 64
  IfFileExists "$INSTDIR\Install-AmsiProvider.ps1" 0 +3
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\Install-AmsiProvider.ps1" -Uninstall -Apply'
    Pop $0
  IfFileExists "$INSTDIR\AntiOS-Guard.exe" 0 +3
    nsExec::Exec '"$INSTDIR\AntiOS-Guard.exe" stop'
    Pop $0
  IfFileExists "$INSTDIR\guard-startup.ps1" 0 +3
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\guard-startup.ps1" -Uninstall -Apply'
    Pop $0
  IfFileExists "$INSTDIR\protection-engine.ps1" 0 +3
    nsExec::Exec '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\protection-engine.ps1" -Uninstall -Apply'
    Pop $0

  Delete "$COMMONDESKTOP\AntiOS.lnk"
  RMDir /r "$COMMONPROGRAMS\AntiOS"

  DeleteRegKey HKLM "${APP_PATH_KEY}"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  DeleteRegKey HKLM "${INSTALL_KEY}"

  RMDir /r "$INSTDIR"
SectionEnd
