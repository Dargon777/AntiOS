Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"

!ifndef APP_VERSION
  !define APP_VERSION "2.0.0a15"
!endif
!ifndef NUMERIC_VERSION
  !define NUMERIC_VERSION "2.0.15.0"
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

  IfFileExists "$INSTDIR\AntiOS-Guard.exe" 0 +3
    ExecWait '"$INSTDIR\AntiOS-Guard.exe" stop' $0
    Sleep 500

  SetOutPath "$INSTDIR"
  SetOverwrite on
  File /r "${SOURCE_DIR}\*.*"

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
    ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\protection-bootstrap.ps1" -ManifestPath "$INSTDIR\clamav-windows.json" -Apply' $0
    WriteRegDWORD HKLM "${INSTALL_KEY}" "ProtectionBootstrapExitCode" $0
    ${If} $0 != 0
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
  IfFileExists "$INSTDIR\AntiOS-Guard.exe" 0 +2
    ExecWait '"$INSTDIR\AntiOS-Guard.exe" stop' $0
  IfFileExists "$INSTDIR\guard-startup.ps1" 0 +2
    ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\guard-startup.ps1" -Uninstall -Apply' $0
  IfFileExists "$INSTDIR\protection-engine.ps1" 0 +2
    ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\protection-engine.ps1" -Uninstall -Apply' $0

  Delete "$COMMONDESKTOP\AntiOS.lnk"
  RMDir /r "$COMMONPROGRAMS\AntiOS"

  DeleteRegKey HKLM "${APP_PATH_KEY}"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  DeleteRegKey HKLM "${INSTALL_KEY}"

  RMDir /r "$INSTDIR"
SectionEnd
