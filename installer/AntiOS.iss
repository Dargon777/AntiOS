#ifndef MyAppVersion
  #define MyAppVersion "2.0.0a13"
#endif
#ifndef MyNumericVersion
  #define MyNumericVersion "2.0.13.0"
#endif
#ifndef MySourceDir
  #define MySourceDir "..\installer-stage"
#endif

#define MyAppName "AntiOS"
#define MyPublisher "DargonITP"
#define MyAppExeName "AntiOS-GUI.exe"
#define MyCliExeName "AntiOS.exe"
#define MyGuardExeName "AntiOS-Guard.exe"
#define MyAppId "{{0B941316-1986-4DD6-A284-8C50400B40A3}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyPublisher}
AppPublisherURL=https://github.com/Dargon777/AntiOS
AppSupportURL=https://github.com/Dargon777/AntiOS/issues
AppUpdatesURL=https://github.com/Dargon777/AntiOS/releases
DefaultDirName={autopf}\AntiOS
DefaultGroupName=AntiOS
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\installer-output
OutputBaseFilename=AntiOS-Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
Uninstallable=yes
UninstallDisplayName=AntiOS
UninstallDisplayIcon={app}\{#MyAppExeName}
VersionInfoVersion={#MyNumericVersion}
VersionInfoCompany={#MyPublisher}
VersionInfoDescription=AntiOS Antivirus & Windows Diagnostics Setup
VersionInfoProductName=AntiOS
VersionInfoProductVersion={#MyAppVersion}
CloseApplications=yes
RestartApplications=no
SetupMutex=AntiOSSetupMutex
ChangesEnvironment=no
UsePreviousAppDir=yes
UsePreviousTasks=yes
AllowNoIcons=yes
CreateUninstallRegKey=yes
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce
Name: "launchatstartup"; Description: "Start AntiOS Resident Guard when I sign in"; GroupDescription: "Protection"; Flags: unchecked

[Files]
Source: "{#MySourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Registry]
Root: HKLM; Subkey: "Software\DargonITP\AntiOS"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\DargonITP\AntiOS"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\AntiOS-GUI.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\AntiOS-GUI.exe"; ValueType: string; ValueName: "Path"; ValueData: "{app}"; Flags: uninsdeletekey

[Icons]
Name: "{group}\AntiOS"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Comment: "AntiOS Antivirus & Windows Diagnostics"
Name: "{group}\AntiOS Command Line"; Filename: "{app}\{#MyCliExeName}"; WorkingDir: "{app}"; Comment: "AntiOS command line"
Name: "{group}\Uninstall AntiOS"; Filename: "{uninstallexe}"
Name: "{autodesktop}\AntiOS"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Comment: "AntiOS Antivirus & Windows Diagnostics"; Tasks: desktopicon

[Run]
Filename: "{cmd}"; Parameters: "/C \"\"{app}\{#MyGuardExeName}\" status >NUL 2>&1\""; Flags: runhidden waituntilterminated; StatusMsg: "Checking Resident Guard..."
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File \"{app}\guard-startup.ps1\" -Install -Apply"; Flags: runhidden waituntilterminated; Tasks: launchatstartup; StatusMsg: "Configuring Resident Guard startup..."
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\{#MyGuardExeName}"; Parameters: "stop"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "AntiOSStopGuard"
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File \"{app}\guard-startup.ps1\" -Uninstall -Apply"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "AntiOSRemoveGuardStartup"

[Code]
function ExistingGuardPath(): String;
begin
  Result := ExpandConstant('{app}\{#MyGuardExeName}');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  GuardPath: String;
begin
  Result := '';
  GuardPath := ExistingGuardPath();

  if FileExists(GuardPath) then
  begin
    if not Exec(GuardPath, 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    begin
      Result := 'AntiOS Resident Guard could not be stopped. Close AntiOS and retry the installation.';
      Exit;
    end;

    if ResultCode <> 0 then
    begin
      Result := 'AntiOS Resident Guard refused to stop. Close AntiOS and retry the installation.';
      Exit;
    end;
  end;
end;
