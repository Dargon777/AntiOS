param(
    [string]$SourceDirectory = $PSScriptRoot,
    [switch]$AddToPath,
    [switch]$DesktopShortcut
)

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\AntiOS"
$CliSource = Join-Path $SourceDirectory "AntiOS.exe"
$GuiSource = Join-Path $SourceDirectory "AntiOS-GUI.exe"
$CliTarget = Join-Path $InstallDir "AntiOS.exe"
$GuiTarget = Join-Path $InstallDir "AntiOS-GUI.exe"
$GuardSource = Join-Path $SourceDirectory "AntiOS-Guard.exe"
$GuardTarget = Join-Path $InstallDir "AntiOS-Guard.exe"
$StartupSource = Join-Path $SourceDirectory "guard-startup.ps1"

foreach ($required in @($CliSource, $GuiSource, $GuardSource, $StartupSource, (Join-Path $SourceDirectory "_cli"), (Join-Path $SourceDirectory "_gui"), (Join-Path $SourceDirectory "_guard"))) {
    if (-not (Test-Path $required)) {
        throw "Required AntiOS file not found: $required"
    }
}

if (Test-Path -LiteralPath $GuardTarget) {
    $guardState = (& $GuardTarget status | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0 -or $guardState.running) {
        throw 'Stop AntiOS Guard and verify its status before updating this installation.'
    }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $CliSource $CliTarget
Copy-Item -Force $GuiSource $GuiTarget
Copy-Item -Force $GuardSource $InstallDir
Copy-Item -Force $StartupSource $InstallDir
foreach ($runtime in @("_cli", "_gui", "_guard")) {
    Copy-Item -Recurse -Force (Join-Path $SourceDirectory $runtime) $InstallDir
}

$Programs = [Environment]::GetFolderPath("Programs")
$StartMenuDir = Join-Path $Programs "AntiOS"
New-Item -ItemType Directory -Force -Path $StartMenuDir | Out-Null

$Shell = New-Object -ComObject WScript.Shell
$StartShortcut = $Shell.CreateShortcut((Join-Path $StartMenuDir "AntiOS.lnk"))
$StartShortcut.TargetPath = $GuiTarget
$StartShortcut.WorkingDirectory = $InstallDir
$StartShortcut.Description = "AntiOS Windows Health & Privacy"
$StartShortcut.IconLocation = $GuiTarget
$StartShortcut.Save()

if ($DesktopShortcut) {
    $Desktop = [Environment]::GetFolderPath("Desktop")
    $DesktopLink = $Shell.CreateShortcut((Join-Path $Desktop "AntiOS.lnk"))
    $DesktopLink.TargetPath = $GuiTarget
    $DesktopLink.WorkingDirectory = $InstallDir
    $DesktopLink.Description = "AntiOS Windows Health & Privacy"
    $DesktopLink.IconLocation = $GuiTarget
    $DesktopLink.Save()
}

if ($AddToPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($userPath -split ";" | Where-Object { $_ })
    if ($parts -notcontains $InstallDir) {
        $newPath = (($parts + $InstallDir) -join ";")
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Host "Added $InstallDir to the current user's PATH."
        Write-Host "Open a new terminal before using 'antios' from PATH."
    } else {
        Write-Host "AntiOS install directory is already in the current user's PATH."
    }
}

Write-Host "Installed AntiOS to $InstallDir"
Write-Host "A Start Menu shortcut was created."
if ($DesktopShortcut) {
    Write-Host "A desktop shortcut was created."
}
Write-Host "GUI: $GuiTarget"
Write-Host "CLI: $CliTarget"
