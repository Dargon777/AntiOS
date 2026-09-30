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

foreach ($required in @($CliSource, $GuiSource)) {
    if (-not (Test-Path $required)) {
        throw "Required AntiOS file not found: $required"
    }
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $CliSource $CliTarget
Copy-Item -Force $GuiSource $GuiTarget

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
