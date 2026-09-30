param(
    [string]$Source = (Join-Path $PSScriptRoot "AntiOS.exe"),
    [switch]$AddToPath
)

$ErrorActionPreference = "Stop"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\AntiOS"
$Target = Join-Path $InstallDir "AntiOS.exe"

if (-not (Test-Path $Source)) {
    throw "AntiOS.exe not found at: $Source"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $Source $Target
Write-Host "Installed AntiOS to $Target"

if ($AddToPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($userPath -split ";" | Where-Object { $_ })
    if ($parts -notcontains $InstallDir) {
        $newPath = (($parts + $InstallDir) -join ";")
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Host "Added $InstallDir to the current user's PATH."
        Write-Host "Open a new terminal before using AntiOS."
    } else {
        Write-Host "AntiOS install directory is already in the current user's PATH."
    }
}

Write-Host "Try: $Target version"
