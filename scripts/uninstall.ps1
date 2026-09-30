param(
    [switch]$RemoveFromPath
)

$ErrorActionPreference = "Stop"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\AntiOS"

if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
    Write-Host "Removed $InstallDir"
} else {
    Write-Host "AntiOS is not installed at $InstallDir"
}

if ($RemoveFromPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @(
        $userPath -split ";" |
        Where-Object { $_ -and $_.TrimEnd("\") -ne $InstallDir.TrimEnd("\") }
    )
    [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
    Write-Host "Removed AntiOS install directory from the current user's PATH."
    Write-Host "Open a new terminal for PATH changes to take effect."
}
