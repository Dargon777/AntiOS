param(
    [switch]$RemoveFromPath
)

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\AntiOS"
$Programs = [Environment]::GetFolderPath("Programs")
$StartMenuDir = Join-Path $Programs "AntiOS"
$Desktop = [Environment]::GetFolderPath("Desktop")
$DesktopLink = Join-Path $Desktop "AntiOS.lnk"

# Stop the current-user companion before removing a live onedir installation.
$Guard = Join-Path $InstallDir 'AntiOS-Guard.exe'
if (Test-Path -LiteralPath $Guard) {
    & $Guard stop | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not request Guard shutdown; installation was preserved.' }
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $state = (& $Guard status | ConvertFrom-Json)
        if ($LASTEXITCODE -ne 0) { throw 'Could not verify Guard shutdown; installation was preserved.' }
        if (-not $state.running) { break }
        if ($state.pid -and -not (Get-Process -Id $state.pid -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($state.running -and (Get-Process -Id $state.pid -ErrorAction SilentlyContinue)) {
        throw 'Guard has not stopped. Review its status before uninstalling; installation was preserved.'
    }
}
$StartupManager = Join-Path $InstallDir 'guard-startup.ps1'
if (Test-Path -LiteralPath $StartupManager) { & $StartupManager -Uninstall -Apply }

if (Test-Path $StartMenuDir) {
    Remove-Item -Recurse -Force $StartMenuDir
    Write-Host "Removed AntiOS Start Menu shortcuts."
}

if (Test-Path $DesktopLink) {
    Remove-Item -Force $DesktopLink
    Write-Host "Removed AntiOS desktop shortcut."
}

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
