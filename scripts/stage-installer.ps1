param(
    [string]$OutputDirectory = ".\installer-stage"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$stage = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDirectory))

Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null

foreach ($source in @(
    @{ Path = "dist\AntiOS"; Name = "CLI" },
    @{ Path = "dist\AntiOS-GUI"; Name = "GUI" },
    @{ Path = "dist\AntiOS-Guard"; Name = "Guard" }
)) {
    $full = Join-Path $repoRoot $source.Path
    if (-not (Test-Path -LiteralPath $full)) {
        throw "$($source.Name) build directory not found: $full"
    }
    Copy-Item (Join-Path $full "*") $stage -Recurse -Force
}

foreach ($path in @(
    "scripts\guard-startup.ps1",
    "scripts\protection-engine.ps1",
    "README.md",
    "README.ru.md",
    "README.es.md",
    "README.zh-CN.md",
    "README.fi.md",
    "README.pl.md",
    "README.mn.md",
    "PRIVACY.md",
    "SUPPORT.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "LICENSE",
    "NOTICE"
)) {
    $source = Join-Path $repoRoot $path
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Installer payload file not found: $source"
    }
    Copy-Item -LiteralPath $source -Destination $stage -Force
}

$clamConfig = Join-Path $repoRoot "config\clamav"
if (Test-Path -LiteralPath $clamConfig) {
    Copy-Item -LiteralPath $clamConfig -Destination (Join-Path $stage "clamav-config") -Recurse -Force
}

$required = @(
    "AntiOS.exe",
    "AntiOS-GUI.exe",
    "AntiOS-Guard.exe",
    "_cli",
    "_gui",
    "_guard",
    "guard-startup.ps1",
    "protection-engine.ps1",
    "LICENSE"
)
foreach ($name in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $stage $name))) {
        throw "Installer staging is incomplete: $name"
    }
}

Write-Host "Prepared AntiOS installer payload at $stage"
