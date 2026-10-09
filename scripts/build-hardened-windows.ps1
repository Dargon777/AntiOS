param(
    [string]$OutputDirectory = ".\hardened-dist"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$version = (Get-Content ".\release\VERSION" -Raw).Trim()
if ($version -notmatch '^2\.0\.0a(\d+)$') {
    throw "Unexpected AntiOS version: $version"
}
$alpha = [int]$Matches[1]
$numericVersion = "2.0.$alpha.0"

$outputRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDirectory))
$workRoot = Join-Path $outputRoot "_nuitka"
$icon = [System.IO.Path]::GetFullPath((Join-Path $repoRoot "build\icons\app_main.ico"))

if (-not (Test-Path -LiteralPath $icon -PathType Leaf)) {
    throw "Build AntiOS icons first. Missing: $icon"
}

Remove-Item -Recurse -Force $outputRoot -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $workRoot | Out-Null

function Build-HardenedProgram {
    param(
        [Parameter(Mandatory = $true)][string]$Entry,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][ValidateSet("force", "disable", "attach", "hide")][string]$ConsoleMode,
        [switch]$RequireAdmin,
        [switch]$IncludeTray
    )

    $entryPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Entry))
    if (-not (Test-Path -LiteralPath $entryPath -PathType Leaf)) {
        throw "Entry point not found: $entryPath"
    }

    $args = @(
        "-m", "nuitka",
        "--mode=standalone",
        "--assume-yes-for-downloads",
        "--msvc=latest",
        "--lto=no",
        "--remove-output",
        "--output-dir=$workRoot",
        "--output-filename=$Name.exe",
        "--windows-company-name=DargonITP",
        "--windows-product-name=AntiOS",
        "--windows-file-description=$Description",
        "--windows-file-version=$numericVersion",
        "--windows-product-version=$numericVersion",
        "--windows-icon-from-ico=$icon",
        "--windows-console-mode=$ConsoleMode",
        "--include-package=antios",
        "--include-package-data=antios"
    )

    if ($RequireAdmin) {
        $args += "--windows-uac-admin"
    }
    if ($IncludeTray) {
        $args += "--include-package=pystray"
    }

    Write-Host "Compiling $Name with Nuitka..."
    & python @args $entryPath
    if ($LASTEXITCODE -ne 0) {
        throw "Nuitka compilation failed for $Name with exit code $LASTEXITCODE"
    }

    $entryStem = [System.IO.Path]::GetFileNameWithoutExtension($Entry)
    $sourceDist = Join-Path $workRoot "$entryStem.dist"
    if (-not (Test-Path -LiteralPath $sourceDist -PathType Container)) {
        throw "Nuitka standalone directory missing for ${Name}: $sourceDist"
    }

    $targetDist = Join-Path $outputRoot $Name
    Remove-Item -Recurse -Force $targetDist -ErrorAction SilentlyContinue
    Move-Item -LiteralPath $sourceDist -Destination $targetDist

    $exe = Join-Path $targetDist "$Name.exe"
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw "Hardened executable missing: $exe"
    }

    return $exe
}

$cli = Build-HardenedProgram -Entry "antios_entry.py" -Name "AntiOS" -Description "AntiOS Command Line" -ConsoleMode "force" -RequireAdmin
$gui = Build-HardenedProgram -Entry "antios_gui_entry.py" -Name "AntiOS-GUI" -Description "AntiOS Endpoint Protection" -ConsoleMode "disable" -RequireAdmin -IncludeTray
$guard = Build-HardenedProgram -Entry "antios_guard_entry.py" -Name "AntiOS-Guard" -Description "AntiOS Resident Guard" -ConsoleMode "force" -IncludeTray

Remove-Item -Recurse -Force $workRoot -ErrorAction SilentlyContinue

$manifest = [ordered]@{
    schema = 1
    product = "AntiOS"
    version = $version
    build_mode = "nuitka-standalone"
    protection = @(
        "Python source is compiled to native C/C++ output by Nuitka",
        "Release does not rely on directly extractable PyInstaller PYZ bytecode",
        "This raises reverse-engineering cost but is not cryptographic secrecy"
    )
    artifacts = @()
}

foreach ($exe in @($cli, $gui, $guard)) {
    $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest.artifacts += [ordered]@{
        path = [System.IO.Path]::GetRelativePath($outputRoot, $exe)
        sha256 = $hash
    }
}

$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputRoot "HARDENING_INFO.json") -Encoding utf8

Write-Host "Prepared hardened AntiOS binaries in $outputRoot"
