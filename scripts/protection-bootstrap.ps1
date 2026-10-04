# Bootstrap or refresh the AntiOS-managed ClamAV engine from a pinned official package.
# Preview by default; -Apply performs the download/install. Defender is never disabled.
[CmdletBinding()]
param(
    [string]$ManifestPath,
    [string]$PackagePath,
    [switch]$Apply,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required to bootstrap protection.'
    }
}

function Resolve-ManifestPath {
    param([string]$Requested)
    if ($Requested) { return (Resolve-Path -LiteralPath $Requested).Path }
    foreach ($candidate in @(
        (Join-Path $PSScriptRoot 'clamav-windows.json'),
        (Join-Path (Split-Path $PSScriptRoot -Parent) 'release\clamav-windows.json')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw 'Pinned ClamAV manifest is missing.'
}

function Resolve-EngineScript {
    $path = Join-Path $PSScriptRoot 'protection-engine.ps1'
    if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    throw 'protection-engine.ps1 is missing.'
}

function Resolve-RepairScript {
    $path = Join-Path $PSScriptRoot 'protection-repair.ps1'
    if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    return $null
}

$manifestFile = Resolve-ManifestPath $ManifestPath
$manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
if ($manifest.schema -ne 1 -or $manifest.architecture -ne 'x64') {
    throw 'Unsupported ClamAV bootstrap manifest.'
}
if ([string]$manifest.url -notmatch '^https://github\.com/Cisco-Talos/clamav/releases/download/clamav-[0-9.]+/clamav-[0-9.]+\.win\.x64\.zip$') {
    throw 'Manifest URL is not an approved official ClamAV x64 release URL.'
}
if ([string]$manifest.sha256 -notmatch '^[a-f0-9]{64}$') {
    throw 'Manifest SHA-256 is invalid.'
}
if ([int64]$manifest.size -lt 100000000 -or [int64]$manifest.size -gt 500000000) {
    throw 'Manifest package size is outside the expected Windows ClamAV range.'
}

$installRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AntiOS\ClamAV'
$managedClamd = Join-Path $installRoot 'clamd.exe'
$managedFresh = Join-Path $installRoot 'freshclam.exe'
$service = Get-Service -Name 'clamd' -ErrorAction SilentlyContinue
$existingManaged = $service -and (Test-Path -LiteralPath $managedClamd -PathType Leaf) -and
                   (Test-Path -LiteralPath $managedFresh -PathType Leaf)

$plan = [ordered]@{
    schema = 1
    kind = 'antios-protection-bootstrap'
    dry_run = -not [bool]$Apply
    version = [string]$manifest.version
    architecture = [string]$manifest.architecture
    source = if ($PackagePath) { $PackagePath } else { [string]$manifest.url }
    sha256 = [string]$manifest.sha256
    expected_size = [int64]$manifest.size
    existing_managed_engine = [bool]$existingManaged
    destination = $installRoot
    defender = 'unchanged'
    native_driver = 'unchanged'
}

if (-not $Apply) {
    if ($Json) { $plan | ConvertTo-Json -Depth 4 } else { [pscustomobject]$plan | Format-List }
    return
}

Assert-Administrator

if ($existingManaged) {
    $repair = Resolve-RepairScript
    if (-not $repair) {
        throw 'Managed engine already exists and protection-repair.ps1 is missing.'
    }
    & $repair -Apply -UpdateSignatures -Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Protection repair failed with exit code $LASTEXITCODE" }
    $plan['action'] = 'repaired-existing'
    if ($Json) { $plan | ConvertTo-Json -Depth 4 } else { [pscustomobject]$plan | Format-List }
    return
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('AntiOS-ClamAV-' + [Guid]::NewGuid().ToString('N'))
$zip = Join-Path $tempRoot 'clamav.zip'
$extract = Join-Path $tempRoot 'extract'
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    if ($PackagePath) {
        $sourceZip = (Resolve-Path -LiteralPath $PackagePath).Path
        Copy-Item -LiteralPath $sourceZip -Destination $zip
    } else {
        Invoke-WebRequest -Uri ([string]$manifest.url) -OutFile $zip -UseBasicParsing
    }

    $file = Get-Item -LiteralPath $zip
    if ($file.Length -ne [int64]$manifest.size) {
        throw "ClamAV package size mismatch: expected $($manifest.size), got $($file.Length)"
    }
    $digest = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($digest -ne [string]$manifest.sha256) {
        throw "ClamAV package SHA-256 mismatch: $digest"
    }

    New-Item -ItemType Directory -Path $extract -Force | Out-Null
    Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
    $source = Join-Path $extract ([string]$manifest.extract_dir)
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "Pinned ClamAV archive did not contain expected directory '$($manifest.extract_dir)'."
    }

    $engineScript = Resolve-EngineScript
    & $engineScript -ClamAVDirectory $source -Apply -RequireValidSignature $true | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Managed engine installation failed with exit code $LASTEXITCODE" }

    $plan['action'] = 'installed'
    if ($Json) { $plan | ConvertTo-Json -Depth 4 } else { [pscustomobject]$plan | Format-List }
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
