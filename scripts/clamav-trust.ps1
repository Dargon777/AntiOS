# Authenticated ClamAV ZIP trust for the exact archive pinned in AntiOS.
# Imported only from the installed, administrator-protected AntiOS script folder.
# An arbitrary source folder must still pass Authenticode in protection-engine.ps1.
Set-StrictMode -Version Latest

function Get-AntiOSPinnedManifest {
    $candidate = Join-Path $PSScriptRoot 'clamav-windows.json'
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        $candidate = Join-Path (Split-Path $PSScriptRoot -Parent) 'release\clamav-windows.json'
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw 'The shipped, pinned ClamAV manifest is missing.'
    }
    $item = Get-Item -LiteralPath $candidate -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'The pinned ClamAV manifest cannot be a reparse point.'
    }
    $manifest = Get-Content -LiteralPath $candidate -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 1 -or $manifest.architecture -ne 'x64' -or
        [string]$manifest.version -notmatch '^\d+\.\d+\.\d+$' -or
        [string]$manifest.sha256 -notmatch '^[a-f0-9]{64}$' -or
        [int64]$manifest.size -lt 100000000 -or [int64]$manifest.size -gt 500000000 -or
        [string]$manifest.extract_dir -cne ('clamav-' + $manifest.version + '.win.x64') -or
        [string]$manifest.url -cne (
            'https://github.com/Cisco-Talos/clamav/releases/download/clamav-' +
            $manifest.version + '/clamav-' + $manifest.version + '.win.x64.zip'
        )) {
        throw 'The shipped ClamAV manifest is invalid or points outside the approved official release.'
    }
    return $manifest
}

function Get-AntiOSSha256([string]$LiteralPath) {
    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-AntiOSArchivePair {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$SourceDirectory,
        [Parameter(Mandatory)]$Manifest
    )
    $archive = Get-Item -LiteralPath $ArchivePath -Force -ErrorAction Stop
    if ($archive.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        $archive.PSIsContainer -or $archive.Length -ne [int64]$Manifest.size) {
        throw 'Trusted ClamAV archive is missing, redirected or has the wrong size.'
    }
    $digest = Get-AntiOSSha256 $archive.FullName
    if ($digest -cne [string]$Manifest.sha256) {
        throw 'Trusted ClamAV archive does not match the official SHA-256 pinned by AntiOS.'
    }
    # An unsigned portable binary is accepted only if its exact *bytes* can be
    # reproduced from this one, hash-pinned archive. Hashing just the ZIP
    # without comparing its extracted executables would allow a swapped EXE.
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archive.FullName)
    $fingerprints = [ordered]@{}
    try {
        foreach ($name in @('clamd.exe', 'freshclam.exe')) {
            $entryName = [string]$Manifest.extract_dir + '/' + $name
            $matches = @($zip.Entries | Where-Object {
                $_.FullName.Replace('\', '/') -ceq $entryName
            })
            if ($matches.Count -ne 1 -or [int64]$matches[0].Length -le 0 -or
                [int64]$matches[0].Length -gt 100000000) {
                throw "Pinned archive must contain exactly one valid $entryName"
            }
            $stream = $matches[0].Open()
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $expected = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
            } finally {
                $stream.Dispose()
                $sha.Dispose()
            }
            $actual = Get-AntiOSSha256 (Join-Path $SourceDirectory $name)
            if ($actual -cne $expected) {
                throw "Extracted $name differs from the pinned official archive."
            }
            $fingerprints[$name] = $expected
        }
    } finally {
        $zip.Dispose()
    }
    return [pscustomobject]@{
        schema = 1
        mode = 'pinned-archive-sha256'
        version = [string]$Manifest.version
        archive_sha256 = $digest
        clamd_sha256 = [string]$fingerprints['clamd.exe']
        freshclam_sha256 = [string]$fingerprints['freshclam.exe']
    }
}

function Assert-AntiOSInstalledPair {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$Manifest
    )
    $receiptPath = Join-Path $Root 'engine-trust.json'
    if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
        throw 'ClamAV archive trust receipt is missing.'
    }
    $item = Get-Item -LiteralPath $receiptPath -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'ClamAV trust receipt cannot be a reparse point.'
    }
    $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    if ($receipt.schema -ne 1 -or $receipt.mode -cne 'pinned-archive-sha256' -or
        [string]$receipt.version -cne [string]$Manifest.version -or
        [string]$receipt.archive_sha256 -cne [string]$Manifest.sha256) {
        throw 'Installed ClamAV trust receipt does not match the pinned AntiOS release.'
    }
    foreach ($name in @('clamd.exe', 'freshclam.exe')) {
        $field = if ($name -eq 'clamd.exe') { 'clamd_sha256' } else { 'freshclam_sha256' }
        if ([string]$receipt.$field -notmatch '^[a-f0-9]{64}$' -or
            (Get-AntiOSSha256 (Join-Path $Root $name)) -cne [string]$receipt.$field) {
            throw "Installed ClamAV $name has changed since its authenticated installation."
        }
    }
    return $receipt
}
