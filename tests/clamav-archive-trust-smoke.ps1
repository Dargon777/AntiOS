# Real Windows PowerShell 5.1 archive trust tests with unsigned inert fixture EXEs.
# There are no services, admin requests, or malware samples in this test.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\scripts\clamav-trust.ps1')

function Must-Throw([scriptblock]$Action, [string]$Reason) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw "Security regression: $Reason was accepted." }
}

# Behavioral ACL tests use synthetic ACEs only; do not change machine ACLs.
# In particular, Program Files ReadAndExecute and generic read/execute bits
# must not be mistaken for write access.
function New-TestClamAclRule {
    param(
        [Parameter(Mandatory)]$Identity,
        [Parameter(Mandatory)][int64]$Rights,
        [Security.AccessControl.AccessControlType]$Type = [Security.AccessControl.AccessControlType]::Allow,
        [Security.AccessControl.PropagationFlags]$Propagation = [Security.AccessControl.PropagationFlags]::None
    )
    return [pscustomobject]@{
        IdentityReference = $Identity
        FileSystemRights = $Rights
        AccessControlType = $Type
        PropagationFlags = $Propagation
    }
}

function Must-RejectAcl([object[]]$Rules, [string]$Reason, [string]$ExpectedMessage) {
    $failure = $null
    try { Assert-AntiOSNonWritableAcl -Rules $Rules } catch { $failure = $_.Exception.Message }
    if (-not $failure -or $failure -notmatch $ExpectedMessage) {
        throw "ACL regression: $Reason was not rejected for the expected reason. Actual: $failure"
    }
}

$users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$trustedInstaller = [Security.Principal.SecurityIdentifier]::new(
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)
$unknownName = [Security.Principal.NTAccount]::new(
    'AntiOS-Unknown-' + [guid]::NewGuid().ToString('N')
)
$rw = 'Unprivileged write permissions'
$unresolved = 'Cannot verify the identity'

$safe = @(
    (New-TestClamAclRule $users ([Security.AccessControl.FileSystemRights]::ReadAndExecute)),
    (New-TestClamAclRule $users ([int64]-1610612736)),
    (New-TestClamAclRule $systemSid ([Security.AccessControl.FileSystemRights]::FullControl)),
    (New-TestClamAclRule $admins ([Security.AccessControl.FileSystemRights]::Modify)),
    (New-TestClamAclRule $trustedInstaller ([Security.AccessControl.FileSystemRights]::FullControl)),
    (New-TestClamAclRule $users ([Security.AccessControl.FileSystemRights]::FullControl) -Propagation InheritOnly),
    (New-TestClamAclRule $users ([Security.AccessControl.FileSystemRights]::FullControl) -Type Deny),
    (New-TestClamAclRule $unknownName ([Security.AccessControl.FileSystemRights]::ReadAndExecute))
)
Assert-AntiOSNonWritableAcl -Rules $safe

foreach ($right in @(
    [Security.AccessControl.FileSystemRights]::WriteData,
    [Security.AccessControl.FileSystemRights]::AppendData,
    [Security.AccessControl.FileSystemRights]::WriteAttributes,
    [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes,
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
    [Security.AccessControl.FileSystemRights]::Delete,
    [Security.AccessControl.FileSystemRights]::ChangePermissions,
    [Security.AccessControl.FileSystemRights]::TakeOwnership,
    [Security.AccessControl.FileSystemRights]::Modify,
    [Security.AccessControl.FileSystemRights]::FullControl,
    [int64]0x40000000, # GENERIC_WRITE
    [int64]0x10000000  # GENERIC_ALL
)) {
    Must-RejectAcl @((New-TestClamAclRule $users $right)) "Users $right" $rw
}
Must-RejectAcl @((New-TestClamAclRule $unknownName ([Security.AccessControl.FileSystemRights]::WriteData))) 'unmapped writable identity' $unresolved
Write-Host 'PASS: read-only and inherited ACLs accepted; unsafe or unmapped write ACLs denied.'

$root = Join-Path $env:RUNNER_TEMP ('AntiOS-Trust-Test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $root -Force | Out-Null
try {
    $stage = Join-Path $root 'package'
    $folder = Join-Path $stage 'test-archive'
    New-Item -ItemType Directory $folder -Force | Out-Null
    $clamd = Join-Path $folder 'clamd.exe'
    $fresh = Join-Path $folder 'freshclam.exe'
    [IO.File]::WriteAllBytes($clamd, [Text.Encoding]::UTF8.GetBytes('fixture-clamd-unsigned'))
    [IO.File]::WriteAllBytes($fresh, [Text.Encoding]::UTF8.GetBytes('fixture-freshclam-unsigned'))
    $zip = Join-Path $root 'official-pinned.zip'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip)
    $fixture = [pscustomobject]@{
        schema=1; version='0.0.1'; architecture='x64'; extract_dir='test-archive';
        sha256=(Get-AntiOSSha256 $zip);
        size=(Get-Item $zip).Length
    }
    # Explicitly disabling Authenticode is not an escape hatch for an
    # arbitrary local source; it must be backed by the pinned official ZIP.
    $engineScript = Join-Path $PSScriptRoot '..\scripts\protection-engine.ps1'
    Must-Throw {
        & $engineScript -ClamAVDirectory $folder -RequireValidSignature:$false
    } 'unauthenticated manual ClamAV source'

    $receipt = Assert-AntiOSArchivePair -ArchivePath $zip -SourceDirectory $folder -Manifest $fixture
    if ($receipt.mode -ne 'pinned-archive-sha256' -or
        $receipt.clamd_sha256 -ne (Get-AntiOSSha256 $clamd)) {
        throw 'Trusted archive did not create expected exact binary fingerprints.'
    }

    $installed = Join-Path $root 'installed'
    Copy-Item $folder $installed -Recurse
    # The test fixture is intentionally in an unprivileged temporary folder.
    # Verify the production receipt check rejects it *before* we replace the
    # ACL preflight with a test-only stub for later hash-specific assertions.
    Must-Throw { Assert-AntiOSProtectedEngineRoot -Root $installed } 'unprotected test directory'
    function Assert-AntiOSProtectedEngineRoot { param([string]$Root) }

    $receiptPath = Join-Path $installed 'engine-trust.json'
    [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json))
    Assert-AntiOSInstalledPair -Root $installed -Manifest $fixture | Out-Null

    $original = [IO.File]::ReadAllBytes($clamd)
    [IO.File]::WriteAllBytes($clamd, [Text.Encoding]::UTF8.GetBytes('attacker-swapped-executable'))
    Must-Throw { Assert-AntiOSArchivePair -ArchivePath $zip -SourceDirectory $folder -Manifest $fixture } 'swapped extracted EXE'
    [IO.File]::WriteAllBytes($clamd, $original)

    $oldDigest = $fixture.sha256
    $fixture.sha256 = '0' * 64
    Must-Throw { Assert-AntiOSArchivePair -ArchivePath $zip -SourceDirectory $folder -Manifest $fixture } 'forged archive hash'
    $fixture.sha256 = $oldDigest

    [IO.File]::WriteAllBytes((Join-Path $installed 'clamd.exe'),
        [Text.Encoding]::UTF8.GetBytes('changed-after-install'))
    Must-Throw { Assert-AntiOSInstalledPair -Root $installed -Manifest $fixture } 'modified installed binary'
    [IO.File]::WriteAllBytes((Join-Path $installed 'clamd.exe'), $original)

    $broken = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    $broken.archive_sha256 = 'f' * 64
    [IO.File]::WriteAllText($receiptPath, ($broken | ConvertTo-Json))
    Must-Throw { Assert-AntiOSInstalledPair -Root $installed -Manifest $fixture } 'tampered trust receipt'

    $noFresh = Join-Path $root 'missing-fresh'
    New-Item -ItemType Directory -Path $noFresh -Force | Out-Null
    Copy-Item $clamd $noFresh
    Must-Throw { Assert-AntiOSArchivePair -ArchivePath $zip -SourceDirectory $noFresh -Manifest $fixture } 'missing engine executable'

    Write-Host 'PASS: only a byte-identical pinned archive can attest ClamAV; swaps and receipt tampering fail closed.'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
