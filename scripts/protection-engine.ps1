# Install or remove the AntiOS-managed ClamAV runtime.
# Preview by default. This script never disables Defender or installs the native filter driver.
[CmdletBinding()]
param(
    [string]$ClamAVDirectory,
    [switch]$Uninstall,
    [switch]$Apply,
    [bool]$RequireValidSignature = $true,
    [string]$TrustedArchivePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'clamav-trust.ps1')

$EngineServiceName = 'clamd'
$UpdaterTaskName = 'AntiOS ClamAV Signature Update'
$InstallRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AntiOS\ClamAV'
$DataRoot = Join-Path $env:ProgramData 'AntiOS-ClamAV'
$ConfigRoot = Join-Path $DataRoot 'config'
$DatabaseRoot = Join-Path $DataRoot 'database'
$TempRoot = Join-Path $DataRoot 'tmp'
$ClamdConfig = Join-Path $ConfigRoot 'clamd.conf'
$FreshConfig = Join-Path $ConfigRoot 'freshclam.conf'
$AntiOSRegistry = 'HKLM:\SOFTWARE\AntiOS'
$ClamRegistry = 'HKLM:\SOFTWARE\ClamAV'

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required.'
    }
}

function Assert-NoReparseTree([string]$Root) {
    $item = Get-Item -LiteralPath $Root -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Reparse points are not accepted in the engine source: $Root"
    }
    Get-ChildItem -LiteralPath $Root -Force -Recurse | ForEach-Object {
        if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Reparse points are not accepted in the engine source: $($_.FullName)"
        }
    }
}

function Assert-SignedPair([string]$Clamd, [string]$FreshClam) {
    $a = Get-AuthenticodeSignature -LiteralPath $Clamd
    $b = Get-AuthenticodeSignature -LiteralPath $FreshClam
    if ($RequireValidSignature) {
        if ($a.Status -ne 'Valid' -or $b.Status -ne 'Valid') {
            throw 'Production engine setup requires valid Authenticode signatures on clamd.exe and freshclam.exe.'
        }
        if (-not $a.SignerCertificate -or -not $b.SignerCertificate -or
            $a.SignerCertificate.Thumbprint -ne $b.SignerCertificate.Thumbprint) {
            throw 'clamd.exe and freshclam.exe must be signed by the same publisher certificate.'
        }
    }
    return [pscustomobject]@{
        ClamdStatus = $a.Status
        FreshClamStatus = $b.Status
        Signer = if ($a.SignerCertificate) { $a.SignerCertificate.Subject } else { '(none)' }
        Thumbprint = if ($a.SignerCertificate) { $a.SignerCertificate.Thumbprint } else { '(none)' }
    }
}

function Get-ConfigSource {
    $packaged = Join-Path $PSScriptRoot 'clamav-config'
    $repo = Join-Path (Split-Path $PSScriptRoot -Parent) 'config\clamav'
    if (Test-Path -LiteralPath (Join-Path $packaged 'clamd.conf.example')) { return $packaged }
    if (Test-Path -LiteralPath (Join-Path $repo 'clamd.conf.example')) { return $repo }
    throw 'AntiOS ClamAV configuration templates are missing.'
}

function Remove-OwnedRegistry {
    if (Test-Path $AntiOSRegistry) {
        $current = Get-ItemPropertyValue -Path $AntiOSRegistry -Name EngineServiceName -ErrorAction SilentlyContinue
        if ($current -eq $EngineServiceName) {
            Remove-ItemProperty -Path $AntiOSRegistry -Name EngineServiceName -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path $ClamRegistry) {
        $confDir = Get-ItemPropertyValue -Path $ClamRegistry -Name ConfDir -ErrorAction SilentlyContinue
        $dataDir = Get-ItemPropertyValue -Path $ClamRegistry -Name DataDir -ErrorAction SilentlyContinue
        if ($confDir -eq $ConfigRoot) {
            Remove-ItemProperty -Path $ClamRegistry -Name ConfDir -ErrorAction SilentlyContinue
        }
        if ($dataDir -eq $DatabaseRoot) {
            Remove-ItemProperty -Path $ClamRegistry -Name DataDir -ErrorAction SilentlyContinue
        }
    }
}

function Assert-ManagedClamdService {
    $registered = Get-CimInstance Win32_Service -Filter "Name='$EngineServiceName'" -ErrorAction Stop
    $expectedExe = Join-Path $InstallRoot 'clamd.exe'
    $escapedExe = [regex]::Escape($expectedExe)
    # Match the actual SCM image path, not a substring that could be present
    # in an unrelated command argument or a similarly named installation.
    $imagePattern = ('^\s*(?:"{0}"|{0})(?=\s|$)' -f $escapedExe)
    if (-not $registered -or $registered.ServiceType -ne 'Own Process' -or
        $registered.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM') -or
        [string]$registered.PathName -notmatch $imagePattern) {
        throw "Refusing to modify a ClamD service not owned by AntiOS: $($registered.PathName)"
    }
}

if ($Uninstall) {
    if (-not $Apply) {
        Write-Output "Preview: stop/remove '$EngineServiceName', unregister '$UpdaterTaskName', remove AntiOS-owned ClamAV registry bindings and managed engine/data directories."
        return
    }
    Assert-Administrator
    # Check *all* managed targets before stopping tasks/services or touching
    # registry state. Recursive deletion must not traverse a junction.
    if (Test-Path -LiteralPath $InstallRoot) { Assert-NoReparseTree $InstallRoot }
    if (Test-Path -LiteralPath $DataRoot) { Assert-NoReparseTree $DataRoot }
    $service = Get-Service -Name $EngineServiceName -ErrorAction SilentlyContinue
    if ($service) { Assert-ManagedClamdService }
    $task = Get-ScheduledTask -TaskPath '\' -TaskName $UpdaterTaskName -ErrorAction SilentlyContinue
    if ($task) {
        $actions = @($task.Actions)
        $managedFresh = Join-Path $InstallRoot 'freshclam.exe'
        if ($actions.Count -ne 1 -or
            [IO.Path]::GetFullPath([string]$actions[0].Execute) -ine
                [IO.Path]::GetFullPath($managedFresh)) {
            throw 'Refusing to unregister a non-AntiOS ClamAV update task.'
        }
    }
    if ($task) {
        Stop-ScheduledTask -TaskPath '\' -TaskName $UpdaterTaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskPath '\' -TaskName $UpdaterTaskName -Confirm:$false
    }
    if ($service) {
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $EngineServiceName -Force
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        # Do not execute an on-disk ClamAV binary with administrator rights
        # during uninstall. The verified SCM service identity is sufficient.
        & "$env:SystemRoot\System32\sc.exe" delete $EngineServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not delete the verified AntiOS ClamD service (sc.exe exit $LASTEXITCODE)"
        }
    }
    Remove-OwnedRegistry
    if (Test-Path -LiteralPath $InstallRoot) { Remove-Item -LiteralPath $InstallRoot -Recurse -Force }
    if (Test-Path -LiteralPath $DataRoot) { Remove-Item -LiteralPath $DataRoot -Recurse -Force }
    Write-Output 'Removed the AntiOS-managed ClamAV runtime. Quarantine and other AntiOS data were not touched.'
    return
}

if (-not $ClamAVDirectory) { throw 'Specify -ClamAVDirectory pointing to an official/reviewed Windows ClamAV x64 installation or extracted package.' }
$Source = (Resolve-Path -LiteralPath $ClamAVDirectory).Path
Assert-NoReparseTree $Source
$SourceClamd = Join-Path $Source 'clamd.exe'
$SourceFresh = Join-Path $Source 'freshclam.exe'
foreach ($required in @($SourceClamd, $SourceFresh)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required ClamAV binary is missing: $required" }
}
$trustedReceipt = $null
if ($TrustedArchivePath) {
    # Only the shipped SHA256-pinned archive and byte-identical extracted EXEs
    # can use archive trust. Manual/third-party sources need Authenticode.
    $manifest = Get-AntiOSPinnedManifest
    $stagingRoot = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($TrustedArchivePath))
    $programFiles = [IO.Path]::GetFullPath([Environment]::GetFolderPath('ProgramFiles'))
    $stagingName = [IO.Path]::GetFileName($stagingRoot)
    $expectedSource = Join-Path (Join-Path $stagingRoot 'extract') ([string]$manifest.extract_dir)
    if ([IO.Path]::GetDirectoryName($stagingRoot) -ine $programFiles -or
        $stagingName -cnotmatch '^AntiOS-ClamAV-Staging-[a-f0-9]{32}$' -or
        $Source -ine [IO.Path]::GetFullPath($expectedSource)) {
        throw 'Archive-based ClamAV trust requires the exact protected AntiOS staging directory.'
    }
    if (Test-Path -LiteralPath $stagingRoot) { Assert-NoReparseTree $stagingRoot }
    $trustedReceipt = Assert-AntiOSArchivePair -ArchivePath $TrustedArchivePath -SourceDirectory $Source -Manifest $manifest
    $signature = [pscustomobject]@{
        ClamdStatus = 'ArchivePinned'
        FreshClamStatus = 'ArchivePinned'
        Signer = '(pinned release archive SHA-256; PE publisher not asserted)'
    }
} else {
    if (-not $RequireValidSignature) {
        throw 'Unsigned arbitrary ClamAV sources are not supported. Use the pinned official archive installer.'
    }
    $signature = Assert-SignedPair $SourceClamd $SourceFresh
}
$configSource = Get-ConfigSource

if (Get-Service -Name $EngineServiceName -ErrorAction SilentlyContinue) {
    throw "A service named '$EngineServiceName' already exists. AntiOS will not replace an existing ClamAV service."
}
if (Test-Path -LiteralPath $InstallRoot) { throw "Managed engine destination already exists: $InstallRoot" }
if (Test-Path -LiteralPath $DataRoot) { throw "Managed engine data destination already exists: $DataRoot" }
if (Test-Path $ClamRegistry) {
    $existingConf = Get-ItemPropertyValue -Path $ClamRegistry -Name ConfDir -ErrorAction SilentlyContinue
    $existingData = Get-ItemPropertyValue -Path $ClamRegistry -Name DataDir -ErrorAction SilentlyContinue
    if ($existingConf -or $existingData) {
        throw 'Existing machine-wide ClamAV ConfDir/DataDir registry configuration was found; refusing to overwrite another installation.'
    }
}

[pscustomobject]@{
    Source = $Source
    Destination = $InstallRoot
    Data = $DataRoot
    Service = $EngineServiceName
    UpdaterTask = $UpdaterTaskName
    Signatures = "$($signature.ClamdStatus) / $($signature.FreshClamStatus)"
    Signer = $signature.Signer
    Defender = 'unchanged'
    NativeDriver = 'unchanged'
} | Format-List

if (-not $Apply) {
    Write-Output 'Preview only. Rerun with -Apply after reviewing the source, signer and destinations.'
    return
}

Assert-Administrator
$createdInstall = $false
$createdData = $false
$serviceInstalled = $false
$taskInstalled = $false
try {
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    $createdInstall = $true
    $engineAcl = New-Object Security.AccessControl.DirectorySecurity
    $engineAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)')
    Set-Acl -LiteralPath $InstallRoot -AclObject $engineAcl
    Copy-Item -Path (Join-Path $Source '*') -Destination $InstallRoot -Recurse -Force

    $ManagedClamd = Join-Path $InstallRoot 'clamd.exe'
    $ManagedFresh = Join-Path $InstallRoot 'freshclam.exe'
    if ($trustedReceipt) {
        foreach ($name in @('clamd.exe', 'freshclam.exe')) {
            $field = if ($name -eq 'clamd.exe') { 'clamd_sha256' } else { 'freshclam_sha256' }
            if ((Get-AntiOSSha256 (Join-Path $InstallRoot $name)) -cne [string]$trustedReceipt.$field) {
                throw "Installed $name differs from the verified official archive."
            }
        }
        # Receipt is stored in protected Program Files; hash checking replaces
        # PE signing *only* for this authenticated, immutable vendor ZIP.
        [IO.File]::WriteAllText(
            (Join-Path $InstallRoot 'engine-trust.json'),
            ($trustedReceipt | ConvertTo-Json -Depth 4),
            [Text.UTF8Encoding]::new($false)
        )
        Assert-AntiOSInstalledPair -Root $InstallRoot -Manifest $manifest | Out-Null
    } else {
        Assert-SignedPair $ManagedClamd $ManagedFresh | Out-Null
    }

    New-Item -ItemType Directory -Path $ConfigRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $DatabaseRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $TempRoot -Force | Out-Null
    $createdData = $true
    $dataAcl = New-Object Security.AccessControl.DirectorySecurity
    $dataAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $DataRoot -AclObject $dataAcl

    Copy-Item -LiteralPath (Join-Path $configSource 'clamd.conf.example') -Destination $ClamdConfig
    Copy-Item -LiteralPath (Join-Path $configSource 'freshclam.conf.example') -Destination $FreshConfig

    New-Item -Path $ClamRegistry -Force | Out-Null
    New-ItemProperty -Path $ClamRegistry -Name ConfDir -PropertyType String -Value $ConfigRoot -Force | Out-Null
    New-ItemProperty -Path $ClamRegistry -Name DataDir -PropertyType String -Value $DatabaseRoot -Force | Out-Null
    New-Item -Path $AntiOSRegistry -Force | Out-Null
    New-ItemProperty -Path $AntiOSRegistry -Name EngineServiceName -PropertyType String -Value $EngineServiceName -Force | Out-Null

    & $ManagedFresh "--config-file=$FreshConfig"
    if ($LASTEXITCODE -ne 0) { throw "Initial FreshClam update failed with exit code $LASTEXITCODE" }

    & $ManagedClamd --install-service
    if ($LASTEXITCODE -ne 0) { throw "clamd --install-service failed with exit code $LASTEXITCODE" }
    $serviceInstalled = $true

    $engine = Get-CimInstance Win32_Service -Filter "Name='$EngineServiceName'"
    if (-not $engine -or $engine.ServiceType -ne 'Own Process' -or
        $engine.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM')) {
        throw 'Installed clamd service is not an own-process LocalSystem service.'
    }
    Assert-ManagedClamdService
    & "$env:SystemRoot\System32\sc.exe" config $EngineServiceName start= auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to configure automatic ClamD startup.' }
    & "$env:SystemRoot\System32\sc.exe" description $EngineServiceName 'AntiOS managed ClamAV scanning engine' | Out-Null
    & "$env:SystemRoot\System32\sc.exe" sdset $EngineServiceName 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCLORC;;;BU)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to harden the ClamD service ACL.' }

    Start-Service -Name $EngineServiceName
    (Get-Service -Name $EngineServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

    $action = New-ScheduledTaskAction -Execute $ManagedFresh -Argument ('--config-file="{0}" --quiet' -f $FreshConfig)
    $startup = New-ScheduledTaskTrigger -AtStartup
    $periodic = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(17) -RepetitionInterval (New-TimeSpan -Hours 2) -RepetitionDuration (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskPath '\' -TaskName $UpdaterTaskName -Action $action -Trigger @($startup, $periodic) -Principal $principal -Settings $settings -Description 'Keeps the AntiOS ClamAV signature database current.' -Force | Out-Null
    $taskInstalled = $true

    Write-Output "AntiOS managed ClamAV is running as '$EngineServiceName'. FreshClam is scheduled and Guard can verify the loopback peer through SCM."
} catch {
    if ($taskInstalled) {
        Unregister-ScheduledTask -TaskPath '\' -TaskName $UpdaterTaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($serviceInstalled) {
        Stop-Service -Name $EngineServiceName -Force -ErrorAction SilentlyContinue
        # Never execute a possibly modified copy to delete its service.
        & "$env:SystemRoot\System32\sc.exe" delete $EngineServiceName | Out-Null
    }
    Remove-OwnedRegistry
    if ($createdInstall -and (Test-Path -LiteralPath $InstallRoot)) {
        Assert-NoReparseTree $InstallRoot
        Remove-Item -LiteralPath $InstallRoot -Recurse -Force
    }
    if ($createdData -and (Test-Path -LiteralPath $DataRoot)) {
        Assert-NoReparseTree $DataRoot
        Remove-Item -LiteralPath $DataRoot -Recurse -Force
    }
    throw
}
