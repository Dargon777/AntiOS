# Install or remove the AntiOS-managed ClamAV runtime.
# Preview by default. This script never disables Defender or installs the native filter driver.
[CmdletBinding()]
param(
    [string]$ClamAVDirectory,
    [switch]$Uninstall,
    [switch]$Apply,
    [bool]$RequireValidSignature = $true
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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
        $current = (Get-ItemProperty -Path $AntiOSRegistry -Name EngineServiceName -ErrorAction SilentlyContinue).EngineServiceName
        if ($current -eq $EngineServiceName) {
            Remove-ItemProperty -Path $AntiOSRegistry -Name EngineServiceName -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path $ClamRegistry) {
        $values = Get-ItemProperty -Path $ClamRegistry
        if ($values.ConfDir -eq $ConfigRoot) {
            Remove-ItemProperty -Path $ClamRegistry -Name ConfDir -ErrorAction SilentlyContinue
        }
        if ($values.DataDir -eq $DatabaseRoot) {
            Remove-ItemProperty -Path $ClamRegistry -Name DataDir -ErrorAction SilentlyContinue
        }
    }
}

if ($Uninstall) {
    if (-not $Apply) {
        Write-Output "Preview: stop/remove '$EngineServiceName', unregister '$UpdaterTaskName', remove AntiOS-owned ClamAV registry bindings and managed engine/data directories."
        return
    }
    Assert-Administrator
    $task = Get-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $UpdaterTaskName -Confirm:$false
    }
    $service = Get-Service -Name $EngineServiceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $EngineServiceName -Force
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
        $managedClamd = Join-Path $InstallRoot 'clamd.exe'
        if (-not (Test-Path -LiteralPath $managedClamd)) {
            throw 'The clamd service exists but the AntiOS-managed executable is missing; refusing ambiguous removal.'
        }
        & $managedClamd --uninstall-service
        if ($LASTEXITCODE -ne 0) { throw "clamd --uninstall-service failed with exit code $LASTEXITCODE" }
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
$signature = Assert-SignedPair $SourceClamd $SourceFresh
$configSource = Get-ConfigSource

if (Get-Service -Name $EngineServiceName -ErrorAction SilentlyContinue) {
    throw "A service named '$EngineServiceName' already exists. AntiOS will not replace an existing ClamAV service."
}
if (Test-Path -LiteralPath $InstallRoot) { throw "Managed engine destination already exists: $InstallRoot" }
if (Test-Path -LiteralPath $DataRoot) { throw "Managed engine data destination already exists: $DataRoot" }
if (Test-Path $ClamRegistry) {
    $existing = Get-ItemProperty -Path $ClamRegistry
    if ($existing.ConfDir -or $existing.DataDir) {
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
    Copy-Item -LiteralPath (Join-Path $Source '*') -Destination $InstallRoot -Recurse -Force

    $ManagedClamd = Join-Path $InstallRoot 'clamd.exe'
    $ManagedFresh = Join-Path $InstallRoot 'freshclam.exe'
    Assert-SignedPair $ManagedClamd $ManagedFresh | Out-Null

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
    if ($engine.PathName -notlike "*$ManagedClamd*") {
        throw "Installed clamd service does not reference the managed executable: $($engine.PathName)"
    }
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
    Register-ScheduledTask -TaskName $UpdaterTaskName -Action $action -Trigger @($startup, $periodic) -Principal $principal -Settings $settings -Description 'Keeps the AntiOS ClamAV signature database current.' -Force | Out-Null
    $taskInstalled = $true

    Write-Output "AntiOS managed ClamAV is running as '$EngineServiceName'. FreshClam is scheduled and Guard can verify the loopback peer through SCM."
} catch {
    if ($taskInstalled) {
        Unregister-ScheduledTask -TaskName $UpdaterTaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($serviceInstalled) {
        Stop-Service -Name $EngineServiceName -Force -ErrorAction SilentlyContinue
        $managed = Join-Path $InstallRoot 'clamd.exe'
        if (Test-Path -LiteralPath $managed) { & $managed --uninstall-service | Out-Null }
    }
    Remove-OwnedRegistry
    if ($createdInstall -and (Test-Path -LiteralPath $InstallRoot)) { Remove-Item -LiteralPath $InstallRoot -Recurse -Force }
    if ($createdData -and (Test-Path -LiteralPath $DataRoot)) { Remove-Item -LiteralPath $DataRoot -Recurse -Force }
    throw
}
