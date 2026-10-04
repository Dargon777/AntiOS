# Diagnose and repair the AntiOS-managed ClamAV runtime.
# Preview by default. Never disables Defender or modifies Windows Security registration.
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$UpdateSignatures,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$EngineServiceName = 'clamd'
$UpdaterTaskName = 'AntiOS ClamAV Signature Update'
$InstallRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AntiOS\ClamAV'
$DataRoot = Join-Path $env:ProgramData 'AntiOS-ClamAV'
$ConfigRoot = Join-Path $DataRoot 'config'
$DatabaseRoot = Join-Path $DataRoot 'database'
$ClamdConfig = Join-Path $ConfigRoot 'clamd.conf'
$FreshConfig = Join-Path $ConfigRoot 'freshclam.conf'
$ManagedClamd = Join-Path $InstallRoot 'clamd.exe'
$ManagedFresh = Join-Path $InstallRoot 'freshclam.exe'

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required to repair protection.'
    }
}

function Get-Signer([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Status = 'Missing'; Subject = $null; Thumbprint = $null }
    }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    return [pscustomobject]@{
        Status = [string]$sig.Status
        Subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
        Thumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
    }
}

function New-UpdaterTask {
    $action = New-ScheduledTaskAction -Execute $ManagedFresh -Argument ('--config-file="{0}" --quiet' -f $FreshConfig)
    $startup = New-ScheduledTaskTrigger -AtStartup
    $periodic = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(17) -RepetitionInterval (New-TimeSpan -Hours 2) -RepetitionDuration (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $UpdaterTaskName -Action $action -Trigger @($startup, $periodic) -Principal $principal -Settings $settings -Description 'Keeps the AntiOS ClamAV signature database current.' -Force | Out-Null
}

$issues = [System.Collections.Generic.List[string]]::new()
$actions = [System.Collections.Generic.List[string]]::new()

foreach ($path in @($ManagedClamd, $ManagedFresh, $ClamdConfig, $FreshConfig)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $issues.Add("missing:$path")
    }
}

$clamdSigner = Get-Signer $ManagedClamd
$freshSigner = Get-Signer $ManagedFresh
if ($clamdSigner.Status -ne 'Valid' -or $freshSigner.Status -ne 'Valid') {
    $issues.Add('engine-signature-invalid')
} elseif (-not $clamdSigner.Thumbprint -or $clamdSigner.Thumbprint -ne $freshSigner.Thumbprint) {
    $issues.Add('engine-signers-do-not-match')
}

$service = Get-CimInstance Win32_Service -Filter "Name='$EngineServiceName'" -ErrorAction SilentlyContinue
if (-not $service) {
    $issues.Add('clamd-service-missing')
} else {
    if ($service.ServiceType -ne 'Own Process') { $issues.Add('clamd-service-not-own-process') }
    if ($service.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) { $issues.Add('clamd-service-not-system') }
    if ($service.PathName -notlike "*$ManagedClamd*") { $issues.Add('clamd-service-path-mismatch') }
    if ($service.StartMode -ne 'Auto') { $issues.Add('clamd-service-not-auto') }
    if ($service.State -ne 'Running') { $issues.Add('clamd-service-not-running') }
}

$task = Get-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction SilentlyContinue
if (-not $task) {
    $issues.Add('freshclam-task-missing')
} else {
    $taskExecute = [string]$task.Actions[0].Execute
    if ([IO.Path]::GetFullPath($taskExecute) -ne [IO.Path]::GetFullPath($ManagedFresh)) {
        $issues.Add('freshclam-task-path-mismatch')
    }
}

$unsafeService = $issues | Where-Object {
    $_ -in @('clamd-service-not-own-process', 'clamd-service-not-system', 'clamd-service-path-mismatch')
}
if ($Apply -and $unsafeService) {
    throw "Refusing to repair an ambiguous clamd service: $($unsafeService -join ', ')"
}

if ($Apply) {
    Assert-Administrator
    if (-not (Test-Path -LiteralPath $ManagedClamd -PathType Leaf) -or
        -not (Test-Path -LiteralPath $ManagedFresh -PathType Leaf) -or
        -not (Test-Path -LiteralPath $ClamdConfig -PathType Leaf) -or
        -not (Test-Path -LiteralPath $FreshConfig -PathType Leaf)) {
        throw 'Managed ClamAV files/configuration are incomplete. Re-bootstrap the engine instead of repairing it.'
    }
    if ($clamdSigner.Status -ne 'Valid' -or $freshSigner.Status -ne 'Valid' -or
        -not $clamdSigner.Thumbprint -or $clamdSigner.Thumbprint -ne $freshSigner.Thumbprint) {
        throw 'Managed ClamAV binaries failed Authenticode validation. Re-bootstrap from the pinned official package.'
    }

    $engineAcl = New-Object Security.AccessControl.DirectorySecurity
    $engineAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)')
    Set-Acl -LiteralPath $InstallRoot -AclObject $engineAcl
    $actions.Add('engine-acl-reset')

    $dataAcl = New-Object Security.AccessControl.DirectorySecurity
    $dataAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $DataRoot -AclObject $dataAcl
    $actions.Add('data-acl-reset')

    if (-not $service) {
        & $ManagedClamd --install-service
        if ($LASTEXITCODE -ne 0) { throw "clamd --install-service failed with exit code $LASTEXITCODE" }
        $actions.Add('clamd-service-installed')
    }

    & "$env:SystemRoot\System32\sc.exe" config $EngineServiceName start= auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to configure ClamD automatic startup.' }
    & "$env:SystemRoot\System32\sc.exe" description $EngineServiceName 'AntiOS managed ClamAV scanning engine' | Out-Null
    & "$env:SystemRoot\System32\sc.exe" sdset $EngineServiceName 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCLORC;;;BU)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to harden the ClamD service ACL.' }
    $actions.Add('clamd-service-policy-reset')

    $running = Get-Service -Name $EngineServiceName
    if ($running.Status -ne 'Running') {
        Start-Service -Name $EngineServiceName
        (Get-Service -Name $EngineServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        $actions.Add('clamd-service-started')
    }

    New-UpdaterTask
    $actions.Add('freshclam-task-reset')

    if ($UpdateSignatures) {
        & $ManagedFresh "--config-file=$FreshConfig" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "FreshClam update failed with exit code $LASTEXITCODE" }
        $actions.Add('freshclam-update')
    }
}

$result = [ordered]@{
    schema = 1
    kind = 'antios-protection-repair'
    dry_run = -not [bool]$Apply
    healthy_before = ($issues.Count -eq 0)
    issues = @($issues)
    actions = @($actions)
    engine_root = $InstallRoot
    data_root = $DataRoot
    clamd_signature = $clamdSigner.Status
    freshclam_signature = $freshSigner.Status
    signer = $clamdSigner.Subject
    updater_task = $UpdaterTaskName
    defender = 'unchanged'
    native_driver = 'unchanged'
}

if ($Json) {
    $result | ConvertTo-Json -Depth 5
} else {
    [pscustomobject]$result | Format-List
    if (-not $Apply) {
        Write-Output 'Preview only. Re-run with -Apply to reset trusted ACLs/service/task; add -UpdateSignatures to refresh databases.'
    }
}
