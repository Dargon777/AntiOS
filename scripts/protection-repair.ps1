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
. (Join-Path $PSScriptRoot 'clamav-trust.ps1')

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
$engineTrust = 'none'
$receiptFile = Join-Path $InstallRoot 'engine-trust.json'
if (Test-Path -LiteralPath $receiptFile) {
    try {
        $pinnedManifest = Get-AntiOSPinnedManifest
        Assert-AntiOSInstalledPair -Root $InstallRoot -Manifest $pinnedManifest | Out-Null
        $engineTrust = 'pinned-archive-sha256'
    } catch {
        $issues.Add('engine-archive-attestation-invalid')
    }
} elseif ($clamdSigner.Status -eq 'Valid' -and $freshSigner.Status -eq 'Valid' -and
          $clamdSigner.Thumbprint -and $clamdSigner.Thumbprint -eq $freshSigner.Thumbprint) {
    $engineTrust = 'authenticode'
} else {
    $issues.Add('engine-signature-invalid')
}

$service = Get-CimInstance Win32_Service -Filter "Name='$EngineServiceName'" -ErrorAction SilentlyContinue
if (-not $service) {
    $issues.Add('clamd-service-missing')
} else {
    if ($service.ServiceType -ne 'Own Process') { $issues.Add('clamd-service-not-own-process') }
    if ($service.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) { $issues.Add('clamd-service-not-system') }
    $exactClamd = [regex]::Escape($ManagedClamd)
    $expectedImage = ('^\s*(?:"{0}"|{0})(?=\s|$)' -f $exactClamd)
    if ([string]$service.PathName -notmatch $expectedImage) {
        $issues.Add('clamd-service-path-mismatch')
    }
    if ($service.StartMode -ne 'Auto') { $issues.Add('clamd-service-not-auto') }
    if ($service.State -ne 'Running') { $issues.Add('clamd-service-not-running') }
}

$task = Get-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction SilentlyContinue
if (-not $task) {
    $issues.Add('freshclam-task-missing')
} else {
    $taskActions = @($task.Actions)
    if ($taskActions.Count -ne 1 -or
        -not $taskActions[0].Execute -or
        [IO.Path]::GetFullPath([string]$taskActions[0].Execute) -ine
            [IO.Path]::GetFullPath($ManagedFresh)) {
        $issues.Add('freshclam-task-path-mismatch')
    }
}

$unsafeService = $issues | Where-Object {
    $_ -in @('clamd-service-not-own-process', 'clamd-service-not-system', 'clamd-service-path-mismatch',
               'freshclam-task-path-mismatch')
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
    # A data-folder junction could otherwise redirect elevated ACL repair or
    # FreshClam updates into an unrelated directory. Refuse all such trees.
    foreach ($target in @($InstallRoot, $DataRoot)) {
        if (Test-Path -LiteralPath $target) {
            $items = @(Get-Item -LiteralPath $target -Force) +
                     @(Get-ChildItem -LiteralPath $target -Force -Recurse)
            if (@($items | Where-Object {
                $_.Attributes -band [IO.FileAttributes]::ReparsePoint
            }).Count) {
                throw "Cannot repair ClamAV through a reparse-point tree: $target"
            }
        }
    }
    if ($engineTrust -eq 'none') {
        throw 'Managed ClamAV binaries failed authenticated archive/Authenticode validation. Re-bootstrap from the pinned official package.'
    }
    if ($engineTrust -eq 'pinned-archive-sha256') {
        Assert-AntiOSInstalledPair -Root $InstallRoot -Manifest (Get-AntiOSPinnedManifest) | Out-Null
    }

    # Snapshot recoverable state BEFORE the first mutation. A repair can fail
    # after the service starts or the updater task is replaced; that must not
    # leave a new half-configured SYSTEM component behind.
    $oldEngineAcl = Get-Acl -LiteralPath $InstallRoot -ErrorAction Stop
    $oldDataAcl = Get-Acl -LiteralPath $DataRoot -ErrorAction Stop
    $taskSnapshot = if ($task) {
        Export-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction Stop
    } else { $null }
    $originalServiceStart = if ($service) { [string]$service.StartMode } else { $null }
    $originalServiceDescription = if ($service) { [string]$service.Description } else { $null }
    $serviceWasRunning = [bool]($service -and $service.State -eq 'Running')
    $originalServiceSddl = $null
    $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
    if ($service) {
        $sddlOutput = @(& $sc sdshow $EngineServiceName)
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to snapshot ClamD service security descriptor before repair.'
        }
        $originalServiceSddl = @($sddlOutput | Where-Object { $_ -match '^\s*D:' } |
            Select-Object -First 1)
        if ($originalServiceSddl.Count -ne 1) {
            throw 'Could not parse the ClamD service security descriptor for rollback.'
        }
        $originalServiceSddl = $originalServiceSddl[0].Trim()
    }
    $serviceInstallAttempted = $false
    $taskWriteAttempted = $false
    $servicePolicyWriteAttempted = $false

    try {
    $engineAcl = New-Object Security.AccessControl.DirectorySecurity
    $engineAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)')
    Set-Acl -LiteralPath $InstallRoot -AclObject $engineAcl
    $actions.Add('engine-acl-reset')

    $dataAcl = New-Object Security.AccessControl.DirectorySecurity
    $dataAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $DataRoot -AclObject $dataAcl
    $actions.Add('data-acl-reset')

    if (-not $service) {
        $serviceInstallAttempted = $true
        & $ManagedClamd --install-service
        if ($LASTEXITCODE -ne 0) { throw "clamd --install-service failed with exit code $LASTEXITCODE" }
        $actions.Add('clamd-service-installed')
    }

    $servicePolicyWriteAttempted = $true
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

    $taskWriteAttempted = $true
    New-UpdaterTask
    $actions.Add('freshclam-task-reset')

    if ($UpdateSignatures) {
        & $ManagedFresh "--config-file=$FreshConfig" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "FreshClam update failed with exit code $LASTEXITCODE" }
        $actions.Add('freshclam-update')
    }

    # Do not report repair success based solely on Start-Service returning.
    # Re-query SCM and the scheduled task, since their state can change while
    # commands execute. ClamAV VERSION/peer readiness is checked separately by
    # the GUI/Guard and is not implied by this system-maintenance outcome.
    $afterService = Get-CimInstance Win32_Service -Filter "Name='$EngineServiceName'" -ErrorAction Stop
    $expectedImage = ('^\s*(?:"{0}"|{0})(?=\s|$)' -f [regex]::Escape($ManagedClamd))
    if (-not $afterService -or $afterService.State -ne 'Running' -or
        $afterService.ServiceType -ne 'Own Process' -or
        $afterService.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM') -or
        [string]$afterService.PathName -notmatch $expectedImage -or
        $afterService.StartMode -ne 'Auto') {
        throw 'ClamD failed post-repair SCM identity/running-state verification.'
    }
    $afterTask = Get-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction Stop
    $afterActions = @($afterTask.Actions)
    if ($afterActions.Count -ne 1 -or -not $afterActions[0].Execute -or
        [IO.Path]::GetFullPath([string]$afterActions[0].Execute) -ine
        [IO.Path]::GetFullPath($ManagedFresh)) {
        throw 'FreshClam update task failed post-repair ownership verification.'
    }
    if ($engineTrust -eq 'pinned-archive-sha256') {
        Assert-AntiOSInstalledPair -Root $InstallRoot -Manifest (Get-AntiOSPinnedManifest) | Out-Null
    }
    $actions.Add('post-repair-service-and-task-verified')
    } catch {
        $originalFailure = $_
        # Rollback is best effort. Never remove/modify a foreign service or a
        # task whose executable no longer matches the AntiOS-owned path.
        if ($taskWriteAttempted) {
            try {
                $rollbackTask = Get-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction SilentlyContinue
                $rollbackActions = if ($rollbackTask) { @($rollbackTask.Actions) } else { @() }
                if ($rollbackTask -and
                    ($rollbackActions.Count -ne 1 -or -not $rollbackActions[0].Execute -or
                     [IO.Path]::GetFullPath([string]$rollbackActions[0].Execute) -ine
                     [IO.Path]::GetFullPath($ManagedFresh))) {
                    throw 'Task ownership changed during repair; refusing rollback of a foreign task.'
                }
                if ($taskSnapshot) {
                    Register-ScheduledTask -TaskName $UpdaterTaskName -Xml $taskSnapshot -Force -ErrorAction Stop | Out-Null
                } elseif ($rollbackTask) {
                    Unregister-ScheduledTask -TaskName $UpdaterTaskName -Confirm:$false -ErrorAction Stop
                }
            } catch {
                Write-Warning "ClamAV updater-task rollback failed: $($_.Exception.Message)"
            }
        }
        if ($serviceInstallAttempted -or $servicePolicyWriteAttempted) {
            try {
                $rollbackService = Get-CimInstance Win32_Service -Filter "Name='$EngineServiceName'" -ErrorAction SilentlyContinue
                if ($rollbackService) {
                    $trustedImage = ('^\s*(?:"{0}"|{0})(?=\s|$)' -f [regex]::Escape($ManagedClamd))
                    if ([string]$rollbackService.PathName -notmatch $trustedImage -or
                        $rollbackService.ServiceType -ne 'Own Process' -or
                        $rollbackService.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) {
                        throw 'Service ownership changed; refusing rollback of a foreign service.'
                    }
                    if ($serviceInstallAttempted -and -not $service) {
                        if ($rollbackService.State -ne 'Stopped') {
                            Stop-Service -Name $EngineServiceName -Force -ErrorAction Stop
                        }
                        & $sc delete $EngineServiceName | Out-Null
                        if ($LASTEXITCODE -ne 0) { throw 'Could not delete newly created ClamD service.' }
                    } elseif ($service) {
                        $oldStart = switch ($originalServiceStart) {
                            'Auto' { 'auto' }
                            'Manual' { 'demand' }
                            'Disabled' { 'disabled' }
                            default { throw 'Unknown previous ClamD service startup mode.' }
                        }
                        & $sc config $EngineServiceName start= $oldStart | Out-Null
                        if ($LASTEXITCODE -ne 0) { throw 'Could not restore ClamD startup mode.' }
                        & $sc sdset $EngineServiceName $originalServiceSddl | Out-Null
                        if ($LASTEXITCODE -ne 0) { throw 'Could not restore ClamD service permissions.' }
                        & $sc description $EngineServiceName $originalServiceDescription | Out-Null
                        if ($LASTEXITCODE -ne 0) { throw 'Could not restore ClamD description.' }
                        if (-not $serviceWasRunning -and $rollbackService.State -eq 'Running') {
                            Stop-Service -Name $EngineServiceName -ErrorAction Stop
                        }
                    }
                }
            } catch {
                Write-Warning "ClamAV service rollback failed: $($_.Exception.Message)"
            }
        }
        foreach ($item in @(
            @{ Path = $InstallRoot; Acl = $oldEngineAcl },
            @{ Path = $DataRoot; Acl = $oldDataAcl }
        )) {
            try {
                $current = Get-Item -LiteralPath $item.Path -Force -ErrorAction Stop
                if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    throw 'Directory became a reparse point during repair.'
                }
                Set-Acl -LiteralPath $item.Path -AclObject $item.Acl -ErrorAction Stop
            } catch {
                Write-Warning "ClamAV directory ACL rollback failed: $($_.Exception.Message)"
            }
        }
        throw $originalFailure
    }
}

$result = [ordered]@{
    schema = 1
    kind = 'antios-protection-repair'
    dry_run = -not [bool]$Apply
    healthy_before = ($issues.Count -eq 0)
    maintenance_verified_after = if ($Apply) { $true } else { $null }
    issues = @($issues)
    actions = @($actions)
    engine_root = $InstallRoot
    data_root = $DataRoot
    clamd_signature = $clamdSigner.Status
    freshclam_signature = $freshSigner.Status
    engine_trust = $engineTrust
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
