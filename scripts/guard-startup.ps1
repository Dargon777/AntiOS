# Explicit current-user startup management. Preview by default; no Defender changes.
[CmdletBinding()]
param(
    [string]$Executable = (Join-Path $PSScriptRoot 'AntiOS-Guard.exe'),
    [string[]]$Roots = @(),
    [ValidateSet('notify', 'quarantine')][string]$Mode = 'notify',
    [ValidatePattern('^[A-Za-z0-9_-]{1,80}$')][string]$EngineServiceName,
    [switch]$Uninstall,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$taskName = "AntiOS Guard ($($identity.User.Value))"

if ($Uninstall) {
    if (-not $Apply) {
        Write-Output "Preview: stop and unregister task '$taskName'; preserve history and quarantine."
        return
    }
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    return
}

$exe = (Resolve-Path -LiteralPath $Executable).Path
if ([IO.Path]::GetFileName($exe) -ne 'AntiOS-Guard.exe') {
    throw 'Use the dedicated AntiOS-Guard.exe companion.'
}
if ($Roots.Count -lt 1 -or $Roots.Count -gt 16) {
    throw 'Select 1..16 roots with -Roots.'
}
$resolvedRoots = @($Roots | ForEach-Object {
    $item = Get-Item -LiteralPath $_ -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Not a regular directory: $_"
    }
    $item.FullName
})

$folder = Join-Path $env:LOCALAPPDATA 'AntiOS\Guard'
$policyPath = Join-Path $folder 'startup-policy.json'
$signature = Get-AuthenticodeSignature -LiteralPath $exe

[pscustomobject]@{
    Task = $taskName
    User = $identity.Name
    Executable = $exe
    Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '(none)' }
    Signature = $signature.Status
    Roots = ($resolvedRoots -join ', ')
    Mode = $Mode
    EngineService = $EngineServiceName
    Policy = $policyPath
    Privilege = 'Limited'
    Trigger = 'Current user logon'
} | Format-List

if (-not $Apply) {
    Write-Output 'Preview only. Use -Apply after reviewing the executable, signer, roots, engine service and mode.'
    return
}
if ($signature.Status -ne 'Valid') {
    throw 'Automatic startup requires a valid Authenticode signature. Manual development runs remain available.'
}

if ($EngineServiceName) {
    $engine = Get-CimInstance Win32_Service -Filter "Name='$EngineServiceName'"
    if (-not $engine -or $engine.ServiceType -ne 'Own Process' -or
        $engine.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) {
        throw 'Resident protection requires the configured ClamD service to be an own-process LocalSystem service.'
    }
}

New-Item -ItemType Directory -Path $folder -Force | Out-Null
$current = Get-Item -LiteralPath $folder -Force
while ($current) {
    if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Guard state directory must not traverse reparse points.'
    }
    $current = $current.Parent
}
if ((Test-Path -LiteralPath $policyPath) -and
    ((Get-Item -LiteralPath $policyPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Policy path must not be a reparse point.'
}

$policyData = @{
    schema = 1
    roots = $resolvedRoots
    auto_quarantine = ($Mode -eq 'quarantine')
}
if ($EngineServiceName) {
    $policyData.engine_service = $EngineServiceName
}
$policy = $policyData | ConvertTo-Json
[IO.File]::WriteAllText($policyPath, $policy, [Text.UTF8Encoding]::new($false))

$action = New-ScheduledTaskAction -Execute $exe -Argument ('run --policy "{0}"' -f $policyPath) -WorkingDirectory ([IO.Path]::GetDirectoryName($exe))
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'AntiOS selected-folder post-write monitoring with trusted ClamD binding; no pre-execution blocking.' -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Output "Started '$taskName'. Stop: AntiOS-Guard.exe stop. Remove startup: guard-startup.ps1 -Uninstall -Apply."
