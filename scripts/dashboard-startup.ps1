# AntiOS Control Center logon startup. Separate from Resident Guard protection.
[CmdletBinding()]
param(
    [string]$Executable,
    [switch]$AllowManagedUnsigned,
    [switch]$Uninstall,
    [switch]$Status,
    [switch]$Json,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$ScriptDirectory = if ($PSScriptRoot) {
    $PSScriptRoot
} else {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$taskName = "AntiOS Control Center ($($identity.User.Value))"

function Get-ControlCenterTask {
    Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
}

function Assert-ManagedUnsignedDashboard([string]$Path) {
    $installKey = 'HKLM:\SOFTWARE\DargonITP\AntiOS'
    $installDir = Get-ItemPropertyValue -Path $installKey -Name InstallDir -ErrorAction Stop
    $expected = [IO.Path]::GetFullPath((Join-Path $installDir 'AntiOS-GUI.exe'))
    if ([IO.Path]::GetFullPath($Path) -ne $expected) {
        throw 'Unsigned dashboard startup is allowed only for the machine-installed AntiOS-GUI.exe.'
    }

    $dangerousSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
    $dangerousRights = [Security.AccessControl.FileSystemRights]::Write -bor
                       [Security.AccessControl.FileSystemRights]::Modify -bor
                       [Security.AccessControl.FileSystemRights]::FullControl
    $acl = Get-Acl -LiteralPath $installDir
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        try {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            continue
        }
        if ($sid -in $dangerousSids -and (($rule.FileSystemRights -band $dangerousRights) -ne 0)) {
            throw "AntiOS install directory is writable by an untrusted broad principal: $sid"
        }
    }
}

if ($Status) {
    $task = Get-ControlCenterTask
    $payload = [ordered]@{
        enabled = ($null -ne $task)
        task = $taskName
        state = if ($task) { [string]$task.State } else { 'Absent' }
        user = $identity.Name
    }
    if ($Json) {
        $payload | ConvertTo-Json -Compress
    } else {
        [pscustomobject]$payload | Format-List
    }
    return
}

if ($Uninstall) {
    if (-not $Apply) {
        Write-Output "Preview: unregister task '$taskName'. Resident Guard is not changed."
        return
    }
    $task = Get-ControlCenterTask
    if ($task) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    return
}

if (-not $Executable) {
    $Executable = Join-Path $ScriptDirectory 'AntiOS-GUI.exe'
}
$exe = (Resolve-Path -LiteralPath $Executable).Path
if ([IO.Path]::GetFileName($exe) -ne 'AntiOS-GUI.exe') {
    throw 'Control Center startup requires AntiOS-GUI.exe.'
}

$signature = Get-AuthenticodeSignature -LiteralPath $exe

[pscustomobject]@{
    Task = $taskName
    User = $identity.Name
    Executable = $exe
    Arguments = '--background'
    Signature = $signature.Status
    Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '(none)' }
    Privilege = 'Highest'
    Trigger = 'Current user logon'
} | Format-List

if (-not $Apply) {
    Write-Output 'Preview only. Use -Apply to enable AntiOS Control Center startup.'
    return
}

if ($signature.Status -ne 'Valid') {
    if (-not $AllowManagedUnsigned) {
        throw 'Automatic Control Center startup requires a valid Authenticode signature.'
    }
    Assert-ManagedUnsignedDashboard $exe
}

$action = New-ScheduledTaskAction -Execute $exe -Argument '--background' -WorkingDirectory ([IO.Path]::GetDirectoryName($exe))
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Starts the AntiOS Control Center in the notification area at user logon. Resident Guard protection is managed separately.' -Force | Out-Null

Write-Output "Enabled '$taskName'. AntiOS will start in the notification area at the next logon."
