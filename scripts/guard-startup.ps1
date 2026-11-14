# Explicit current-user startup management. Preview by default; no Defender changes.
[CmdletBinding()]
param(
    [string]$Executable,
    [string[]]$Roots = @(),
    [string]$RootsJson,
    [ValidateSet('notify', 'quarantine')][string]$Mode = 'notify',
    [switch]$AllowManagedUnsigned,
    [switch]$ReuseExisting,
    [switch]$RepairStateAccess,
    [switch]$Uninstall,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$ScriptDirectory = if ($PSScriptRoot) {
    $PSScriptRoot
} else {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}

if ($RootsJson) {
    if ($Roots.Count -gt 0) {
        throw 'Use -Roots or -RootsJson, not both.'
    }
    $decodedRoots = ConvertFrom-Json -InputObject $RootsJson
    if ($decodedRoots -is [string]) {
        $Roots = @([string]$decodedRoots)
    } else {
        $Roots = @($decodedRoots | ForEach-Object { [string]$_ })
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$taskName = "AntiOS Guard ($($identity.User.Value))"

function Restore-GuardUserAccess([string]$Directory) {
    # Change only DACLs on the directory and known Guard files, by verified
    # handles. This works even when an old database blocks ACL inheritance.
    $current = Get-Item -LiteralPath $Directory -Force
    if (-not $current.PSIsContainer) { throw 'Guard state must be a directory.' }
    while ($current) {
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Guard state directory must not traverse reparse points.'
        }
        $current = $current.Parent
    }
    foreach ($entry in Get-ChildItem -LiteralPath $Directory -Force -ErrorAction Stop) {
        # A terminated scanner can leave a private workspace. The repair
        # opens only fixed state files and never descends into workspaces.
        if ($entry.PSIsContainer -and $entry.Name -cmatch '^antios-scan-[a-z0-9_]{8}$' -and
            -not $entry.LinkType -and -not ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            continue
        }
        if ($entry.PSIsContainer -or $entry.LinkType -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Guard state contains an unexpected directory or linked file.'
        }
    }
    if (-not ('AntiOS.GuardFileAccess' -as [type])) {
        Add-Type -Path (Join-Path $ScriptDirectory 'guard-state-access.cs')
    }
    [AntiOS.GuardFileAccess]::Repair($Directory, $identity.User)
}

if ($RepairStateAccess) {
    if (-not $Apply -or $Uninstall) { throw 'Guard access repair requires -Apply.' }
    $interactive = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
    if (-not $interactive -or $interactive -ine $identity.Name) { return }
    $folder = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'AntiOS\Guard'
    if (Test-Path -LiteralPath $folder -ErrorAction Stop) { Restore-GuardUserAccess $folder }
    return
}

function Assert-GuardTaskOwned($Task, [string]$ExpectedExecutable) {
    if (-not $Task) { return }
    $account = [string]$Task.Principal.UserId
    if ($account -notin @($identity.Name, $identity.User.Value)) {
        try {
            $sid = [Security.Principal.NTAccount]::new($account).Translate(
                [Security.Principal.SecurityIdentifier]).Value
        } catch {
            $sid = $null
        }
        if ($sid -ne $identity.User.Value) {
            throw 'Existing Guard task belongs to a different Windows user; refusing modification.'
        }
    }
    $actions = @($Task.Actions)
    if ($actions.Count -ne 1 -or -not $actions[0].Execute) {
        throw 'Existing Guard task has unexpected actions; refusing modification.'
    }
    try {
        $actual = [IO.Path]::GetFullPath([string]$actions[0].Execute)
        $expected = [IO.Path]::GetFullPath($ExpectedExecutable)
    } catch {
        throw 'Existing Guard task has an invalid executable path.'
    }
    if ($actual -ine $expected) {
        throw 'Existing Guard task points to another executable; refusing modification.'
    }
}

function Get-GuardTask {
    try {
        Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -ne 'CmdletizationQuery_NotFound,Get-ScheduledTask') { throw }
    }
}

function Assert-GuardTaskCanRestart($Task, [string]$Arguments, [string]$Directory) {
    if ($Task.Principal.LogonType -ne 'Interactive' -or $Task.Principal.RunLevel -ne 'Limited' -or
        $Task.Actions[0].Arguments -ine $Arguments -or $Task.Actions[0].WorkingDirectory -ine $Directory) {
        throw 'Existing Guard task has unexpected arguments, working directory, or privileges.'
    }
    if ($Task.State -eq 'Disabled') { throw 'Existing Guard task is disabled in Task Scheduler.' }
}

function Stop-GuardTaskAndWait {
    Stop-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $task = Get-GuardTask
        if (-not $task -or $task.State -notin @('Running', 'Queued')) { return }
        Start-Sleep -Milliseconds 100
    }
    throw 'Existing Resident Guard task did not stop.'
}

function Get-GuardStartupStatus([string]$Path, [string]$Folder) {
    $process = [Diagnostics.Process]::new()
    try {
        $process.StartInfo.FileName = $Path
        $process.StartInfo.Arguments = 'status --state-dir "{0}"' -f $Folder
        $process.StartInfo.WorkingDirectory = [IO.Path]::GetDirectoryName($Path)
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(5000)) {
            $process.Kill()
            return
        }
        if ($process.ExitCode -eq 0 -and $stdout.Wait(250) -and $stderr.Wait(250)) {
            $stdout.Result | ConvertFrom-Json -ErrorAction Stop
        }
    } catch {
        # A new Guard may not have created readable state yet.
    } finally {
        $process.Dispose()
    }
}

function Wait-GuardStartup([string]$Path, [string]$Folder, [double]$StartedAfter) {
    $first = $null
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        $task = Get-GuardTask
        if ($task -and $task.State -eq 'Running') {
            $status = Get-GuardStartupStatus $Path $Folder
            if ($status -and $status.kind -eq 'antivirus-guard' -and $status.running -eq $true -and
                $status.run_id -and $status.state -in @('monitoring', 'scanning', 'attention', 'degraded') -and
                $status.started_at -ge $StartedAfter -and $status.heartbeat -ge $StartedAfter) {
                if ($first -and $status.run_id -eq $first.run_id -and $status.heartbeat -gt $first.heartbeat) {
                    return
                }
                $first = $status
            }
        } else {
            $first = $null
        }
        Start-Sleep -Milliseconds 500
    } while ($clock.Elapsed.TotalSeconds -lt 20)

    $info = Get-ScheduledTaskInfo -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
    $last = if ($info) { '0x{0:X8}' -f ([int64]$info.LastTaskResult -band 0xFFFFFFFFL) } else { '(unavailable)' }
    throw "Resident Guard did not publish advancing heartbeats after startup. LastTaskResult=$last"
}

function Stop-ManagedGuardProcess([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $expected = [IO.Path]::GetFullPath($Path)
    Get-Process -Name 'AntiOS-Guard' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $actual = [IO.Path]::GetFullPath($_.Path)
        } catch {
            return
        }
        if ($actual -eq $expected) {
            $processId = $_.Id
            Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            for ($attempt = 0; $attempt -lt 30; $attempt++) {
                if (-not (Get-Process -Id $processId -ErrorAction SilentlyContinue)) { break }
                Start-Sleep -Milliseconds 100
            }
        }
    }
}

if ($Uninstall) {
    if (-not $Apply) {
        Write-Output "Preview: stop and unregister task '$taskName'; preserve history and quarantine."
        return
    }
    $uninstallExe = if ($Executable) { $Executable } else { Join-Path $ScriptDirectory 'AntiOS-Guard.exe' }
    $task = Get-GuardTask
    if ($task) {
        Assert-GuardTaskOwned -Task $task -ExpectedExecutable $uninstallExe
        Stop-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false
    }
    Stop-ManagedGuardProcess $uninstallExe
    return
}

if (-not $Executable) {
    $Executable = Join-Path $ScriptDirectory 'AntiOS-Guard.exe'
}

$exe = (Resolve-Path -LiteralPath $Executable).Path
if ([IO.Path]::GetFileName($exe) -ne 'AntiOS-Guard.exe') {
    throw 'Use the dedicated AntiOS-Guard.exe companion.'
}
$folder = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'AntiOS\Guard'
$policyPath = Join-Path $folder 'startup-policy.json'
$signature = Get-AuthenticodeSignature -LiteralPath $exe

function Assert-ManagedUnsignedGuard([string]$Path) {
    $installKey = 'HKLM:\SOFTWARE\DargonITP\AntiOS'
    $installDir = Get-ItemPropertyValue -Path $installKey -Name InstallDir -ErrorAction Stop
    $expected = [IO.Path]::GetFullPath((Join-Path $installDir 'AntiOS-Guard.exe'))
    if ([IO.Path]::GetFullPath($Path) -ne $expected) {
        throw 'Unsigned Guard startup is allowed only for the machine-installed AntiOS-Guard.exe.'
    }

    . (Join-Path $ScriptDirectory 'guard-trust.ps1')
    Assert-AntiOSProtectedInstallPath $expected
}

if ($Apply -and $signature.Status -ne 'Valid') {
    if (-not $AllowManagedUnsigned) {
        throw 'Automatic startup requires a valid Authenticode signature. Manual development runs remain available.'
    }
    Assert-ManagedUnsignedGuard $exe
}

# Check the existing task before rewriting policy files or stopping anything.
$existing = if ($Apply) { Get-GuardTask }
if ($existing) { Assert-GuardTaskOwned -Task $existing -ExpectedExecutable $exe }
$arguments = 'run --policy "{0}"' -f $policyPath
$workingDirectory = [IO.Path]::GetDirectoryName($exe)
$reuse = $ReuseExisting -and $existing
$keepPolicy = $Apply -and $ReuseExisting -and (Test-Path -LiteralPath $policyPath)
if ($reuse) {
    Assert-GuardTaskCanRestart $existing $arguments $workingDirectory
    if (-not $keepPolicy) {
        throw 'Existing Guard policy is missing. Configure Resident Guard with explicit roots to recreate it.'
    }
    if ($existing.State -eq 'Running') {
        $status = Get-GuardStartupStatus $exe $folder
        if ($status -and $status.kind -eq 'antivirus-guard' -and $status.running -eq $true) {
            return
        }
    }
    if ($existing.State -in @('Running', 'Queued')) { Stop-GuardTaskAndWait }
}
if (-not $keepPolicy) {
    if ($Roots.Count -lt 1 -or $Roots.Count -gt 16) { throw 'Select 1..16 roots with -Roots.' }
    $resolvedRoots = @($Roots | ForEach-Object {
        $item = Get-Item -LiteralPath $_ -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Not a regular directory: $_"
        }
        $item.FullName
    })

    [pscustomobject]@{
        Task = $taskName
        User = $identity.Name
        Executable = $exe
        Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '(none)' }
        Signature = $signature.Status
        Roots = ($resolvedRoots -join ', ')
        Mode = $Mode
        Engine = 'AntiOS Engine'
        Policy = $policyPath
        Privilege = 'Limited'
        Trigger = 'Current user logon'
    } | Format-List

    if (-not $Apply) {
        Write-Output 'Preview only. Use -Apply after reviewing the executable, signer, roots and mode.'
        return
    }
}

$existingParent = $folder
while (-not (Test-Path -LiteralPath $existingParent)) {
    $existingParent = Split-Path -Parent $existingParent
}
$current = Get-Item -LiteralPath $existingParent -Force
while ($current) {
    if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Guard state directory must not traverse reparse points.'
    }
    $current = $current.Parent
}
New-Item -ItemType Directory -Path $folder -Force | Out-Null
Restore-GuardUserAccess $folder
if ((Test-Path -LiteralPath $policyPath) -and
    ((Get-Item -LiteralPath $policyPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Policy path must not be a reparse point.'
}

if ($reuse) {
    # Restart the verified registration without rewriting its policy or task settings.
    $startedAfter = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000
    Start-ScheduledTask -TaskPath '\' -TaskName $taskName
    Wait-GuardStartup $exe $folder $startedAfter
    Write-Output "Restarted '$taskName' using the existing Guard policy."
    return
}

$action = New-ScheduledTaskAction -Execute $exe -Argument $arguments -WorkingDirectory $workingDirectory
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

# Reconfiguring resident protection must never leave an old task instance
# holding guard.lock. Stop the existing task first, then replace its definition.
$existing = Get-GuardTask
if ($existing) {
    Assert-GuardTaskOwned -Task $existing -ExpectedExecutable $exe
    if ($ReuseExisting) { throw 'Guard task was configured concurrently. Retry startup without replacing its policy.' }
    Stop-GuardTaskAndWait
}

# A task from an older build can have lost scheduler ownership while its
# process remains alive. Kill only a process whose full image path matches this
# managed Guard executable, so a stale lock cannot block the replacement.
Stop-ManagedGuardProcess $exe

if (-not $keepPolicy) {
    $policy = @{
        schema = 1
        roots = $resolvedRoots
        auto_quarantine = ($Mode -eq 'quarantine')
        scan_engine = 'antios'
    } | ConvertTo-Json
    [IO.File]::WriteAllText($policyPath, $policy, [Text.UTF8Encoding]::new($false))
}
Register-ScheduledTask -TaskPath '\' -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'AntiOS Engine local post-write monitoring; no pre-execution blocking.' -Force | Out-Null
$startedAfter = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000
Start-ScheduledTask -TaskPath '\' -TaskName $taskName
Wait-GuardStartup $exe $folder $startedAfter

Write-Output "Started '$taskName'. Stop: AntiOS-Guard.exe stop. Remove startup: guard-startup.ps1 -Uninstall -Apply."
