# Pure SCM/task ownership predicates, no privileged changes.
Set-StrictMode -Version Latest

function Test-AntiOSRepairService {
    [CmdletBinding()]
    param(
        [AllowNull()]$Service,
        [Parameter(Mandatory)][string]$ManagedExecutable,
        [switch]$RequireRunning,
        [switch]$RequireAutoStart
    )
    if (-not $Service -or -not $ManagedExecutable) { return $false }
    $imagePattern = ('^\s*(?:"{0}"|{0})(?=\s|$)' -f [regex]::Escape($ManagedExecutable))
    if ($Service.ServiceType -ne 'Own Process' -or
        $Service.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM') -or
        [string]$Service.PathName -notmatch $imagePattern) {
        return $false
    }
    if ($RequireRunning -and $Service.State -ne 'Running') { return $false }
    if ($RequireAutoStart -and $Service.StartMode -ne 'Auto') { return $false }
    return $true
}

function Test-AntiOSRepairTask {
    [CmdletBinding()]
    param(
        [AllowNull()]$Task,
        [Parameter(Mandatory)][string]$ManagedExecutable
    )
    if (-not $Task -or -not $ManagedExecutable) { return $false }
    $taskActions = @($Task.Actions)
    if ($taskActions.Count -ne 1 -or -not $taskActions[0].Execute) { return $false }
    try {
        $actual = [IO.Path]::GetFullPath([string]$taskActions[0].Execute)
        $expected = [IO.Path]::GetFullPath($ManagedExecutable)
        return $actual -ieq $expected
    } catch [ArgumentException] {
        return $false
    } catch [NotSupportedException] {
        return $false
    }
}

function Assert-AntiOSRepairPostconditions {
    [CmdletBinding()]
    param(
        [AllowNull()]$Service,
        [AllowNull()]$Task,
        [Parameter(Mandatory)][string]$ManagedClamd,
        [Parameter(Mandatory)][string]$ManagedFresh
    )
    $serviceValid = Test-AntiOSRepairService -Service $Service -ManagedExecutable $ManagedClamd -RequireRunning -RequireAutoStart
    if (-not $serviceValid) {
        throw 'ClamD failed post-repair SCM identity/running-state verification.'
    }
    if (-not (Test-AntiOSRepairTask -Task $Task -ManagedExecutable $ManagedFresh)) {
        throw 'FreshClam update task failed post-repair ownership verification.'
    }
}
