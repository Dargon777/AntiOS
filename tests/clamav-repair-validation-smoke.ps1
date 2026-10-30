# PowerShell 5.1 behavioral tests for the service/task trust boundary.
# Pure fixture data: never install, stop or modify an actual service/task.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\scripts\clamav-repair-validation.ps1')

function Should-Be($Actual, $Expected, [string]$Description) {
    if ([bool]$Actual -ne [bool]$Expected) {
        throw "FAILED ${Description}: expected $Expected, got $Actual"
    }
}
function Should-Throw([scriptblock]$Block, [string]$Description) {
    $caught = $false
    try { & $Block | Out-Null } catch { $caught = $true }
    if (-not $caught) { throw "FAILED ${Description}: expected explicit refusal" }
}

$clamd = 'C:\Program Files\AntiOS\ClamAV\clamd.exe'
$fresh = 'C:\Program Files\AntiOS\ClamAV\freshclam.exe'
$service = [pscustomobject]@{
    Name = 'clamd'; ServiceType = 'Own Process'; StartName = 'LocalSystem';
    State = 'Running'; StartMode = 'Auto';
    PathName = '"' + $clamd + '" --service'
}
$task = [pscustomobject]@{ Actions = @([pscustomobject]@{
    Execute = $fresh; Arguments = '--config-file="C:\ProgramData\AntiOS-ClamAV\config\freshclam.conf"'
}) }
Should-Be (Test-AntiOSRepairService -Service $service -ManagedExecutable $clamd -RequireRunning -RequireAutoStart) $true 'trusted SCM state'
Should-Be (Test-AntiOSRepairTask -Task $task -ManagedExecutable $fresh) $true 'trusted scheduled task'
Assert-AntiOSRepairPostconditions -Service $service -Task $task -ManagedClamd $clamd -ManagedFresh $fresh

$fake = $service.PSObject.Copy()
$fake.PathName = '"' + $clamd + '.evil" --service'
Should-Be (Test-AntiOSRepairService -Service $fake -ManagedExecutable $clamd) $false 'lookalike executable'
Should-Throw { Assert-AntiOSRepairPostconditions -Service $fake -Task $task -ManagedClamd $clamd -ManagedFresh $fresh } 'lookalike service'
$fake.PathName = 'C:\Other\clamd.exe'
Should-Be (Test-AntiOSRepairService -Service $fake -ManagedExecutable $clamd) $false 'foreign SCM executable'
$fake = $service.PSObject.Copy()
$fake.StartName = 'NT AUTHORITY\LOCAL SERVICE'
Should-Be (Test-AntiOSRepairService -Service $fake -ManagedExecutable $clamd) $false 'low-privilege SCM account'
$fake = $service.PSObject.Copy()
$fake.ServiceType = 'Share Process'
Should-Be (Test-AntiOSRepairService -Service $fake -ManagedExecutable $clamd) $false 'shared process service'
$fake = $service.PSObject.Copy()
$fake.State = 'Stopped'
Should-Be (Test-AntiOSRepairService -Service $fake -ManagedExecutable $clamd -RequireRunning) $false 'stopped service'
$fake = $service.PSObject.Copy()
$fake.StartMode = 'Manual'
Should-Be (Test-AntiOSRepairService -Service $fake -ManagedExecutable $clamd -RequireAutoStart) $false 'non-autostart service'

$badTask = [pscustomobject]@{ Actions = @([pscustomobject]@{ Execute = 'C:\Other\freshclam.exe' }) }
Should-Be (Test-AntiOSRepairTask -Task $badTask -ManagedExecutable $fresh) $false 'foreign update task'
Should-Throw { Assert-AntiOSRepairPostconditions -Service $service -Task $badTask -ManagedClamd $clamd -ManagedFresh $fresh } 'foreign update task postcondition'
$multiTask = [pscustomobject]@{ Actions = @(
    [pscustomobject]@{ Execute = $fresh },
    [pscustomobject]@{ Execute = 'C:\Other\helper.exe' }
) }
Should-Be (Test-AntiOSRepairTask -Task $multiTask -ManagedExecutable $fresh) $false 'extra updater action'
Should-Be (Test-AntiOSRepairTask -Task $null -ManagedExecutable $fresh) $false 'missing update task'
Should-Be (Test-AntiOSRepairService -Service $null -ManagedExecutable $clamd) $false 'missing clamd service'
Write-Host 'PASS: SCM/task identity predicates reject all foreign or unhealthy fixtures.'
