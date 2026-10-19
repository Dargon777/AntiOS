# Behavioral Windows PowerShell 5.1 tests for preflight and logon task ownership.
# Load only audited function AST nodes to avoid executing installers or services.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Import-OneFunction([string]$Script, [string]$FunctionName) {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot $Script), [ref]$tokens, [ref]$parseErrors
    )
    if ($parseErrors.Count) { throw "Cannot parse fixture script: $Script" }
    $matched = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $FunctionName
    }, $true))
    if ($matched.Count -ne 1) { throw "Expected exactly one $FunctionName function" }
    # Imported functions must outlive this helper's local function scope.
    $definition = $matched[0].Extent.Text -replace '^function\s+', 'function script:'
    . ([scriptblock]::Create($definition))
}

function Should-Throw([scriptblock]$Block, [string]$Description) {
    $failed = $false
    try { & $Block | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw "Failed to reject: $Description" }
}

# Function definitions loaded from actual application scripts, not replicas.
Import-OneFunction '..\scripts\protection-engine.ps1' 'Assert-FreshEngineInstallTargets'
Import-OneFunction '..\scripts\guard-startup.ps1' 'Assert-GuardTaskOwned'
Import-OneFunction '..\scripts\dashboard-startup.ps1' 'Assert-ControlCenterTaskOwned'

$identity = [pscustomobject]@{
    Name = 'AUDIT\InteractiveUser'
    User = [pscustomobject]@{ Value = 'S-1-5-21-1000-2000-3000-1001' }
}
$clamdExe = 'C:\Program Files\AntiOS\ClamAV\clamd.exe'
$guardExe = 'C:\Program Files\AntiOS\AntiOS-Guard.exe'
$dashboardExe = 'C:\Program Files\AntiOS\AntiOS-GUI.exe'

foreach ($case in @(
    @{ Kind = 'Guard'; Exe = $guardExe; Validator = 'Assert-GuardTaskOwned' },
    @{ Kind = 'Dashboard'; Exe = $dashboardExe; Validator = 'Assert-ControlCenterTaskOwned' }
)) {
    $task = [pscustomobject]@{
        Principal = [pscustomobject]@{ UserId = $identity.Name }
        Actions = @([pscustomobject]@{ Execute = $case.Exe })
    }
    if ($case.Kind -eq 'Guard') {
        Assert-GuardTaskOwned -Task $task -ExpectedExecutable $case.Exe
    } else {
        Assert-ControlCenterTaskOwned -Task $task -ExpectedExecutable $case.Exe
    }
    $other = $task.PSObject.Copy()
    $other.Principal = [pscustomobject]@{ UserId = 'AUDIT\OtherAccount' }
    if ($case.Kind -eq 'Guard') {
        Should-Throw { Assert-GuardTaskOwned -Task $other -ExpectedExecutable $case.Exe } "$($case.Kind): foreign account"
    } else {
        Should-Throw { Assert-ControlCenterTaskOwned -Task $other -ExpectedExecutable $case.Exe } "$($case.Kind): foreign account"
    }
    $other = $task.PSObject.Copy()
    $other.Actions = @([pscustomobject]@{ Execute = $case.Exe + '.evil' })
    if ($case.Kind -eq 'Guard') {
        Should-Throw { Assert-GuardTaskOwned -Task $other -ExpectedExecutable $case.Exe } "$($case.Kind): lookalike executable"
    } else {
        Should-Throw { Assert-ControlCenterTaskOwned -Task $other -ExpectedExecutable $case.Exe } "$($case.Kind): lookalike executable"
    }
    $other = $task.PSObject.Copy()
    $other.Actions = @(
        [pscustomobject]@{ Execute = $case.Exe },
        [pscustomobject]@{ Execute = 'C:\Other\unwanted.exe' }
    )
    if ($case.Kind -eq 'Guard') {
        Should-Throw { Assert-GuardTaskOwned -Task $other -ExpectedExecutable $case.Exe } "$($case.Kind): multiple actions"
    } else {
        Should-Throw { Assert-ControlCenterTaskOwned -Task $other -ExpectedExecutable $case.Exe } "$($case.Kind): multiple actions"
    }
}

# The preflight must reject a foreign scheduled task BEFORE modifying folders.
$EngineServiceName = 'clamd'
$UpdaterTaskName = 'AntiOS ClamAV Signature Update'
$InstallRoot = Join-Path $env:RUNNER_TEMP 'AntiOS-Audit-Neither-Here'
$DataRoot = Join-Path $env:RUNNER_TEMP 'AntiOS-Audit-Nor-Here'
$AntiOSRegistry = 'HKCU:\Software\AntiOS-Audit-Does-Not-Exist'
$ClamRegistry = 'HKCU:\Software\ClamAV-Audit-Does-Not-Exist'
function Get-Service { param($Name, $ErrorAction) return $null }
function Get-ScheduledTask {
    param($TaskPath, $TaskName, $ErrorAction)
    if ($TaskPath -ne '\' -or $TaskName -ne $UpdaterTaskName) {
        throw 'Expected exact root task lookup.'
    }
    return [pscustomobject]@{ TaskName = $UpdaterTaskName }
}
Should-Throw { Assert-FreshEngineInstallTargets } 'pre-existing FreshClam updater task'
Write-Host 'PASS: both user startup tasks reject foreign identity/actions; engine preflight blocks task collision.'
