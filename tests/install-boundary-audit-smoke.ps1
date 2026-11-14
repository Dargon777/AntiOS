# Behavioral Windows PowerShell 5.1 tests for preflight and logon task ownership.
# Load only audited function AST nodes to avoid executing installers or services.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Import-OneFunction([string]$Script, [string]$FunctionName) {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot $Script), [ref]$tokens, [ref]$parseErrors
    )
    if ($parseErrors.Count) { throw "Cannot parse fixture script: $Script" }
    $matched = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
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
$ScriptDirectory = (Resolve-Path (Join-Path $PSScriptRoot '..\scripts')).Path
Import-OneFunction '..\scripts\guard-startup.ps1' 'Restore-GuardUserAccess'
Import-OneFunction '..\scripts\guard-startup.ps1' 'Assert-GuardTaskOwned'
Import-OneFunction '..\scripts\guard-startup.ps1' 'Assert-GuardTaskCanRestart'
Import-OneFunction '..\scripts\guard-startup.ps1' 'Wait-GuardStartup'
Import-OneFunction '..\scripts\dashboard-startup.ps1' 'Assert-ControlCenterTaskOwned'

$identity = [pscustomobject]@{
    Name = 'AUDIT\InteractiveUser'
    User = [pscustomobject]@{ Value = 'S-1-5-21-1000-2000-3000-1001' }
}
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

# Repair the file-specific DACL from an old elevated Guard run without
# modifying data, broad system principals or unrelated user files.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$unqualifiedName = $identity.Name.Split('\')[-1]
$unqualifiedTask = [pscustomobject]@{
    Principal = [pscustomobject]@{UserId = $unqualifiedName; LogonType = 'Interactive'; RunLevel = 'Limited'}
    Actions = @([pscustomobject]@{Execute = $guardExe; Arguments = 'run --policy "C:\Policy"'; WorkingDirectory = 'C:\Program Files\AntiOS'})
    State = 'Ready'
}
Assert-GuardTaskOwned -Task $unqualifiedTask -ExpectedExecutable $guardExe
Assert-GuardTaskCanRestart $unqualifiedTask 'run --policy "C:\Policy"' 'C:\Program Files\AntiOS'
Should-Throw { Assert-GuardTaskCanRestart $unqualifiedTask 'history' 'C:\Program Files\AntiOS' } 'untrusted startup arguments'
$unqualifiedTask.Principal.RunLevel = 'Highest'
Should-Throw { Assert-GuardTaskCanRestart $unqualifiedTask 'run --policy "C:\Policy"' 'C:\Program Files\AntiOS' } 'elevated Guard task'
$unqualifiedTask.Actions[0].Execute = $dashboardExe
Assert-ControlCenterTaskOwned -Task $unqualifiedTask -ExpectedExecutable $dashboardExe

# Fake Scheduler/status reads. A heartbeat left by another run or repeated
# status snapshot must not be sufficient to report a successful startup.
$script:startupChecks = 0
function Get-GuardTask { [pscustomobject]@{State = 'Running'} }
function Get-GuardStartupStatus([string]$Path, [string]$Folder) {
    $script:startupChecks++
    $started = if ($script:startupChecks -eq 1) { 99 } else { 100 }
    $heartbeat = if ($script:startupChecks -lt 4) { 101 } else { 102 }
    [pscustomobject]@{
        kind = 'antivirus-guard'; running = $true; run_id = 'test-run'; state = 'monitoring'
        started_at = $started; heartbeat = $heartbeat
    }
}
Wait-GuardStartup $guardExe 'C:\Policy' 100
if ($script:startupChecks -ne 4) { throw 'Guard startup accepted an old or repeated heartbeat.' }

$taskName = 'Fixture only'
$script:taskReads = 0
function Get-GuardTask {
    $script:taskReads++
    [pscustomobject]@{State = $(if ($script:taskReads -eq 1) { 'Running' } else { 'Ready' })}
}
function Get-ScheduledTaskInfo { [pscustomobject]@{LastTaskResult = -1073741510} }
$reported = $null
try { Wait-GuardStartup $guardExe 'C:\Policy' 100 } catch { $reported = $_.Exception.Message }
if ($reported -notlike 'Resident Guard task ended before startup verification*0xC000013A' -or $script:taskReads -ne 2) {
    throw "Guard process exit was reported as a heartbeat timeout: $reported"
}

$stateDir = Join-Path $env:RUNNER_TEMP ("AntiOS-GuardACL-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stateDir | Out-Null
try {
    $database = Join-Path $stateDir 'guard.sqlite3'
    $wal = Join-Path $stateDir 'guard.sqlite3-wal'
    $unrelated = Join-Path $stateDir 'unrelated.txt'
    $workspace = Join-Path $stateDir 'antios-scan-test1234'
    New-Item -ItemType Directory -Path $workspace | Out-Null
    $oldWorkerFile = Join-Path $workspace 'events.jsonl'
    [IO.File]::WriteAllText($oldWorkerFile, 'preserve-old-worker-data')
    [IO.File]::WriteAllText($database, 'keep-guard-history')
    [IO.File]::WriteAllText($wal, 'keep-uncommitted-history')
    [IO.File]::WriteAllText($unrelated, 'keep-other-file')

    $dbAcl = Get-Acl -LiteralPath $database
    $dbAcl.SetAccessRuleProtection($true, $false) # imitate old protected file DACL
    Set-Acl -LiteralPath $database -AclObject $dbAcl
    $unrelatedAcl = @((Get-Acl -LiteralPath $unrelated).Access | ForEach-Object {
        '{0}|{1}|{2}|{3}' -f $_.IdentityReference.Value, $_.FileSystemRights,
            $_.AccessControlType, $_.IsInherited
    } | Sort-Object) -join ';'

    Restore-GuardUserAccess $stateDir
    $rootRules = (Get-Acl -LiteralPath $stateDir).GetAccessRules(
        $true, $false, [Security.Principal.SecurityIdentifier]
    )
    $expectedFlags = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    if (-not ($rootRules | Where-Object {
        $_.IdentityReference.Value -eq $identity.User.Value -and
        $_.AccessControlType -eq 'Allow' -and $_.InheritanceFlags -eq $expectedFlags
    })) {
        throw 'Guard repair must install an explicit inheritable current-user grant.'
    }
    $recreated = Join-Path $stateDir 'guard.sqlite3-shm'
    [IO.File]::WriteAllText($recreated, 'new-sqlite-sidecar')
    $inheritedRules = (Get-Acl -LiteralPath $recreated).GetAccessRules(
        $false, $true, [Security.Principal.SecurityIdentifier]
    )
    $inheritedUser = @($inheritedRules | Where-Object {
        $_.IdentityReference.Value -eq $identity.User.Value -and
        $_.AccessControlType -eq 'Allow' -and
        ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
            [Security.AccessControl.FileSystemRights]::FullControl
    })
    if ($inheritedUser.Count -lt 1) {
        throw 'Recreated Guard sidecars must inherit explicit current-user access from the directory.'
    }
    foreach ($path in @($database, $wal)) {
        $rules = (Get-Acl -LiteralPath $path).GetAccessRules(
            $true, ($path -ne $database), [Security.Principal.SecurityIdentifier]
        )
        $owned = @($rules | Where-Object {
            $_.IdentityReference.Value -eq $identity.User.Value -and
            $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
                [Security.AccessControl.FileSystemRights]::FullControl
        })
        if ($owned.Count -lt 1) {
            throw "Guard repair did not restore current-user access: $path"
        }
    }
    if ([IO.File]::ReadAllText($database) -cne 'keep-guard-history' -or
        [IO.File]::ReadAllText($wal) -cne 'keep-uncommitted-history' -or
        [IO.File]::ReadAllText($unrelated) -cne 'keep-other-file' -or
        [IO.File]::ReadAllText($oldWorkerFile) -cne 'preserve-old-worker-data') {
        throw 'Guard ACL repair must preserve all file content.'
    }
    $afterUnrelatedAcl = @((Get-Acl -LiteralPath $unrelated).Access | ForEach-Object {
        '{0}|{1}|{2}|{3}' -f $_.IdentityReference.Value, $_.FileSystemRights,
            $_.AccessControlType, $_.IsInherited
    } | Sort-Object) -join ';'
    if ($afterUnrelatedAcl -cne $unrelatedAcl) {
        throw 'Guard ACL repair must not change unrelated file access rules.'
    }
    New-Item -ItemType Directory -Path (Join-Path $stateDir 'unexpected-subfolder') | Out-Null
    Should-Throw { Restore-GuardUserAccess $stateDir } 'unexpected Guard subdirectory'
} finally {
    Remove-Item -LiteralPath $stateDir -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'PASS: pre-existing Guard state ACL repaired in place without deleting history.'
Write-Host 'PASS: Guard and dashboard startup tasks reject foreign identities and actions.'
