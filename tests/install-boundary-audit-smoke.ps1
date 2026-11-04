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
Import-OneFunction '..\scripts\protection-engine.ps1' 'Assert-FreshEngineInstallTargets'
Import-OneFunction '..\scripts\protection-engine.ps1' 'Get-OptionalEngineRegistryValue'
Import-OneFunction '..\scripts\protection-engine.ps1' 'Remove-OwnedRegistry'
Import-OneFunction '..\scripts\guard-startup.ps1' 'Restore-GuardUserAccess'
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
    if ($script:AuditUpdaterTaskPresent) {
        return [pscustomobject]@{ TaskName = $UpdaterTaskName }
    }
    return $null
}
$script:AuditUpdaterTaskPresent = $true
Should-Throw { Assert-FreshEngineInstallTargets } 'pre-existing FreshClam updater task'
$script:AuditUpdaterTaskPresent = $false

# A standard AntiOS installation owns HKLM:\SOFTWARE\AntiOS long before a
# managed ClamAV service exists. Model this case with disposable HKCU keys.
$testTag = [guid]::NewGuid().ToString('N')
$AntiOSRegistry = "HKCU:\Software\AntiOS-EngineAudit-$testTag"
$ClamRegistry = "HKCU:\Software\ClamAV-EngineAudit-$testTag"
$ConfigRoot = Join-Path $env:RUNNER_TEMP "AntiOS-EngineAudit-$testTag-config"
$DatabaseRoot = Join-Path $env:RUNNER_TEMP "AntiOS-EngineAudit-$testTag-db"
try {
    New-Item -Path $AntiOSRegistry -Force | Out-Null
    New-Item -Path $ClamRegistry -Force | Out-Null
    if ($null -ne (Get-OptionalEngineRegistryValue -Path $AntiOSRegistry -Name 'EngineServiceName')) {
        throw 'A missing optional registry value must return null.'
    }
    Assert-FreshEngineInstallTargets

    New-ItemProperty -Path $AntiOSRegistry -Name EngineServiceName -Value 'foreign' -PropertyType String | Out-Null
    Should-Throw { Assert-FreshEngineInstallTargets } 'foreign engine binding'
    Remove-OwnedRegistry
    if ((Get-OptionalEngineRegistryValue -Path $AntiOSRegistry -Name 'EngineServiceName') -ne 'foreign') {
        throw 'Registry cleanup must not remove a foreign engine binding.'
    }
    Remove-ItemProperty -Path $AntiOSRegistry -Name EngineServiceName

    foreach ($case in @(
        @{ Name = 'ConfDir'; Value = 'C:\Foreign-ClamAV\config' },
        @{ Name = 'DataDir'; Value = 'C:\Foreign-ClamAV\database' }
    )) {
        New-ItemProperty -Path $ClamRegistry -Name $case.Name -Value $case.Value -PropertyType String | Out-Null
        Should-Throw { Assert-FreshEngineInstallTargets } "foreign ClamAV $($case.Name)"
        Remove-OwnedRegistry
        if ((Get-OptionalEngineRegistryValue -Path $ClamRegistry -Name $case.Name) -ne $case.Value) {
            throw "Registry cleanup removed a foreign $($case.Name) binding."
        }
        Remove-ItemProperty -Path $ClamRegistry -Name $case.Name
    }

    New-ItemProperty -Path $AntiOSRegistry -Name EngineServiceName -Value $EngineServiceName -PropertyType String | Out-Null
    New-ItemProperty -Path $ClamRegistry -Name ConfDir -Value $ConfigRoot -PropertyType String | Out-Null
    New-ItemProperty -Path $ClamRegistry -Name DataDir -Value $DatabaseRoot -PropertyType String | Out-Null
    Remove-OwnedRegistry
    foreach ($case in @(
        @{ Path = $AntiOSRegistry; Name = 'EngineServiceName' },
        @{ Path = $ClamRegistry; Name = 'ConfDir' },
        @{ Path = $ClamRegistry; Name = 'DataDir' }
    )) {
        if ($null -ne (Get-OptionalEngineRegistryValue -Path $case.Path -Name $case.Name)) {
            throw "Owned registry entry $($case.Name) was not removed."
        }
    }
    # An existing registry key which cannot be read must still fail closed.
    function Get-ItemProperty { param($LiteralPath, $ErrorAction) throw 'simulated registry access denied' }
    Should-Throw {
        Get-OptionalEngineRegistryValue -Path $AntiOSRegistry -Name 'EngineServiceName'
    } 'registry read error'
} finally {
    Remove-Item Function:Get-ItemProperty -ErrorAction SilentlyContinue
    Remove-Item -Path $AntiOSRegistry -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $ClamRegistry -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'PASS: optional registry values, ownership boundaries and fail-closed registry read errors.'

# Repair the file-specific DACL from an old elevated Guard run without
# modifying data, broad system principals or unrelated user files.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$stateDir = Join-Path $env:RUNNER_TEMP ("AntiOS-GuardACL-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stateDir | Out-Null
try {
    $database = Join-Path $stateDir 'guard.sqlite3'
    $wal = Join-Path $stateDir 'guard.sqlite3-wal'
    $unrelated = Join-Path $stateDir 'unrelated.txt'
    [IO.File]::WriteAllText($database, 'keep-guard-history')
    [IO.File]::WriteAllText($wal, 'keep-uncommitted-history')
    [IO.File]::WriteAllText($unrelated, 'keep-other-file')

    $dbInfo = Get-Item -LiteralPath $database -Force
    $dbAcl = $dbInfo.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
    $dbAcl.SetAccessRuleProtection($true, $false) # imitate old protected file DACL
    $dbInfo.SetAccessControl($dbAcl)
    $unrelatedAcl = @((Get-Acl -LiteralPath $unrelated).Access | ForEach-Object {
        '{0}|{1}|{2}|{3}' -f $_.IdentityReference.Value, $_.FileSystemRights,
            $_.AccessControlType, $_.IsInherited
    } | Sort-Object) -join ';'

    Restore-GuardUserAccess $stateDir
    foreach ($path in @($database, $wal)) {
        $rules = (Get-Acl -LiteralPath $path).GetAccessRules(
            $true, $false, [Security.Principal.SecurityIdentifier]
        )
        $owned = @($rules | Where-Object {
            $_.IdentityReference.Value -eq $identity.User.Value -and
            $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
                [Security.AccessControl.FileSystemRights]::FullControl
        })
        if ($owned.Count -lt 1) {
            throw "Guard repair did not restore explicit current-user access: $path"
        }
    }
    if ([IO.File]::ReadAllText($database) -cne 'keep-guard-history' -or
        [IO.File]::ReadAllText($wal) -cne 'keep-uncommitted-history' -or
        [IO.File]::ReadAllText($unrelated) -cne 'keep-other-file') {
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
Write-Host 'PASS: both user startup tasks reject foreign identity/actions; engine preflight blocks task collision.'
