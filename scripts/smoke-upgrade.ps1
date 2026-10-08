param(
    [string]$CurrentSetup = ".\installer-output\AntiOS-Setup.exe",
    [string]$PreviousTag = "",
    [string]$ExpectedPreviousVersion = "",
    [string]$ExpectedCurrentVersion = ""
)

$ErrorActionPreference = "Stop"

if (-not $ExpectedCurrentVersion) {
    $ExpectedCurrentVersion = (Get-Content ".\release\VERSION" -Raw).Trim()
}
if ($ExpectedCurrentVersion -notmatch '^2\.0\.0a(\d+)
function Invoke-Setup {
    param(
        [Parameter(Mandatory = $true)][string]$Setup,
        [Parameter(Mandatory = $true)][string]$InstallDir
    )

    $process = Start-Process -FilePath $Setup -ArgumentList @("/S", "/NOENGINE=1", "/D=$InstallDir") -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Setup failed with exit code $($process.ExitCode): $Setup"
    }
}

function Assert-Version {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$Expected
    )

    $output = (& $Executable --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Version command failed for $Executable"
    }
    if ($output -notmatch [regex]::Escape($Expected)) {
        throw "Unexpected version from $Executable. Expected $Expected, got: $output"
    }
}

$installDir = Join-Path $env:RUNNER_TEMP "AntiOS-Upgrade-Smoke"
$previousSetup = Join-Path $env:RUNNER_TEMP "AntiOS-Previous-Setup.exe"
$configDir = Join-Path $env:APPDATA "AntiOS"
$configPath = Join-Path $configDir "antios.toml"
$configBackup = Join-Path $env:RUNNER_TEMP "AntiOS-Upgrade-Smoke-antios.toml.backup"
$hadConfig = Test-Path -LiteralPath $configPath

try {
    Remove-Item -Recurse -Force $installDir -ErrorAction SilentlyContinue
    Remove-Item -Force $previousSetup -ErrorAction SilentlyContinue
    Remove-Item -Force $configBackup -ErrorAction SilentlyContinue

    if ($hadConfig) {
        New-Item -ItemType Directory -Force (Split-Path -Parent $configBackup) | Out-Null
        Copy-Item -LiteralPath $configPath -Destination $configBackup -Force
    }

    $downloadUrl = "https://github.com/Dargon777/AntiOS/releases/download/$PreviousTag/AntiOS-Setup.exe"
    Write-Host "Downloading previous AntiOS Setup from $downloadUrl"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $previousSetup -UseBasicParsing

    if (-not (Test-Path -LiteralPath $previousSetup)) {
        throw "Previous installer was not downloaded."
    }

    Write-Host "Installing previous release $PreviousTag"
    Invoke-Setup -Setup $previousSetup -InstallDir $installDir

    $cli = Join-Path $installDir "AntiOS.exe"
    $gui = Join-Path $installDir "AntiOS-GUI.exe"
    $uninstaller = Join-Path $installDir "Uninstall.exe"

    foreach ($required in @($cli, $gui, $uninstaller)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "Previous install is missing required file: $required"
        }
    }

    Assert-Version -Executable $cli -Expected $ExpectedPreviousVersion

    New-Item -ItemType Directory -Force $configDir | Out-Null
    @'
[general]
computer_name_prefix = "LAB"
backup_path = "antios-backup.json"
color = "auto"

[logging]
level = "INFO"
file = ""

[ui]
language = "pl"
theme = "light"

[cleanup]
old_days = 91
large_mb = 321
duplicate_min_mb = 7
remember_folder = false
last_path = ""

[protection]
resident_enabled = false

[updates]
auto_update = false
'@ | Set-Content -LiteralPath $configPath -Encoding utf8NoBOM

    $configHashBefore = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash

    Write-Host "Upgrading previous release with current Setup"
    Invoke-Setup -Setup (Resolve-Path $CurrentSetup).Path -InstallDir $installDir

    Assert-Version -Executable $cli -Expected $ExpectedCurrentVersion

    $configHashAfter = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    if ($configHashAfter -ne $configHashBefore) {
        throw "Upgrade changed the user's antios.toml."
    }

    $env:ANTIOS_UPGRADE_SMOKE_CONFIG = $configPath
    python -c "import os; from antios.config import load_config; c=load_config(os.environ['ANTIOS_UPGRADE_SMOKE_CONFIG']); assert c.ui.language == 'pl'; assert c.ui.theme == 'light'; assert c.cleanup.old_days == 91; assert c.cleanup.large_mb == 321; assert c.cleanup.duplicate_min_mb == 7; assert c.protection.resident_enabled is False; assert c.updates.auto_update is False"
    if ($LASTEXITCODE -ne 0) {
        throw "Current AntiOS could not load the preserved configuration."
    }

    & $gui --self-test
    if ($LASTEXITCODE -ne 0) {
        throw "Upgraded GUI self-test failed."
    }

    & $gui --ui-self-test
    if ($LASTEXITCODE -ne 0) {
        throw "Upgraded GUI UI self-test failed."
    }

    $registeredVersion = (Get-ItemProperty "HKLM:\Software\DargonITP\AntiOS" -Name Version).Version
    if ($registeredVersion -ne $ExpectedCurrentVersion) {
        throw "Installer registry version mismatch after upgrade: $registeredVersion"
    }

    Write-Host "Upgrade smoke passed: $ExpectedPreviousVersion -> $ExpectedCurrentVersion"
}
finally {
    if (Test-Path -LiteralPath (Join-Path $installDir "Uninstall.exe")) {
        $uninstall = Start-Process -FilePath (Join-Path $installDir "Uninstall.exe") -ArgumentList "/S" -Wait -PassThru
        if ($uninstall.ExitCode -ne 0) {
            Write-Warning "Upgrade smoke uninstaller exited with code $($uninstall.ExitCode)"
        }
    }

    if ($hadConfig -and (Test-Path -LiteralPath $configBackup)) {
        New-Item -ItemType Directory -Force $configDir | Out-Null
        Copy-Item -LiteralPath $configBackup -Destination $configPath -Force
    }
    elseif (-not $hadConfig) {
        Remove-Item -Force $configPath -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $configDir) {
            $remaining = Get-ChildItem -LiteralPath $configDir -Force -ErrorAction SilentlyContinue
            if (-not $remaining) {
                Remove-Item -Force $configDir -ErrorAction SilentlyContinue
            }
        }
    }

    Remove-Item -Force $previousSetup -ErrorAction SilentlyContinue
    Remove-Item -Force $configBackup -ErrorAction SilentlyContinue
}
) {
    throw "Unexpected current alpha version: $ExpectedCurrentVersion"
}
$currentAlpha = [int]$Matches[1]
if ($currentAlpha -le 1) {
    throw "Upgrade smoke requires a previous alpha release."
}
$previousAlpha = $currentAlpha - 1
if (-not $ExpectedPreviousVersion) {
    $ExpectedPreviousVersion = "2.0.0a$previousAlpha"
}
if (-not $PreviousTag) {
    $PreviousTag = "v2.0.0-alpha.$previousAlpha"
}

function Invoke-Setup {
    param(
        [Parameter(Mandatory = $true)][string]$Setup,
        [Parameter(Mandatory = $true)][string]$InstallDir
    )

    $process = Start-Process -FilePath $Setup -ArgumentList @("/S", "/NOENGINE=1", "/D=$InstallDir") -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Setup failed with exit code $($process.ExitCode): $Setup"
    }
}

function Assert-Version {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$Expected
    )

    $output = (& $Executable --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Version command failed for $Executable"
    }
    if ($output -notmatch [regex]::Escape($Expected)) {
        throw "Unexpected version from $Executable. Expected $Expected, got: $output"
    }
}

$installDir = Join-Path $env:RUNNER_TEMP "AntiOS-Upgrade-Smoke"
$previousSetup = Join-Path $env:RUNNER_TEMP "AntiOS-Previous-Setup.exe"
$configDir = Join-Path $env:APPDATA "AntiOS"
$configPath = Join-Path $configDir "antios.toml"
$configBackup = Join-Path $env:RUNNER_TEMP "AntiOS-Upgrade-Smoke-antios.toml.backup"
$hadConfig = Test-Path -LiteralPath $configPath

try {
    Remove-Item -Recurse -Force $installDir -ErrorAction SilentlyContinue
    Remove-Item -Force $previousSetup -ErrorAction SilentlyContinue
    Remove-Item -Force $configBackup -ErrorAction SilentlyContinue

    if ($hadConfig) {
        New-Item -ItemType Directory -Force (Split-Path -Parent $configBackup) | Out-Null
        Copy-Item -LiteralPath $configPath -Destination $configBackup -Force
    }

    $downloadUrl = "https://github.com/Dargon777/AntiOS/releases/download/$PreviousTag/AntiOS-Setup.exe"
    Write-Host "Downloading previous AntiOS Setup from $downloadUrl"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $previousSetup -UseBasicParsing

    if (-not (Test-Path -LiteralPath $previousSetup)) {
        throw "Previous installer was not downloaded."
    }

    Write-Host "Installing previous release $PreviousTag"
    Invoke-Setup -Setup $previousSetup -InstallDir $installDir

    $cli = Join-Path $installDir "AntiOS.exe"
    $gui = Join-Path $installDir "AntiOS-GUI.exe"
    $uninstaller = Join-Path $installDir "Uninstall.exe"

    foreach ($required in @($cli, $gui, $uninstaller)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "Previous install is missing required file: $required"
        }
    }

    Assert-Version -Executable $cli -Expected $ExpectedPreviousVersion

    New-Item -ItemType Directory -Force $configDir | Out-Null
    @'
[general]
computer_name_prefix = "LAB"
backup_path = "antios-backup.json"
color = "auto"

[logging]
level = "INFO"
file = ""

[ui]
language = "pl"
theme = "light"

[cleanup]
old_days = 91
large_mb = 321
duplicate_min_mb = 7
remember_folder = false
last_path = ""

[protection]
resident_enabled = false

[updates]
auto_update = false
'@ | Set-Content -LiteralPath $configPath -Encoding utf8NoBOM

    $configHashBefore = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash

    Write-Host "Upgrading previous release with current Setup"
    Invoke-Setup -Setup (Resolve-Path $CurrentSetup).Path -InstallDir $installDir

    Assert-Version -Executable $cli -Expected $ExpectedCurrentVersion

    $configHashAfter = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    if ($configHashAfter -ne $configHashBefore) {
        throw "Upgrade changed the user's antios.toml."
    }

    $env:ANTIOS_UPGRADE_SMOKE_CONFIG = $configPath
    python -c "import os; from antios.config import load_config; c=load_config(os.environ['ANTIOS_UPGRADE_SMOKE_CONFIG']); assert c.ui.language == 'pl'; assert c.ui.theme == 'light'; assert c.cleanup.old_days == 91; assert c.cleanup.large_mb == 321; assert c.cleanup.duplicate_min_mb == 7; assert c.protection.resident_enabled is False; assert c.updates.auto_update is False"
    if ($LASTEXITCODE -ne 0) {
        throw "Current AntiOS could not load the preserved configuration."
    }

    & $gui --self-test
    if ($LASTEXITCODE -ne 0) {
        throw "Upgraded GUI self-test failed."
    }

    & $gui --ui-self-test
    if ($LASTEXITCODE -ne 0) {
        throw "Upgraded GUI UI self-test failed."
    }

    $registeredVersion = (Get-ItemProperty "HKLM:\Software\DargonITP\AntiOS" -Name Version).Version
    if ($registeredVersion -ne $ExpectedCurrentVersion) {
        throw "Installer registry version mismatch after upgrade: $registeredVersion"
    }

    Write-Host "Upgrade smoke passed: $ExpectedPreviousVersion -> $ExpectedCurrentVersion"
}
finally {
    if (Test-Path -LiteralPath (Join-Path $installDir "Uninstall.exe")) {
        $uninstall = Start-Process -FilePath (Join-Path $installDir "Uninstall.exe") -ArgumentList "/S" -Wait -PassThru
        if ($uninstall.ExitCode -ne 0) {
            Write-Warning "Upgrade smoke uninstaller exited with code $($uninstall.ExitCode)"
        }
    }

    if ($hadConfig -and (Test-Path -LiteralPath $configBackup)) {
        New-Item -ItemType Directory -Force $configDir | Out-Null
        Copy-Item -LiteralPath $configBackup -Destination $configPath -Force
    }
    elseif (-not $hadConfig) {
        Remove-Item -Force $configPath -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $configDir) {
            $remaining = Get-ChildItem -LiteralPath $configDir -Force -ErrorAction SilentlyContinue
            if (-not $remaining) {
                Remove-Item -Force $configDir -ErrorAction SilentlyContinue
            }
        }
    }

    Remove-Item -Force $previousSetup -ErrorAction SilentlyContinue
    Remove-Item -Force $configBackup -ErrorAction SilentlyContinue
}
