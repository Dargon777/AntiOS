"""Regression checks for the 2026-10-20 whole-source safety audit.

These are static ordering/contract checks; Windows PowerShell fixture tests
exercise the real functions in tests/install-boundary-audit-smoke.ps1.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_engine_fresh_install_refuses_existing_scheduler_and_registry_bindings():
    script = read("scripts/protection-engine.ps1")
    assert "function Assert-FreshEngineInstallTargets" in script
    preflight = script.split("function Assert-FreshEngineInstallTargets {", 1)[1].split(
        "\n}\n", 1
    )[0]
    for requirement in (
        "Get-Service -Name $EngineServiceName",
        "Get-ScheduledTask -TaskPath '\\' -TaskName $UpdaterTaskName",
        "Test-Path -LiteralPath $destination",
        "EngineServiceName -ErrorAction SilentlyContinue",
        "ConfDir -ErrorAction SilentlyContinue",
        "DataDir -ErrorAction SilentlyContinue",
    ):
        assert requirement in preflight, requirement
    assert script.count("Assert-FreshEngineInstallTargets") >= 3
    assert script.index("Assert-Administrator\n# Do not trust a pre-elevation dry-run") < (
        script.index("New-Item -ItemType Directory -Path $InstallRoot -ErrorAction Stop")
    )


def test_engine_install_never_forces_clamav_task_or_existing_destinations():
    script = read("scripts/protection-engine.ps1")
    assert "Register-ScheduledTask -TaskPath '\\' -TaskName $UpdaterTaskName" in script
    registration = next(line for line in script.splitlines() if
                        "Register-ScheduledTask -TaskPath '\\' -TaskName $UpdaterTaskName" in line)
    assert " -Force" not in registration
    assert "New-Item -ItemType Directory -Path $InstallRoot -Force" not in script
    assert "New-Item -ItemType Directory -Path $DataRoot -Force" not in script
    assert script.index("$createdData = $true") < script.index(
        "Set-Acl -LiteralPath $DataRoot -AclObject $dataAcl"
    )


def test_engine_install_failed_operations_have_owned_rollback_and_original_error():
    script = read("scripts/protection-engine.ps1")
    for marker in (
        "$serviceInstallAttempted = $true",
        "$taskInstallAttempted = $true",
        "Assert-ManagedClamdService",
        "Get-ScheduledTask -TaskPath '\\' -TaskName $UpdaterTaskName",
        "Scheduled-task rollback:",
        "ClamD service rollback:",
        "$unsafeToRemovePayload",
        "Keeping managed files and registry values",
        "throw $installFailure",
    ):
        assert marker in script, marker
    assert script.index("$serviceInstallAttempted = $true") < script.index(
        "& $ManagedClamd --install-service"
    )
    assert script.index("$taskInstallAttempted = $true") < script.index(
        "Register-ScheduledTask -TaskPath '\\' -TaskName $UpdaterTaskName"
    )


def test_logon_guard_and_dashboard_do_not_touch_foreign_scheduler_tasks():
    for path, task in (
        ("scripts/guard-startup.ps1", "Guard"),
        ("scripts/dashboard-startup.ps1", "ControlCenter"),
    ):
        script = read(path)
        assert "-TaskPath '\\' -TaskName $taskName" in script, path
        assert "Get-ScheduledTask -TaskName $taskName" not in script, path
        assert "Unregister-ScheduledTask -TaskName $taskName" not in script, path
        assert f"function Assert-{task}TaskOwned" in script, path
        assert "Principal.UserId" in script, path
        assert "Actions" in script, path
    guard = read("scripts/guard-startup.ps1")
    assert guard.index("Assert-GuardTaskOwned -Task $existing -ExpectedExecutable $exe") < (
        guard.index("Stop-ScheduledTask -TaskPath '\\' -TaskName $taskName")
        if "Stop-ScheduledTask -TaskPath '\\' -TaskName $taskName" in guard
        else 1000000
    ) or "Assert-GuardTaskOwned -Task $task -ExpectedExecutable $uninstallExe" in guard


def test_windows_behavioral_gate_registered():
    workflow = read(".github/workflows/full-source-audit.yml")
    assert "tests/install-boundary-audit-smoke.ps1" in workflow
    assert "shell: powershell" in workflow
