"""Truthful aggregate status for AntiOS antivirus protection layers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

from .clamav import ClamAVScanner
from .guard_state import read_guard_state
from .windows_antivirus import coexistence_profile, defender_status
from .windows_process import hidden_process_kwargs, system_executable


def _managed_runtime_status() -> dict:
    if os.name != "nt":
        return {"available": False, "reason": "windows-only"}
    program_files = Path(os.environ.get("ProgramFiles") or r"C:\Program Files")
    program_data = Path(os.environ.get("ProgramData") or r"C:\ProgramData")
    install = program_files / "AntiOS" / "ClamAV"
    data = program_data / "AntiOS-ClamAV"
    required = {
        "clamd": install / "clamd.exe",
        "freshclam": install / "freshclam.exe",
        "clamd_config": data / "config" / "clamd.conf",
        "freshclam_config": data / "config" / "freshclam.conf",
        "database": data / "database",
    }
    files = {key: path.exists() for key, path in required.items()}
    task = {"available": False}
    schtasks = system_executable("schtasks.exe")
    try:
        process = subprocess.run(
            [str(schtasks), "/Query", "/TN", "AntiOS ClamAV Signature Update", "/FO", "LIST"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            **hidden_process_kwargs(),
        )
        task = {
            "available": process.returncode == 0,
            "exit_code": process.returncode,
        }
    except (OSError, subprocess.SubprocessError) as exc:
        task = {"available": False, "error": str(exc)[:300]}

    bootstrap_exit = None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\DargonITP\AntiOS") as key:
            bootstrap_exit = int(winreg.QueryValueEx(key, "ProtectionBootstrapExitCode")[0])
    except (OSError, ValueError):
        pass

    healthy = all(files.values()) and task.get("available") is True
    return {
        "available": install.exists(),
        "healthy": healthy,
        "install_root": str(install),
        "data_root": str(data),
        "files": files,
        "updater_task": task,
        "bootstrap_exit_code": bootstrap_exit,
    }


def _native_status() -> dict:
    if os.name != "nt":
        return {"available": False, "reason": "windows-only"}
    program_files = os.environ.get("ProgramFiles")
    if not program_files:
        return {"available": False, "reason": "ProgramFiles unavailable"}
    executable = Path(program_files) / "AntiOSNative" / "AntiOS-Service.exe"
    if not executable.is_file():
        return {"available": False, "reason": "not-installed"}
    result = {"available": True, "path": str(executable)}
    for key, flag in (("service", "--status"), ("driver", "--driver-status")):
        try:
            process = subprocess.run(
                [str(executable), flag],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                **hidden_process_kwargs(),
            )
            payload = json.loads(process.stdout) if process.stdout.strip() else {}
            payload["exit_code"] = process.returncode
            if process.stderr.strip():
                payload["stderr"] = process.stderr.strip()[:500]
            result[key] = payload
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            result[key] = {"error": str(exc)[:500]}
    return result


def collect_protection_status(engine_service: str | None = None) -> dict:
    engine: dict
    try:
        scanner = ClamAVScanner(
            service_name=engine_service,
            require_verified_peer=os.name == "nt",
            timeout=5,
        )
        try:
            engine = dict(scanner.metadata, available=True)
        finally:
            scanner.close()
    except (OSError, RuntimeError, ValueError) as exc:
        engine = {"available": False, "detail": str(exc)[:500]}

    guard = read_guard_state()
    managed = _managed_runtime_status()
    native = _native_status()
    defender = defender_status()
    coexistence = coexistence_profile(defender)
    peer_ok = (not engine.get("peer_verification_required") or
               engine.get("peer_verified") is True)
    engine_ready = bool(
        engine.get("available") and
        engine.get("database_freshness") == "current" and
        peer_ok
    )
    guard_running = bool(
        guard.get("running") and
        guard.get("state") not in {"failed", "stopped", "unresponsive", "not-running"}
    )
    service = native.get("service", {})
    driver = native.get("driver", {})
    native_running = service.get("service_state") == 4 and service.get("exit_code") == 0
    native_coexistence = bool(
        native_running and
        driver.get("driver_available") is True and
        driver.get("exit_code") == 0 and
        driver.get("coexistence_mode") == 1 and
        driver.get("fail_open_on_incomplete") is True and
        isinstance(driver.get("max_pending"), int) and
        1 <= driver.get("max_pending") <= 4 and
        isinstance(driver.get("pending"), int) and
        0 <= driver.get("pending") <= driver.get("max_pending")
    )
    pre_execution = bool(
        native_running and
        driver.get("driver_available") is True and
        driver.get("enforcement") == 1 and
        driver.get("exit_code") == 0
    )

    blockers = []
    if not engine_ready:
        blockers.append("trusted-current-engine")
    if not guard_running:
        blockers.append("resident-post-write-guard")
    if not pre_execution:
        blockers.append("signed-native-pre-execution-enforcement")
    # These are intentionally never inferred from local process state.
    blockers.extend(["windows-security-center-registration", "elam-ppl-production-approval"])

    return {
        "schema": 1,
        "kind": "antios-protection-status",
        "engine": engine,
        "guard": guard,
        "managed_runtime": managed,
        "native": native,
        "defender": defender,
        "coexistence": coexistence,
        "capabilities": {
            "standalone_detection_engine": engine_ready,
            "resident_post_write_detection": guard_running and engine_ready,
            "pre_execution_blocking": pre_execution and engine_ready,
            "native_coexistence_ready": native_coexistence,
            "defender_dependency": False,
            "defender_realtime_active": defender.get("realtime_active") is True,
            "layered_with_defender": coexistence["layered_with_defender"],
        },
        "production_primary_antivirus": False,
        "remaining_gates": blockers,
    }


def render_protection_status(status: dict) -> str:
    caps = status["capabilities"]
    engine = status["engine"]
    guard = status["guard"]
    managed = status.get("managed_runtime", {})
    native = status["native"]
    defender = status.get("defender", {})
    coexistence = status.get("coexistence", {})
    return "\n".join([
        "AntiOS protection status",
        f"Engine: {'ready' if caps['standalone_detection_engine'] else 'not ready'}"
        f" ({engine.get('version', engine.get('detail', 'unavailable'))})",
        f"Database: {engine.get('database_freshness', 'unknown')}",
        f"Engine identity: {engine.get('peer_identity', 'unknown')}",
        f"Resident Guard: {guard.get('state', 'not-running')}",
        f"Managed runtime: {'healthy' if managed.get('healthy') else 'needs review'}",
        f"Updater task: {'ready' if managed.get('updater_task', {}).get('available') else 'missing'}",
        f"Native service: {native.get('service', {}).get('service_state', 'not-running')}",
        f"Native coexistence: {'healthy' if caps.get('native_coexistence_ready') else 'inactive/not-validated'}",
        f"Native max wait: {native.get('driver', {}).get('max_wait_ms', 'unknown')} ms",
        f"Pre-execution enforcement: {'active' if caps['pre_execution_blocking'] else 'inactive'}",
        f"Microsoft Defender: {'real-time active' if defender.get('realtime_active') else defender.get('running_mode', 'unavailable')}",
        f"Coexistence mode: {coexistence.get('mode', 'unknown')}",
        "AntiOS role: independent companion; Defender settings unchanged",
        "Primary Windows antivirus registration: not claimed",
        "Remaining gates: " + ", ".join(status["remaining_gates"]),
    ])
