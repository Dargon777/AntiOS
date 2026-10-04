"""Truthful aggregate status for AntiOS antivirus protection layers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

from .clamav import ClamAVScanner
from .guard_state import read_guard_state


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
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
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
    native = _native_status()
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
        "native": native,
        "capabilities": {
            "standalone_detection_engine": engine_ready,
            "resident_post_write_detection": guard_running and engine_ready,
            "pre_execution_blocking": pre_execution and engine_ready,
            "defender_dependency": False,
        },
        "production_primary_antivirus": False,
        "remaining_gates": blockers,
    }


def render_protection_status(status: dict) -> str:
    caps = status["capabilities"]
    engine = status["engine"]
    guard = status["guard"]
    native = status["native"]
    return "\n".join([
        "AntiOS protection status",
        f"Engine: {'ready' if caps['standalone_detection_engine'] else 'not ready'}"
        f" ({engine.get('version', engine.get('detail', 'unavailable'))})",
        f"Database: {engine.get('database_freshness', 'unknown')}",
        f"Engine identity: {engine.get('peer_identity', 'unknown')}",
        f"Resident Guard: {guard.get('state', 'not-running')}",
        f"Native service: {native.get('service', {}).get('service_state', 'not-running')}",
        f"Pre-execution enforcement: {'active' if caps['pre_execution_blocking'] else 'inactive'}",
        "Primary Windows antivirus registration: not claimed",
        "Remaining gates: " + ", ".join(status["remaining_gates"]),
    ])
