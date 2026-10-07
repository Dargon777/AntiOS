"""Read-only Defender/Windows Security coexistence diagnostics.

AntiOS deliberately does not register itself as the primary antivirus here.  The
module only observes Windows Security/Defender state and whether the optional
AntiOS AMSI provider is registered.  It never disables Defender, changes WSC
registration, exclusions, Tamper Protection or AMSI policy.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import subprocess

from .windows_process import hidden_process_kwargs, system_executable

AMSI_PROVIDER_CLSID = "{8E8A9D7D-814F-4A83-A127-8C4894E41121}"
WSC_SECURITY_PROVIDER_ANTIVIRUS = 0x4
_WSC_HEALTH = {
    0: "good",
    1: "not-monitored",
    2: "poor",
    3: "snooze",
}


def _wsc_antivirus_health() -> dict:
    if os.name != "nt":
        return {"available": False, "reason": "windows-only"}
    try:
        health = ctypes.c_int(-1)
        api = ctypes.WinDLL("wscapi.dll")
        function = api.WscGetSecurityProviderHealth
        function.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_int)]
        function.restype = ctypes.c_long
        result = int(function(WSC_SECURITY_PROVIDER_ANTIVIRUS, ctypes.byref(health)))
        if result < 0:
            return {"available": False, "hresult": result}
        value = int(health.value)
        return {
            "available": True,
            "category": "antivirus",
            "health": _WSC_HEALTH.get(value, "unknown"),
            "health_value": value,
        }
    except (AttributeError, OSError, ValueError) as exc:
        return {"available": False, "error": str(exc)[:300]}


def _defender_status() -> dict:
    if os.name != "nt":
        return {"available": False, "reason": "windows-only"}
    command = (
        "Get-MpComputerStatus | "
        "Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,"
        "RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,"
        "NISEnabled,OnAccessProtectionEnabled,AMRunningMode | "
        "ConvertTo-Json -Compress"
    )
    try:
        process = subprocess.run(
            [
                str(system_executable(r"WindowsPowerShell\v1.0\powershell.exe")),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            **hidden_process_kwargs(),
        )
        if process.returncode != 0 or not process.stdout.strip():
            return {
                "available": False,
                "exit_code": process.returncode,
                "error": process.stderr.strip()[:300],
            }
        data = json.loads(process.stdout)
        return {
            "available": True,
            "service_enabled": bool(data.get("AMServiceEnabled")),
            "antivirus_enabled": bool(data.get("AntivirusEnabled")),
            "antispyware_enabled": bool(data.get("AntispywareEnabled")),
            "real_time_protection": bool(data.get("RealTimeProtectionEnabled")),
            "behavior_monitor": bool(data.get("BehaviorMonitorEnabled")),
            "ioav_protection": bool(data.get("IoavProtectionEnabled")),
            "network_inspection": bool(data.get("NISEnabled")),
            "on_access_protection": bool(data.get("OnAccessProtectionEnabled")),
            "running_mode": data.get("AMRunningMode"),
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return {"available": False, "error": str(exc)[:300]}


def _amsi_provider_status() -> dict:
    if os.name != "nt":
        return {"available": False, "registered": False, "reason": "windows-only"}
    try:
        import winreg
        flags = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        provider_path = rf"SOFTWARE\Microsoft\AMSI\Providers\{AMSI_PROVIDER_CLSID}"
        clsid_path = rf"SOFTWARE\Classes\CLSID\{AMSI_PROVIDER_CLSID}\InprocServer32"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, provider_path, 0, flags):
            pass
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, clsid_path, 0, flags) as key:
            module, _ = winreg.QueryValueEx(key, None)
        expanded = os.path.expandvars(str(module))
        return {
            "available": True,
            "registered": True,
            "clsid": AMSI_PROVIDER_CLSID,
            "module": expanded,
            "module_exists": Path(expanded).is_file(),
        }
    except (OSError, ValueError) as exc:
        return {
            "available": True,
            "registered": False,
            "clsid": AMSI_PROVIDER_CLSID,
            "detail": str(exc)[:300],
        }


def evaluate_coexistence(defender: dict, wsc: dict, amsi: dict) -> dict:
    defender_active = bool(
        defender.get("available")
        and defender.get("service_enabled")
        and defender.get("antivirus_enabled")
        and defender.get("real_time_protection")
    )
    if defender_active:
        mode = "layered-with-defender"
    elif defender.get("available"):
        mode = "defender-present-not-realtime"
    else:
        mode = "defender-state-unavailable"
    return {
        "mode": mode,
        "defender_active_parallel": defender_active,
        "wsc_antivirus_health_good": wsc.get("health") == "good",
        "amsi_provider_registered": bool(amsi.get("registered") and amsi.get("module_exists")),
        # Invariant: coexistence must not advertise AntiOS as the primary AV.
        "antios_primary_wsc_registration": False,
        "defender_changes_required": False,
    }


def collect_coexistence_status() -> dict:
    defender = _defender_status()
    wsc = _wsc_antivirus_health()
    amsi = _amsi_provider_status()
    return {
        "schema": 1,
        "kind": "antios-defender-coexistence",
        "defender": defender,
        "windows_security": wsc,
        "antios_amsi": amsi,
        "coexistence": evaluate_coexistence(defender, wsc, amsi),
        "policy": {
            "disable_defender": False,
            "register_primary_antivirus": False,
            "modify_defender_exclusions": False,
            "modify_amsi_feature_bits": False,
        },
    }


def render_coexistence_status(status: dict) -> str:
    coexist = status["coexistence"]
    defender = status["defender"]
    amsi = status["antios_amsi"]
    wsc = status["windows_security"]
    return "\n".join([
        "AntiOS + Microsoft Defender coexistence",
        f"Mode: {coexist['mode']}",
        f"Defender real-time: {'active' if coexist['defender_active_parallel'] else 'not confirmed'}",
        f"Defender running mode: {defender.get('running_mode', 'unknown')}",
        f"Windows Security AV health: {wsc.get('health', 'unknown')}",
        f"AntiOS AMSI provider: {'registered' if amsi.get('registered') else 'not registered'}",
        "AntiOS primary WSC registration: no",
        "Defender settings changed by AntiOS: no",
    ])
