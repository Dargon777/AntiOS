"""Documented Windows antivirus APIs; no changes to protection settings."""
from __future__ import annotations

import ctypes
import os
import subprocess
from pathlib import Path


class AmsiScanner:
    name = "Windows AMSI"

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("AMSI requires Windows 10 or later")
        # LOAD_LIBRARY_SEARCH_SYSTEM32: never resolve a DLL from a scanned folder.
        self.dll = ctypes.WinDLL("amsi.dll", winmode=0x800)
        pointer = ctypes.c_void_p
        self.dll.AmsiInitialize.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(pointer)]
        self.dll.AmsiInitialize.restype = ctypes.c_int32
        self.dll.AmsiScanBuffer.argtypes = [
            pointer, pointer, ctypes.c_uint32, ctypes.c_wchar_p,
            pointer, ctypes.POINTER(ctypes.c_int32),
        ]
        self.dll.AmsiScanBuffer.restype = ctypes.c_int32
        self.dll.AmsiUninitialize.argtypes = [pointer]
        self.dll.AmsiUninitialize.restype = None
        self.context = pointer()
        self._check(self.dll.AmsiInitialize("AntiOS", ctypes.byref(self.context)))

    @staticmethod
    def _check(result: int) -> None:
        if result < 0:
            raise OSError(f"AMSI failed (0x{result & 0xffffffff:08X})")

    def scan(self, content: bytes, name: str) -> int:
        if not content:
            return 0
        buffer = ctypes.create_string_buffer(content)
        result = ctypes.c_int32()
        self._check(self.dll.AmsiScanBuffer(
            self.context, buffer, len(content), name, None, ctypes.byref(result),
        ))
        return result.value

    def close(self) -> None:
        if self.context:
            self.dll.AmsiUninitialize(self.context)
            self.context = ctypes.c_void_p()


def defender_action(action: str, *, runner=subprocess.run) -> dict:
    """Run an allowlisted operation. A scan completion is not a clean verdict.

    Start-MpScan follows Defender's configured remediation/cloud policies.
    There is deliberately no arbitrary PowerShell, path or option interpolation.
    """
    commands = {
        "quick": "Start-MpScan -ScanType QuickScan",
        "full": "Start-MpScan -ScanType FullScan",
        "update": "Update-MpSignature",
    }
    if action not in commands:
        raise ValueError("Defender action must be quick, full or update")
    if os.name != "nt":
        raise OSError("Microsoft Defender operations require Windows")
    system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    executable = system / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = runner(
        [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
         "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
         + commands[action]],
        capture_output=True, text=True, errors="replace", check=False,
        timeout=86400 if action == "full" else 3600,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        detail = (result.stderr or result.stdout or "Operation failed").strip()[:2000]
        raise OSError(f"Microsoft Defender: {detail}")
    return {"action": action, "completed": True, "verdict": "see-windows-security"}
