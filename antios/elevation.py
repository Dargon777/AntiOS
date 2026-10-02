"""Request a normal Windows UAC consent prompt before opening the dashboard."""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys


def ensure_administrator(language: str | None = None) -> int | None:
    """None: already elevated/not Windows; 0: relaunched; 1: denied/failed."""
    if os.name != "nt":
        return None
    shell = ctypes.WinDLL("shell32", use_last_error=True, winmode=0x800)
    shell.IsUserAnAdmin.argtypes = []
    shell.IsUserAnAdmin.restype = ctypes.c_int
    if shell.IsUserAnAdmin():
        return None
    if getattr(sys, "frozen", False):
        arguments = sys.argv[1:]
    else:
        arguments = ["-m", "antios", "dashboard"]
        if language:
            arguments += ["--lang", language]
    shell.ShellExecuteW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                   ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    shell.ShellExecuteW.restype = ctypes.c_void_p
    status = shell.ShellExecuteW(None, "runas", sys.executable,
                                subprocess.list2cmdline(arguments), os.getcwd(), 1)
    return 0 if status and status > 32 else 1
