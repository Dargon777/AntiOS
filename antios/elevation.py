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


def is_administrator() -> bool:
    """Check elevation without triggering UAC or changing user identity."""
    if os.name != "nt":
        return False
    try:
        shell = ctypes.WinDLL("shell32", use_last_error=True, winmode=0x800)
        shell.IsUserAnAdmin.restype = ctypes.c_int
        return bool(shell.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def managed_cli_path():
    """Only elevate the installed, machine-managed CLI beside this GUI.

    Portable/user-writable executable trees are intentionally not an elevation
    target; they may be replaced between GUI verification and UAC approval.
    """
    from pathlib import Path
    if not getattr(sys, "frozen", False):
        raise RuntimeError("Install AntiOS first to repair the machine-wide engine from the GUI")
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\DargonITP\AntiOS") as key:
        registered, _ = winreg.QueryValueEx(key, "InstallDir")
    installed = Path(registered).resolve()
    gui_dir = Path(sys.executable).resolve().parent
    # Use the machine-wide installation root, not the caller's mutable
    # environment variables, to decide whether a UAC target is managed.
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion"
    ) as key:
        program_files_dir, _ = winreg.QueryValueEx(key, "ProgramFilesDir")
    program_files = Path(program_files_dir).resolve()
    if installed != gui_dir or installed == program_files or program_files not in installed.parents:
        raise RuntimeError("Privileged repair requires an installed AntiOS in Program Files")
    cli = installed / "AntiOS.exe"
    if not cli.is_file() or cli.is_symlink():
        raise FileNotFoundError("Managed AntiOS.exe for elevated repair is missing or unsafe")
    return cli


def request_protection_elevation(action: str) -> None:
    """Launch an allowlisted machine repair via a separate UAC-elevated CLI.

    Successful ShellExecute means only that Windows accepted the launch. The
    dashboard must not assume the elevated operation completed successfully.
    """
    if action not in {"repair", "bootstrap"}:
        raise ValueError("Unsupported privileged protection operation")
    if os.name != "nt":
        raise OSError("Windows UAC is required")
    cli = managed_cli_path()
    arguments = (
        ["protection-repair", "--yes", "--update-signatures", "--json"]
        if action == "repair" else
        ["protection-bootstrap", "--yes", "--json"]
    )
    shell = ctypes.WinDLL("shell32", use_last_error=True, winmode=0x800)
    shell.ShellExecuteW.argtypes = [
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int,
    ]
    shell.ShellExecuteW.restype = ctypes.c_void_p
    status = shell.ShellExecuteW(
        None, "runas", str(cli), subprocess.list2cmdline(arguments), str(cli.parent), 1,
    )
    if not status or status <= 32:
        raise PermissionError("Administrator consent was denied or repair could not launch")
