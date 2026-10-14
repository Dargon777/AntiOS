"""Restrict elevated AntiOS operations to explicit, allowlisted UAC maintenance."""
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

    # A signed image can be swapped before UAC if its directory is writable
    # by the current (unelevated) Windows user. Deny that installation instead
    # of elevating from an unsafe location.
    from .windows_acl import assert_protected_install
    assert_protected_install(cli, program_files)
    return cli


def request_protection_elevation(action: str) -> dict:
    """Launch an allowlisted machine repair via a separate UAC-elevated CLI.

    Returns completion only after the elevated process exits with code zero.
    Callers must also independently re-probe managed engine health.
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
    # ShellExecuteW only confirms that UAC launched a process; it cannot
    # distinguish successful repair from a failed bootstrap. Wait on a real
    # Windows process handle instead of trusting a writable status file or IPC
    # message from a potentially different administrator account.
    timeout = 1200 if action == "bootstrap" else 360
    return _run_elevated_cli(cli, arguments, timeout_seconds=timeout)


def _run_elevated_cli(cli, arguments: list[str], *, timeout_seconds: int) -> dict:
    """Wait for one allowlisted elevated CLI and inspect its OS exit status.

    Must be called from a GUI worker, never the Tk/UI thread. Timeout closes
    our process handle but does not terminate the elevated maintenance job.
    """
    if os.name != "nt":
        raise OSError("Windows UAC is required")
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 3600:
        raise ValueError("Invalid privileged-operation timeout")

    from ctypes import wintypes

    class _ShellExecuteInfo(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", wintypes.ULONG),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIconOrMonitor", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    shell = ctypes.WinDLL("shell32", use_last_error=True, winmode=0x800)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True, winmode=0x800)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfo)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

    request = _ShellExecuteInfo()
    request.cbSize = ctypes.sizeof(_ShellExecuteInfo)
    request.fMask = 0x00000040 | 0x00000100  # SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    request.lpVerb = "runas"
    request.lpFile = str(cli)
    request.lpParameters = subprocess.list2cmdline(arguments)
    request.lpDirectory = str(cli.parent)
    request.nShow = 1  # CLI window visible for administrator diagnostics

    # ShellExecuteEx can invoke COM-based shell handlers. Microsoft recommends
    # initializing the calling worker thread as an STA. Avoid an implicit
    # uninitialized-COM dependency when the dashboard is launched from Tk.
    ole = ctypes.WinDLL("ole32", use_last_error=True, winmode=0x800)
    ole.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    ole.CoInitializeEx.restype = ctypes.c_long
    ole.CoUninitialize.argtypes = []
    ole.CoUninitialize.restype = None
    hr = ole.CoInitializeEx(None, 0x2 | 0x4)  # STA | disable legacy OLE1 DDE
    com_initialized = hr in (0, 1)  # S_OK / S_FALSE both require CoUninitialize
    if not com_initialized and hr != -2147417850:  # RPC_E_CHANGED_MODE
        raise OSError(f"Cannot initialize Windows shell COM apartment: HRESULT {hr:#x}")

    # UAC interaction stays in the native Windows shell. No PowerShell Bypass,
    # user-writable executable/script or untrusted arguments are involved.
    try:
        launched = shell.ShellExecuteExW(ctypes.byref(request))
        launch_error = ctypes.get_last_error() if not launched else 0
    finally:
        if com_initialized:
            ole.CoUninitialize()
    if not launched:
        if launch_error == 1223:  # ERROR_CANCELLED
            raise PermissionError("Administrator consent was cancelled")
        raise OSError(launch_error, "Cannot launch elevated AntiOS maintenance CLI")
    if not request.hProcess:
        raise RuntimeError("Windows did not return an elevated process handle")

    try:
        wait = kernel.WaitForSingleObject(request.hProcess, timeout_seconds * 1000)
        if wait == 258:  # WAIT_TIMEOUT
            raise TimeoutError(
                "AntiOS maintenance is still running; completion is unverified. "
                "Refresh protection state after it finishes."
            )
        if wait != 0:  # WAIT_OBJECT_0
            raise OSError(ctypes.get_last_error(), "Unable to wait for elevated AntiOS CLI")
        code = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(request.hProcess, ctypes.byref(code)):
            raise OSError(ctypes.get_last_error(), "Unable to read elevated AntiOS exit status")
        if code.value != 0:
            raise RuntimeError(f"AntiOS administrator repair failed (exit code {code.value})")
        return {"completed": True, "exit_code": 0}
    finally:
        kernel.CloseHandle(request.hProcess)
