"""Verify the Windows ClamD TCP peer against an administrator-controlled SCM service.

ClamD TCP has no authentication.  AntiOS therefore treats a loopback port alone
as insufficient for resident protection: the server side of the established
connection must belong to the configured running own-process LocalSystem service.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
import socket
import struct

_SERVICE_RE = re.compile(r"[A-Za-z0-9_-]{1,80}")


def validate_service_name(name: str | None) -> str | None:
    if name is None:
        return None
    if not isinstance(name, str) or not _SERVICE_RE.fullmatch(name):
        raise ValueError("ClamD service name must contain only A-Z, a-z, 0-9, _ or -")
    return name


def configured_service_name(explicit: str | None = None) -> str | None:
    """Resolve an explicit/env/administrator registry service binding."""
    if explicit is not None:
        return validate_service_name(explicit)
    value = os.environ.get("ANTIOS_CLAMD_SERVICE")
    if value:
        return validate_service_name(value)
    if os.name != "nt":
        return None
    try:
        import winreg
        candidates = (
            (r"SYSTEM\CurrentControlSet\Services\AntiOSNative\Parameters", "EngineServiceName"),
            (r"SOFTWARE\AntiOS", "EngineServiceName"),
        )
        for path, key in candidates:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as handle:
                    value, kind = winreg.QueryValueEx(handle, key)
                if kind == winreg.REG_SZ and value:
                    return validate_service_name(value)
            except FileNotFoundError:
                continue
    except (OSError, ImportError):
        return None
    return None


@dataclass(frozen=True)
class ServiceProcess:
    name: str
    pid: int
    account: str


def _require_windows() -> None:
    if os.name != "nt":
        raise OSError("Windows SCM peer verification is available only on Windows")


def query_service_process(service_name: str) -> ServiceProcess:
    """Return a running own-process LocalSystem service and its current PID."""
    _require_windows()
    service_name = validate_service_name(service_name)
    import ctypes
    from ctypes import wintypes

    SC_MANAGER_CONNECT = 0x0001
    SERVICE_QUERY_CONFIG = 0x0001
    SERVICE_QUERY_STATUS = 0x0004
    SC_STATUS_PROCESS_INFO = 0
    SERVICE_WIN32_OWN_PROCESS = 0x00000010
    SERVICE_RUNNING = 0x00000004
    ERROR_INSUFFICIENT_BUFFER = 122

    class SERVICE_STATUS_PROCESS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
            ("dwProcessId", wintypes.DWORD),
            ("dwServiceFlags", wintypes.DWORD),
        ]

    class QUERY_SERVICE_CONFIGW(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwStartType", wintypes.DWORD),
            ("dwErrorControl", wintypes.DWORD),
            ("lpBinaryPathName", wintypes.LPWSTR),
            ("lpLoadOrderGroup", wintypes.LPWSTR),
            ("dwTagId", wintypes.DWORD),
            ("lpDependencies", wintypes.LPWSTR),
            ("lpServiceStartName", wintypes.LPWSTR),
            ("lpDisplayName", wintypes.LPWSTR),
        ]

    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    api.OpenSCManagerW.restype = wintypes.HANDLE
    api.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    api.OpenServiceW.restype = wintypes.HANDLE
    api.QueryServiceStatusEx.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.QueryServiceStatusEx.restype = wintypes.BOOL
    api.QueryServiceConfigW.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.QueryServiceConfigW.restype = wintypes.BOOL
    api.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    api.CloseServiceHandle.restype = wintypes.BOOL
    manager = api.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not manager:
        raise OSError(ctypes.get_last_error(), "OpenSCManagerW failed")
    service = None
    try:
        service = api.OpenServiceW(manager, service_name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)
        if not service:
            raise OSError(ctypes.get_last_error(), f"ClamD service {service_name!r} is unavailable")
        state = SERVICE_STATUS_PROCESS()
        needed = wintypes.DWORD()
        if not api.QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, ctypes.byref(state),
                                         ctypes.sizeof(state), ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "QueryServiceStatusEx failed")
        if (state.dwServiceType != SERVICE_WIN32_OWN_PROCESS or
                state.dwCurrentState != SERVICE_RUNNING or not state.dwProcessId):
            raise OSError("Configured ClamD service is not a running own-process service")

        config_needed = wintypes.DWORD()
        api.QueryServiceConfigW(service, None, 0, ctypes.byref(config_needed))
        error = ctypes.get_last_error()
        if error != ERROR_INSUFFICIENT_BUFFER or not config_needed.value or config_needed.value > 1024 * 1024:
            raise OSError(error, "QueryServiceConfigW size query failed")
        buffer = ctypes.create_string_buffer(config_needed.value)
        if not api.QueryServiceConfigW(service, buffer, config_needed.value, ctypes.byref(config_needed)):
            raise OSError(ctypes.get_last_error(), "QueryServiceConfigW failed")
        config = ctypes.cast(buffer, ctypes.POINTER(QUERY_SERVICE_CONFIGW)).contents
        account = config.lpServiceStartName or ""
        if account.casefold() not in {"localsystem", r".\localsystem", r"nt authority\system"}:
            raise OSError("Configured ClamD service must run as LocalSystem")
        return ServiceProcess(service_name, int(state.dwProcessId), account)
    finally:
        if service:
            api.CloseServiceHandle(service)
        api.CloseServiceHandle(manager)


def _ipv4_dword(address: str) -> int:
    return struct.unpack("=I", socket.inet_aton(address))[0]


def verify_connected_socket(connection: socket.socket, expected_pid: int) -> bool:
    """Match the server side of this exact established loopback TCP connection."""
    _require_windows()
    if not isinstance(expected_pid, int) or expected_pid <= 0:
        return False
    import ctypes
    from ctypes import wintypes

    AF_INET = 2
    TCP_TABLE_OWNER_PID_CONNECTIONS = 4
    MIB_TCP_STATE_ESTAB = 5
    ERROR_INSUFFICIENT_BUFFER = 122
    NO_ERROR = 0

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwState", wintypes.DWORD),
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwRemoteAddr", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    local_host, local_port = connection.getsockname()[:2]
    remote_host, remote_port = connection.getpeername()[:2]
    if local_host != "127.0.0.1" or remote_host != "127.0.0.1":
        return False

    api = ctypes.WinDLL("iphlpapi", use_last_error=True)
    api.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL,
        wintypes.ULONG, ctypes.c_int, wintypes.ULONG,
    ]
    api.GetExtendedTcpTable.restype = wintypes.DWORD
    needed = wintypes.ULONG()
    status = api.GetExtendedTcpTable(None, ctypes.byref(needed), False, AF_INET,
                                     TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
    if status != ERROR_INSUFFICIENT_BUFFER or needed.value < 4 or needed.value > 4 * 1024 * 1024:
        return False
    buffer = ctypes.create_string_buffer(needed.value)
    capacity = needed.value
    status = api.GetExtendedTcpTable(buffer, ctypes.byref(needed), False, AF_INET,
                                     TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
    if status != NO_ERROR or needed.value > capacity:
        return False
    count = ctypes.c_uint32.from_buffer_copy(buffer.raw[:4]).value
    row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
    if count > (needed.value - 4) // row_size:
        return False

    server_addr = _ipv4_dword(remote_host)
    client_addr = _ipv4_dword(local_host)
    server_port = socket.htons(remote_port)
    client_port = socket.htons(local_port)
    for index in range(count):
        offset = 4 + index * row_size
        row = MIB_TCPROW_OWNER_PID.from_buffer_copy(buffer.raw[offset:offset + row_size])
        if (row.dwState == MIB_TCP_STATE_ESTAB and
                row.dwLocalAddr == server_addr and row.dwRemoteAddr == client_addr and
                row.dwLocalPort == server_port and row.dwRemotePort == client_port and
                row.dwOwningPid == expected_pid):
            return True
    return False
