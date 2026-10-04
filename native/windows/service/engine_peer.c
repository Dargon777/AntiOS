/* MS-PL. Never identify the engine by a port number or executable name alone. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stddef.h>
#include "engine_peer.h"

DWORD ao_engine_service_name(wchar_t name[81]) {
    DWORD bytes = 81 * sizeof(wchar_t), i, error;
    ZeroMemory(name, bytes);
    error = RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\AntiOSNative\\Parameters",
                        L"EngineServiceName", RRF_RT_REG_SZ | RRF_ZEROONFAILURE, NULL, name, &bytes);
    if (error) return error;
    if (!name[0] || name[80]) return ERROR_INVALID_DATA;
    for (i = 0; name[i]; ++i) {
        wchar_t c = name[i];
        if (!((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
              (c >= L'0' && c <= L'9') || c == L'_' || c == L'-')) return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}
int ao_engine_peer_valid(struct ao_engine_peer *peer) {
    SERVICE_STATUS_PROCESS state = {0};
    DWORD needed = 0;
    return peer->process && WaitForSingleObject(peer->process, 0) == WAIT_TIMEOUT &&
        QueryServiceStatusEx(peer->service, SC_STATUS_PROCESS_INFO, (BYTE *)&state, sizeof(state), &needed) &&
        state.dwServiceType == SERVICE_WIN32_OWN_PROCESS && state.dwCurrentState == SERVICE_RUNNING &&
        state.dwProcessId == peer->pid;
}
void ao_engine_peer_close(struct ao_engine_peer *peer) {
    if (peer->process) CloseHandle(peer->process);
    if (peer->service) CloseServiceHandle(peer->service);
    if (peer->manager) CloseServiceHandle(peer->manager);
    ZeroMemory(peer, sizeof(*peer));
}
int ao_engine_peer_open(struct ao_engine_peer *peer, const wchar_t *service_name) {
    SERVICE_STATUS_PROCESS state = {0};
    DWORD needed = 0;
    HANDLE token = NULL;
    union { TOKEN_USER alignment; BYTE bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]; } user_buffer;
    int system_user = 0;
    ZeroMemory(peer, sizeof(*peer));
    peer->manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!peer->manager) goto failed;
    peer->service = OpenServiceW(peer->manager, service_name, SERVICE_QUERY_STATUS);
    if (!peer->service || !QueryServiceStatusEx(peer->service, SC_STATUS_PROCESS_INFO,
        (BYTE *)&state, sizeof(state), &needed) || state.dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
        state.dwCurrentState != SERVICE_RUNNING || !state.dwProcessId) goto failed;
    peer->pid = state.dwProcessId;
    /* Hold the process object throughout both VERSION and INSTREAM connections. */
    peer->process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, peer->pid);
    if (!peer->process || !OpenProcessToken(peer->process, TOKEN_QUERY, &token)) goto failed;
    if (GetTokenInformation(token, TokenUser, user_buffer.bytes, sizeof(user_buffer), &needed))
        system_user = IsWellKnownSid(((TOKEN_USER *)user_buffer.bytes)->User.Sid, WinLocalSystemSid) != 0;
    CloseHandle(token);
    if (!system_user || !ao_engine_peer_valid(peer)) goto failed;
    return 1;
failed:
    ao_engine_peer_close(peer);
    return 0;
}
int ao_engine_peer_socket(uintptr_t socket_value, void *context) {
    struct ao_engine_peer *peer = context;
    SOCKET socket_handle = (SOCKET)socket_value;
    struct sockaddr_in local = {0}, remote = {0};
    int size = sizeof(local), found = 0;
    DWORD bytes = 0, capacity, i, status;
    MIB_TCPTABLE_OWNER_PID *table = NULL;
    if (!ao_engine_peer_valid(peer) || getsockname(socket_handle, (struct sockaddr *)&local, &size)) return 0;
    size = sizeof(remote);
    if (getpeername(socket_handle, (struct sockaddr *)&remote, &size) || local.sin_family != AF_INET ||
        remote.sin_family != AF_INET || remote.sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
        local.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) return 0;
    status = GetExtendedTcpTable(NULL, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    /* Bound allocation even if another application creates very many connections. */
    if (status != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof(DWORD) || bytes > 4 * 1024 * 1024) return 0;
    capacity = bytes;
    table = HeapAlloc(GetProcessHeap(), 0, capacity);
    if (!table) return 0;
    status = GetExtendedTcpTable(table, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    if (status == NO_ERROR && bytes <= capacity && bytes >= offsetof(MIB_TCPTABLE_OWNER_PID, table) &&
        table->dwNumEntries <= (bytes - offsetof(MIB_TCPTABLE_OWNER_PID, table)) / sizeof(table->table[0])) {
        for (i = 0; i < table->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID *row = &table->table[i];
            /* Match the server side of THIS established connection, not the listener. */
            if (row->dwState == MIB_TCP_STATE_ESTAB && row->dwLocalAddr == remote.sin_addr.s_addr &&
                row->dwRemoteAddr == local.sin_addr.s_addr && row->dwLocalPort == remote.sin_port &&
                row->dwRemotePort == local.sin_port && row->dwOwningPid == peer->pid) {
                found = 1; break;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, table);
    return found && ao_engine_peer_valid(peer);
}

struct ao_outcome ao_engine_scan(const wchar_t *service_name, const void *data, size_t size,
                                unsigned timeout, ao_cancel_fn cancel, void *context) {
    struct ao_engine_peer peer;
    struct ao_outcome outcome = {AO_UNKNOWN, 0, "", "trusted engine service unavailable"};
    ULONGLONG started = GetTickCount64(), elapsed;
    if (!ao_engine_peer_open(&peer, service_name)) return outcome;
    elapsed = GetTickCount64() - started;
    if (elapsed < timeout) {
        outcome = ao_clam_scan_verified(data, size, 3310, timeout - (unsigned)elapsed,
                                       cancel, context, ao_engine_peer_socket, &peer);
        if (!ao_engine_peer_valid(&peer) || GetTickCount64() - started >= timeout ||
            (cancel && cancel(context))) {
            struct ao_outcome unknown = {AO_UNKNOWN, 0, "", "engine identity or scan deadline no longer valid"};
            outcome = unknown;
        }
    }
    ao_engine_peer_close(&peer);
    return outcome;
}
