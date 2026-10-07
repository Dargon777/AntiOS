/* AntiOS native SCM host. MS-PL; see ../LICENSE.microsoft. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fltuser.h>
#include "../inc/avlib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "userscan.h"
#include "engine_peer.h"
#include "../engine/engine.h"

static HANDLE stop_event;
static SERVICE_STATUS_HANDLE status_handle;
static SRWLOCK status_lock = SRWLOCK_INIT;
static DWORD checkpoint;
struct run_context { HANDLE stop, ready; DWORD result; };

static void log_event(WORD level, const wchar_t *message) {
    HANDLE log = RegisterEventSourceW(NULL, AO_SERVICE_NAME);
    if (log) { ReportEventW(log, level, 0, 1, NULL, 1, 0, &message, NULL); DeregisterEventSource(log); }
}
static void report_status(DWORD state, DWORD error) {
    SERVICE_STATUS status = {0};
    AcquireSRWLockExclusive(&status_lock);
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwWin32ExitCode = error ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
    status.dwServiceSpecificExitCode = error;
    if (state == SERVICE_RUNNING) status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        status.dwCheckPoint = ++checkpoint; status.dwWaitHint = 15000;
    }
    SetServiceStatus(status_handle, &status);
    ReleaseSRWLockExclusive(&status_lock);
}
static DWORD WINAPI control(DWORD code, DWORD event_type, void *event_data, void *context) {
    (void)event_type; (void)event_data; (void)context;
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        /* Handler never waits for a scanner; service main drains pending I/O. */
        SetEvent(stop_event);
        return NO_ERROR;
    }
    return code == SERVICE_CONTROL_INTERROGATE ? NO_ERROR : ERROR_CALL_NOT_IMPLEMENTED;
}
static DWORD WINAPI broker_thread(void *context) {
    struct run_context *run = context;
    run->result = ao_broker_run(run->stop, run->ready, log_event);
    return 0;
}
static void WINAPI service_main(DWORD argc, wchar_t **argv) {
    struct run_context run = {0};
    HANDLE worker = NULL, waits[2];
    DWORD error = 0, wait_result;
    (void)argc; (void)argv;
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop_event) return;
    status_handle = RegisterServiceCtrlHandlerExW(AO_SERVICE_NAME, control, NULL);
    if (!status_handle) { CloseHandle(stop_event); return; }
    report_status(SERVICE_START_PENDING, 0);
    run.stop = stop_event; run.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!run.ready) { error = GetLastError(); goto done; }
    worker = CreateThread(NULL, 0, broker_thread, &run, 0, NULL);
    if (!worker) { error = GetLastError(); goto done; }
    waits[0] = worker; waits[1] = run.ready;
    wait_result = WaitForMultipleObjects(2, waits, FALSE, 15000);
    if (wait_result == WAIT_OBJECT_0 + 1 && WaitForSingleObject(stop_event, 0) != WAIT_OBJECT_0) {
        log_event(EVENTLOG_INFORMATION_TYPE, L"Native broker connected. Execute-open coverage only; Windows Defender remains enabled. SCM running does not imply engine readiness or PPL protection.");
        report_status(SERVICE_RUNNING, 0);
        WaitForSingleObject(stop_event, INFINITE);
    } else if (wait_result == WAIT_TIMEOUT) error = ERROR_TIMEOUT;
    else if (wait_result == WAIT_FAILED) error = GetLastError();
    SetEvent(stop_event);
    report_status(SERVICE_STOP_PENDING, 0);
    /* Never terminate a thread that owns filter I/O/sections. Keep SCM informed. */
    while (WaitForSingleObject(worker, 1000) == WAIT_TIMEOUT) report_status(SERVICE_STOP_PENDING, 0);
    if (!error) error = run.result;
done:
    if (worker) CloseHandle(worker);
    if (run.ready) CloseHandle(run.ready);
    if (error) log_event(EVENTLOG_ERROR_TYPE, L"Native service stopped with a failure. Check driver load, signatures and LocalSystem port access.");
    report_status(SERVICE_STOPPED, error);
    CloseHandle(stop_event); stop_event = NULL;
}
static int status_json(void) {
    SC_HANDLE manager, service;
    SERVICE_STATUS_PROCESS state = {0};
    /* SERVICE_LAUNCH_PROTECTED_INFO is one DWORD (older MinGW omits the typedef). */
    struct { DWORD dwLaunchProtected; } configured = {0};
    PROCESS_PROTECTION_LEVEL_INFORMATION actual = {0};
    DWORD needed = 0;
    int config_known = 0, actual_known = 0;
    HANDLE process;
    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) { printf("{\"error\":%lu}\n", GetLastError()); return 2; }
    service = OpenServiceW(manager, AO_SERVICE_NAME, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!service) {
        DWORD error = GetLastError(); CloseServiceHandle(manager);
        printf("{\"installed\":false,\"error\":%lu}\n", error); return 2;
    }
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&state, sizeof(state), &needed)) {
        DWORD error = GetLastError(); CloseServiceHandle(service); CloseServiceHandle(manager);
        printf("{\"error\":%lu}\n", error); return 2;
    }
    config_known = QueryServiceConfig2W(service, SERVICE_CONFIG_LAUNCH_PROTECTED,
                                      (BYTE *)&configured, sizeof(configured), &needed) != 0;
    if (state.dwProcessId) {
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, state.dwProcessId);
        if (process) {
            actual_known = GetProcessInformation(process, ProcessProtectionLevelInfo, &actual, sizeof(actual)) != 0;
            CloseHandle(process);
        }
    }
    printf("{\"installed\":true,\"service_state\":%lu,\"pid\":%lu,\"configured_protection_known\":%s,"
           "\"configured_protection\":%lu,\"actual_protection_known\":%s,\"actual_protection\":%lu,"
           "\"primary_antivirus\":false,\"windows_security_registration\":false,"
           "\"defender_changes\":false,\"coexistence_mode\":\"parallel-secondary\","
           "\"engine_readiness\":\"not_measured\"}\n",
           state.dwCurrentState, state.dwProcessId, config_known ? "true" : "false", configured.dwLaunchProtected,
           actual_known ? "true" : "false", actual.ProtectionLevel);
    CloseServiceHandle(service); CloseServiceHandle(manager);
    return 0;
}
static int driver_status_json(void) {
    AV_CONNECTION_CONTEXT connection = {AvConnectForQuery, AO_PROTOCOL_VERSION};
    COMMAND_MESSAGE command = {0};
    AO_DRIVER_STATUS state = {0};
    HANDLE port = NULL;
    DWORD returned = 0;
    HRESULT result = FilterConnectCommunicationPort(AV_QUERY_PORT_NAME, 0, &connection,
                                                     sizeof(connection), NULL, &port);
    if (SUCCEEDED(result)) {
        command.Command = AvCmdGetStatus;
        result = FilterSendMessage(port, &command, sizeof(command), &state, sizeof(state), &returned);
        CloseHandle(port);
    }
    if (SUCCEEDED(result) && (returned != sizeof(state) || state.ProtocolVersion != AO_PROTOCOL_VERSION))
        result = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (FAILED(result)) {
        printf("{\"driver_available\":false,\"error\":%lu}\n", (DWORD)result);
        return 2;
    }
    printf("{\"driver_available\":true,\"enforcement\":%lu,\"fail_open_on_unknown\":true,\"pending\":%ld,"
           "\"attempts\":%lld,\"incomplete\":%lld,\"detections\":%lld,\"blocked\":%lld}\n",
           state.Enforcement, state.PendingScans, (long long)state.Attempts, (long long)state.Incomplete,
           (long long)state.Detections, (long long)state.Blocked);
    return 0;
}
/* Diagnostics only: fixed loopback engine, no service installation or file changes. */
static int scan_file(const wchar_t *path, int verified) {
    wchar_t engine_service[81];
    HANDLE file;
    LARGE_INTEGER length;
    unsigned char *data = NULL;
    DWORD got = 0;
    struct ao_outcome result = {AO_UNKNOWN, 0, "", "file unreadable or outside size limit"};
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        if (GetFileSizeEx(file, &length) && length.QuadPart >= 0 && length.QuadPart <= AO_MAX_FILE_BYTES) {
            data = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)length.QuadPart + 1);
            if (data && ReadFile(file, data, (DWORD)length.QuadPart, &got, NULL) && got == length.QuadPart) {
                if (!verified) result = ao_clam_scan(data, got, 3310, AO_SCAN_TIMEOUT_MS, NULL, NULL);
                else if (ao_engine_service_name(engine_service) == ERROR_SUCCESS)
                    result = ao_engine_scan(engine_service, data, got, AO_SCAN_TIMEOUT_MS, NULL, NULL);
                else strcpy_s(result.detail, sizeof(result.detail), "trusted engine configuration unavailable");
            }
        }
        CloseHandle(file);
    }
    if (data) HeapFree(GetProcessHeap(), 0, data);
    /* Name/detail are bounded printable ASCII from the strict engine parser. */
    printf("{\"result\":%d,\"database_current\":%s,\"name\":\"%s\",\"detail\":\"%s\"}\n",
           (int)result.result, result.database_current ? "true" : "false", result.name, result.detail);
    return result.result == AO_CLEAR ? 0 : result.result == AO_THREAT ? 1 : 2;
}
int wmain(int argc, wchar_t **argv) {
    SERVICE_TABLE_ENTRYW table[] = {{AO_SERVICE_NAME, service_main}, {NULL, NULL}};
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (argc == 2 && !wcscmp(argv[1], L"--driver-status")) return driver_status_json();
    if (argc == 2 && !wcscmp(argv[1], L"--status")) return status_json();
    if (argc == 3 && !wcscmp(argv[1], L"--scan-file")) return scan_file(argv[2], 0);
    if (argc == 3 && !wcscmp(argv[1], L"--scan-file-verified")) return scan_file(argv[2], 1);
    if (argc != 1) { fputs("Usage: AntiOS-Service.exe [--status | --driver-status | --scan-file PATH | --scan-file-verified PATH]\n", stderr); return 2; }
    if (!StartServiceCtrlDispatcherW(table)) {
        fprintf(stderr, "SCM dispatcher failed: %lu. Install using the signed lab package instructions.\n", GetLastError());
        return 2;
    }
    return 0;
}
