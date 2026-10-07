/* Transport rebuilt around per-worker overlapped receives and explicit ownership.
 * Wire protocol/section lifecycle derived from Microsoft AvScan (MS-PL).
 * Copyright (c) 2011 Microsoft Corporation. AntiOS modifications: 2026.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <fltuser.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "userscan.h"
#include "engine_peer.h"
#include "../inc/avlib.h"
#include "../engine/engine.h"

#define WORKERS AO_BROKER_WORKERS
#define CLEAN_CACHE_ENTRIES 128u

struct clean_cache_entry {
    unsigned char digest[32];
    ULONGLONG expires_ms;
    SIZE_T size;
};

struct broker;
struct worker {
    struct broker *broker;
    HANDLE thread;
    DWORD thread_id;
    CRITICAL_SECTION lock;
    LONGLONG scan_id;
    volatile LONG aborted;
};
struct broker {
    HANDLE stop, scan_port, abort_port, abort_thread;
    struct worker workers[WORKERS];
    volatile LONG failure;
    volatile LONG gap_logged;
    ao_log_fn log;
    wchar_t engine_service[81];

    SRWLOCK cache_lock;
    struct clean_cache_entry clean_cache[CLEAN_CACHE_ENTRIES];
    ULONG cache_cursor;
    ULONG clean_cache_ttl_ms;
    BCRYPT_ALG_HANDLE sha256;
    DWORD sha256_object_bytes;
};
struct message { FILTER_MESSAGE_HEADER header; AV_SCANNER_NOTIFICATION notification; };
struct reply { FILTER_REPLY_HEADER header; ULONG thread_id; };

static ULONG read_clean_cache_ttl(void) {
    DWORD ttl = 30000, bytes = sizeof(ttl);
    LONG error = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\AntiOS-Filter\\Parameters",
        L"CleanCacheTtlMs",
        RRF_RT_REG_DWORD | RRF_ZEROONFAILURE,
        NULL, &ttl, &bytes);
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return 30000;
    if (error != ERROR_SUCCESS || bytes != sizeof(ttl) || ttl > 300000) return 0;
    return ttl;
}

static int hash_snapshot(struct broker *broker, const unsigned char *data, SIZE_T size,
                         unsigned char digest[32]) {
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR object = NULL;
    NTSTATUS status;
    if (!broker->sha256 || !broker->sha256_object_bytes || size > AO_MAX_FILE_BYTES) return 0;
    object = HeapAlloc(GetProcessHeap(), 0, broker->sha256_object_bytes);
    if (!object) return 0;
    status = BCryptCreateHash(broker->sha256, &hash, object, broker->sha256_object_bytes,
                              NULL, 0, 0);
    if (status == 0)
        status = BCryptHashData(hash, (PUCHAR)data, (ULONG)size, 0);
    if (status == 0)
        status = BCryptFinishHash(hash, digest, 32, 0);
    if (hash) BCryptDestroyHash(hash);
    SecureZeroMemory(object, broker->sha256_object_bytes);
    HeapFree(GetProcessHeap(), 0, object);
    return status == 0;
}

static int clean_cache_lookup(struct broker *broker, const unsigned char digest[32], SIZE_T size) {
    ULONGLONG now;
    unsigned i;
    int found = 0;
    if (!broker->clean_cache_ttl_ms) return 0;
    now = GetTickCount64();
    AcquireSRWLockExclusive(&broker->cache_lock);
    for (i = 0; i < CLEAN_CACHE_ENTRIES; ++i) {
        struct clean_cache_entry *entry = &broker->clean_cache[i];
        if (entry->expires_ms && entry->expires_ms <= now) {
            SecureZeroMemory(entry, sizeof(*entry));
            continue;
        }
        if (entry->expires_ms && entry->size == size &&
            memcmp(entry->digest, digest, sizeof(entry->digest)) == 0) {
            found = 1;
            break;
        }
    }
    ReleaseSRWLockExclusive(&broker->cache_lock);
    return found;
}

static void clean_cache_store(struct broker *broker, const unsigned char digest[32], SIZE_T size) {
    struct clean_cache_entry *entry;
    ULONG slot;
    if (!broker->clean_cache_ttl_ms) return;
    AcquireSRWLockExclusive(&broker->cache_lock);
    slot = broker->cache_cursor++ % CLEAN_CACHE_ENTRIES;
    entry = &broker->clean_cache[slot];
    CopyMemory(entry->digest, digest, sizeof(entry->digest));
    entry->size = size;
    entry->expires_ms = GetTickCount64() + broker->clean_cache_ttl_ms;
    ReleaseSRWLockExclusive(&broker->cache_lock);
}

static void fail(struct broker *broker, HRESULT result) {
    InterlockedCompareExchange(&broker->failure, (LONG)result, 0);
    SetEvent(broker->stop);
}
static int cancelled(void *context) {
    struct worker *worker = context;
    return WaitForSingleObject(worker->broker->stop, 0) == WAIT_OBJECT_0 ||
           InterlockedCompareExchange(&worker->aborted, 0, 0) != 0;
}
/* A pending receive never outlives its OVERLAPPED, event or message buffer. */
static HRESULT receive(HANDLE port, HANDLE stop, struct message *message) {
    OVERLAPPED operation = {0};
    HANDLE waits[2];
    DWORD bytes = 0, waited, error;
    HRESULT result;
    operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!operation.hEvent) return HRESULT_FROM_WIN32(GetLastError());
    ZeroMemory(message, sizeof(*message));
    result = FilterGetMessage(port, &message->header, sizeof(*message), &operation);
    if (result == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
        waits[0] = stop; waits[1] = operation.hEvent;
        waited = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (waited != WAIT_OBJECT_0 + 1) {
            error = waited == WAIT_FAILED ? GetLastError() : ERROR_OPERATION_ABORTED;
            CancelIoEx(port, &operation);
            /* Even on ERROR_NOT_FOUND, completion may be racing cancellation. */
            GetOverlappedResult(port, &operation, &bytes, TRUE);
            result = HRESULT_FROM_WIN32(error);
        } else if (!GetOverlappedResult(port, &operation, &bytes, FALSE)) {
            result = HRESULT_FROM_WIN32(GetLastError());
        } else {
            result = bytes == sizeof(*message) ? S_OK : HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
    } else if (SUCCEEDED(result)) {
        if (!GetOverlappedResult(port, &operation, &bytes, FALSE))
            result = HRESULT_FROM_WIN32(GetLastError());
        else if (bytes != sizeof(*message)) result = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }
    CloseHandle(operation.hEvent);
    return result;
}
static HRESULT acknowledge(HANDLE port, const struct message *message, DWORD thread_id) {
    struct reply reply = {0};
    /* Abort notifications have no reply; unload/start carry one ULONG. */
    if (!message->header.ReplyLength) return S_OK;
    if (message->header.ReplyLength != sizeof(FILTER_REPLY_HEADER) + sizeof(ULONG))
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    reply.header.MessageId = message->header.MessageId;
    reply.thread_id = thread_id;
    return FilterReplyMessage(port, &reply.header,
                             (DWORD)(offsetof(struct reply, thread_id) + sizeof(reply.thread_id)));
}
static void scan_section(struct worker *worker) {
    struct broker *broker = worker->broker;
    COMMAND_MESSAGE command = {0};
    AO_SECTION_REPLY section = {0};
    struct ao_outcome outcome = {AO_UNKNOWN, 0, "", "section unavailable"};
    unsigned char *snapshot = NULL, *view = NULL;
    unsigned char digest[32] = {0};
    DWORD returned = 0;
    size_t offset, size = 0;
    int digest_valid = 0, cache_hit = 0;
    HRESULT result;
    ULONGLONG deadline = GetTickCount64() + AO_SCAN_TIMEOUT_MS;
    command.Command = AvCmdCreateSectionForDataScan;
    command.ScanId = worker->scan_id;
    command.ScanThreadId = worker->thread_id;
    result = FilterSendMessage(broker->scan_port, &command, sizeof(command),
                              &section, sizeof(section), &returned);
    if (FAILED(result)) goto finish;
    if (returned != sizeof(section) || !section.SectionHandle ||
        section.SectionHandle == INVALID_HANDLE_VALUE || section.FileSize <= 0 ||
        section.FileSize > AO_MAX_FILE_BYTES || cancelled(worker)) goto cleanup;
    size = (size_t)section.FileSize;
    view = MapViewOfFile(section.SectionHandle, FILE_MAP_READ, 0, 0, size);
    snapshot = HeapAlloc(GetProcessHeap(), 0, size);
    if (!view || !snapshot) goto cleanup;
    /* ReadProcessMemory reports inaccessible/truncated pages instead of an SEH crash.
       A separate snapshot avoids submitting padding past EOF or mutable mapped bytes. */
    for (offset = 0; offset < size;) {
        SIZE_T copied = 0, amount = size - offset > 65536 ? 65536 : size - offset;
        if (cancelled(worker) || GetTickCount64() >= deadline ||
            !ReadProcessMemory(GetCurrentProcess(), view + offset, snapshot + offset, amount, &copied) ||
            copied != amount) goto cleanup;
        offset += amount;
    }
    if (!cancelled(worker) && GetTickCount64() < deadline) {
        digest_valid = hash_snapshot(broker, snapshot, size, digest);
        if (digest_valid && clean_cache_lookup(broker, digest, size)) {
            outcome.result = AO_CLEAR;
            outcome.database_current = 1;
            strcpy_s(outcome.detail, sizeof(outcome.detail), "bounded SHA-256 clean cache");
            cache_hit = 1;
        } else {
            unsigned remaining = (unsigned)(deadline - GetTickCount64());
            if (remaining && remaining <= AO_SCAN_TIMEOUT_MS)
                outcome = ao_engine_scan(broker->engine_service, snapshot, size, remaining, cancelled, worker);
        }
    }
cleanup:
    if (snapshot) HeapFree(GetProcessHeap(), 0, snapshot);
    if (view) UnmapViewOfFile(view);
    if (section.SectionHandle && section.SectionHandle != INVALID_HANDLE_VALUE) CloseHandle(section.SectionHandle);
finish:
    if (cancelled(worker)) {
        outcome.result = AO_UNKNOWN;
        cache_hit = 0;
    }
    if (outcome.result == AO_CLEAR && outcome.database_current && digest_valid && !cache_hit) {
        clean_cache_store(broker, digest, size);
    }
    command.Command = AvCmdCloseSectionForDataScan;
    command.ResultFlags = cache_hit ? AO_SCAN_FLAG_CLEAN_CACHE_HIT : 0;
    command.ScanResult = outcome.result == AO_THREAT ? AvScanResultInfected :
                        outcome.result == AO_CLEAR ? AvScanResultClean : AvScanResultUndetermined;
    /* Also complete failed section requests; kernel may already have cancelled them. */
    FilterSendMessage(broker->scan_port, &command, sizeof(command), NULL, 0, &returned);
    if (outcome.result == AO_THREAT) {
        wchar_t event[384];
        _snwprintf(event, 383, L"Confirmed detection; scan_id=%lld; signature=%hs. Blocking depends on driver Enforcement policy.",
                   (long long)command.ScanId, outcome.name);
        event[383] = 0;
        broker->log(EVENTLOG_WARNING_TYPE, event);
    } else if (outcome.result != AO_CLEAR && !InterlockedExchange(&broker->gap_logged, 1)) {
        broker->log(EVENTLOG_WARNING_TYPE, L"Native coverage incomplete: engine, database freshness, section or scan limit. Unknown results are allowed, not marked clean. Further gaps suppressed until recovery.");
    } else if (outcome.result == AO_CLEAR && InterlockedExchange(&broker->gap_logged, 0)) {
        broker->log(EVENTLOG_INFORMATION_TYPE, L"Native scanner recovered; current database and successful scan.");
    }
}
static DWORD WINAPI scan_worker(void *context) {
    struct worker *worker = context;
    struct broker *broker = worker->broker;
    struct message message;
    HRESULT result;
    worker->thread_id = GetCurrentThreadId();
    while (WaitForSingleObject(broker->stop, 0) != WAIT_OBJECT_0) {
        result = receive(broker->scan_port, broker->stop, &message);
        if (FAILED(result)) { if (WaitForSingleObject(broker->stop, 0) != WAIT_OBJECT_0) fail(broker, result); break; }
        if (message.notification.Message != AvMsgStartScanning || message.notification.ScanId <= 0) {
            fail(broker, HRESULT_FROM_WIN32(ERROR_INVALID_DATA)); break;
        }
        EnterCriticalSection(&worker->lock);
        worker->scan_id = message.notification.ScanId;
        InterlockedExchange(&worker->aborted, 0);
        LeaveCriticalSection(&worker->lock);
        result = acknowledge(broker->scan_port, &message, worker->thread_id);
        if (SUCCEEDED(result)) scan_section(worker);
        EnterCriticalSection(&worker->lock);
        worker->scan_id = 0;
        LeaveCriticalSection(&worker->lock);
        /* A timed-out request is not a dead service; keep serving subsequent opens. */
        if (FAILED(result) && result != ERROR_FLT_NO_WAITER_FOR_REPLY) {
            fail(broker, result); break;
        }
    }
    return 0;
}
static DWORD WINAPI abort_worker(void *context) {
    struct broker *broker = context;
    struct message message;
    HRESULT result;
    unsigned i;
    while (WaitForSingleObject(broker->stop, 0) != WAIT_OBJECT_0) {
        result = receive(broker->abort_port, broker->stop, &message);
        if (FAILED(result)) {
            if (WaitForSingleObject(broker->stop, 0) != WAIT_OBJECT_0) fail(broker, result);
            break;
        }
        if (message.notification.Message == AvMsgFilterUnloading) {
            acknowledge(broker->abort_port, &message, GetCurrentThreadId());
            fail(broker, HRESULT_FROM_WIN32(ERROR_DEVICE_NOT_CONNECTED)); break;
        }
        if (message.notification.Message != AvMsgAbortScanning) {
            fail(broker, HRESULT_FROM_WIN32(ERROR_INVALID_DATA)); break;
        }
        for (i = 0; i < WORKERS; ++i) {
            struct worker *worker = &broker->workers[i];
            EnterCriticalSection(&worker->lock);
            if (worker->scan_id == message.notification.ScanId && worker->thread_id == message.notification.ScanThreadId)
                InterlockedExchange(&worker->aborted, 1);
            LeaveCriticalSection(&worker->lock);
        }
    }
    return 0;
}
DWORD ao_broker_run(HANDLE stop, HANDLE ready, ao_log_fn log) {
    struct broker broker = {0};
    AV_CONNECTION_CONTEXT connection = {AvConnectForScan, AO_PROTOCOL_VERSION};
    HRESULT result;
    unsigned i;
    DWORD config_error = ao_engine_service_name(broker.engine_service);
    DWORD property_bytes = 0;
    NTSTATUS crypto_status;
    if (config_error) return config_error;
    broker.stop = stop; broker.log = log;
    InitializeSRWLock(&broker.cache_lock);
    broker.clean_cache_ttl_ms = read_clean_cache_ttl();
    crypto_status = BCryptOpenAlgorithmProvider(&broker.sha256, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (crypto_status == 0) {
        crypto_status = BCryptGetProperty(
            broker.sha256, BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&broker.sha256_object_bytes, sizeof(broker.sha256_object_bytes),
            &property_bytes, 0);
    }
    if (crypto_status != 0 || property_bytes != sizeof(broker.sha256_object_bytes) ||
        broker.sha256_object_bytes == 0 || broker.sha256_object_bytes > 65536) {
        if (broker.sha256) BCryptCloseAlgorithmProvider(broker.sha256, 0);
        broker.sha256 = NULL;
        broker.sha256_object_bytes = 0;
        broker.clean_cache_ttl_ms = 0;
    }
    for (i = 0; i < WORKERS; ++i) {
        broker.workers[i].broker = &broker;
        InitializeCriticalSection(&broker.workers[i].lock);
    }
    result = FilterConnectCommunicationPort(AV_SCAN_PORT_NAME, 0, &connection, sizeof(connection), NULL, &broker.scan_port);
    if (FAILED(result)) { fail(&broker, result); goto done; }
    connection.Type = AvConnectForAbort;
    result = FilterConnectCommunicationPort(AV_ABORT_PORT_NAME, 0, &connection, sizeof(connection), NULL, &broker.abort_port);
    if (FAILED(result)) { fail(&broker, result); goto done; }
    broker.abort_thread = CreateThread(NULL, 0, abort_worker, &broker, 0, NULL);
    if (!broker.abort_thread) { fail(&broker, HRESULT_FROM_WIN32(GetLastError())); goto done; }
    for (i = 0; i < WORKERS; ++i) {
        broker.workers[i].thread = CreateThread(NULL, 0, scan_worker, &broker.workers[i], 0, NULL);
        if (!broker.workers[i].thread) { fail(&broker, HRESULT_FROM_WIN32(GetLastError())); goto done; }
    }
    SetEvent(ready);
    WaitForSingleObject(stop, INFINITE);
done:
    SetEvent(stop);
    /* Do not free worker state or close ports until outstanding I/O has drained. */
    for (i = 0; i < WORKERS; ++i) {
        if (broker.workers[i].thread) {
            WaitForSingleObject(broker.workers[i].thread, INFINITE);
            CloseHandle(broker.workers[i].thread);
        }
    }
    if (broker.abort_thread) { WaitForSingleObject(broker.abort_thread, INFINITE); CloseHandle(broker.abort_thread); }
    if (broker.scan_port && broker.scan_port != INVALID_HANDLE_VALUE) CloseHandle(broker.scan_port);
    if (broker.abort_port && broker.abort_port != INVALID_HANDLE_VALUE) CloseHandle(broker.abort_port);
    if (broker.sha256) BCryptCloseAlgorithmProvider(broker.sha256, 0);
    SecureZeroMemory(broker.clean_cache, sizeof(broker.clean_cache));
    for (i = 0; i < WORKERS; ++i) DeleteCriticalSection(&broker.workers[i].lock);
    return (DWORD)broker.failure;
}
