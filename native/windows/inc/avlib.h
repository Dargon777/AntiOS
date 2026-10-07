/*++

Copyright (c) 2011  Microsoft Corporation

Module Name:

    avlib.h

Abstract:

    This header file defines the common data structure used by kernel and user.

Environment:

    User mode
    Kernel mode

--*/

#ifndef __AVLIB_H__
#define __AVLIB_H__

#if defined(_MSC_VER)
#if (_MSC_VER >= 1200)
#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used : nameless struct/union
#endif
#endif

//
//  Name of AV filter server ports
//

#define AV_SCAN_PORT_NAME                    L"\\AntiOSAccessV1ScanPort"
#define AV_ABORT_PORT_NAME                   L"\\AntiOSAccessV1AbortPort"
#define AV_QUERY_PORT_NAME                   L"\\AntiOSAccessV1QueryPort"


//
//  Definition of invalide section handle for data scan
//

#define AV_INVALID_SECTION_HANDLE   ((HANDLE)((LONG_PTR)(-1)))


//
//  Command type enumeration, please see COMMAND_MESSAGE below
//

typedef enum _AVSCAN_COMMAND {

    AvIsFileModified,
    AvCmdCreateSectionForDataScan,
    AvCmdCloseSectionForDataScan,
    AvCmdGetStatus,
    AvCmdSetDatabaseGeneration

} AVSCAN_COMMAND;

//
//  Message type enumeration, please see AV_SCANNER_NOTIFICATION below
//

typedef enum _AVSCAN_MESSAGE {

    AvMsgStartScanning,
    AvMsgAbortScanning,
    AvMsgFilterUnloading

} AVSCAN_MESSAGE;

typedef enum _AVSCAN_REASON {
    AvScanOnOpen,
    AvScanOnCleanup

} AVSCAN_REASON;

typedef enum _AVSCAN_RESULT {

    AvScanResultUndetermined,
    AvScanResultInfected,
    AvScanResultClean

} AVSCAN_RESULT;

//
//  Defines the commands between the user program and the filter
//  Command: User -> Kernel
//

typedef struct _COMMAND_MESSAGE {

    //
    //  Command type
    //

    AVSCAN_COMMAND      Command;

    //
    //  Scan identifier.
    //  This argument will be checked in message notificaiton callback.
    //

    LONGLONG  ScanId;

    //
    //  Scan thread id. This id will be used in cancel message passing.
    //  So that we will know which scan thread to cancel.
    //

    ULONG  ScanThreadId;

    // Result metadata from the trusted broker. Must be zero for non-close commands.
    ULONG  ResultFlags;

    union {

        //
        //  When user program is connecting for query (AvConnectForQuery)
        //  it has to pass the file handle to query the status of the file.
        //  Valid when Command == AvIsFileModified
        //

        HANDLE FileHandle;

        //
        //  The result result.
        //  Valid when Command == AvCmdCloseSectionForDataScan
        //
        AVSCAN_RESULT ScanResult;
    };

    // Signature database generation used for this verdict, or the new global
    // generation for AvCmdSetDatabaseGeneration. Zero means unknown.
    ULONGLONG DatabaseGeneration;

} COMMAND_MESSAGE, *PCOMMAND_MESSAGE;

//
//  Message: Kernel -> User Message
//

typedef struct _SCANNER_NOTIFICATION {

    //
    //  Message type
    //

    AVSCAN_MESSAGE Message;

    //
    //  Reason
    //

    AVSCAN_REASON  Reason;

    //
    //  Scan identifier.
    //  This argument will be checked in message notificaiton callback.
    //

    LONGLONG  ScanId;

    //
    //  Scan thread id. This id will be used in cancel message passing.
    //  So that we will know which scan thread to cancel.
    //

    ULONG  ScanThreadId;

} AV_SCANNER_NOTIFICATION, *PAV_SCANNER_NOTIFICATION;

//
//  Connection type enumeration. It would be mainly used in connection context.
//

typedef enum _AVSCAN_CONNECTION_TYPE {

    AvConnectForScan = 1,
    AvConnectForAbort,
    AvConnectForQuery

} AVSCAN_CONNECTION_TYPE, *PAVSCAN_CONNECTION_TYPE;

//
//  Connection context. It will be passed through FilterConnectCommunicationPort(...)
//

typedef struct _AV_CONNECTION_CONTEXT {

    AVSCAN_CONNECTION_TYPE   Type;
    ULONG ProtocolVersion;

} AV_CONNECTION_CONTEXT, *PAV_CONNECTION_CONTEXT;

/* Native wire version; x64 only in this experimental module. */
typedef struct _AO_DRIVER_STATUS {
    ULONG ProtocolVersion;
    ULONG Enforcement;
    ULONG CoexistenceMode;
    ULONG LocalScanTimeoutMs;
    ULONG CleanCacheTtlMs;
    ULONG MaxPendingScans;
    LONG PendingScans;
    LONG PeakPendingScans;
    ULONG SectionConflicts;
    LONGLONG Attempts;
    LONGLONG Incomplete;
    LONGLONG Detections;
    LONGLONG Blocked;
    LONGLONG BusyBypass;
    LONGLONG DeliveryTimeouts;
    LONGLONG CompletionTimeouts;
    LONGLONG CancelledOpens;
    LONGLONG CleanCacheHits;
    LONGLONG CleanCacheExpired;
    LONGLONG CleanCacheInvalidations;
    LONGLONG DatabaseGeneration;
    LONGLONG DatabaseGenerationChanges;
    LONGLONG TotalWait100ns;
    LONGLONG MaxWait100ns;
} AO_DRIVER_STATUS;

#define AO_PROTOCOL_VERSION 4u
#define AO_BROKER_WORKERS 4u
#define AO_SCAN_FLAG_CLEAN_CACHE_HIT 0x00000001u
#define AO_MAX_SECTION_BYTES (32u * 1024u * 1024u)
typedef struct _AO_SECTION_REPLY {
    HANDLE SectionHandle;
    LONGLONG FileSize;
} AO_SECTION_REPLY;

/* Wire format is deliberately x64-only; mismatched packing must fail the build. */
C_ASSERT(sizeof(void *) == 8);
C_ASSERT(sizeof(AV_CONNECTION_CONTEXT) == 8);
C_ASSERT(sizeof(COMMAND_MESSAGE) == 40);
C_ASSERT(sizeof(AV_SCANNER_NOTIFICATION) == 24);
C_ASSERT(sizeof(AO_SECTION_REPLY) == 16);
C_ASSERT(sizeof(AO_DRIVER_STATUS) == 160);

#if defined(_MSC_VER)
#if (_MSC_VER >= 1200)
#pragma warning(pop)
#endif
#endif

#endif
