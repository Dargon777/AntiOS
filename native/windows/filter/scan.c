/*++

Copyright (c) 2011  Microsoft Corporation

Module Name:

    scan.c

Abstract:

    This modules wraps the scanning routines.

Environment:

    Kernel mode

--*/

#include "avscan.h"

static VOID AvRecordWait(_In_ ULONGLONG Elapsed100ns)
{
    LONGLONG observed;
    InterlockedExchangeAdd64(&Globals.TotalWait100ns, (LONGLONG)Elapsed100ns);
    observed = InterlockedCompareExchange64(&Globals.MaxWait100ns, 0, 0);
    while ((LONGLONG)Elapsed100ns > observed) {
        LONGLONG previous = InterlockedCompareExchange64(
            &Globals.MaxWait100ns, (LONGLONG)Elapsed100ns, observed);
        if (previous == observed) break;
        observed = previous;
    }
}

static VOID AvRecordPeakPending(_In_ LONG Pending)
{
    LONG observed = InterlockedCompareExchange(&Globals.PeakPendingScans, 0, 0);
    while (Pending > observed) {
        LONG previous = InterlockedCompareExchange(&Globals.PeakPendingScans, Pending, observed);
        if (previous == observed) break;
        observed = previous;
    }
}

/* Removed the sample's demonstration string matcher. There is no kernel AV engine. */
NTSTATUS
AvScanInKernel(PCFLT_RELATED_OBJECTS FltObjects, UCHAR Major, BOOLEAN Tx, PAV_STREAM_CONTEXT Stream)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Major);
    UNREFERENCED_PARAMETER(Tx);
    UNREFERENCED_PARAMETER(Stream);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
AvScanInUserImpl (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ UCHAR IOMajorFunctionAtScan,
    _In_ BOOLEAN IsInTxWriter,
    _In_ DEVICE_TYPE DeviceType
    )
/*++

Routine Description

    This function is a high level function which
    will do the user-mode data scan.

Arguments

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - related objects for the IO operation.

    IOMajorFunctionAtScan - The major function of the IRP that issues this scan.

    IsInTxWriter - If this file is enlisted in a transacted writer.

    StreamContext - The stream context of this data stream.

Return Value

    Returns the status of this operation.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG scanThreadId = 0;
    ULONG replyLength = sizeof(ULONG);
    PAV_SCAN_CONTEXT scanCtx = NULL;
    AV_SCANNER_NOTIFICATION notification = {0};
    LONGLONG _1ms = 10000;
    LARGE_INTEGER timeout = {0};

    status = AvAllocateScanContext(FltObjects->Instance,
                                   FltObjects->FileObject,
                                   &scanCtx);
    if (!NT_SUCCESS(status)) {

        return status;
    }

    //
    //  Scan context is passed to the user service program.
    //  Initialize it here.
    //

    KeInitializeEvent( &scanCtx->ScanCompleteNotification, NotificationEvent, FALSE );
    scanCtx->IOMajorFunctionAtScan = IOMajorFunctionAtScan;
    scanCtx->IsFileInTxWriter = IsInTxWriter;
    scanCtx->SectionContext = NULL;

    AvAcquireResourceExclusive( &Globals.ScanCtxListLock );
    if (Globals.Unloading) {
        //
        //  If the filter is being unloaded, we failed the scan.
        //
        AvReleaseResource( &Globals.ScanCtxListLock );
        AvReleaseScanContext( scanCtx );

        return STATUS_FLT_DELETING_OBJECT;
    }
    scanCtx->ScanId = (++Globals.ScanIdCounter);
    InsertTailList (&Globals.ScanCtxListHead, &scanCtx->List);
    AvReleaseResource( &Globals.ScanCtxListLock );

    //
    //  Tell the user-scanner to start to scan the file
    //

    notification.Message = AvMsgStartScanning;
    notification.ScanId = scanCtx->ScanId;
    notification.Reason = AvScanOnOpen;

    if (IOMajorFunctionAtScan == IRP_MJ_CLEANUP) {
        notification.Reason = AvScanOnCleanup;
    }

    //
    //  Set the scan timeout for this file based on if it is a local or
    //  network file.  These values can come from the registry.
    //

    if (DeviceType == FILE_DEVICE_NETWORK) {
        timeout.QuadPart = Globals.NetworkScanTimeout;
    } else {
        timeout.QuadPart = Globals.LocalScanTimeout;
    }

    timeout.QuadPart = -(timeout.QuadPart * _1ms);

    status = FltSendMessage( Globals.Filter,
                             &Globals.ScanClientPort,
                             &notification,
                             sizeof(AV_SCANNER_NOTIFICATION),
                             &scanThreadId,
                             &replyLength,
                             &timeout );
    //
    //  If the message is not delievered or time-out, we can make sure that
    //  the scanner thread did not acknowledged this scan task, and thus
    //  we can safely remove it from the list.
    //
    if (!NT_SUCCESS( status ) || status == STATUS_TIMEOUT) {

        if (status == STATUS_TIMEOUT) {
            InterlockedIncrement64(&Globals.DeliveryTimeouts);
        }
        if ((status != STATUS_PORT_DISCONNECTED) &&
            (status != STATUS_TIMEOUT)) {

            AV_DBG_PRINT( AVDBG_TRACE_ERROR,
                    ("[Av]: AvScanInUser: Failed to FltSendMessage.\n, 0x%08x\n",
                    status) );
        }
        goto Cleanup;
    }

    if (replyLength != sizeof(ULONG) || scanThreadId == 0) {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }
    scanCtx->ScanThreadId = scanThreadId;

    //
    //  Wait for an event that the scanner completes or aborts.
    //

    status = FltCancellableWaitForSingleObject( &scanCtx->ScanCompleteNotification,
                                                &timeout,
                                                Data );

    if (!NT_SUCCESS(status) ||
        (status == STATUS_TIMEOUT)) {

        if (status == STATUS_TIMEOUT) {
            InterlockedIncrement64(&Globals.CompletionTimeouts);
        } else if (status == STATUS_CANCELLED) {
            InterlockedIncrement64(&Globals.CancelledOpens);
        }
        //
        //  At this point we came out of the wait with an error. We are in one of the following conditions:
        //
        //  1. This thread is being terminated
        //  2. The IO operation represented by Data was cancelled
        //  3. If we are in user-mode scan mode, the communication to the user mode component timed out
        //  4. If we are in user-mode scan mode, the user-mode component died and the wait timed out.
        //

        NTSTATUS statusAbort = STATUS_SUCCESS;
        //
        //  Notify the user scan thread to abort the scan.
        //
        statusAbort = AvSendAbortToUser(scanCtx->ScanThreadId,
                                        scanCtx->ScanId);
        if (NT_SUCCESS(statusAbort) &&
            (statusAbort != STATUS_TIMEOUT)) {

            LARGE_INTEGER timeoutForAbortComplete = {0};
            timeoutForAbortComplete.QuadPart = - 1000 * (LONGLONG)_1ms;  // 1s
            //
            //  Wait again on completion notification.
            //  The scan thread should close the section very soon because we have already notified
            //  the scan thread to abort the task.
            //
            statusAbort = FltCancellableWaitForSingleObject(
                                              &scanCtx->ScanCompleteNotification,
                                              &timeoutForAbortComplete,
                                              NULL );
        }
        //
        //  If send abortion failed or wait failed, which general means the service is dead,
        //  we have to close section context/handle here by ourself.
        //
        if (!NT_SUCCESS(statusAbort) ||
            (statusAbort == STATUS_TIMEOUT)) {

            scanCtx->IoWaitOnScanCompleteNotificationAborted = TRUE;
            //
            // If this thread who the race, it will close the section.
            //
            AvFinalizeScanAndSection(scanCtx);
        }
    }

    //
    //  If the wait for scan to complete is cancelled (e.g. by CancelSynchronousIo )
    //
    if (!NT_SUCCESS(status) &&
        (IOMajorFunctionAtScan == IRP_MJ_CREATE)) {

        AvCancelFileOpen(Data, FltObjects, status);
    }

Cleanup:

    //
    //  Here scanCtx must be non-NULL because we checked it in the beginning.
    //

    AvAcquireResourceExclusive( &Globals.ScanCtxListLock );
    RemoveEntryList (&scanCtx->List);
    AvReleaseResource( &Globals.ScanCtxListLock );

    AvReleaseScanContext( scanCtx );

    return status;
}


NTSTATUS
AvCloseSectionForDataScan(
    _Inout_ PAV_SECTION_CONTEXT SectionContext
    )
/*++

Routine Description

    A wrapper function that wraps FltCloseSectionForDataScan and performs appropriate cleanup.

Arguments

    SectionContext - The seciton handle and object will be cleaned up in sectino context.

Return Value

    Returns the status of this operation.

--*/
{
    //
    //  Synchronized with AvScanAbortCallbackAsync(...)
    //
    InterlockedExchangePointer( &SectionContext->ScanContext, NULL );
    ObDereferenceObject( SectionContext->SectionObject );

    SectionContext->SectionHandle = NULL;
    SectionContext->SectionObject = NULL;
    return FltCloseSectionForDataScan( (PFLT_CONTEXT)SectionContext );
}


/* Bound outstanding requests and their kernel contexts even under an execution storm. */
NTSTATUS
AvScanInUser(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects, UCHAR Major,
             BOOLEAN Tx, DEVICE_TYPE DeviceType)
{
    NTSTATUS status;
    LONG pending;
    ULONGLONG started = KeQueryInterruptTime();

    InterlockedIncrement64(&Globals.Attempts);
    pending = InterlockedIncrement(&Globals.PendingScans);
    if ((ULONG)pending > Globals.MaxPendingScans) {
        /* Coexistence is intentionally fail-open on overload. A second AV can
           briefly own file resources; queueing unbounded execute opens would
           create a system-wide launch stall without improving verdict quality. */
        InterlockedIncrement64(&Globals.Incomplete);
        InterlockedIncrement64(&Globals.BusyBypass);
        InterlockedDecrement(&Globals.PendingScans);
        AvRecordWait(KeQueryInterruptTime() - started);
        return STATUS_DEVICE_BUSY;
    }
    AvRecordPeakPending(pending);

    status = AvScanInUserImpl(Data, Objects, Major, Tx, DeviceType);
    if (status != STATUS_SUCCESS) InterlockedIncrement64(&Globals.Incomplete);
    InterlockedDecrement(&Globals.PendingScans);
    AvRecordWait(KeQueryInterruptTime() - started);
    return status;
}
