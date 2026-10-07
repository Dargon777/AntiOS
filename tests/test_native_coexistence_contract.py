from pathlib import Path


def test_native_coexistence_protocol_contract():
    avlib = Path("native/windows/inc/avlib.h").read_text(encoding="utf-8")
    assert "#define AO_PROTOCOL_VERSION 4u" in avlib
    assert "#define AO_BROKER_WORKERS 4u" in avlib
    for field in (
        "CoexistenceMode", "LocalScanTimeoutMs", "CleanCacheTtlMs", "MaxPendingScans",
        "PeakPendingScans", "SectionConflicts", "BusyBypass", "DeliveryTimeouts",
        "CompletionTimeouts", "CancelledOpens", "CleanCacheHits", "CleanCacheExpired",
        "CleanCacheInvalidations", "TotalWait100ns", "MaxWait100ns",
    ):
        assert field in avlib
    assert "C_ASSERT(sizeof(AO_DRIVER_STATUS) == 160);" in avlib


def test_native_coexistence_defaults_are_bounded_and_non_takeover():
    inf = Path("native/windows/AntiOS-Filter.inf.in").read_text(encoding="utf-8")
    assert '"Enforcement",0x00010001,0' in inf
    assert '"CoexistenceMode",0x00010001,1' in inf
    assert '"MaxPendingScans",0x00010001,4' in inf
    assert '"CleanCacheTtlMs",0x00010001,30000' in inf
    assert 'LoadOrderGroup="FSFilter Anti-Virus"' in inf

    service = Path("native/windows/service/main.c").read_text(encoding="utf-8")
    assert "independent-companion" in service
    assert "defender_configuration_changed" in service
    assert "fail_open_on_incomplete" in service
    assert "section_conflicts" in service


def test_native_coexistence_harness_requires_defender_to_remain_active():
    script = Path("native/windows/Test-NativeCoexistence.ps1").read_text(encoding="utf-8")
    assert "Get-MpComputerStatus" in script
    assert "RealTimeProtectionEnabled" in script
    assert "defenderAfter" in script
    assert "WdFilter" in script
    assert "CoexistenceMode must be enabled" in script
    assert "Get-MpPreference" in script
    assert "ExclusionPath" in script
    assert "ExclusionProcess" in script
    assert "root/SecurityCenter2" in script
    assert "AntiVirusProduct" in script
    assert "Set-MpPreference" not in script
    assert "Add-MpPreference" not in script
    assert "Remove-MpPreference" not in script


def test_native_admission_matches_broker_capacity():
    avlib = Path("native/windows/inc/avlib.h").read_text(encoding="utf-8")
    broker = Path("native/windows/service/userscan.c").read_text(encoding="utf-8")
    driver = Path("native/windows/filter/avscan.c").read_text(encoding="utf-8")
    installer = Path("native/windows/Install-NativeService.ps1").read_text(encoding="utf-8")
    harness = Path("native/windows/Test-NativeCoexistence.ps1").read_text(encoding="utf-8")
    assert "#define AO_BROKER_WORKERS 4u" in avlib
    assert "#define WORKERS AO_BROKER_WORKERS" in broker
    assert "<= AO_BROKER_WORKERS" in driver
    assert "four native broker workers" in installer
    assert "four-worker native broker capacity" in harness


def test_altitude_generator_rejects_out_of_group_values():
    script = Path("native/windows/New-DriverInf.ps1").read_text(encoding="utf-8")
    assert "320000 <= altitude < 329999" in script
    assert "$altitudeValue -lt [decimal]320000" in script
    assert "$altitudeValue -ge [decimal]329999" in script


def test_native_admission_never_transiently_exceeds_limit():
    scan = Path("native/windows/filter/scan.c").read_text(encoding="utf-8")
    assert "static BOOLEAN AvTryAcquireScanSlot" in scan
    assert "InterlockedCompareExchange(&Globals.PendingScans, current + 1, current)" in scan
    admission = scan[scan.index("NTSTATUS\nAvScanInUser("):]
    assert "InterlockedIncrement(&Globals.PendingScans)" not in admission



def test_clean_cache_is_bounded_and_invalidated_by_writes():
    context = Path("native/windows/filter/context.h").read_text(encoding="utf-8")
    communication = Path("native/windows/filter/communication.c").read_text(encoding="utf-8")
    driver = Path("native/windows/filter/avscan.c").read_text(encoding="utf-8")
    installer = Path("native/windows/Install-NativeService.ps1").read_text(encoding="utf-8")
    assert "CleanValidUntil100ns" in context
    assert "TxCleanValidUntil100ns" in context
    assert "AvFileNotInfected, AvFileScanning" in communication
    assert "AvFileModified, AvFileScanning" not in communication[communication.index("case AvScanResultClean:"):communication.index("default:", communication.index("case AvScanResultClean:"))]
    assert "static BOOLEAN\nAvFileNeedsScan" in driver
    assert "Globals.CleanCacheTtlMs = 30000" in driver
    assert "*(PULONG)value->Data <= 300000" in driver
    assert "CleanCacheInvalidations" in driver
    assert "CleanCacheTtlMs must stay between 0 and 300000 milliseconds." in installer



def test_broker_clean_cache_is_fixed_bounded_and_clean_only():
    broker = Path("native/windows/service/userscan.c").read_text(encoding="utf-8")
    build = Path("native/windows/build.ps1").read_text(encoding="utf-8")
    wire = Path("native/windows/inc/avlib.h").read_text(encoding="utf-8")
    communication = Path("native/windows/filter/communication.c").read_text(encoding="utf-8")
    assert "#define CLEAN_CACHE_ENTRIES 128u" in broker
    assert "BCryptHashData" in broker
    assert "BCryptFinishHash" in broker
    assert "outcome.result == AO_CLEAR && outcome.database_current" in broker
    assert "clean_cache_store(broker, digest, size)" in broker
    assert "AO_SCAN_FLAG_CLEAN_CACHE_HIT" in broker
    assert "bcrypt.lib" in build
    assert "#define AO_SCAN_FLAG_CLEAN_CACHE_HIT 0x00000001u" in wire
    assert "(command.ResultFlags & ~AO_SCAN_FLAG_CLEAN_CACHE_HIT) != 0" in communication
    assert "command.ResultFlags != 0 && command.ScanResult != AvScanResultClean" in communication



def test_legacy_file_id_cache_does_not_store_clean_verdicts():
    driver = Path("native/windows/filter/avscan.c").read_text(encoding="utf-8")
    cleanup_start = driver.rindex("FLT_PREOP_CALLBACK_STATUS\nAvPreCleanup")
    cleanup_end = driver.rindex("NTSTATUS\nAvKtmNotificationCallback")
    cleanup = driver[cleanup_start:cleanup_end]
    assert "if (IS_FILE_INFECTED( streamContext ))" in cleanup
    assert "clean file in the legacy" not in cleanup
    load_start = driver.rindex("NTSTATUS\nAvLoadFileStateFromCache")
    load_end = driver.rindex("NTSTATUS\nAvSyncCache")
    load = driver[load_start:load_end]
    assert "entry->InfectedState == AvFileNotInfected" in load
    assert "AvFileModified : entry->InfectedState" in load



def test_database_generation_invalidates_kernel_and_broker_cache():
    wire = Path("native/windows/inc/avlib.h").read_text(encoding="utf-8")
    context = Path("native/windows/filter/context.h").read_text(encoding="utf-8")
    communication = Path("native/windows/filter/communication.c").read_text(encoding="utf-8")
    driver = Path("native/windows/filter/avscan.c").read_text(encoding="utf-8")
    broker = Path("native/windows/service/userscan.c").read_text(encoding="utf-8")
    engine = Path("native/windows/engine/engine.h").read_text(encoding="utf-8")
    assert "AvCmdSetDatabaseGeneration" in wire
    assert "ULONGLONG DatabaseGeneration" in wire
    assert "DatabaseGenerationChanges" in wire
    assert "CleanDatabaseGeneration" in context
    assert "TxCleanDatabaseGeneration" in context
    assert "command.Command == AvCmdSetDatabaseGeneration" in communication
    assert "DatabaseGeneration == 0 || (LONGLONG)DatabaseGeneration != activeGeneration" in communication
    assert "verdictGeneration != activeGeneration" in driver
    assert "#define GENERATION_POLL_MS 2000u" in broker
    assert "ao_engine_generation(" in broker
    assert "clear_clean_cache(broker)" in broker
    assert "entry->database_generation == database_generation" in broker
    assert "uint64_t database_generation;" in engine
