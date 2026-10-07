from pathlib import Path


def test_native_coexistence_protocol_contract():
    avlib = Path("native/windows/inc/avlib.h").read_text(encoding="utf-8")
    assert "#define AO_PROTOCOL_VERSION 2u" in avlib
    assert "#define AO_BROKER_WORKERS 4u" in avlib
    for field in (
        "CoexistenceMode", "LocalScanTimeoutMs", "MaxPendingScans",
        "PeakPendingScans", "SectionConflicts", "BusyBypass", "DeliveryTimeouts",
        "CompletionTimeouts", "CancelledOpens", "TotalWait100ns", "MaxWait100ns",
    ):
        assert field in avlib
    assert "C_ASSERT(sizeof(AO_DRIVER_STATUS) == 112);" in avlib


def test_native_coexistence_defaults_are_bounded_and_non_takeover():
    inf = Path("native/windows/AntiOS-Filter.inf.in").read_text(encoding="utf-8")
    assert '"Enforcement",0x00010001,0' in inf
    assert '"CoexistenceMode",0x00010001,1' in inf
    assert '"MaxPendingScans",0x00010001,4' in inf
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


def test_driver_inf_altitude_range_matches_antivirus_group():
    script = Path("native/windows/New-DriverInf.ps1").read_text(encoding="utf-8")
    assert "[decimal]320000" in script
    assert "[decimal]329999" in script
    assert "-gt [decimal]329999" in script
    assert "320000 <= altitude <= 329999" in script


def test_native_admission_never_transiently_exceeds_limit():
    scan = Path("native/windows/filter/scan.c").read_text(encoding="utf-8")
    assert "static BOOLEAN AvTryAcquireScanSlot" in scan
    assert "InterlockedCompareExchange(&Globals.PendingScans, current + 1, current)" in scan
    admission = scan[scan.index("NTSTATUS\nAvScanInUser("):]
    assert "InterlockedIncrement(&Globals.PendingScans)" not in admission
