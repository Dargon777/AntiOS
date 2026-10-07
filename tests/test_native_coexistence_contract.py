from pathlib import Path


def test_native_coexistence_protocol_contract():
    avlib = Path("native/windows/inc/avlib.h").read_text(encoding="utf-8")
    assert "#define AO_PROTOCOL_VERSION 2u" in avlib
    for field in (
        "CoexistenceMode", "LocalScanTimeoutMs", "MaxPendingScans",
        "PeakPendingScans", "BusyBypass", "DeliveryTimeouts",
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
    assert '"role":"independent-companion"' in service
    assert '"defender_configuration_changed":false' in service
    assert '"fail_open_on_incomplete":true' in service


def test_native_coexistence_harness_requires_defender_to_remain_active():
    script = Path("native/windows/Test-NativeCoexistence.ps1").read_text(encoding="utf-8")
    assert "Get-MpComputerStatus" in script
    assert "RealTimeProtectionEnabled" in script
    assert "WdFilter" in script
    assert "CoexistenceMode must be enabled" in script
    assert "Set-MpPreference" not in script
    assert "Add-MpPreference" not in script
    assert "Remove-MpPreference" not in script
