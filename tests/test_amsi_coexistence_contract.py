from pathlib import Path


def test_amsi_provider_contract_is_secondary_and_signed_only():
    provider = Path("native/windows/amsi/provider.cpp").read_text(encoding="utf-8")
    installer = Path("native/windows/amsi/Install-AmsiProvider.ps1").read_text(encoding="utf-8")
    build = Path("native/windows/build.ps1").read_text(encoding="utf-8")

    assert "IAntimalwareProvider" in provider
    assert "AMSI_RESULT_DETECTED" in provider
    assert "AMSI_RESULT_NOT_DETECTED" in provider
    assert "ao_engine_scan" in provider
    assert "SOFTWARE\\AntiOS" in provider
    assert "WSC" not in provider

    assert "valid Authenticode signature" in installer
    assert "AMSI\\Providers" in installer
    assert "FeatureBits" in installer
    assert "unchanged" in installer
    assert "Set-MpPreference" not in installer
    assert "DisableRealtimeMonitoring" not in installer

    assert "'Amsi'" in build
    assert "AntiOS-AmsiProvider.dll" in build


def test_coexistence_docs_forbid_primary_registration_and_defender_changes():
    text = Path("docs/COEXISTENCE.md").read_text(encoding="utf-8")
    assert "does not disable, stop or reconfigure Microsoft Defender" in text
    assert "does not write fake Windows Security Center antivirus registration" in text
    assert "does not add Defender exclusions" in text
