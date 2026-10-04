import os

import pytest

from antios.windows_clamd_peer import (
    configured_service_name,
    query_service_process,
    validate_service_name,
)


@pytest.mark.parametrize("name", ["clamd", "AntiOSClamD", "clamd_1", "CLAM-D"])
def test_service_name_validation_accepts_bounded_scm_names(name):
    assert validate_service_name(name) == name


@pytest.mark.parametrize("name", ["", "bad service", "../clamd", "x" * 81, "clamd.exe"])
def test_service_name_validation_rejects_ambiguous_values(name):
    with pytest.raises(ValueError):
        validate_service_name(name)


def test_explicit_binding_precedes_environment(monkeypatch):
    monkeypatch.setenv("ANTIOS_CLAMD_SERVICE", "EnvironmentClamD")
    assert configured_service_name("PolicyClamD") == "PolicyClamD"


def test_environment_binding_is_available_cross_platform(monkeypatch):
    monkeypatch.setenv("ANTIOS_CLAMD_SERVICE", "EnvironmentClamD")
    assert configured_service_name() == "EnvironmentClamD"


@pytest.mark.skipif(os.name == "nt", reason="non-Windows contract")
def test_scm_query_never_falls_back_to_guessing_off_windows():
    with pytest.raises(OSError, match="only on Windows"):
        query_service_process("clamd")
