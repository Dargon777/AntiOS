import os
import socket

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



@pytest.mark.skipif(os.name != "nt", reason="Windows SCM integration")
def test_missing_windows_service_fails_without_guessing():
    with pytest.raises(OSError):
        query_service_process("AntiOSDefinitelyMissingClamD")


@pytest.mark.skipif(os.name != "nt", reason="Windows TCP owner integration")
def test_exact_loopback_connection_is_bound_to_server_pid():
    from antios.windows_clamd_peer import verify_connected_socket

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client.connect(listener.getsockname())
        server, _ = listener.accept()
        try:
            assert verify_connected_socket(client, os.getpid())
            assert not verify_connected_socket(client, os.getpid() + 100000)
        finally:
            server.close()
    finally:
        client.close()
        listener.close()
