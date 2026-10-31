from __future__ import annotations

import json
import subprocess

import pytest

from antios import private_core, protection


def _core_file(tmp_path):
    path = tmp_path / "AntiOS-Core.exe"
    path.write_bytes(b"test")
    return path


def test_private_core_rejects_unknown_operation_before_launch(monkeypatch, tmp_path):
    core = _core_file(tmp_path)
    monkeypatch.setattr(private_core, "_resolve_core_path", lambda: core)

    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not be started")

    monkeypatch.setattr(private_core.subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="Unsupported private-core operation"):
        private_core.invoke_private_core("internal.anything", {})

    assert called is False


def test_private_core_round_trip_is_request_bound(monkeypatch, tmp_path):
    core = _core_file(tmp_path)
    monkeypatch.setattr(private_core, "_resolve_core_path", lambda: core)

    def fake_run(args, **kwargs):
        request = json.loads(kwargs["input"].decode("utf-8"))
        assert args == [str(core), "--stdio-rpc"]
        assert request["schema"] == private_core.INTERFACE_VERSION
        assert request["operation"] == "core.ping"
        response = {
            "schema": private_core.INTERFACE_VERSION,
            "request_id": request["request_id"],
            "ok": True,
            "result": {"pong": True},
        }
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=json.dumps(response).encode("utf-8"),
            stderr=b"",
        )

    monkeypatch.setattr(private_core.subprocess, "run", fake_run)
    assert private_core.invoke_private_core("core.ping") == {"pong": True}


def test_private_core_rejects_mismatched_response(monkeypatch, tmp_path):
    core = _core_file(tmp_path)
    monkeypatch.setattr(private_core, "_resolve_core_path", lambda: core)

    def fake_run(args, **kwargs):
        response = {
            "schema": private_core.INTERFACE_VERSION,
            "request_id": "not-the-request",
            "ok": True,
            "result": {},
        }
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=json.dumps(response).encode("utf-8"),
            stderr=b"",
        )

    monkeypatch.setattr(private_core.subprocess, "run", fake_run)
    with pytest.raises(private_core.PrivateCoreProtocolError, match="does not match"):
        private_core.invoke_private_core("core.ping")


def test_protection_prefers_private_core(monkeypatch):
    private_status = {
        "schema": 1,
        "kind": "antios-protection-status",
        "capabilities": {
            "standalone_detection_engine": True,
            "pre_execution_blocking": True,
        },
        "production_primary_antivirus": False,
        "remaining_gates": [],
    }

    def fake_invoke(operation, payload, *, timeout_seconds):
        assert operation == "protection.status"
        assert payload == {"engine_service": "managed"}
        assert timeout_seconds == 10
        return private_status

    class MustNotRunScanner:
        def __init__(self, **kwargs):
            raise AssertionError("open-core scanner must not run when private core answered")

    monkeypatch.setattr(protection, "invoke_private_core", fake_invoke)
    monkeypatch.setattr(protection, "ClamAVScanner", MustNotRunScanner)

    status = protection.collect_protection_status("managed")
    assert status["private_core"] == {
        "active": True,
        "interface": private_core.INTERFACE_VERSION,
    }
    assert status["capabilities"]["pre_execution_blocking"] is True


def test_invalid_private_status_falls_back_to_open_core(monkeypatch):
    monkeypatch.setattr(
        protection,
        "invoke_private_core",
        lambda *args, **kwargs: {"schema": 1, "kind": "wrong", "capabilities": {}},
    )

    class ReadyScanner:
        metadata = {
            "version": "test",
            "database_freshness": "current",
            "peer_verification_required": False,
        }

        def __init__(self, **kwargs):
            pass

        def close(self):
            pass

    monkeypatch.setattr(protection, "ClamAVScanner", ReadyScanner)
    monkeypatch.setattr(
        protection,
        "read_guard_state",
        lambda: {"running": False, "state": "not-running"},
    )
    monkeypatch.setattr(protection, "_managed_runtime_status", lambda: {"available": False})
    monkeypatch.setattr(protection, "_native_status", lambda: {"available": False})
    monkeypatch.setattr(protection, "defender_status", lambda: {"available": False})
    monkeypatch.setattr(
        protection,
        "coexistence_profile",
        lambda defender: {
            "mode": "independent-companion",
            "primary_antivirus_registration": False,
        },
    )
    monkeypatch.setattr(
        protection,
        "amsi_provider_status",
        lambda: {"available": False, "registered": False, "module_exists": False},
    )

    status = protection.collect_protection_status()
    assert status["kind"] == "antios-protection-status"
    assert "private_core" not in status
