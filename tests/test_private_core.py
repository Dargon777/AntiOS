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


def test_protection_ignores_legacy_private_core_even_when_it_claims_enforcement(monkeypatch):
    """No unverified sidecar may override the bundled engine's capabilities."""
    from antios import protection
    legacy = {"schema": 1, "kind": "antios-protection-status",
              "capabilities": {"pre_execution_blocking": True}}
    monkeypatch.setattr(private_core, "invoke_private_core",
                        lambda *_args, **_kwargs: legacy)
    monkeypatch.setattr(protection, "read_guard_state",
                        lambda: {"state": "not-running", "running": False})
    monkeypatch.setattr(protection, "defender_status",
                        lambda: {"available": False})
    result = protection.collect_protection_status("managed")
    assert result["engine"]["version"].startswith("AntiOS Engine/")
    assert result["capabilities"]["pre_execution_blocking"] is False
    assert result["production_primary_antivirus"] is False


def test_local_engine_status_is_fail_closed_when_its_signatures_fail(monkeypatch):
    from antios import protection
    def fail():
        raise ValueError("corrupt native signature database")
    monkeypatch.setattr(protection, "load_signatures", fail)
    monkeypatch.setattr(protection, "read_guard_state",
                        lambda: {"state": "not-running", "running": False})
    monkeypatch.setattr(protection, "defender_status",
                        lambda: {"available": False})
    result = protection.collect_protection_status()
    assert result["engine"]["available"] is False
    assert result["capabilities"]["standalone_detection_engine"] is False
    assert result["capabilities"]["pre_execution_blocking"] is False
