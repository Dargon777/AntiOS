from antios import protection


class ReadyScanner:
    metadata = {
        "version": "ClamAV test",
        "database_freshness": "current",
        "peer_verification_required": True,
        "peer_verified": True,
        "peer_identity": "windows-service:clamd",
    }

    def __init__(self, **kwargs):
        pass

    def close(self):
        pass


def _active_defender():
    return {
        "available": True,
        "running_mode": "Normal",
        "antivirus_enabled": True,
        "real_time_protection_enabled": True,
        "realtime_active": True,
    }


def test_status_requires_every_runtime_layer_for_blocking(monkeypatch):
    monkeypatch.setattr(protection, "ClamAVScanner", ReadyScanner)
    monkeypatch.setattr(protection, "read_guard_state",
                        lambda: {"running": True, "state": "monitoring"})
    monkeypatch.setattr(protection, "_native_status", lambda: {
        "available": True,
        "service": {"service_state": 4, "exit_code": 0},
        "driver": {"driver_available": True, "enforcement": 1, "exit_code": 0},
    })
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    status = protection.collect_protection_status("clamd")
    assert status["capabilities"]["standalone_detection_engine"]
    assert status["capabilities"]["resident_post_write_detection"]
    assert status["capabilities"]["pre_execution_blocking"]
    assert status["capabilities"]["defender_realtime_active"]
    assert status["capabilities"]["layered_with_defender"]
    assert status["coexistence"]["mode"] == "layered"
    assert status["coexistence"]["primary_antivirus_registration"] is False
    assert status["production_primary_antivirus"] is False
    assert "windows-security-center-registration" in status["remaining_gates"]


def test_degraded_engine_never_becomes_protected(monkeypatch):
    class StaleScanner(ReadyScanner):
        metadata = dict(ReadyScanner.metadata, database_freshness="stale")

    monkeypatch.setattr(protection, "ClamAVScanner", StaleScanner)
    monkeypatch.setattr(protection, "read_guard_state",
                        lambda: {"running": True, "state": "monitoring"})
    monkeypatch.setattr(protection, "_native_status", lambda: {
        "service": {"service_state": 4, "exit_code": 0},
        "driver": {"driver_available": True, "enforcement": 1, "exit_code": 0},
    })
    monkeypatch.setattr(protection, "defender_status", lambda: {"available": False})
    status = protection.collect_protection_status()
    assert not status["capabilities"]["standalone_detection_engine"]
    assert not status["capabilities"]["resident_post_write_detection"]
    assert not status["capabilities"]["pre_execution_blocking"]


def test_render_does_not_claim_primary_registration(monkeypatch):
    monkeypatch.setattr(protection, "ClamAVScanner", ReadyScanner)
    monkeypatch.setattr(protection, "read_guard_state",
                        lambda: {"running": False, "state": "not-running"})
    monkeypatch.setattr(protection, "_native_status", lambda: {"available": False})
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    rendered = protection.render_protection_status(protection.collect_protection_status())
    assert "Primary Windows antivirus registration: not claimed" in rendered
    assert "Coexistence mode: layered" in rendered
    assert "Defender settings unchanged" in rendered
