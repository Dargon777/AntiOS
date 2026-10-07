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
    assert "Coexistence mode: defender-active-antios-incomplete" in rendered
    assert "Defender settings unchanged" in rendered


def test_native_coexistence_health_requires_bounded_policy(monkeypatch):
    monkeypatch.setattr(protection, "ClamAVScanner", ReadyScanner)
    monkeypatch.setattr(protection, "read_guard_state",
                        lambda: {"running": True, "state": "monitoring"})
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    monkeypatch.setattr(protection, "_native_status", lambda: {
        "available": True,
        "service": {"service_state": 4, "exit_code": 0},
        "driver": {
            "driver_available": True,
            "exit_code": 0,
            "protocol": 4,
            "enforcement": 0,
            "coexistence_mode": 1,
            "fail_open_on_incomplete": True,
            "max_pending": 4,
            "pending": 0,
            "clean_cache_ttl_ms": 30000,
            "attempts": 10,
            "incomplete": 0,
            "busy_bypass": 0,
            "section_conflicts": 0,
            "delivery_timeouts": 0,
            "completion_timeouts": 0,
            "cancelled_opens": 0,
            "cache_hits": 7,
            "cache_expired": 1,
            "cache_invalidations": 2,
            "database_generation": 28123,
            "database_generation_changes": 3,
            "max_wait_ms": 120,
        },
    })
    status = protection.collect_protection_status("clamd")
    assert status["capabilities"]["native_coexistence_ready"] is True
    assert status["capabilities"]["native_coexistence_observed_operational"] is True
    assert status["native_coexistence"]["state"] == "operational"
    assert status["capabilities"]["pre_execution_blocking"] is False
    rendered = protection.render_protection_status(status)
    assert "Native coexistence: operational" in rendered
    assert "Native clean cache: ttl=30000 ms, hits=7, expired=1, invalidations=2, db-gen=28123, db-changes=3" in rendered

    broken = status["native"]["driver"].copy()
    broken["max_pending"] = 5
    monkeypatch.setattr(protection, "_native_status", lambda: {
        "available": True,
        "service": {"service_state": 4, "exit_code": 0},
        "driver": broken,
    })
    status = protection.collect_protection_status("clamd")
    assert status["capabilities"]["native_coexistence_ready"] is False


def test_native_coexistence_timeout_is_attention_not_healthy():
    driver = {
        "driver_available": True,
        "exit_code": 0,
        "protocol": 4,
        "coexistence_mode": 1,
        "fail_open_on_incomplete": True,
        "max_pending": 4,
        "pending": 0,
        "clean_cache_ttl_ms": 30000,
        "database_generation": 28123,
        "database_generation_changes": 1,
        "attempts": 20,
        "incomplete": 1,
        "busy_bypass": 0,
        "section_conflicts": 0,
        "delivery_timeouts": 1,
        "completion_timeouts": 0,
        "cancelled_opens": 0,
        "max_wait_ms": 5000,
    }
    health = protection._native_coexistence_health(True, driver)
    assert health["configured"] is True
    assert health["observed"] is True
    assert health["state"] == "attention"
    assert "delivery-timeouts" in health["attention_reasons"]


def test_native_coexistence_reports_operational_gaps_without_calling_them_timeouts():
    driver = {
        "driver_available": True,
        "exit_code": 0,
        "protocol": 4,
        "coexistence_mode": 1,
        "fail_open_on_incomplete": True,
        "max_pending": 4,
        "pending": 0,
        "clean_cache_ttl_ms": 30000,
        "database_generation": 28123,
        "database_generation_changes": 1,
        "attempts": 25,
        "incomplete": 2,
        "busy_bypass": 1,
        "section_conflicts": 1,
        "delivery_timeouts": 0,
        "completion_timeouts": 0,
        "cancelled_opens": 0,
        "max_wait_ms": 800,
    }
    health = protection._native_coexistence_health(True, driver)
    assert health["state"] == "operational-with-gaps"
    assert health["attention_reasons"] == []



def test_defender_alone_is_not_reported_as_layered(monkeypatch):
    monkeypatch.setattr(protection, "ClamAVScanner", ReadyScanner)
    monkeypatch.setattr(protection, "read_guard_state",
                        lambda: {"running": False, "state": "not-running"})
    monkeypatch.setattr(protection, "_native_status", lambda: {"available": False})
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    status = protection.collect_protection_status("clamd")
    assert status["capabilities"]["defender_realtime_active"] is True
    assert status["capabilities"]["layered_with_defender"] is False
    assert status["coexistence"]["mode"] == "defender-active-antios-incomplete"



def test_native_coexistence_rejects_unbounded_clean_cache():
    driver = {
        "driver_available": True,
        "exit_code": 0,
        "protocol": 4,
        "coexistence_mode": 1,
        "fail_open_on_incomplete": True,
        "max_pending": 4,
        "pending": 0,
        "clean_cache_ttl_ms": 300001,
        "database_generation": 28123,
        "database_generation_changes": 1,
    }
    health = protection._native_coexistence_health(True, driver)
    assert health["configured"] is False
    assert health["state"] == "inactive/not-validated"



def test_native_coexistence_rejects_unknown_database_generation():
    driver = {
        "driver_available": True,
        "exit_code": 0,
        "protocol": 4,
        "coexistence_mode": 1,
        "fail_open_on_incomplete": True,
        "max_pending": 4,
        "pending": 0,
        "clean_cache_ttl_ms": 30000,
        "database_generation": 0,
        "database_generation_changes": 2,
    }
    health = protection._native_coexistence_health(True, driver)
    assert health["configured"] is False
    assert health["state"] == "inactive/not-validated"



def test_behavior_monitoring_is_reported_without_claiming_blocking(monkeypatch):
    monkeypatch.setattr(protection, "ClamAVScanner", ReadyScanner)
    monkeypatch.setattr(protection, "read_guard_state", lambda: {
        "running": True,
        "state": "attention",
        "behavior": {
            "state": "attention",
            "mode": "detect-only",
            "collector": "toolhelp-snapshot",
            "highest_score": 85,
            "recent_findings": 1,
        },
    })
    monkeypatch.setattr(protection, "_native_status", lambda: {"available": False})
    monkeypatch.setattr(protection, "defender_status", _active_defender)
    status = protection.collect_protection_status("clamd")
    assert status["capabilities"]["behavior_monitoring"] is True
    assert status["capabilities"]["behavior_process_visibility"] is True
    assert status["capabilities"]["pre_execution_blocking"] is False
    rendered = protection.render_protection_status(status)
    assert "Behavior monitor: attention (toolhelp-snapshot, score=85, findings=1)" in rendered
