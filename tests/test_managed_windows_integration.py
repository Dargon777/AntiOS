"""Exercise the installed engine on a disposable Windows acceptance runner."""
import os
import threading
import time

import pytest

from antios.clamav import ClamAVScanner
from antios.guard import Guard, GuardPolicy
from antios.guard_state import read_guard_state
from antios.scan_process import run_scan_process


pytestmark = pytest.mark.skipif(
    os.name != "nt" or os.environ.get("ANTIOS_TEST_MANAGED") != "1",
    reason="Requires the managed engine on a disposable Windows acceptance runner",
)


def test_installed_engine_scans_large_file_in_worker(tmp_path):
    small = tmp_path / "ordinary.txt"
    small.write_bytes(b"AntiOS benign acceptance document")
    large = tmp_path / "large.bin"
    with large.open("wb") as stream:
        stream.truncate(33 * 1024 * 1024)
    result = run_scan_process(tmp_path, engine_service="clamd", require_verified_peer=True,
                              use_cache=False, timeout=120)
    assert result["verdict"] == "no-threats-found", result
    assert result["summary"]["provider_scanned"] == 2, result
    assert result["summary"]["bytes_scanned"] == large.stat().st_size + small.stat().st_size
    assert result["summary"]["cache_hits"] == 0
    assert result["engine"]["peer_verified"] is True


def test_installed_engine_recognizes_standard_test_in_memory():
    # Standard harmless EICAR test. Keep it in memory so another antivirus
    # cannot quarantine the fixture before AntiOS submits it to the engine.
    sample = bytes.fromhex(
        "58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d"
        "5354414e444152442d414e544956495255532d544553542d46494c452124482b482a"
    )
    engine = ClamAVScanner(service_name="clamd", require_verified_peer=True)
    try:
        outcome = engine.scan(sample, "standard-in-memory-test")
        assert outcome.kind == "threat", outcome
        assert "eicar" in outcome.name.lower(), outcome
    finally:
        engine.close()


def test_user_facing_self_check_with_installed_engine():
    from antios.protection_check import run_checks
    report = run_checks()
    states = {item["id"]: item["state"] for item in report["checks"]}
    for name in ("engine", "database", "benign-scan", "test-detection", "recovery"):
        assert states[name] == "passed", report
    assert report["status"] in {"passed", "attention"}, report


def test_resident_guard_scans_and_saves_history_with_installed_engine(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    state = tmp_path / "state"
    guard = Guard(GuardPolicy((watched,), interval=0.1, settle=0.1, engine_service="clamd"), state)
    stop, failures = threading.Event(), []

    def run():
        try:
            guard.run(stop)
        except Exception as exc:
            failures.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        target = watched / "new.txt"
        target.write_text("ordinary benign document", encoding="utf-8")
        deadline = time.monotonic() + 45
        while not (guard.status["scanned"] >= 1 and guard.status["state"] == "monitoring"):
            assert not failures, failures
            assert time.monotonic() < deadline, guard.status
            time.sleep(0.05)
        assert guard.status["engine"]["peer_verified"] is True
        assert target.read_text(encoding="utf-8") == "ordinary benign document"
    finally:
        stop.set()
        thread.join(15)
    assert not thread.is_alive()
    assert not failures
    saved = read_guard_state(state, history=True)
    assert saved["state"] == "stopped", saved
    assert saved["scanned"] >= 1, saved
