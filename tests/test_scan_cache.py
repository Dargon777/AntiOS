import threading
import time

from antios import antivirus
from antios.scan_cache import ScanCache


class ReadyClamProvider:
    metadata = {
        "version": "ClamAV test/42/Mon Oct  4 00:00:00 2026",
        "database_freshness": "current",
        "peer_verification_required": True,
        "peer_verified": True,
        "peer_identity": "windows-service:clamd",
    }

    def __init__(self):
        self.calls = 0
        self.closed = False

    def scan(self, content, name):
        self.calls += 1
        return 0

    def close(self):
        self.closed = True


def test_clean_cache_skips_unchanged_file_and_invalidates_on_change(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"ordinary fixture")
    cache = tmp_path / "cache.sqlite3"

    first = ReadyClamProvider()
    result1 = antivirus.scan_files(
        target,
        engine="clamav",
        provider_factory=lambda: first,
        cache_path=cache,
        workers=2,
    )
    assert result1["verdict"] == "no-threats-found"
    assert first.calls == 1
    assert result1["summary"]["cache_hits"] == 0

    second = ReadyClamProvider()
    result2 = antivirus.scan_files(
        target,
        engine="clamav",
        provider_factory=lambda: second,
        cache_path=cache,
        workers=2,
    )
    assert result2["verdict"] == "no-threats-found"
    assert second.calls == 0
    assert result2["summary"]["cache_hits"] == 1

    target.write_bytes(b"changed fixture")
    third = ReadyClamProvider()
    result3 = antivirus.scan_files(
        target,
        engine="clamav",
        provider_factory=lambda: third,
        cache_path=cache,
        workers=2,
    )
    assert third.calls == 1
    assert result3["summary"]["cache_hits"] == 0


def test_engine_identity_change_invalidates_cache(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"ordinary fixture")
    cache = tmp_path / "cache.sqlite3"

    first = ReadyClamProvider()
    antivirus.scan_files(
        target, engine="clamav", provider_factory=lambda: first, cache_path=cache
    )

    class UpdatedProvider(ReadyClamProvider):
        metadata = dict(ReadyClamProvider.metadata, version="ClamAV test/43/Mon Oct  4 00:00:00 2026")

    updated = UpdatedProvider()
    result = antivirus.scan_files(
        target, engine="clamav", provider_factory=lambda: updated, cache_path=cache
    )
    assert updated.calls == 1
    assert result["summary"]["cache_hits"] == 0


def test_clamav_workers_are_bounded_and_concurrent(tmp_path):
    for index in range(12):
        (tmp_path / f"{index}.bin").write_bytes(f"fixture-{index}".encode())

    lock = threading.Lock()
    state = {"active": 0, "peak": 0}

    class SlowProvider(ReadyClamProvider):
        def scan(self, content, name):
            with lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            try:
                time.sleep(0.02)
                return 0
            finally:
                with lock:
                    state["active"] -= 1

    provider = SlowProvider()
    result = antivirus.scan_files(
        tmp_path,
        engine="clamav",
        provider_factory=lambda: provider,
        cache_path=None,
        workers=4,
    )
    assert result["verdict"] == "no-threats-found"
    assert result["limits"]["effective_workers"] == 4
    assert 2 <= state["peak"] <= 4


def test_cache_database_prunes_and_closes(tmp_path):
    cache = ScanCache(tmp_path / "cache.sqlite3")
    cache.close()
    assert (tmp_path / "cache.sqlite3").is_file()
