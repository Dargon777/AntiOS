"""Offline regressions for the opt-in AntiOS unified scan mode."""
from __future__ import annotations

import hashlib
import json
import tracemalloc

import pytest

from antios import antivirus
from antios.clamav import ScanOutcome
from antios.unified_engine import UnifiedScanner


class FakeClamAV:
    metadata = {"version": "ClamAV test", "database_freshness": "current"}

    def __init__(self, **_kwargs):
        self.closed = False

    def scan(self, content, _name):
        if b"clam-threat" in content:
            return ScanOutcome("threat", "Inert ClamAV fixture")
        if b"clam-review" in content:
            return ScanOutcome("review", "Inert review fixture")
        return ScanOutcome()

    def scan_stream(self, chunks):
        for _ in chunks:
            pass
        return ScanOutcome()

    def close(self):
        self.closed = True


class FakeAMSI:
    def scan(self, content, _name):
        return 32768 if b"amsi-threat" in content else 0

    def close(self):
        pass


def scanner(*, use_amsi=True, clamav_factory=FakeClamAV, amsi_factory=FakeAMSI):
    return UnifiedScanner(
        clamav_factory=clamav_factory,
        amsi_factory=amsi_factory,
        use_amsi=use_amsi,
    )


def test_unified_scan_merges_provider_findings_without_writing_to_file(tmp_path):
    target = tmp_path / "fixture"
    target.write_bytes(b"clam-review amsi-threat")
    original = target.read_bytes(), target.stat().st_mtime_ns
    result = antivirus.scan_files(
        target, engine="antios", provider_factory=scanner, use_cache=False
    )
    assert result["verdict"] == "threats-found"
    assert result["coverage"] == "antios-unified-and-signatures"
    assert result["findings"][0]["engine"] == "Windows AMSI"
    assert result["summary"]["provider_scanned"] == 1
    assert (target.read_bytes(), target.stat().st_mtime_ns) == original


def test_unified_clean_needs_all_required_providers(tmp_path):
    target = tmp_path / "safe.txt"
    target.write_bytes(b"benign fixture")
    complete = antivirus.scan_files(target, engine="antios", provider_factory=scanner)
    assert complete["verdict"] == "no-threats-found"

    def missing_amsi():
        raise OSError("not installed")

    incomplete = antivirus.scan_files(
        target, engine="antios",
        provider_factory=lambda: scanner(amsi_factory=missing_amsi),
    )
    assert incomplete["verdict"] == "incomplete"
    assert incomplete["coverage"] == "limited"
    assert incomplete["engine"]["components"]["amsi"] is False


def test_unified_keeps_amsi_detection_when_clamav_fails(tmp_path):
    class BrokenClam(FakeClamAV):
        def scan(self, _content, _name):
            raise OSError("deliberate provider failure")

    target = tmp_path / "suspicious"
    target.write_bytes(b"amsi-threat")
    result = antivirus.scan_files(
        target, engine="antios",
        provider_factory=lambda: scanner(clamav_factory=BrokenClam),
    )
    assert result["verdict"] == "threats-found"
    assert result["coverage"] == "limited"
    assert result["findings"][0]["engine"] == "Windows AMSI"
    assert result["summary"]["errors"] == 1


def test_stream_only_coverage_is_not_misreported_as_full():
    mixed = scanner(use_amsi=True)
    assert not mixed.scan_stream([b"arbitrary bytes"]).complete
    mixed.close()
    clam_only = scanner(use_amsi=False)
    assert clam_only.scan_stream([b"arbitrary bytes"]).complete
    clam_only.close()


def test_local_sha256_remains_a_detection_source(tmp_path):
    target = tmp_path / "local-fixture"
    target.write_bytes(b"inert signature fixture")
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({
        "schema": 1,
        "sha256": {hashlib.sha256(target.read_bytes()).hexdigest(): "Local signature"},
    }))
    result = antivirus.scan_files(
        target, engine="antios", signature_path=database,
        provider_factory=scanner,
    )
    assert result["findings"][0]["engine"] == "SHA-256"


def test_small_file_does_not_allocate_entire_read_limit(tmp_path):
    target = tmp_path / "tiny"
    target.write_bytes(b"x" * 1024)
    tracemalloc.start()
    try:
        payload, _info = antivirus.read_regular(target, 64 * 1024 * 1024)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(payload) == 1024
    assert peak < 8 * 1024 * 1024
