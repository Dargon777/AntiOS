"""Adversarial fixtures for the independent, read-only AntiOS Engine.

All payloads are inert test bytes; no malware or external services required.
"""
import hashlib
import io
import zipfile

import pytest

from antios import engine
from antios.engine import AntiOSEngine
from antios.engine_types import ScanOutcome


def zipped(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return out.getvalue()


def test_signature_is_confirmed_even_when_wrapped_in_archive():
    payload = b"inert nested signature fixture"
    signature = hashlib.sha256(payload).hexdigest()
    scanner = AntiOSEngine(signatures={signature: "Inert test rule"})
    result = scanner.scan(zipped({"folder/inner.bin": payload}), "outer.zip")
    assert result.kind == "threat"
    assert result.name == "Inert test rule"
    assert result.engine == scanner.name


def test_bad_zip_returns_review_and_incomplete():
    result = AntiOSEngine().scan(b"PK\x03\x04invalid zip data", "archive.zip")
    assert result.kind == "review"
    assert not result.complete


def test_zip_entry_count_budget_precedes_decompression(monkeypatch):
    monkeypatch.setattr(engine, "MAX_ARCHIVE_MEMBERS", 2)
    data = zipped({"a.txt": b"one", "b.txt": b"two", "c.txt": b"three"})
    outcome = AntiOSEngine().scan(data, "three-files.zip")
    assert outcome.kind == "review"
    assert not outcome.complete


def test_zip_traversal_path_review_never_writes_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    package = zipped({"../../outside.txt": b"inert"})
    result = AntiOSEngine().scan(package, "attempt.zip")
    assert result.kind == "review"
    assert not (tmp_path / "outside.txt").exists()


def test_zip_decompression_ratio_limit_is_incomplete():
    data = zipped({"filler.txt": b"x" * 100_000})
    result = AntiOSEngine().scan(data, "large-ratio.zip")
    assert result.kind == "review"
    assert not result.complete


def test_nested_zip_depth_budget_is_conservative():
    data = zipped({"nested.zip": zipped({"deep.zip": zipped({"x": b"plain"})})})
    result = AntiOSEngine().scan(data, "outer.zip")
    assert result.kind == "review"
    assert not result.complete


@pytest.mark.parametrize("sample,filename", [
    (b"invoke-expression downloadstring('inert')", "example.ps1"),
    (b"frombase64string('a')\nset-mppreference -disable", "example.ps1"),
    (b"iex('inert')\ndownloadfile('inert')", "example.ps1"),
])
def test_script_multi_signal_is_advisory_not_threat(sample, filename):
    result = AntiOSEngine().scan(sample, filename)
    assert result.kind == "review"
    assert result.engine == "AntiOS Engine"
    assert result.complete


def test_single_script_signal_is_not_a_confirmed_threat():
    result = AntiOSEngine().scan(b"invoke-expression 'fixture'", "sample.ps1")
    assert result.kind is None


def test_truncated_pe_is_incomplete_review():
    result = AntiOSEngine().scan(b"MZ" + b"\x00" * 20, "sample.exe")
    assert result.kind == "review"
    assert not result.complete


def test_non_archive_without_signature_has_no_detections():
    result = AntiOSEngine().scan(b"benign fixture", "example.txt")
    assert result.kind is None
    assert result.complete


def test_large_stream_is_not_misreported_as_fully_scanned():
    scanner = AntiOSEngine()
    payload = b"a" * (engine.STREAM_PREVIEW_BYTES + 1)
    outcome = scanner.scan_stream_named(iter((payload,)), "sample.bin")
    assert not outcome.complete
    assert outcome.kind is None


def test_engine_does_not_require_network_or_external_providers(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection",
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("network call")))
    assert AntiOSEngine().scan(b"inert content", "fixture").complete
