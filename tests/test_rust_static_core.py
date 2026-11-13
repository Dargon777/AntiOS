import hashlib
import io
import os
from pathlib import Path
import struct
import zipfile

import pytest

from antios import engine
from antios.antivirus import scan_files
from antios.rust_static_core import RustStaticCore
from antios.scan_verdict import replay_scan_report


@pytest.fixture
def rust_core():
    path = os.environ.get("ANTIOS_TEST_RUST_LIBRARY")
    if not path:
        pytest.skip("ANTIOS_TEST_RUST_LIBRARY is unset")
    return RustStaticCore(Path(path))


def _pe():
    content = bytearray(144 + 4096)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 60, 64)
    content[64:68] = b"PE\0\0"
    struct.pack_into("<H", content, 70, 1)
    struct.pack_into("<H", content, 84, 2)
    struct.pack_into("<II12xI", content, 106, 4096, 144, 0xA0000000)
    content[144:] = bytes(range(256)) * 16
    return bytes(content)


def _elf(endian):
    content = bytearray(64)
    content[:7] = b"\x7fELF\x02" + bytes([1 if endian == "<" else 2, 1])
    struct.pack_into(endian + "H", content, 52, 64)
    return bytes(content)


def test_native_hash_and_static_result_parity(rust_core, monkeypatch):
    monkeypatch.setattr(engine, "load_static_core", lambda: rust_core)
    native = engine.AntiOSEngine()
    pe = _pe()
    script = "# -encodedcommand IEX  (\n"
    inputs = [(b"", "empty"), (b"a\0b", "bytes"), (script.encode(), "sample.PS1"),
              (b"\xff\xfe" + script.encode("utf-16-le"), "sample.ps1"),
              (b"\xfe\xff" + script.encode("utf-16-be"), "sample.js"),
              (b"# -encodedcommand _iex (", "sample.ps1"),
              (b" " * (16 * 1024 * 1024 + 1), "long.ps1")]
    inputs += [(pe[:size], "header.bin") for size in (2, 63, 65, 100, 129, 130, len(pe))]
    inputs += [(data[:size], "header.bin") for data in (_elf("<"), _elf(">")) for size in (5, 20, 63, 64)]
    assert native._static_signal(pe, "header.bin").rule_id == "executable.unusual-pe-section"
    for data, name in inputs:
        expected = engine._preferred(engine._script_signal(data, name), engine._executable_signal(data))
        assert native._static_signal(data, name) == expected
        assert native.hash_content(data) == hashlib.sha256(data).hexdigest()
    assert native.metadata["static_core"] == "rust"


def test_scan_receipt_matches_with_native_core_and_archives(rust_core, monkeypatch, tmp_path):
    (tmp_path / "file.bin").write_bytes(_pe())
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("inert.ps1", b"# -encodedcommand IEX (")
    (tmp_path / "archive.zip").write_bytes(archive.getvalue())
    monkeypatch.setattr(engine, "load_static_core", lambda: None)
    expected = scan_files(tmp_path, use_cache=False)
    monkeypatch.setattr(engine, "load_static_core", lambda: rust_core)
    actual = scan_files(tmp_path, use_cache=False)
    assert actual["engine"]["static_core"] == "rust"
    assert actual["findings"] == expected["findings"]
    assert actual["coverage_contract"] == expected["coverage_contract"]
    assert replay_scan_report(actual) == replay_scan_report(expected)


def test_native_error_switches_to_python(monkeypatch, tmp_path):
    class RejectedCore:
        def digest(self, data):
            raise ValueError("Rejected")

    target = tmp_path / "file.exe"
    target.write_bytes(b"MZ")
    monkeypatch.setattr(engine, "load_static_core", lambda: RejectedCore())
    report = scan_files(target, use_cache=False)
    assert report["engine"]["static_core"] == "python"
    assert report["engine"]["static_core_fallback"] is True
    assert report["coverage_contract"]["file_gaps"] == {"invalid-pe-header": 1}
