"""Read-only format controls. Every known-match fixture is inert text."""
import hashlib
import gzip
import io
import lzma
import stat
import struct
import tarfile
import zipfile

import pytest

from antios import engine
from antios.engine_types import ScanOutcome


_FIXTURE = b"AntiOS inert signature fixture"


def _scanner():
    return engine.AntiOSEngine(signatures={hashlib.sha256(_FIXTURE).hexdigest(): "Inert control"})


def _ar_entry(name, data):
    header = b"".join((
        name.ljust(16), b"0".ljust(12), b"0".ljust(6), b"0".ljust(6),
        b"100644".ljust(8), str(len(data)).encode().ljust(10), b"\x60\n",
    ))
    return header + data + b"\n" * (len(data) % 2)


def _tar(name, data, *, archive_format=tarfile.USTAR_FORMAT, pax_headers=None, entry_headers=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=archive_format, pax_headers=pax_headers) as archive:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        if entry_headers:
            info.pax_headers.update(entry_headers)
        archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


@pytest.mark.parametrize("archive_format", [tarfile.PAX_FORMAT, tarfile.GNU_FORMAT])
def test_tar_extended_names_find_members_and_keep_clean_coverage(archive_format, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    name = "long-folder/" + "document-" * 13 + ".txt"
    for data, expected in ((_FIXTURE, ScanOutcome("threat", "Inert control")), (b"ordinary", ScanOutcome())):
        content = _tar(name, data, archive_format=archive_format)
        assert _scanner().scan(content, "renamed") == expected
        assert _scanner().scan(gzip.compress(content, mtime=0), "controls.tgz") == expected
    assert not list(tmp_path.iterdir())


def test_tar_pax_global_metadata_and_per_entry_name():
    content = _tar("sample", b"ordinary", archive_format=tarfile.PAX_FORMAT,
                   pax_headers={"comment": "ordinary archive"},
                   entry_headers={"path": "../parent.txt", "mtime": "123.5", "size": "8"})
    outcome = _scanner().scan(content, "fixture.tar")
    assert outcome.rule_id == "archive.suspicious-entry-path"
    assert outcome.complete


def test_tar_extended_metadata_shares_inspection_budget(monkeypatch):
    content = _tar("q" * 101, _FIXTURE, archive_format=tarfile.PAX_FORMAT)
    monkeypatch.setattr(engine, "MAX_ARCHIVE_DIRECTORY_BYTES", 16)
    outcome = _scanner().scan(content, "fixture.tar")
    assert outcome.coverage_gaps == {"archive-budget-exceeded"}
    assert outcome.kind != "threat"


def test_tar_extended_metadata_without_member_has_incomplete_coverage():
    content = _tar("q" * 101, _FIXTURE, archive_format=tarfile.PAX_FORMAT)
    metadata = content[:2 * tarfile.BLOCKSIZE] + bytes(2 * tarfile.BLOCKSIZE)
    assert _scanner().scan(metadata, "fixture.tar").coverage_gaps == {"unreadable-archive"}


def test_tar_pax_keeps_unsupported_field_incomplete():
    content = _tar("sample", _FIXTURE, archive_format=tarfile.PAX_FORMAT,
                   entry_headers={"vendor.extension": "opaque metadata"})
    outcome = _scanner().scan(content, "fixture.tar")
    assert outcome.coverage_gaps == {"unsupported-archive-entry"}
    assert outcome.kind != "threat"


def _cpio_entry(name, data=b"", *, mode=stat.S_IFREG | 0o644, checksum=None):
    filename = name.encode() + b"\x00"
    numbers = (1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(filename), checksum or 0)
    header = (b"070701" if checksum is None else b"070702") + b"".join(b"%08x" % field for field in numbers)
    framed = header + filename
    return framed + bytes((-len(framed)) % 4) + data + bytes((-len(data)) % 4)


def test_ar_deb_and_long_names_find_member():
    scanner = _scanner()
    content = b"!<arch>\n" + _ar_entry(b"debian-binary/", b"2.0\n") + _ar_entry(b"data.tar/", _tar("sample", _FIXTURE))
    assert scanner.scan(content, "sample.deb") == ScanOutcome("threat", "Inert control")
    long = b"long-archive-member-name.txt"
    gnu = b"!<arch>\n" + _ar_entry(b"//", long + b"/\n") + _ar_entry(b"/0", _FIXTURE)
    bsd = b"!<arch>\n" + _ar_entry(b"#1/" + str(len(long)).encode(), long + _FIXTURE)
    for content in (gnu, bsd):
        assert scanner.scan(content, "renamed-file") == ScanOutcome("threat", "Inert control")
        assert engine.AntiOSEngine().scan(content, "renamed-file") == ScanOutcome()
    assert "unreadable-archive" in scanner.scan(gnu[:-2], "sample.ar").coverage_gaps


def test_cpio_validates_crc_and_reports_links():
    entry = _cpio_entry("sample", _FIXTURE, checksum=sum(_FIXTURE))
    trailer = _cpio_entry("TRAILER!!!", mode=0)
    assert _scanner().scan(entry + trailer, "renamed") == ScanOutcome("threat", "Inert control")
    assert engine.AntiOSEngine().scan(entry + trailer, "sample.cpio") == ScanOutcome()
    wrong = _cpio_entry("sample", _FIXTURE, checksum=1) + trailer
    assert "unreadable-archive-entry" in _scanner().scan(wrong, "sample.cpio").coverage_gaps
    missing_trailer = engine.AntiOSEngine().scan(entry, "sample.cpio")
    assert "unreadable-archive" in missing_trailer.coverage_gaps
    link = _cpio_entry("link", b"sample", mode=stat.S_IFLNK | 0o777)
    assert "archive-link-skipped" in _scanner().scan(link + trailer, "sample.cpio").coverage_gaps


def test_linear_archives_share_nested_budgets(monkeypatch):
    monkeypatch.setattr(engine, "MAX_ARCHIVE_MEMBERS", 1)
    content = b"!<arch>\n" + _ar_entry(b"data.tar/", _tar("sample", _FIXTURE))
    assert "archive-budget-exceeded" in _scanner().scan(content, "sample.deb").coverage_gaps


def test_rpm_payload_detects_inner_member_but_declares_metadata_gap():
    cpio = _cpio_entry("sample", _FIXTURE) + _cpio_entry("TRAILER!!!", mode=0)
    lead = b"\xed\xab\xee\xdb\x03\x00" + bytes(90)
    header = b"\x8e\xad\xe8\x01" + bytes(12)
    fixture = lead + header * 2 + gzip.compress(cpio, mtime=0)
    report = _scanner().scan(fixture, "renamed")
    assert report.kind == "threat" and report.coverage_gaps == {"rpm-metadata-not-inspected"}
    assert "unreadable-archive" in _scanner().scan(fixture[:110], "sample.rpm").coverage_gaps


def test_standalone_lzma_detects_inner_member():
    content = lzma.compress(_FIXTURE, format=lzma.FORMAT_ALONE)
    assert _scanner().scan(content, "sample.lzma").kind == "threat"
    assert "unreadable-archive" in _scanner().scan(content[:-2], "sample.lzma").coverage_gaps


def test_zstd_standalone_tar_and_deb(tmp_path, monkeypatch):
    if engine.zstd is None:
        pytest.skip("Zstandard decoder unavailable")
    monkeypatch.chdir(tmp_path)
    scanner = _scanner()
    compressed = engine.zstd.compress(_FIXTURE)
    assert scanner.scan(compressed, "renamed").kind == "threat"
    assert engine.AntiOSEngine().scan(compressed, "ordinary.zst") == ScanOutcome()
    tar_zstd = engine.zstd.compress(_tar("sample", _FIXTURE))
    assert scanner.scan(tar_zstd, "sample.tzst").kind == "threat"
    deb = b"!<arch>\n" + _ar_entry(b"debian-binary/", b"2.0\n") + _ar_entry(b"data.tar.zst/", tar_zstd)
    assert scanner.scan(deb, "sample.deb") == ScanOutcome("threat", "Inert control")
    assert not list(tmp_path.iterdir())
    assert "unreadable-archive" in scanner.scan(compressed[:-2], "broken.zst").coverage_gaps
    assert "uninspected-compressed-data" in scanner.scan(compressed * 2, "multiple.zst").coverage_gaps
    skippable = b"\x50\x2a\x4d\x18" + struct.pack("<I", len(_FIXTURE)) + _FIXTURE
    assert "uninspected-compressed-data" in scanner.scan(skippable, "renamed").coverage_gaps
    oversized = engine.zstd.compress(b"\x00" * 1_000_000)
    assert "archive-budget-exceeded" in scanner.scan(oversized, "large.zst").coverage_gaps


def _custom_zip(encoded, method, payload):
    """Replace an ordinary local member's encoded bytes and both compression fields."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("sample", payload)
    data = bytearray(output.getvalue())
    central = data.index(b"PK\x01\x02")
    eocd = data.index(b"PK\x05\x06")
    struct.pack_into("<H", data, 8, method)
    struct.pack_into("<H", data, central + 10, method)
    struct.pack_into("<I", data, 18, len(encoded))
    struct.pack_into("<I", data, central + 20, len(encoded))
    struct.pack_into("<I", data, eocd + 16, central - len(payload) + len(encoded))
    data[central - len(payload):central] = encoded
    return bytes(data)


@pytest.mark.parametrize("method", [20, 93])
def test_zip_zstandard_is_bounded_and_checks_crc(method):
    if engine.zstd is None:
        pytest.skip("Zstandard decoder unavailable")
    encoded = engine.zstd.compress(_FIXTURE)
    assert _scanner().scan(_custom_zip(encoded, method, _FIXTURE), "app.msix").kind == "threat"
    bad = _custom_zip(encoded, method, b"x" * len(_FIXTURE))
    assert "unreadable-archive-entry" in _scanner().scan(bad, "app.zip").coverage_gaps
    malformed_size = _custom_zip(encoded, method, b"x")
    assert "unreadable-archive-entry" in _scanner().scan(malformed_size, "app.zip").coverage_gaps


def test_zip_lzma_respects_dictionary_cap():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_LZMA) as archive:
        archive.writestr("sample", _FIXTURE)
    data = bytearray(output.getvalue())
    assert _scanner().scan(bytes(data), "sample.zip").kind == "threat"
    struct.pack_into("<I", data, 30 + len("sample") + 5, 128 * 1024 * 1024)
    assert "unreadable-archive-entry" in _scanner().scan(bytes(data), "sample.zip").coverage_gaps


@pytest.mark.parametrize("suffix", [".docx", ".odt", ".apk", ".jar", ".msix", ".whl", ".epub"])
def test_malformed_common_zip_container_has_coverage_gap(suffix):
    result = engine.AntiOSEngine().scan(b"inert malformed container", "download" + suffix)
    assert "archive-directory-unavailable" in result.coverage_gaps


def test_zip_symlink_is_skipped():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, _FIXTURE)
    outcome = _scanner().scan(output.getvalue(), "archive.zip")
    assert outcome.kind == "review"
    assert "archive-link-skipped" in outcome.coverage_gaps


def test_zstd_missing_decoder_is_not_clean(monkeypatch):
    monkeypatch.setattr(engine, "zstd", None)
    assert "unsupported-archive-compression" in _scanner().scan(engine._ZSTD_MAGIC, "fixture.zst").coverage_gaps
